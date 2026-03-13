use crate::error::JacsError;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Set secure file permissions on key files (Unix only)
/// Private keys get 0600 (owner read/write), directories get 0700 (owner rwx)
#[cfg(unix)]
fn set_secure_permissions(path: &str, is_directory: bool) -> Result<(), JacsError> {
    use std::fs;
    use std::path::Path;

    let path = Path::new(path);
    if !path.exists() {
        return Ok(()); // File doesn't exist yet, skip
    }

    let mode = if is_directory { 0o700 } else { 0o600 };
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;

    Ok(())
}

/// Write a private key file with owner-only permissions.
///
/// Uses `create_new(true)` to avoid overwriting existing files or following
/// symlink targets.
fn write_private_key_securely(path: &str, key_bytes: &[u8]) -> Result<(), JacsError> {
    let path_obj = std::path::Path::new(path);

    if let Some(parent) = path_obj.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    let mut file = options.open(path_obj)?;
    file.write_all(key_bytes)?;
    file.sync_all()?;
    Ok(())
}

/// No-op on non-Unix systems
#[cfg(not(unix))]
fn set_secure_permissions(_path: &str, _is_directory: bool) -> Result<(), JacsError> {
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyBackend {
    FsEncrypted,
    VaultTransit,
    AwsKms,
    GcpKms,
    AzureKeyVault,
    Pkcs11,
    IosKeychain,
    AndroidKeystore,
}

#[derive(Debug, Clone, Default)]
pub struct KeySpec {
    pub algorithm: String,      // "RSA-PSS", "ring-Ed25519", "pq2025"
    pub key_id: Option<String>, // Remote key identifier / ARN / URL
}

pub trait KeyStore: Send + Sync + fmt::Debug {
    fn generate(&self, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError>;
    fn load_private(&self) -> Result<Vec<u8>, JacsError>;
    fn load_public(&self) -> Result<Vec<u8>, JacsError>;
    fn sign_detached(
        &self,
        _private_key: &[u8],
        _message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, JacsError>;

    /// Rotate keys: archive the current keypair with a version suffix and generate
    /// a new keypair at the standard paths. Returns `(new_private_key, new_public_key)`.
    ///
    /// For filesystem-backed stores this renames old key files to
    /// `{name}.{old_version}.{ext}` before generating fresh keys. If generation
    /// fails after archival the old files are restored (rollback).
    ///
    /// In-memory stores simply regenerate keys (no archival step).
    ///
    /// Backends that do not support rotation return an error via this default impl.
    fn rotate(&self, _old_version: &str, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        Err("rotate() not implemented for this key backend".into())
    }
}

/// Check that `JACS_PRIVATE_KEY_PASSWORD` is set and non-empty.
///
/// Returns `Ok(())` if the password is available, or an error describing what
/// the user needs to do. This is the single policy-enforcement point used by
/// `save_private_key` to ensure keys are never written unencrypted.
pub fn require_encryption_password() -> Result<(), JacsError> {
    let password = std::env::var("JACS_PRIVATE_KEY_PASSWORD").unwrap_or_default();
    if password.trim().is_empty() {
        return Err(
            "SECURITY: JACS_PRIVATE_KEY_PASSWORD is not set or is empty. \
            Private keys must be encrypted before writing to disk. \
            Set this environment variable to a strong password."
                .into(),
        );
    }
    Ok(())
}

// Default filesystem-encrypted backend placeholder.
// Current code paths in Agent/crypt already implement FS behavior; this scaffold
// exists for future refactors. For now these functions are unimplemented.
use crate::crypt::aes_encrypt::{decrypt_private_key_secure, encrypt_private_key};
use crate::crypt::{self, CryptoSigningAlgorithm};
use crate::storage::MultiStorage;
use crate::storage::jenv::get_required_env_var;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tracing::debug;

#[derive(Debug)]
pub struct FsEncryptedStore;
impl FsEncryptedStore {
    fn storage_for_key_dir(key_dir: &str) -> Result<MultiStorage, JacsError> {
        let root = if std::path::Path::new(key_dir).is_absolute() {
            std::path::PathBuf::from("/")
        } else {
            std::env::current_dir()?
        };
        MultiStorage::_new("fs".to_string(), root).map_err(|e| {
            format!(
                "Failed to initialize storage for key operations: {}. Check that the storage root is accessible.",
                e
            )
            .into()
        })
    }

    /// Compute the current on-disk paths for the private and public key files.
    fn key_paths() -> Result<(String, String, String), JacsError> {
        let key_dir =
            get_required_env_var("JACS_KEY_DIRECTORY", true).map_err(|e| e.to_string())?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)
            .map_err(|e| e.to_string())?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)
            .map_err(|e| e.to_string())?;
        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let pub_path = format!("{}/{}", key_dir.trim_start_matches("./"), pub_name);
        let final_priv_path = if !priv_path.ends_with(".enc") {
            format!("{}.enc", priv_path)
        } else {
            priv_path
        };
        Ok((final_priv_path, pub_path, key_dir))
    }

    /// Build versioned archive paths from the standard paths.
    fn archive_paths(priv_path: &str, pub_path: &str, old_version: &str) -> (String, String) {
        // For private key: insert version before the extension cluster
        // e.g. "keys/jacs.private.pem.enc" -> "keys/jacs.private.{ver}.pem.enc"
        let archive_priv = Self::insert_version_in_path(priv_path, old_version);
        let archive_pub = Self::insert_version_in_path(pub_path, old_version);
        (archive_priv, archive_pub)
    }

    /// Insert a version string before the PEM/key file extensions.
    ///
    /// `"keys/jacs.private.pem.enc"` -> `"keys/jacs.private.{ver}.pem.enc"`
    /// `"keys/jacs.public.pem"`      -> `"keys/jacs.public.{ver}.pem"`
    ///
    /// Strategy: find the first occurrence of `.pem` (case-insensitive) and
    /// insert `.{version}` just before it.  If `.pem` is not found, fall back
    /// to inserting before the last `.`-delimited extension.
    fn insert_version_in_path(path: &str, version: &str) -> String {
        // Try to find `.pem` which is the canonical key-file extension boundary
        if let Some(pem_pos) = path.to_ascii_lowercase().find(".pem") {
            let (before, after) = path.split_at(pem_pos);
            return format!("{}.{}{}", before, version, after);
        }
        // Fallback: insert before the last dot-extension in the filename
        if let Some(slash_pos) = path.rfind('/') {
            let (dir, filename) = path.split_at(slash_pos + 1);
            if let Some(dot_pos) = filename.rfind('.') {
                let (stem, ext) = filename.split_at(dot_pos);
                return format!("{}{}.{}{}", dir, stem, version, ext);
            }
            return format!("{}{}.{}", dir, filename, version);
        }
        if let Some(dot_pos) = path.rfind('.') {
            let (stem, ext) = path.split_at(dot_pos);
            return format!("{}.{}{}", stem, version, ext);
        }
        format!("{}.{}", path, version)
    }
}

impl KeyStore for FsEncryptedStore {
    fn generate(&self, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        debug!(
            algorithm = %spec.algorithm,
            "FsEncryptedStore::generate called"
        );
        let algo = match spec.algorithm.as_str() {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => return Err(JacsError::CryptoError(format!(
                "Unsupported key algorithm: '{}'. Supported algorithms are: 'ring-Ed25519', 'RSA-PSS', 'pq2025'. \
                Check your JACS_AGENT_KEY_ALGORITHM environment variable or config file.",
                other
            )).into()),
        };
        let (priv_key, pub_key) = match algo {
            CryptoSigningAlgorithm::RsaPss => crypt::rsawrapper::generate_keys()?,
            CryptoSigningAlgorithm::RingEd25519 => crypt::ringwrapper::generate_keys()?,
            CryptoSigningAlgorithm::Pq2025 => crypt::pq2025::generate_keys()?,
        };
        debug!(
            priv_len = priv_key.len(),
            pub_len = pub_key.len(),
            "FsEncryptedStore::generate keys created"
        );
        let key_dir =
            get_required_env_var("JACS_KEY_DIRECTORY", true).map_err(|e| e.to_string())?;
        let storage = Self::storage_for_key_dir(&key_dir)?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)
            .map_err(|e| e.to_string())?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)
            .map_err(|e| e.to_string())?;

        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let pub_path = format!("{}/{}", key_dir.trim_start_matches("./"), pub_name);

        let _password =
            get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", true).map_err(|e| e.to_string())?;
        let enc = encrypt_private_key(&priv_key).map_err(|e| {
            format!(
                "Failed to encrypt private key for storage: {}. Check your JACS_PRIVATE_KEY_PASSWORD meets the security requirements.",
                e
            )
        })?;
        let final_priv_path = if !priv_path.ends_with(".enc") {
            format!("{}.enc", priv_path)
        } else {
            priv_path.clone()
        };
        write_private_key_securely(&final_priv_path, &enc).map_err(|e| {
            format!(
                "Failed to save encrypted private key to '{}': {}. Check whether the file already exists or the directory '{}' is writable.",
                final_priv_path, e, key_dir
            )
        })?;
        storage.save_file(&pub_path, &pub_key).map_err(|e| {
            format!(
                "Failed to save public key to '{}': {}. Check that the key directory '{}' exists and is writable.",
                pub_path, e, key_dir
            )
        })?;

        // Set secure file permissions (0600 for private key, 0700 for key directory)
        // This prevents other users on shared systems from reading private keys
        set_secure_permissions(&final_priv_path, false)?;
        set_secure_permissions(&pub_path, false)?;
        set_secure_permissions(&key_dir, true)?;

        Ok((priv_key, pub_key))
    }

    fn load_private(&self) -> Result<Vec<u8>, JacsError> {
        let key_dir =
            get_required_env_var("JACS_KEY_DIRECTORY", true).map_err(|e| e.to_string())?;
        let storage = Self::storage_for_key_dir(&key_dir)?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)
            .map_err(|e| e.to_string())?;
        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let enc_path = format!("{}.enc", priv_path);
        let _password =
            get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", true).map_err(|e| e.to_string())?;

        let bytes = storage.get_file(&priv_path, None).or_else(|e1| {
            storage.get_file(&enc_path, None).map_err(|e2| {
                format!(
                    "Failed to load encrypted private key: file not found at '{}' or '{}'. \
                    Ensure the key file exists or run key generation first. \
                    Original errors: unencrypted: {}, encrypted: {}",
                    priv_path, enc_path, e1, e2
                )
            })
        })?;

        // Use secure decryption - the ZeroizingVec will be zeroized when dropped
        let decrypted = decrypt_private_key_secure(&bytes).map_err(|e| {
            format!(
                "Failed to decrypt private key from '{}': {}. \
                Private keys must be encrypted and JACS_PRIVATE_KEY_PASSWORD must be set.",
                if priv_path.ends_with(".enc") {
                    &priv_path
                } else {
                    &enc_path
                },
                e
            )
        })?;
        Ok(decrypted.as_slice().to_vec())
    }

    fn load_public(&self) -> Result<Vec<u8>, JacsError> {
        let key_dir =
            get_required_env_var("JACS_KEY_DIRECTORY", true).map_err(|e| e.to_string())?;
        let storage = Self::storage_for_key_dir(&key_dir)?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)
            .map_err(|e| e.to_string())?;
        let pub_path = format!("{}/{}", key_dir.trim_start_matches("./"), pub_name);
        let bytes = storage.get_file(&pub_path, None).map_err(|e| {
            format!(
                "Failed to load public key from '{}': {}. \
                Ensure the key file exists or run key generation first.",
                pub_path, e
            )
        })?;
        Ok(bytes)
    }

    fn sign_detached(
        &self,
        private_key: &[u8],
        message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, JacsError> {
        let algo = match algorithm {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => {
                return Err(
                    JacsError::CryptoError(format!("Unsupported algorithm: {}", other)).into(),
                );
            }
        };
        // SECURITY: Reject non-UTF8 messages instead of silently signing empty string
        let data = std::str::from_utf8(message).map_err(|e| {
            format!(
                "Message contains invalid UTF-8 at byte offset {}: {}. \
                Cannot sign non-UTF8 data as string — this would silently \
                change the signed content.",
                e.valid_up_to(),
                e
            )
        })?;
        let sig_b64 = match algo {
            CryptoSigningAlgorithm::RsaPss => {
                crypt::rsawrapper::sign_string(private_key.to_vec(), data)?
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                crypt::ringwrapper::sign_string(private_key.to_vec(), &data.to_string())?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                crypt::pq2025::sign_string(private_key.to_vec(), &data.to_string())?
            }
        };
        Ok(STANDARD
            .decode(sig_b64)
            .map_err(|e| JacsError::CryptoError(format!("Invalid base64 signature: {}", e)))?)
    }

    fn rotate(&self, old_version: &str, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        debug!(
            old_version = %old_version,
            algorithm = %spec.algorithm,
            "FsEncryptedStore::rotate called"
        );

        let (priv_path, pub_path, _) = Self::key_paths()?;
        let (archive_priv, archive_pub) = Self::archive_paths(&priv_path, &pub_path, old_version);

        // Step 1: Archive (rename) old key files
        std::fs::rename(&priv_path, &archive_priv).map_err(|e| {
            format!(
                "Failed to archive private key '{}' -> '{}': {}",
                priv_path, archive_priv, e
            )
        })?;

        if let Err(e) = std::fs::rename(&pub_path, &archive_pub) {
            // Rollback private key archive
            let _ = std::fs::rename(&archive_priv, &priv_path);
            return Err(format!(
                "Failed to archive public key '{}' -> '{}': {}. Private key archive rolled back.",
                pub_path, archive_pub, e
            )
            .into());
        }

        // Step 2: Generate new keys at the standard paths
        match self.generate(spec) {
            Ok(keys) => {
                debug!("FsEncryptedStore::rotate new keys generated successfully");
                Ok(keys)
            }
            Err(e) => {
                // Rollback: restore archived keys to standard paths
                debug!("FsEncryptedStore::rotate generation failed, rolling back");
                let _ = std::fs::rename(&archive_priv, &priv_path);
                let _ = std::fs::rename(&archive_pub, &pub_path);
                Err(format!("Key generation failed after archival, rolled back: {}", e).into())
            }
        }
    }
}

macro_rules! unimplemented_store {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name;
        impl KeyStore for $name {
            fn generate(&self, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn load_private(&self) -> Result<Vec<u8>, JacsError> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn load_public(&self) -> Result<Vec<u8>, JacsError> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn sign_detached(
                &self,
                _private_key: &[u8],
                _message: &[u8],
                _algorithm: &str,
            ) -> Result<Vec<u8>, JacsError> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
        }
    };
}

unimplemented_store!(VaultTransitStore);
unimplemented_store!(AwsKmsStore);
unimplemented_store!(GcpKmsStore);
unimplemented_store!(AzureKeyVaultStore);
unimplemented_store!(Pkcs11Store);
unimplemented_store!(IosKeychainStore);
unimplemented_store!(AndroidKeystoreStore);

/// In-memory key store for ephemeral agents. Keys never touch disk.
/// Private key bytes are zeroized on Drop.
pub struct InMemoryKeyStore {
    private_key: Mutex<Option<Vec<u8>>>,
    public_key: Mutex<Option<Vec<u8>>>,
    algorithm: String,
}

impl InMemoryKeyStore {
    pub fn new(algorithm: &str) -> Self {
        Self {
            private_key: Mutex::new(None),
            public_key: Mutex::new(None),
            algorithm: algorithm.to_string(),
        }
    }
}

impl fmt::Debug for InMemoryKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryKeyStore")
            .field("algorithm", &self.algorithm)
            .field(
                "has_private_key",
                &self.private_key.lock().unwrap().is_some(),
            )
            .field("has_public_key", &self.public_key.lock().unwrap().is_some())
            .finish()
    }
}

impl Drop for InMemoryKeyStore {
    fn drop(&mut self) {
        if let Ok(mut key) = self.private_key.lock() {
            if let Some(ref mut bytes) = *key {
                bytes.zeroize();
            }
        }
    }
}

impl KeyStore for InMemoryKeyStore {
    fn generate(&self, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        let algo = match spec.algorithm.as_str() {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => {
                return Err(JacsError::CryptoError(format!(
                    "Unsupported key algorithm: '{}'. Supported: 'ring-Ed25519', 'RSA-PSS', 'pq2025'.",
                    other
                ))
                .into());
            }
        };
        let (priv_key, pub_key) = match algo {
            CryptoSigningAlgorithm::RsaPss => crypt::rsawrapper::generate_keys()?,
            CryptoSigningAlgorithm::RingEd25519 => crypt::ringwrapper::generate_keys()?,
            CryptoSigningAlgorithm::Pq2025 => crypt::pq2025::generate_keys()?,
        };
        // Store copies in memory — no disk, no encryption
        *self.private_key.lock().unwrap() = Some(priv_key.clone());
        *self.public_key.lock().unwrap() = Some(pub_key.clone());
        Ok((priv_key, pub_key))
    }

    fn load_private(&self) -> Result<Vec<u8>, JacsError> {
        self.private_key
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "InMemoryKeyStore: no private key generated yet".into())
    }

    fn load_public(&self) -> Result<Vec<u8>, JacsError> {
        self.public_key
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "InMemoryKeyStore: no public key generated yet".into())
    }

    fn sign_detached(
        &self,
        private_key: &[u8],
        message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, JacsError> {
        let algo = match algorithm {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => {
                return Err(
                    JacsError::CryptoError(format!("Unsupported algorithm: {}", other)).into(),
                );
            }
        };
        // SECURITY: Reject non-UTF8 messages instead of silently signing empty string
        let data = std::str::from_utf8(message).map_err(|e| {
            format!(
                "Message contains invalid UTF-8 at byte offset {}: {}. \
                Cannot sign non-UTF8 data as string — this would silently \
                change the signed content.",
                e.valid_up_to(),
                e
            )
        })?;
        let sig_b64 = match algo {
            CryptoSigningAlgorithm::RsaPss => {
                crypt::rsawrapper::sign_string(private_key.to_vec(), data)?
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                crypt::ringwrapper::sign_string(private_key.to_vec(), &data.to_string())?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                crypt::pq2025::sign_string(private_key.to_vec(), &data.to_string())?
            }
        };
        Ok(STANDARD
            .decode(sig_b64)
            .map_err(|e| JacsError::CryptoError(format!("Invalid base64 signature: {}", e)))?)
    }

    fn rotate(&self, _old_version: &str, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        // In-memory stores have no files to archive — just regenerate.
        self.generate(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::Path;

    #[test]
    fn test_in_memory_generate_returns_keys() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (priv_key, pub_key) = ks.generate(&spec).unwrap();
        assert!(!priv_key.is_empty(), "private key should not be empty");
        assert!(!pub_key.is_empty(), "public key should not be empty");
    }

    #[test]
    fn test_in_memory_load_private_returns_generated_key() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (priv_key, _) = ks.generate(&spec).unwrap();
        let loaded = ks.load_private().unwrap();
        assert_eq!(priv_key, loaded);
    }

    #[test]
    fn test_in_memory_load_public_returns_generated_key() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (_, pub_key) = ks.generate(&spec).unwrap();
        let loaded = ks.load_public().unwrap();
        assert_eq!(pub_key, loaded);
    }

    #[test]
    fn test_in_memory_load_before_generate_errors() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        assert!(ks.load_private().is_err());
        assert!(ks.load_public().is_err());
    }

    #[test]
    fn test_in_memory_sign_detached_produces_valid_signature() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (priv_key, pub_key) = ks.generate(&spec).unwrap();
        let message = b"hello world";
        let sig_bytes = ks
            .sign_detached(&priv_key, message, "ring-Ed25519")
            .unwrap();
        assert!(!sig_bytes.is_empty());
        // Verify using the public key
        let sig_b64 = STANDARD.encode(&sig_bytes);
        crypt::ringwrapper::verify_string(pub_key, "hello world", &sig_b64).unwrap();
    }

    #[test]
    fn test_in_memory_no_files_on_disk() {
        let temp = std::env::temp_dir().join("jacs_in_memory_test_no_files");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let _ = ks.generate(&spec).unwrap();

        // No files should have been created in the temp dir
        let entries: Vec<_> = std::fs::read_dir(&temp).unwrap().collect();
        assert!(
            entries.is_empty(),
            "InMemoryKeyStore should not create files"
        );
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_in_memory_ed25519_keys() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (priv_key, pub_key) = ks.generate(&spec).unwrap();
        // Ed25519 PKCS8 keys are typically 83 bytes, public keys are 32 bytes
        assert!(priv_key.len() > 30, "Ed25519 private key too small");
        assert_eq!(pub_key.len(), 32, "Ed25519 public key should be 32 bytes");
    }

    #[test]
    fn test_in_memory_pq2025_keys() {
        let ks = InMemoryKeyStore::new("pq2025");
        let spec = KeySpec {
            algorithm: "pq2025".to_string(),
            key_id: None,
        };
        let (priv_key, pub_key) = ks.generate(&spec).unwrap();
        // ML-DSA-87 keys are large
        assert!(
            priv_key.len() > 1000,
            "ML-DSA-87 private key should be large"
        );
        assert!(pub_key.len() > 1000, "ML-DSA-87 public key should be large");
    }

    #[test]
    fn test_in_memory_unsupported_algorithm() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "not-a-real-algo".to_string(),
            key_id: None,
        };
        assert!(ks.generate(&spec).is_err());
    }

    #[test]
    fn test_in_memory_debug_impl() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let debug_str = format!("{:?}", ks);
        assert!(debug_str.contains("InMemoryKeyStore"));
        assert!(debug_str.contains("ring-Ed25519"));
        assert!(debug_str.contains("has_private_key"));
    }

    #[cfg(unix)]
    #[test]
    fn test_set_secure_permissions_file_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jacs_key_file_perm_{}_{}",
            std::process::id(),
            suffix
        ));
        let _ = std::fs::remove_file(&path);

        std::fs::write(&path, b"secret").expect("write test file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set initial permissions");

        set_secure_permissions(
            path.to_str().expect("temporary path should be valid UTF-8"),
            false,
        )
        .expect("set secure file permissions");

        let mode = std::fs::metadata(&path)
            .expect("read file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn test_set_secure_permissions_directory_mode_700() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jacs_key_dir_perm_{}_{}",
            std::process::id(),
            suffix
        ));
        let _ = std::fs::remove_dir_all(&path);

        std::fs::create_dir_all(&path).expect("create test directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("set initial permissions");

        set_secure_permissions(
            path.to_str().expect("temporary path should be valid UTF-8"),
            true,
        )
        .expect("set secure directory permissions");

        let mode = std::fs::metadata(&path)
            .expect("read directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);

        let _ = std::fs::remove_dir_all(path);
    }

    // =========================================================================
    // rotate() tests
    // =========================================================================

    /// Mutex to prevent concurrent env-var stomping across FS-backed rotation tests.
    static FS_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_rotate_trait_has_default_error() {
        // Unimplemented backends should return an error from the default impl
        let store = VaultTransitStore;
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let result = store.rotate("old-ver", &spec);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not implemented"),
            "Expected 'not implemented' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_in_memory_rotate_replaces_keys() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (old_priv, old_pub) = ks.generate(&spec).unwrap();

        let (new_priv, new_pub) = ks.rotate("v1", &spec).unwrap();

        // New keys should differ from old keys
        assert_ne!(old_priv, new_priv, "private key should change after rotate");
        assert_ne!(old_pub, new_pub, "public key should change after rotate");

        // load_private/load_public should return the new keys
        assert_eq!(ks.load_private().unwrap(), new_priv);
        assert_eq!(ks.load_public().unwrap(), new_pub);
    }

    /// Helper: set up an isolated temp directory and env overrides for
    /// `FsEncryptedStore`. Uses absolute paths to avoid CWD-related test races.
    ///
    /// Caller MUST hold `FS_TEST_MUTEX` before calling.
    fn setup_fs_test_dir(label: &str) -> String {
        use crate::storage::jenv::set_env_var;
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir_name = std::env::temp_dir()
            .join(format!("jacs_test_{}_{}", label, suffix))
            .to_string_lossy()
            .to_string();

        let key_dir = format!("{}/keys", dir_name);
        let data_dir = format!("{}/data", dir_name);

        std::fs::create_dir_all(&key_dir).unwrap();
        std::fs::create_dir_all(format!("{}/agent", data_dir)).unwrap();
        std::fs::create_dir_all(format!("{}/public_keys", data_dir)).unwrap();

        set_env_var("JACS_KEY_DIRECTORY", &key_dir).unwrap();
        set_env_var("JACS_DATA_DIRECTORY", &data_dir).unwrap();
        set_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem").unwrap();
        set_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem").unwrap();
        set_env_var("JACS_PRIVATE_KEY_PASSWORD", "Test!Secure#Pass123").unwrap();
        set_env_var("JACS_DEFAULT_STORAGE", "fs").unwrap();

        dir_name
    }

    fn clear_fs_test_env() {
        let keys = [
            "JACS_KEY_DIRECTORY",
            "JACS_DATA_DIRECTORY",
            "JACS_AGENT_PRIVATE_KEY_FILENAME",
            "JACS_AGENT_PUBLIC_KEY_FILENAME",
            "JACS_PRIVATE_KEY_PASSWORD",
            "JACS_DEFAULT_STORAGE",
        ];
        for key in keys {
            let _ = crate::storage::jenv::clear_env_var(key);
        }
    }

    #[test]
    #[serial]
    fn test_fs_encrypted_rotate_archives_old_keys() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let dir_name = setup_fs_test_dir("archive");
        let key_dir = format!("{}/keys", dir_name);

        let store = FsEncryptedStore;
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };

        // Generate initial keys
        let _ = store.generate(&spec).unwrap();

        let priv_path = format!("{}/jacs.private.pem.enc", key_dir);
        let pub_path = format!("{}/jacs.public.pem", key_dir);
        assert!(
            Path::new(&priv_path).exists(),
            "initial private key should exist"
        );
        assert!(
            Path::new(&pub_path).exists(),
            "initial public key should exist"
        );

        // Rotate
        let old_version = "test-v1-uuid";
        let _ = store.rotate(old_version, &spec).unwrap();

        // Archived files should exist
        let archive_priv = format!("{}/jacs.private.{}.pem.enc", key_dir, old_version);
        let archive_pub = format!("{}/jacs.public.{}.pem", key_dir, old_version);
        assert!(
            Path::new(&archive_priv).exists(),
            "archived private key should exist at {}",
            archive_priv
        );
        assert!(
            Path::new(&archive_pub).exists(),
            "archived public key should exist at {}",
            archive_pub
        );

        // New key files should still be at standard paths
        assert!(
            Path::new(&priv_path).exists(),
            "new private key should exist at standard path"
        );
        assert!(
            Path::new(&pub_path).exists(),
            "new public key should exist at standard path"
        );

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    #[test]
    #[serial]
    fn test_fs_encrypted_rotate_generates_new_keys() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let dir_name = setup_fs_test_dir("newkeys");
        let key_dir = format!("{}/keys", dir_name);

        let store = FsEncryptedStore;
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };

        // Generate initial keys
        let (old_priv, old_pub) = store.generate(&spec).unwrap();

        // Rotate
        let (new_priv, new_pub) = store.rotate("test-v2-uuid", &spec).unwrap();

        assert_ne!(
            old_priv, new_priv,
            "private key bytes should differ after rotation"
        );
        assert_ne!(
            old_pub, new_pub,
            "public key bytes should differ after rotation"
        );

        // load_public should return the new public key
        let loaded_pub = store.load_public().unwrap();
        assert_eq!(loaded_pub, new_pub);

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    #[test]
    #[serial]
    fn test_fs_encrypted_rotate_rollback_on_failure() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let dir_name = setup_fs_test_dir("rollback");
        let key_dir = format!("{}/keys", dir_name);

        let store = FsEncryptedStore;
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };

        // Generate initial keys
        let _ = store.generate(&spec).unwrap();

        let priv_path = format!("{}/jacs.private.pem.enc", key_dir);
        let pub_path = format!("{}/jacs.public.pem", key_dir);

        let orig_priv_bytes = std::fs::read(&priv_path).unwrap();
        let orig_pub_bytes = std::fs::read(&pub_path).unwrap();

        // Rotate with an invalid algorithm so generate() fails after archival
        let bad_spec = KeySpec {
            algorithm: "not-a-real-algo".to_string(),
            key_id: None,
        };
        let result = store.rotate("rollback-ver", &bad_spec);
        assert!(result.is_err(), "rotate with bad algo should fail");

        // Original files should be restored (rollback)
        assert!(
            Path::new(&priv_path).exists(),
            "private key should be restored after rollback"
        );
        assert!(
            Path::new(&pub_path).exists(),
            "public key should be restored after rollback"
        );

        let restored_priv = std::fs::read(&priv_path).unwrap();
        let restored_pub = std::fs::read(&pub_path).unwrap();
        assert_eq!(
            orig_priv_bytes, restored_priv,
            "private key content should match original after rollback"
        );
        assert_eq!(
            orig_pub_bytes, restored_pub,
            "public key content should match original after rollback"
        );

        // Archived files should NOT remain (they were rolled back)
        let archive_priv = format!("{}/jacs.private.rollback-ver.pem.enc", key_dir);
        let archive_pub = format!("{}/jacs.public.rollback-ver.pem", key_dir);
        assert!(
            !Path::new(&archive_priv).exists(),
            "archived private key should be cleaned up after rollback"
        );
        assert!(
            !Path::new(&archive_pub).exists(),
            "archived public key should be cleaned up after rollback"
        );

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    #[test]
    fn test_fs_encrypted_insert_version_in_path() {
        assert_eq!(
            FsEncryptedStore::insert_version_in_path("keys/jacs.private.pem.enc", "v1-uuid"),
            "keys/jacs.private.v1-uuid.pem.enc"
        );
        assert_eq!(
            FsEncryptedStore::insert_version_in_path("keys/jacs.public.pem", "v1-uuid"),
            "keys/jacs.public.v1-uuid.pem"
        );
        assert_eq!(
            FsEncryptedStore::insert_version_in_path("nodir.pem", "v2"),
            "nodir.v2.pem"
        );
    }
}
