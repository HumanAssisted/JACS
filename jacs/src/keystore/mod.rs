use crate::error::JacsError;
use std::error::Error;
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
fn set_secure_permissions(path: &str, is_directory: bool) -> Result<(), Box<dyn Error>> {
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
fn write_private_key_securely(path: &str, key_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
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
fn set_secure_permissions(_path: &str, _is_directory: bool) -> Result<(), Box<dyn Error>> {
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
    fn generate(&self, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>;
    fn load_private(&self) -> Result<Vec<u8>, Box<dyn Error>>;
    fn load_public(&self) -> Result<Vec<u8>, Box<dyn Error>>;
    fn sign_detached(
        &self,
        _private_key: &[u8],
        _message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>>;
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
impl KeyStore for FsEncryptedStore {
    fn generate(&self, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
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
        // Persist using MultiStorage
        let storage = MultiStorage::default_new().map_err(|e| {
            format!(
                "Failed to initialize storage for key generation: {}. Check that the current directory is accessible.",
                e
            )
        })?;
        let key_dir = get_required_env_var("JACS_KEY_DIRECTORY", true)?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;

        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let pub_path = format!("{}/{}", key_dir.trim_start_matches("./"), pub_name);

        let _password = get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", true)?;
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

    fn load_private(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let storage = MultiStorage::default_new().map_err(|e| {
            format!(
                "Failed to initialize storage for key loading: {}. Check that the current directory is accessible.",
                e
            )
        })?;
        let key_dir = get_required_env_var("JACS_KEY_DIRECTORY", true)?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let enc_path = format!("{}.enc", priv_path);
        let _password = get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", true)?;

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

    fn load_public(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let storage = MultiStorage::default_new().map_err(|e| {
            format!(
                "Failed to initialize storage for key loading: {}. Check that the current directory is accessible.",
                e
            )
        })?;
        let key_dir = get_required_env_var("JACS_KEY_DIRECTORY", true)?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;
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
    ) -> Result<Vec<u8>, Box<dyn Error>> {
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
        let data = std::str::from_utf8(message).unwrap_or("").to_string();
        let sig_b64 = match algo {
            CryptoSigningAlgorithm::RsaPss => {
                crypt::rsawrapper::sign_string(private_key.to_vec(), &data)?
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                crypt::ringwrapper::sign_string(private_key.to_vec(), &data)?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                crypt::pq2025::sign_string(private_key.to_vec(), &data)?
            }
        };
        Ok(STANDARD.decode(sig_b64)?)
    }
}

macro_rules! unimplemented_store {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name;
        impl KeyStore for $name {
            fn generate(&self, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn load_private(&self) -> Result<Vec<u8>, Box<dyn Error>> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn load_public(&self) -> Result<Vec<u8>, Box<dyn Error>> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn sign_detached(
                &self,
                _private_key: &[u8],
                _message: &[u8],
                _algorithm: &str,
            ) -> Result<Vec<u8>, Box<dyn Error>> {
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
    fn generate(&self, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
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

    fn load_private(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        self.private_key
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "InMemoryKeyStore: no private key generated yet".into())
    }

    fn load_public(&self) -> Result<Vec<u8>, Box<dyn Error>> {
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
    ) -> Result<Vec<u8>, Box<dyn Error>> {
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
        let data = std::str::from_utf8(message).unwrap_or("").to_string();
        let sig_b64 = match algo {
            CryptoSigningAlgorithm::RsaPss => {
                crypt::rsawrapper::sign_string(private_key.to_vec(), &data)?
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                crypt::ringwrapper::sign_string(private_key.to_vec(), &data)?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                crypt::pq2025::sign_string(private_key.to_vec(), &data)?
            }
        };
        Ok(STANDARD.decode(sig_b64)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
