pub mod keychain;

use crate::crypt::private_key::LockedVec;
use crate::error::JacsError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

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

/// Write a rotation journal file without following pre-existing path entries.
///
/// New journals must be created with `create_new(true)` so an unexpected
/// existing file or symlink cannot be clobbered. Existing journals are updated
/// only if the on-disk entry is a regular file.
fn write_journal_file_securely(
    path: &str,
    contents: &[u8],
    create_new: bool,
) -> Result<(), JacsError> {
    let path_obj = std::path::Path::new(path);

    if create_new {
        crate::secure_io::write_new_file(path_obj, contents, 0o600).map_err(|e| {
            JacsError::Internal {
                message: format!(
                    "Failed to create rotation journal at '{}': {}. \
                     If a stale journal exists, repair it before starting another rotation.",
                    path, e
                ),
            }
        })?;
    } else {
        crate::secure_io::write_atomic_replace_no_symlink(path_obj, contents, 0o600, true)
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to update rotation journal at '{}': {}", path, e),
            })?;
    }

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
    /// Desktop OS credential store (macOS Keychain / Linux Secret Service).
    /// Used for storing the private key *password*, not the key itself.
    OsKeychain,
}

#[derive(Debug, Clone, Default)]
pub struct KeySpec {
    pub algorithm: String,      // "ring-Ed25519", "pq2025"
    pub key_id: Option<String>, // Remote key identifier / ARN / URL
}

pub trait KeyStore: Send + Sync + fmt::Debug {
    fn generate(&self, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError>;
    /// Load the private key material. Returns `LockedVec` so that bytes remain
    /// mlock'd (pinned to RAM, excluded from core dumps) for the caller's
    /// entire usage lifetime.
    fn load_private(&self) -> Result<LockedVec, JacsError>;
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

/// Check that a private key password is available from any source.
///
/// Returns `Ok(())` if the password is available (env var, keychain, or password file),
/// or an error describing what the user needs to do. This is the single
/// policy-enforcement point used by `save_private_key` to ensure keys are
/// never written unencrypted.
pub fn require_encryption_password(
    explicit_password: Option<&str>,
    agent_id: Option<&str>,
) -> Result<(), JacsError> {
    crate::crypt::aes_encrypt::resolve_private_key_password(explicit_password, agent_id)?;
    Ok(())
}

// Default filesystem-encrypted backend placeholder.
// Current code paths in Agent/crypt already implement FS behavior; this scaffold
// exists for future refactors. For now these functions are unimplemented.
// encrypt/decrypt now use _with_password variants via FsEncryptedStore.password
use crate::crypt::{self, CryptoSigningAlgorithm};
use crate::storage::MultiStorage;
// get_required_env_var no longer needed — KeyPaths::from_env() deleted
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tracing::{debug, warn};

/// Resolved filesystem paths for an agent's key material.
///
/// This struct replaces the pattern of reading `JACS_KEY_DIRECTORY`,
/// `JACS_AGENT_PRIVATE_KEY_FILENAME`, and `JACS_AGENT_PUBLIC_KEY_FILENAME`
/// from environment variables at every key operation. Instead, paths are
/// resolved once at construction time and threaded through explicitly.
#[derive(Debug, Clone)]
pub struct KeyPaths {
    pub key_directory: String,
    pub private_key_filename: String,
    pub public_key_filename: String,
}

impl KeyPaths {
    /// Full path to the private key file (without `.enc` suffix).
    pub fn private_key_path(&self) -> String {
        format!(
            "{}/{}",
            self.key_directory.trim_start_matches("./"),
            self.private_key_filename
        )
    }

    /// Full path to the public key file.
    pub fn public_key_path(&self) -> String {
        format!(
            "{}/{}",
            self.key_directory.trim_start_matches("./"),
            self.public_key_filename
        )
    }

    /// Full path to the encrypted private key file (with `.enc` suffix).
    pub fn private_key_enc_path(&self) -> String {
        let p = self.private_key_path();
        if p.ends_with(".enc") {
            p
        } else {
            format!("{}.enc", p)
        }
    }
}

#[derive(Debug)]
pub struct FsEncryptedStore {
    paths: KeyPaths,
    /// Agent-scoped password for encrypt/decrypt operations.
    /// When `Some`, used directly instead of resolving from env/jenv.
    password: Option<String>,
}

impl FsEncryptedStore {
    /// Create a new `FsEncryptedStore` with explicit key paths and optional password.
    pub fn new(paths: KeyPaths) -> Self {
        Self {
            paths,
            password: None,
        }
    }

    /// Create a new `FsEncryptedStore` with explicit key paths and agent-scoped password.
    pub fn with_password(paths: KeyPaths, password: Option<String>) -> Self {
        Self { paths, password }
    }
}
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

    /// Access the stored `KeyPaths`.
    pub fn key_paths(&self) -> &KeyPaths {
        &self.paths
    }

    /// Build versioned archive paths from the standard paths.
    fn archive_paths(priv_path: &str, pub_path: &str, old_version: &str) -> (String, String) {
        // For private key: insert version before the extension cluster
        // e.g. "keys/jacs.private.pem.enc" -> "keys/jacs.private.{ver}.pem.enc"
        let archive_priv = Self::insert_version_in_path(priv_path, old_version);
        let archive_pub = Self::insert_version_in_path(pub_path, old_version);
        (archive_priv, archive_pub)
    }

    /// Write the obsolescence marker that records a rotated-out (archived) key
    /// as superseded. The marker lives alongside the archived private key as
    /// `<archive>.obsolete.json` and is written owner-only (0o600).
    fn write_obsolescence_marker(archive_priv: &str, old_version: &str) -> Result<(), JacsError> {
        let marker_path = Self::marker_path_for_archive(archive_priv);
        let record = serde_json::json!({
            "jacsKeyObsolescence": "v1",
            "obsoletedAtVersion": old_version,
            "rotatedAt": crate::time_utils::now_rfc3339(),
            "reason": "superseded-by-rotation",
            "archivedPrivateKey": archive_priv,
            "warning": "This archived private key is OBSOLETE: it was superseded by a \
                        newer agent version's key during rotation. It is retained for \
                        audit/recovery but is still decryptable with the OLD password. \
                        Do not sign new documents with it; securely delete it if this \
                        rotation was prompted by a suspected compromise."
        });
        let bytes = serde_json::to_vec_pretty(&record).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize key obsolescence marker: {}", e),
        })?;
        crate::secure_io::write_atomic_replace_no_symlink(&marker_path, &bytes, 0o600, false)
            .map_err(|e| JacsError::Internal {
                message: format!(
                    "Failed to write key obsolescence marker '{}': {}",
                    marker_path, e
                ),
            })
    }

    fn marker_path_for_archive(archive_priv: &str) -> String {
        format!("{}.obsolete.json", archive_priv)
    }

    /// Filesystem path of the obsolescence marker for a rotated-out key version.
    pub fn obsolescence_marker_path(&self, old_version: &str) -> String {
        let priv_path = self.paths.private_key_enc_path();
        let archive_priv = Self::insert_version_in_path(&priv_path, old_version);
        Self::marker_path_for_archive(&archive_priv)
    }

    /// Read the obsolescence record for a rotated-out key version, if present.
    ///
    /// Returns the parsed marker JSON when the key for `old_version` has been
    /// superseded by a rotation, or `None` if no marker exists. This lets
    /// tooling and verifiers detect that an old key is stale — the agent's
    /// current (newer) version holds the authoritative key.
    pub fn archived_key_obsolescence(&self, old_version: &str) -> Option<serde_json::Value> {
        let path = self.obsolescence_marker_path(old_version);
        let bytes = crate::secure_io::read_no_follow(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Whether the archived key for `old_version` has been marked obsolete.
    pub fn is_archived_key_obsolete(&self, old_version: &str) -> bool {
        self.archived_key_obsolescence(old_version).is_some()
    }

    fn validate_archive_version_component(version: &str) -> Result<(), JacsError> {
        if version.is_empty()
            || version == "."
            || version == ".."
            || version.contains('/')
            || version.contains('\\')
            || version.contains('\0')
        {
            return Err(JacsError::ValidationError(format!(
                "Unsafe key rotation version '{}': version identifiers used in archive filenames must not contain path separators or traversal markers.",
                version
            )));
        }
        Ok(())
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
        crate::crypt::ensure_private_key_operation_allowed(&spec.algorithm, "key generation")?;
        let algo = match spec.algorithm.as_str() {
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => {
                return Err(JacsError::CryptoError(format!(
                    "Unsupported key algorithm: '{}'. Supported algorithms are: 'ring-Ed25519', 'pq2025'. \
                Check your JACS_AGENT_KEY_ALGORITHM environment variable or config file.",
                    other
                )));
            }
        };
        let (priv_key, pub_key) = match algo {
            CryptoSigningAlgorithm::RingEd25519 => crypt::ringwrapper::generate_keys()?,
            CryptoSigningAlgorithm::Pq2025 => crypt::pq2025::generate_keys()?,
        };
        debug!(
            priv_len = priv_key.len(),
            pub_len = pub_key.len(),
            "FsEncryptedStore::generate keys created"
        );

        if self.paths.key_directory.is_empty() {
            return Err(JacsError::ConfigError(
                "FsEncryptedStore: key_directory is empty. Provide a valid key directory."
                    .to_string(),
            ));
        }

        let key_dir = &self.paths.key_directory;
        let storage = Self::storage_for_key_dir(key_dir)?;
        let pub_path = self.paths.public_key_path();
        let final_priv_path = self.paths.private_key_enc_path();

        let resolved_pw = crate::crypt::aes_encrypt::resolve_private_key_password(
            self.password.as_deref(),
            None,
        )?;
        let enc = crate::crypt::aes_encrypt::encrypt_private_key_with_password(&priv_key, &resolved_pw).map_err(|e| {
            format!(
                "Failed to encrypt private key for storage: {}. Check your JACS_PRIVATE_KEY_PASSWORD meets the security requirements.",
                e
            )
        })?;
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
        set_secure_permissions(key_dir, true)?;

        // Protect key directory from accidental git commits / Docker inclusion
        let key_dir_path = std::path::Path::new(key_dir.trim_start_matches("./"));
        crate::simple::core::write_key_directory_ignore_files(key_dir_path);

        Ok((priv_key, pub_key))
    }

    fn load_private(&self) -> Result<LockedVec, JacsError> {
        let key_dir = &self.paths.key_directory;
        let storage = Self::storage_for_key_dir(key_dir)?;
        let priv_path = self.paths.private_key_path();
        let enc_path = self.paths.private_key_enc_path();
        let _password = crate::crypt::aes_encrypt::resolve_private_key_password(
            self.password.as_deref(),
            None,
        )?;

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

        // Use secure decryption with agent-scoped password if available
        let resolved_pw = crate::crypt::aes_encrypt::resolve_private_key_password(
            self.password.as_deref(),
            None,
        )?;
        let decrypted = crate::crypt::aes_encrypt::decrypt_private_key_secure_with_password(
            &bytes,
            &resolved_pw,
        )
        .map_err(|e| {
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
        // Return LockedVec directly — key material stays mlock'd (pinned to
        // RAM, excluded from core dumps) for the caller's entire usage lifetime.
        Ok(LockedVec::new(decrypted.as_slice().to_vec()))
    }

    fn load_public(&self) -> Result<Vec<u8>, JacsError> {
        let key_dir = &self.paths.key_directory;
        let storage = Self::storage_for_key_dir(key_dir)?;
        let pub_path = self.paths.public_key_path();
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
        crate::crypt::ensure_private_key_operation_allowed(algorithm, "signing")?;
        let algo = match algorithm {
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => {
                return Err(JacsError::CryptoError(format!(
                    "Unsupported algorithm: {}",
                    other
                )));
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
            CryptoSigningAlgorithm::RingEd25519 => {
                crypt::ringwrapper::sign_string(private_key.to_vec(), &data.to_string())?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                crypt::pq2025::sign_string(private_key.to_vec(), &data.to_string())?
            }
        };
        STANDARD
            .decode(sig_b64)
            .map_err(|e| JacsError::CryptoError(format!("Invalid base64 signature: {}", e)))
    }

    fn rotate(&self, old_version: &str, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        debug!(
            old_version = %old_version,
            algorithm = %spec.algorithm,
            "FsEncryptedStore::rotate called"
        );
        crate::crypt::ensure_private_key_operation_allowed(&spec.algorithm, "key rotation")?;

        Self::validate_archive_version_component(old_version)?;
        let priv_path = self.paths.private_key_enc_path();
        let pub_path = self.paths.public_key_path();
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
                // The old encrypted key is intentionally RETAINED on disk (the
                // archive) for audit/recovery — deletion is not automatic. But it
                // is now OBSOLETE: superseded by the new key of the agent's newer
                // version, and still decryptable with the OLD password. Record an
                // obsolescence marker so tooling can detect a stale key, and warn
                // the operator loudly (best-effort: marker failure must not fail
                // the rotation, which has already succeeded on disk).
                if let Err(e) = Self::write_obsolescence_marker(&archive_priv, old_version) {
                    warn!(
                        "Failed to write key obsolescence marker for archived key '{}': {}",
                        archive_priv, e
                    );
                }
                warn!(
                    event = "key_rotation_old_key_retained",
                    archived_private_key = %archive_priv,
                    obsoleted_version = %old_version,
                    "Old private key retained at archive path after rotation. It is \
                     OBSOLETE (superseded by the new key for this agent's newer version) \
                     but is still decryptable with the OLD password. If this rotation was \
                     prompted by a suspected key or password compromise, securely delete \
                     the archived key file."
                );
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
            fn load_private(&self) -> Result<LockedVec, JacsError> {
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
/// Private key bytes are stored in mlock'd memory (via [`LockedVec`]) and
/// zeroized on Drop.
pub struct InMemoryKeyStore {
    private_key: Mutex<Option<LockedVec>>,
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

    /// Poison the private_key mutex for testing. Only available in test builds.
    #[cfg(test)]
    fn poison_private_key_mutex(&self) {
        let mutex = &self.private_key;
        let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex.lock().unwrap();
            panic!("intentional panic to poison mutex");
        }));
    }

    /// Poison the public_key mutex for testing. Only available in test builds.
    #[cfg(test)]
    fn poison_public_key_mutex(&self) {
        let mutex = &self.public_key;
        let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex.lock().unwrap();
            panic!("intentional panic to poison mutex");
        }));
    }
}

impl fmt::Debug for InMemoryKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryKeyStore")
            .field("algorithm", &self.algorithm)
            .field(
                "has_private_key",
                &self.private_key.lock().ok().as_ref().map(|g| g.is_some()),
            )
            .field(
                "has_public_key",
                &self.public_key.lock().ok().as_ref().map(|g| g.is_some()),
            )
            .finish()
    }
}

impl Drop for InMemoryKeyStore {
    fn drop(&mut self) {
        // LockedVec::drop() handles both zeroization and munlock automatically.
        // We just need to take the value so it gets dropped.
        if let Ok(mut key) = self.private_key.lock() {
            let _ = key.take();
        }
    }
}

impl KeyStore for InMemoryKeyStore {
    fn generate(&self, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        crate::crypt::ensure_private_key_operation_allowed(&spec.algorithm, "key generation")?;
        let algo = match spec.algorithm.as_str() {
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => {
                return Err(JacsError::CryptoError(format!(
                    "Unsupported key algorithm: '{}'. Supported: 'ring-Ed25519', 'pq2025'.",
                    other
                )));
            }
        };
        let (priv_key, pub_key) = match algo {
            CryptoSigningAlgorithm::RingEd25519 => crypt::ringwrapper::generate_keys()?,
            CryptoSigningAlgorithm::Pq2025 => crypt::pq2025::generate_keys()?,
        };
        // Store copies in memory — no disk, no encryption.
        // Private key is wrapped in LockedVec for mlock + zeroize-on-drop protection.
        *self.private_key.lock().map_err(|e| {
            JacsError::CryptoError(format!("KeyStore private_key mutex poisoned: {e}"))
        })? = Some(LockedVec::new(priv_key.clone()));
        *self.public_key.lock().map_err(|e| {
            JacsError::CryptoError(format!("KeyStore public_key mutex poisoned: {e}"))
        })? = Some(pub_key.clone());
        Ok((priv_key, pub_key))
    }

    fn load_private(&self) -> Result<LockedVec, JacsError> {
        // Clone into a fresh LockedVec so the caller gets its own mlock'd copy
        // without holding the Mutex beyond this scope.
        self.private_key
            .lock()
            .map_err(|e| {
                JacsError::CryptoError(format!("KeyStore private_key mutex poisoned: {e}"))
            })?
            .as_ref()
            .map(|lv| LockedVec::new(lv.as_slice().to_vec()))
            .ok_or_else(|| "InMemoryKeyStore: no private key generated yet".into())
    }

    fn load_public(&self) -> Result<Vec<u8>, JacsError> {
        self.public_key
            .lock()
            .map_err(|e| {
                JacsError::CryptoError(format!("KeyStore public_key mutex poisoned: {e}"))
            })?
            .clone()
            .ok_or_else(|| "InMemoryKeyStore: no public key generated yet".into())
    }

    fn sign_detached(
        &self,
        private_key: &[u8],
        message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, JacsError> {
        crate::crypt::ensure_private_key_operation_allowed(algorithm, "signing")?;
        let algo = match algorithm {
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => {
                return Err(JacsError::CryptoError(format!(
                    "Unsupported algorithm: {}",
                    other
                )));
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
            CryptoSigningAlgorithm::RingEd25519 => {
                crypt::ringwrapper::sign_string(private_key.to_vec(), &data.to_string())?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                crypt::pq2025::sign_string(private_key.to_vec(), &data.to_string())?
            }
        };
        STANDARD
            .decode(sig_b64)
            .map_err(|e| JacsError::CryptoError(format!("Invalid base64 signature: {}", e)))
    }

    fn rotate(&self, _old_version: &str, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        // In-memory stores have no files to archive — just regenerate.
        crate::crypt::ensure_private_key_operation_allowed(&spec.algorithm, "key rotation")?;
        self.generate(spec)
    }
}

// =============================================================================
// Rotation Journal (Write-Ahead Log for crash recovery)
// =============================================================================

/// A small JSON journal file that tracks key rotation progress.
///
/// Created before rotation begins, updated at each stage, and deleted on
/// successful completion. If the process crashes mid-rotation, the journal
/// file remains on disk so that the next agent load can detect the incomplete
/// rotation and auto-repair (see `warn_if_config_tampered` in agent/mod.rs).
///
/// Stages: `started` -> `keys_rotated` -> `agent_saved` -> `config_signed` -> (deleted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationJournal {
    /// Current stage of the rotation process.
    pub stage: String,
    /// ISO 8601 timestamp when the journal was created.
    pub timestamp: String,
    /// The agent's stable identity (UUID).
    pub agent_id: String,
    /// The agent version before rotation.
    pub old_version: String,
    /// SHA-256 hash of the old public key.
    pub old_key_hash: String,
    /// The signing algorithm used for rotation.
    pub algorithm: String,
    /// Path to the config file (for recovery).
    pub config_path: String,
    /// Path to this journal file on disk (transient, not serialized).
    #[serde(skip)]
    file_path: String,
}

impl RotationJournal {
    /// Canonical journal filename.
    const FILENAME: &'static str = ".jacs_rotation_journal.json";

    /// Compute the full path to the journal file for a given key directory.
    pub fn journal_path(key_directory: &str) -> String {
        format!("{}/{}", key_directory.trim_end_matches('/'), Self::FILENAME)
    }

    /// Create a new journal file on disk at the start of rotation.
    ///
    /// The journal is written atomically: the JSON is serialized and written
    /// in a single `fs::write` call. The initial stage is `"started"`.
    pub fn create(
        key_directory: &str,
        agent_id: &str,
        old_version: &str,
        old_key_hash: &str,
        algorithm: &str,
        config_path: &str,
    ) -> Result<Self, JacsError> {
        let file_path = Self::journal_path(key_directory);

        let journal = Self {
            stage: "started".to_string(),
            timestamp: crate::time_utils::now_rfc3339(),
            agent_id: agent_id.to_string(),
            old_version: old_version.to_string(),
            old_key_hash: old_key_hash.to_string(),
            algorithm: algorithm.to_string(),
            config_path: config_path.to_string(),
            file_path: file_path.clone(),
        };

        let json = serde_json::to_string_pretty(&journal).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize rotation journal: {}", e),
        })?;
        write_journal_file_securely(&file_path, json.as_bytes(), true)?;

        debug!(
            "Rotation journal created at '{}' (stage: started)",
            file_path
        );
        Ok(journal)
    }

    /// Load an existing journal from disk.
    ///
    /// Returns `None` if the file does not exist. Logs a warning and returns
    /// `None` if the file exists but cannot be read or parsed (corrupted
    /// journal, permission issues, schema changes). This ensures crash
    /// recovery failures are visible rather than silently swallowed.
    pub fn load(file_path: &str) -> Option<Self> {
        let path = std::path::Path::new(file_path);
        if !path.exists() {
            return None;
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                warn!(
                    "Rotation journal path '{}' is not a regular file. Crash recovery may not work.",
                    file_path
                );
                return None;
            }
            Err(e) => {
                warn!(
                    "Rotation journal exists at '{}' but could not be stat'ed: {}. Crash recovery may not work.",
                    file_path, e
                );
                return None;
            }
        }
        let data = match std::fs::read_to_string(file_path) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Rotation journal exists at '{}' but cannot be read: {}. Crash recovery may not work.",
                    file_path, e
                );
                return None;
            }
        };
        match serde_json::from_str::<Self>(&data) {
            Ok(mut journal) => {
                journal.file_path = file_path.to_string();
                Some(journal)
            }
            Err(e) => {
                warn!(
                    "Rotation journal at '{}' is corrupted: {}. Crash recovery may not work.",
                    file_path, e
                );
                None
            }
        }
    }

    /// Advance the journal to the next stage and write the update to disk.
    pub fn advance(&mut self, new_stage: &str) -> Result<(), JacsError> {
        self.stage = new_stage.to_string();

        let json = serde_json::to_string_pretty(self).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize rotation journal: {}", e),
        })?;
        write_journal_file_securely(&self.file_path, json.as_bytes(), false)?;

        debug!(
            "Rotation journal advanced to stage '{}' at '{}'",
            new_stage, self.file_path
        );
        Ok(())
    }

    /// Delete the journal file from disk (called on successful rotation completion).
    pub fn complete(&self) -> Result<(), JacsError> {
        if std::path::Path::new(&self.file_path).exists() {
            std::fs::remove_file(&self.file_path).map_err(|e| JacsError::Internal {
                message: format!(
                    "Failed to delete rotation journal at '{}': {}",
                    self.file_path, e
                ),
            })?;
            debug!("Rotation journal deleted at '{}'", self.file_path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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
    /// Returns `(dir_name, KeyPaths)`.
    ///
    /// Caller MUST hold `FS_TEST_MUTEX` before calling.
    fn setup_fs_test_dir(label: &str) -> (String, KeyPaths) {
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

        // Still set env vars for backward compatibility with code that reads them
        set_env_var("JACS_KEY_DIRECTORY", &key_dir).unwrap();
        set_env_var("JACS_DATA_DIRECTORY", &data_dir).unwrap();
        set_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem").unwrap();
        set_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem").unwrap();
        set_env_var("JACS_PRIVATE_KEY_PASSWORD", "Test!Secure#Pass123").unwrap();
        set_env_var("JACS_DEFAULT_STORAGE", "fs").unwrap();

        let paths = KeyPaths {
            key_directory: key_dir,
            private_key_filename: "jacs.private.pem".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };

        (dir_name, paths)
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
    #[serial(jacs_env)]
    fn test_fs_encrypted_rotate_archives_old_keys() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let (dir_name, paths) = setup_fs_test_dir("archive");
        let key_dir = format!("{}/keys", dir_name);

        let store = FsEncryptedStore::new(paths);
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
    #[serial(jacs_env)]
    fn test_fs_encrypted_rotate_generates_new_keys() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let (dir_name, paths) = setup_fs_test_dir("newkeys");
        let _key_dir = format!("{}/keys", dir_name);

        let store = FsEncryptedStore::new(paths);
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
    #[serial(jacs_env)]
    fn test_fs_encrypted_rotate_rollback_on_failure() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let (dir_name, paths) = setup_fs_test_dir("rollback");
        let key_dir = format!("{}/keys", dir_name);

        let store = FsEncryptedStore::new(paths);
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

    // =========================================================================
    // LockedVec integration tests (Task 010: memory pinning)
    // =========================================================================

    #[test]
    fn test_in_memory_keystore_uses_locked_storage() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let _ = ks.generate(&spec).unwrap();

        // Verify the stored private key is in a LockedVec
        let guard = ks.private_key.lock().unwrap();
        let locked_vec = guard.as_ref().expect("private key should be stored");
        assert!(
            !locked_vec.is_empty(),
            "stored private key should not be empty"
        );
        // On Unix, the memory should be mlock'd
        if cfg!(unix) {
            assert!(
                locked_vec.is_locked(),
                "InMemoryKeyStore private key should be in mlock'd memory on Unix"
            );
        }
    }

    #[test]
    fn test_sign_with_locked_key_material() {
        // Generate keys, load private key (which comes from LockedVec storage),
        // sign a message, verify signature — ensures the locked memory path
        // doesn't break signing.
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (_priv_key, pub_key) = ks.generate(&spec).unwrap();

        // load_private() returns LockedVec — key material stays mlock'd
        let loaded_priv = ks.load_private().unwrap();
        assert!(
            !loaded_priv.is_empty(),
            "loaded private key should not be empty"
        );

        // Sign using the loaded key (LockedVec → &[u8] via as_ref)
        let message = b"test message for locked key signing";
        let sig_bytes = ks
            .sign_detached(loaded_priv.as_ref(), message, "ring-Ed25519")
            .unwrap();
        assert!(!sig_bytes.is_empty(), "signature should not be empty");

        // Verify the signature with the public key
        let sig_b64 = STANDARD.encode(&sig_bytes);
        crypt::ringwrapper::verify_string(pub_key, "test message for locked key signing", &sig_b64)
            .expect("signature from locked key material should verify");
    }

    #[test]
    #[serial(jacs_env)]
    fn test_fs_encrypted_load_private_returns_locked_bytes() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let (dir_name, paths) = setup_fs_test_dir("locked_load");
        let _key_dir = format!("{}/keys", dir_name);

        let store = FsEncryptedStore::new(paths);
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };

        // Generate keys on disk
        let (orig_priv, _) = store.generate(&spec).unwrap();

        // load_private() decrypts through LockedVec internally
        let loaded = store.load_private().unwrap();
        assert_eq!(
            orig_priv, loaded,
            "loaded private key should match generated key"
        );
        assert!(!loaded.is_empty(), "loaded private key should not be empty");

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    // =========================================================================
    // KeyPaths struct tests (Task 001)
    // =========================================================================

    #[test]
    fn test_key_paths_private_key_path() {
        let paths = KeyPaths {
            key_directory: "my_keys".to_string(),
            private_key_filename: "jacs.private.pem".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        assert_eq!(paths.private_key_path(), "my_keys/jacs.private.pem");
    }

    #[test]
    fn test_key_paths_public_key_path() {
        let paths = KeyPaths {
            key_directory: "my_keys".to_string(),
            private_key_filename: "jacs.private.pem".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        assert_eq!(paths.public_key_path(), "my_keys/jacs.public.pem");
    }

    #[test]
    fn test_key_paths_enc_path() {
        let paths = KeyPaths {
            key_directory: "my_keys".to_string(),
            private_key_filename: "jacs.private.pem".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        assert_eq!(paths.private_key_enc_path(), "my_keys/jacs.private.pem.enc");
    }

    #[test]
    fn test_key_paths_enc_path_already_enc() {
        let paths = KeyPaths {
            key_directory: "my_keys".to_string(),
            private_key_filename: "jacs.private.pem.enc".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        assert_eq!(paths.private_key_enc_path(), "my_keys/jacs.private.pem.enc");
    }

    #[test]
    fn test_key_paths_trims_leading_dot_slash() {
        let paths = KeyPaths {
            key_directory: "./jacs_keys".to_string(),
            private_key_filename: "jacs.private.pem".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        assert_eq!(paths.private_key_path(), "jacs_keys/jacs.private.pem");
        assert_eq!(paths.public_key_path(), "jacs_keys/jacs.public.pem");
    }

    #[test]
    #[serial(jacs_env)]
    fn test_fs_encrypted_store_new_no_env() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        // Clear all JACS env vars to prove the struct paths are used
        clear_fs_test_env();

        use std::time::{SystemTime, UNIX_EPOCH};
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir_name = std::env::temp_dir()
            .join(format!("jacs_test_new_no_env_{}", suffix))
            .to_string_lossy()
            .to_string();
        let key_dir = format!("{}/keys", dir_name);
        std::fs::create_dir_all(&key_dir).unwrap();

        // Set only the password (still needed for encryption)
        crate::storage::jenv::set_env_var("JACS_PRIVATE_KEY_PASSWORD", "Test!Secure#Pass123")
            .unwrap();

        let paths = KeyPaths {
            key_directory: key_dir.clone(),
            private_key_filename: "jacs.private.pem".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        let store = FsEncryptedStore::new(paths);
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };

        // Should succeed using only struct paths, no env for key directory
        let result = store.generate(&spec);
        assert!(
            result.is_ok(),
            "generate should work without JACS_KEY_DIRECTORY env: {:?}",
            result.err()
        );

        let enc_path = format!("{}/jacs.private.pem.enc", key_dir);
        let pub_path = format!("{}/jacs.public.pem", key_dir);
        assert!(
            Path::new(&enc_path).exists(),
            "encrypted private key should exist"
        );
        assert!(Path::new(&pub_path).exists(), "public key should exist");

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    #[test]
    #[serial(jacs_env)]
    fn test_fs_encrypted_store_load_no_env() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let (dir_name, paths) = setup_fs_test_dir("load_no_env");

        let store = FsEncryptedStore::new(paths.clone());
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (orig_priv, orig_pub) = store.generate(&spec).unwrap();

        // Clear env to prove load uses struct paths
        clear_fs_test_env();
        // Re-set only the password for decryption
        crate::storage::jenv::set_env_var("JACS_PRIVATE_KEY_PASSWORD", "Test!Secure#Pass123")
            .unwrap();

        let loaded_priv = store.load_private().unwrap();
        let loaded_pub = store.load_public().unwrap();
        assert_eq!(orig_priv, loaded_priv, "loaded private key should match");
        assert_eq!(orig_pub, loaded_pub, "loaded public key should match");

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    #[test]
    #[serial(jacs_env)]
    fn test_fs_encrypted_store_rotate_no_env() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let (dir_name, paths) = setup_fs_test_dir("rotate_no_env");

        let store = FsEncryptedStore::new(paths.clone());
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (old_priv, old_pub) = store.generate(&spec).unwrap();

        // Clear env to prove rotate uses struct paths
        clear_fs_test_env();
        crate::storage::jenv::set_env_var("JACS_PRIVATE_KEY_PASSWORD", "Test!Secure#Pass123")
            .unwrap();

        let (new_priv, new_pub) = store.rotate("test-v-no-env", &spec).unwrap();
        assert_ne!(old_priv, new_priv, "private key should change after rotate");
        assert_ne!(old_pub, new_pub, "public key should change after rotate");

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    #[test]
    fn test_key_paths_missing_key_directory() {
        let paths = KeyPaths {
            key_directory: "".to_string(),
            private_key_filename: "jacs.private.pem".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        let store = FsEncryptedStore::new(paths);
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let result = store.generate(&spec);
        assert!(
            result.is_err(),
            "generate with empty key_directory should fail"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("key_directory is empty"),
            "error should mention empty key_directory, got: {}",
            err
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn test_key_paths_missing_private_filename() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        clear_fs_test_env();

        use std::time::{SystemTime, UNIX_EPOCH};
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir_name = std::env::temp_dir()
            .join(format!("jacs_test_missing_priv_{}", suffix))
            .to_string_lossy()
            .to_string();
        let key_dir = format!("{}/keys", dir_name);
        std::fs::create_dir_all(&key_dir).unwrap();

        crate::storage::jenv::set_env_var("JACS_PRIVATE_KEY_PASSWORD", "Test!Secure#Pass123")
            .unwrap();

        let paths = KeyPaths {
            key_directory: key_dir.clone(),
            private_key_filename: "".to_string(),
            public_key_filename: "jacs.public.pem".to_string(),
        };
        let store = FsEncryptedStore::new(paths);

        // load_private on an empty filename should gracefully fail
        // (there's no file at "keydir/.enc")
        let result = store.load_private();
        assert!(
            result.is_err(),
            "load_private with empty filename should fail"
        );

        let _ = std::fs::remove_dir_all(&dir_name);
        clear_fs_test_env();
    }

    // --- M7 fix: Mutex poison handling returns Err instead of panicking ---

    #[test]
    fn test_in_memory_generate_poisoned_mutex_returns_err() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        ks.poison_private_key_mutex();
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let result = ks.generate(&spec);
        assert!(
            result.is_err(),
            "generate() should return Err on poisoned mutex, not panic"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("mutex poisoned"),
            "Error should mention 'mutex poisoned', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_in_memory_load_private_poisoned_mutex_returns_err() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        ks.poison_private_key_mutex();
        let result = ks.load_private();
        assert!(
            result.is_err(),
            "load_private() should return Err on poisoned mutex, not panic"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("mutex poisoned"),
            "Error should mention 'mutex poisoned', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_in_memory_load_public_poisoned_mutex_returns_err() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        ks.poison_public_key_mutex();
        let result = ks.load_public();
        assert!(
            result.is_err(),
            "load_public() should return Err on poisoned mutex, not panic"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("mutex poisoned"),
            "Error should mention 'mutex poisoned', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_in_memory_debug_poisoned_mutex_does_not_panic() {
        let ks = InMemoryKeyStore::new("ring-Ed25519");
        ks.poison_private_key_mutex();
        ks.poison_public_key_mutex();
        // Debug formatting should not panic even with poisoned mutexes
        let debug_str = format!("{:?}", ks);
        assert!(
            debug_str.contains("InMemoryKeyStore"),
            "Debug should still produce output, got: {}",
            debug_str
        );
    }

    // =========================================================================
    // RotationJournal tests
    // =========================================================================

    #[test]
    fn test_journal_path_computation() {
        assert_eq!(
            RotationJournal::journal_path("./jacs_keys"),
            "./jacs_keys/.jacs_rotation_journal.json"
        );
        assert_eq!(
            RotationJournal::journal_path("/tmp/keys/"),
            "/tmp/keys/.jacs_rotation_journal.json"
        );
    }

    #[test]
    fn test_journal_write_creates_file() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let key_dir_path = tmp.path().canonicalize().expect("canonical temp dir");
        let key_dir = key_dir_path.to_str().unwrap();

        let journal = RotationJournal::create(
            key_dir,
            "agent-123",
            "v1",
            "hash-old",
            "ring-Ed25519",
            "./jacs.config.json",
        )
        .expect("journal create should succeed");

        assert_eq!(journal.stage, "started");
        assert_eq!(journal.agent_id, "agent-123");
        assert_eq!(journal.old_version, "v1");
        assert_eq!(journal.old_key_hash, "hash-old");

        let path = RotationJournal::journal_path(key_dir);
        assert!(
            Path::new(&path).exists(),
            "Journal file should exist on disk"
        );
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path)
                .expect("journal metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "journal should be created owner-only");
        }
    }

    #[test]
    fn test_journal_advance_stage() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let key_dir_path = tmp.path().canonicalize().expect("canonical temp dir");
        let key_dir = key_dir_path.to_str().unwrap();

        let mut journal = RotationJournal::create(
            key_dir,
            "agent-123",
            "v1",
            "hash-old",
            "ring-Ed25519",
            "./jacs.config.json",
        )
        .expect("journal create");

        journal
            .advance("keys_rotated")
            .expect("advance should succeed");
        assert_eq!(journal.stage, "keys_rotated");

        // Re-read from disk to confirm persistence
        let path = RotationJournal::journal_path(key_dir);
        let reloaded = RotationJournal::load(&path).expect("should reload after advance");
        assert_eq!(reloaded.stage, "keys_rotated");
    }

    #[test]
    fn test_journal_delete() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let key_dir_path = tmp.path().canonicalize().expect("canonical temp dir");
        let key_dir = key_dir_path.to_str().unwrap();

        let journal = RotationJournal::create(
            key_dir,
            "agent-123",
            "v1",
            "hash-old",
            "ring-Ed25519",
            "./jacs.config.json",
        )
        .expect("journal create");

        let path = RotationJournal::journal_path(key_dir);
        assert!(
            Path::new(&path).exists(),
            "Journal should exist before complete"
        );

        journal.complete().expect("complete should succeed");
        assert!(
            !Path::new(&path).exists(),
            "Journal should be deleted after complete"
        );
    }

    #[test]
    fn test_journal_read_existing() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let key_dir_path = tmp.path().canonicalize().expect("canonical temp dir");
        let key_dir = key_dir_path.to_str().unwrap();

        let _journal = RotationJournal::create(
            key_dir,
            "agent-456",
            "v2",
            "hash-xyz",
            "pq2025",
            "/some/config.json",
        )
        .expect("journal create");

        let path = RotationJournal::journal_path(key_dir);
        let loaded = RotationJournal::load(&path).expect("should load existing journal");
        assert_eq!(loaded.stage, "started");
        assert_eq!(loaded.agent_id, "agent-456");
        assert_eq!(loaded.old_version, "v2");
        assert_eq!(loaded.old_key_hash, "hash-xyz");
        assert_eq!(loaded.algorithm, "pq2025");
        assert_eq!(loaded.config_path, "/some/config.json");
    }

    #[test]
    fn test_journal_create_refuses_overwrite() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let key_dir_path = tmp.path().canonicalize().expect("canonical temp dir");
        let key_dir = key_dir_path.to_str().unwrap();

        let _journal = RotationJournal::create(
            key_dir,
            "agent-456",
            "v2",
            "hash-xyz",
            "pq2025",
            "/some/config.json",
        )
        .expect("first journal create");

        let second = RotationJournal::create(
            key_dir,
            "agent-456",
            "v2",
            "hash-xyz",
            "pq2025",
            "/some/config.json",
        );
        assert!(
            second.is_err(),
            "Creating a second journal at the same path should fail"
        );
    }

    #[test]
    fn test_journal_update_replaces_hardlink_without_modifying_target() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let key_dir_path = tmp.path().canonicalize().expect("canonical temp dir");
        let key_dir = key_dir_path.to_str().unwrap();

        let mut journal = RotationJournal::create(
            key_dir,
            "agent-456",
            "v2",
            "hash-xyz",
            "pq2025",
            "/some/config.json",
        )
        .expect("journal create");

        let path = RotationJournal::journal_path(key_dir);
        std::fs::remove_file(&path).expect("remove journal");

        let target = key_dir_path.join("external_target");
        std::fs::write(&target, b"do not mutate").expect("write target");
        std::fs::hard_link(&target, &path).expect("hard link journal path");

        journal.advance("rewritten").expect("advance journal");

        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"do not mutate",
            "journal update must replace the path, not write through the hard link"
        );
        let rewritten = std::fs::read_to_string(&path).expect("read rewritten journal");
        assert!(
            rewritten.contains("\"stage\": \"rewritten\""),
            "journal path should contain the updated journal: {}",
            rewritten
        );
    }

    #[test]
    fn test_journal_load_missing_returns_none() {
        let result = RotationJournal::load("/nonexistent/path/.jacs_rotation_journal.json");
        assert!(
            result.is_none(),
            "Loading from nonexistent path should return None"
        );
    }
}
