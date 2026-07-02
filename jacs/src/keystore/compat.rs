//! Role-based keyring metadata + ecosystem (ES256) compatibility key storage.
//!
//! P2 Task 002. One agent, two roles:
//! - `native_root` — the pq2025 (or grandfathered ring-Ed25519) key that
//!   signs native JACS documents. Managed by the existing keystore paths.
//! - `ecosystem_signing` — the ES256 compatibility key used ONLY for
//!   targeted ecosystem exports (Tasks 004/004b/004c). It never signs
//!   native documents.
//!
//! The keyring metadata file (`jacs.keyring.json`, in the key directory)
//! records roles — it contains no secret material and is rebuildable. The
//! ES256 private key is PKCS#8 DER inside the existing AES-256-GCM +
//! Argon2id envelope, written `create_new` + 0600 like every other private
//! key. The PQ signing library is never used as an encryption primitive.

use crate::error::JacsError;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Fixed on-disk names for the ecosystem compatibility key. There is no
/// per-purpose slot in `KeyPaths`; the compat key gets distinct filenames
/// beside the native root in the same key directory.
pub const ECOSYSTEM_PRIVATE_KEY_FILENAME: &str = "jacs.ecosystem.private.pem.enc";
pub const ECOSYSTEM_PUBLIC_KEY_FILENAME: &str = "jacs.ecosystem.public.pem";
pub const KEYRING_FILENAME: &str = "jacs.keyring.json";

/// One entry in the role-based keyring metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRoleEntry {
    /// `native_root` or `ecosystem_signing`.
    pub role: String,
    /// `pq2025` / `ring-Ed25519` for the root; `ES256` for the compat key.
    pub algorithm: String,
    /// Stable key id: RFC 7638 JWK thumbprint for ES256; the JACS
    /// public-key hash for the native root.
    pub kid: String,
}

/// The keyring metadata document (no secrets; rebuildable).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Keyring {
    pub keys: Vec<KeyRoleEntry>,
}

fn joined(key_directory: &str, filename: &str) -> String {
    format!("{}/{}", key_directory.trim_end_matches('/'), filename)
}

fn keyring_path(key_directory: &str) -> String {
    joined(key_directory, KEYRING_FILENAME)
}

/// Path of the encrypted ES256 private key inside `key_directory`.
pub fn ecosystem_private_key_path(key_directory: &str) -> String {
    joined(key_directory, ECOSYSTEM_PRIVATE_KEY_FILENAME)
}

/// Path of the ES256 SPKI PEM public key inside `key_directory`.
pub fn ecosystem_public_key_path(key_directory: &str) -> String {
    joined(key_directory, ECOSYSTEM_PUBLIC_KEY_FILENAME)
}

/// Read the keyring metadata (empty keyring if the file is absent).
pub fn read_keyring(key_directory: &str) -> Result<Keyring, JacsError> {
    let path = keyring_path(key_directory);
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| {
            JacsError::ValidationError(format!("keyring metadata parse failed ({path}): {e}"))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Keyring::default()),
        Err(e) => Err(JacsError::FileReadFailed {
            path,
            reason: e.to_string(),
        }),
    }
}

/// Write the keyring metadata atomically (0600; no symlink follow).
fn write_keyring(key_directory: &str, keyring: &Keyring) -> Result<(), JacsError> {
    let path = keyring_path(key_directory);
    let bytes = serde_json::to_vec_pretty(keyring).map_err(|e| {
        JacsError::ValidationError(format!("keyring metadata serialize failed: {e}"))
    })?;
    crate::secure_io::write_atomic_replace_no_symlink(
        std::path::Path::new(&path),
        &bytes,
        0o600,
        false,
    )
    .map_err(|e| JacsError::FileWriteFailed {
        path,
        reason: e.to_string(),
    })
}

/// Result of creating (or describing) the ecosystem compatibility key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatKeyInfo {
    pub role: String,
    pub algorithm: String,
    pub kid: String,
    pub public_key_path: String,
    pub private_key_path: String,
}

/// Create the ES256 `ecosystem_signing` key for an agent: generate, encrypt
/// with the agent's password (existing AES-256-GCM + Argon2id envelope),
/// write both key files (`create_new` + 0600 private, 0644 public), and
/// update the role keyring. Errors if a compat key already exists — no
/// silent re-mint; ES256 key rotation is out of P2 scope.
///
/// `native_algorithm` / `native_kid` describe the agent's root so the
/// keyring records both roles.
pub fn create_ecosystem_key(
    key_directory: &str,
    password: &str,
    native_algorithm: &str,
    native_kid: &str,
) -> Result<CompatKeyInfo, JacsError> {
    let priv_path = ecosystem_private_key_path(key_directory);
    let pub_path = ecosystem_public_key_path(key_directory);

    if std::path::Path::new(&priv_path).exists() {
        return Err(JacsError::ValidationError(format!(
            "an ecosystem compatibility key already exists at {priv_path}; \
             ES256 key rotation is out of scope for P2 (no silent re-mint)"
        )));
    }

    let keypair = crate::crypt::es256::generate_es256_keypair()?;

    // Encrypt with the SAME password/envelope as the native root key.
    let encrypted = crate::crypt::aes_encrypt::encrypt_private_key_with_password(
        &keypair.private_pkcs8_der,
        password,
    )?;

    super::write_private_key_securely(&priv_path, &encrypted)?;
    crate::secure_io::write_new_file(
        std::path::Path::new(&pub_path),
        keypair.public_spki_pem.as_bytes(),
        0o644,
    )
    .map_err(|e| JacsError::FileWriteFailed {
        path: pub_path.clone(),
        reason: e.to_string(),
    })?;

    // Update the role keyring: root entry (if absent) + ecosystem entry.
    let mut keyring = read_keyring(key_directory)?;
    if !keyring.keys.iter().any(|k| k.role == "native_root") {
        keyring.keys.push(KeyRoleEntry {
            role: "native_root".to_string(),
            algorithm: native_algorithm.to_string(),
            kid: native_kid.to_string(),
        });
    }
    keyring.keys.push(KeyRoleEntry {
        role: "ecosystem_signing".to_string(),
        algorithm: "ES256".to_string(),
        kid: keypair.kid.clone(),
    });
    write_keyring(key_directory, &keyring)?;

    info!(
        event = "compatibility_key_created",
        kid = %keypair.kid,
        key_directory = %key_directory,
        "ES256 ecosystem compatibility key created"
    );

    Ok(CompatKeyInfo {
        role: "ecosystem_signing".to_string(),
        algorithm: "ES256".to_string(),
        kid: keypair.kid,
        public_key_path: pub_path,
        private_key_path: priv_path,
    })
}

/// Describe the existing ecosystem key. Typed key-not-found error pointing
/// at the migration command when absent (no silent creation on load).
pub fn ecosystem_key_info(key_directory: &str) -> Result<CompatKeyInfo, JacsError> {
    let priv_path = ecosystem_private_key_path(key_directory);
    if !std::path::Path::new(&priv_path).exists() {
        return Err(JacsError::KeyNotFound {
            path: format!(
                "{priv_path} (no ecosystem compatibility key; run `jacs agent add-compat-key` \
                 or SimpleAgent::add_compat_key to add one to this existing agent)"
            ),
        });
    }
    let keyring = read_keyring(key_directory)?;
    let entry = keyring
        .keys
        .iter()
        .find(|k| k.role == "ecosystem_signing")
        .cloned()
        .ok_or_else(|| {
            JacsError::ValidationError(
                "ecosystem key file exists but keyring metadata is missing its entry".to_string(),
            )
        })?;
    Ok(CompatKeyInfo {
        role: entry.role,
        algorithm: entry.algorithm,
        kid: entry.kid,
        public_key_path: ecosystem_public_key_path(key_directory),
        private_key_path: priv_path,
    })
}
