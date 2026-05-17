//! Encrypted private-key envelope: AES-256-GCM + Argon2id (V2 writer) +
//! legacy PBKDF2 raw-binary reader.
//!
//! The native side has shipped two on-disk formats for encrypted private
//! keys; jacs-core preserves both reads and the V2 write so wasm builds
//! decrypt every key ever produced by the CLI.
//!
//! - **V2 JSON envelope (current writer)**:
//!   `{ "jacsEncryptedPrivateKeyVersion": 2, "cipher": "AES-256-GCM",
//!     "kdf": { "name": "Argon2id", "version": 19, "mCostKib": …, "tCost": …,
//!              "pCost": … }, "salt": "<base64url>", "nonce": "<base64url>",
//!     "ciphertext": "<base64url>" }`
//! - **Legacy raw-binary PBKDF2 envelope** (read-only):
//!   `salt(16) || nonce(12) || ciphertext`, PBKDF2-HMAC-SHA256 @ 600k
//!   iterations with a 100k fallback for pre-0.6.0 keys.
//!
//! See PRD §4.6.

use crate::CoreError;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =========================================================================
// Crypto constants (mirror jacs::crypt::constants for the four numbers we
// actually use; keeping them inline avoids a jacs-core → jacs reverse dep).
// =========================================================================

/// AES-256 key size in bytes.
pub const AES_256_KEY_SIZE: usize = 32;
/// AES-GCM nonce size in bytes.
pub const AES_GCM_NONCE_SIZE: usize = 12;
/// Salt length for password-based key derivation in bytes.
pub const PBKDF2_SALT_SIZE: usize = 16;
/// Minimum encrypted data size: salt (16) + nonce (12).
pub const MIN_ENCRYPTED_HEADER_SIZE: usize = PBKDF2_SALT_SIZE + AES_GCM_NONCE_SIZE;
/// Current OWASP-recommended PBKDF2 iteration count.
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// Legacy iteration count, used as a fallback when the current count fails
/// (pre-0.6.0 keys were encrypted with this).
pub const PBKDF2_ITERATIONS_LEGACY: u32 = 100_000;
/// On-disk version field value for the V2 JSON envelope.
const ENCRYPTED_PRIVATE_KEY_VERSION_V2: u8 = 2;
/// Argon2id memory cost (KiB).
const ARGON2ID_MEMORY_COST_KIB: u32 = 19_456;
/// Argon2id time cost.
const ARGON2ID_TIME_COST: u32 = 2;
/// Argon2id parallelism.
const ARGON2ID_PARALLELISM: u32 = 1;

// =========================================================================
// ZeroizingVec — secure buffer for decrypted private key material
// =========================================================================

/// A `Vec<u8>` that zeroizes itself when dropped. Lives here (not in jacs)
/// so jacs-core can return decrypted private-key bytes safely; the native
/// `jacs::crypt::private_key::ZeroizingVec` is a `pub use` re-export of
/// this type.
#[derive(Clone)]
pub struct ZeroizingVec(Vec<u8>);

impl ZeroizingVec {
    /// Wrap an existing `Vec<u8>` so its contents are zeroized on drop.
    pub fn new(data: Vec<u8>) -> Self {
        ZeroizingVec(data)
    }

    /// Borrow the underlying bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for ZeroizingVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for ZeroizingVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZeroizingVec {}

impl std::fmt::Debug for ZeroizingVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizingVec([REDACTED, {} bytes])", self.0.len())
    }
}

// =========================================================================
// V2 JSON envelope (current writer + reader)
// =========================================================================

#[derive(Debug, Serialize, Deserialize)]
struct KdfEnvelope {
    name: String,
    version: u32,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedPrivateKeyEnvelope {
    jacs_encrypted_private_key_version: u8,
    cipher: String,
    kdf: KdfEnvelope,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn default_argon2id_kdf() -> KdfEnvelope {
    KdfEnvelope {
        name: "Argon2id".to_string(),
        version: 19,
        m_cost_kib: ARGON2ID_MEMORY_COST_KIB,
        t_cost: ARGON2ID_TIME_COST,
        p_cost: ARGON2ID_PARALLELISM,
    }
}

fn derive_argon2id_key(
    password: &str,
    salt: &[u8],
    kdf: &KdfEnvelope,
) -> Result<[u8; AES_256_KEY_SIZE], CoreError> {
    if kdf.name != "Argon2id" || kdf.version != 19 {
        return Err(CoreError::UnsupportedAlgorithm(format!(
            "private key KDF '{}'/version {}",
            kdf.name, kdf.version
        )));
    }
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(AES_256_KEY_SIZE))
        .map_err(|e| CoreError::MalformedEnvelope(format!("invalid Argon2id parameters: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; AES_256_KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| CoreError::DecryptionFailed(format!("Argon2id key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypt `data` under `password` and emit the V2 JSON envelope as bytes.
///
/// This is the bytes-for-bytes equivalent of `jacs::crypt::aes_encrypt::
/// encrypt_v2_envelope`. Password strength validation is **not** performed
/// here — it is a separate concern handled by the native facade
/// (`validate_password` in `jacs/src/crypt/aes_encrypt.rs`).
pub fn encrypt_v2_envelope(data: &[u8], password: &str) -> Result<Vec<u8>, CoreError> {
    let mut salt = [0u8; PBKDF2_SALT_SIZE];
    rand::rng().fill(&mut salt[..]);
    let kdf = default_argon2id_kdf();
    let mut key = derive_argon2id_key(password, &salt, &kdf)?;
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted = cipher
        .encrypt(&nonce, data)
        .map_err(|e| CoreError::EncryptionFailed(format!("AES-GCM encryption failed: {e}")))?;
    let envelope = EncryptedPrivateKeyEnvelope {
        jacs_encrypted_private_key_version: ENCRYPTED_PRIVATE_KEY_VERSION_V2,
        cipher: "AES-256-GCM".to_string(),
        kdf,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce.as_slice()),
        ciphertext: URL_SAFE_NO_PAD.encode(encrypted),
    };
    serde_json::to_vec(&envelope).map_err(|e| {
        CoreError::EncryptionFailed(format!("failed to serialize encrypted key envelope: {e}"))
    })
}

/// Sniff for a V2 JSON envelope. Returns `Ok(Some(plaintext))` if the input
/// is a V2 envelope and decryption succeeded, `Ok(None)` if the input is
/// not a V2 envelope (caller should fall through to the legacy PBKDF2
/// reader), or `Err(_)` if the envelope was V2 but malformed / wrong
/// password.
pub fn decrypt_v2_envelope(
    encrypted_data: &[u8],
    password: &str,
) -> Result<Option<Vec<u8>>, CoreError> {
    let first_non_ws = encrypted_data
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace());
    if first_non_ws != Some(b'{') {
        return Ok(None);
    }
    let envelope: EncryptedPrivateKeyEnvelope = serde_json::from_slice(encrypted_data)
        .map_err(|e| CoreError::MalformedEnvelope(format!("invalid V2 envelope JSON: {e}")))?;
    if envelope.jacs_encrypted_private_key_version != ENCRYPTED_PRIVATE_KEY_VERSION_V2 {
        return Err(CoreError::UnsupportedAlgorithm(format!(
            "encrypted private key envelope version {}",
            envelope.jacs_encrypted_private_key_version
        )));
    }
    if envelope.cipher != "AES-256-GCM" {
        return Err(CoreError::UnsupportedAlgorithm(format!(
            "encrypted private key cipher '{}'",
            envelope.cipher
        )));
    }
    let salt = URL_SAFE_NO_PAD
        .decode(envelope.salt.as_bytes())
        .map_err(|e| CoreError::MalformedEnvelope(format!("invalid envelope salt: {e}")))?;
    let nonce = URL_SAFE_NO_PAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|e| CoreError::MalformedEnvelope(format!("invalid envelope nonce: {e}")))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|e| CoreError::MalformedEnvelope(format!("invalid envelope ciphertext: {e}")))?;
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(CoreError::MalformedEnvelope(format!(
            "invalid envelope nonce length: expected {}, got {}",
            AES_GCM_NONCE_SIZE,
            nonce.len()
        )));
    }
    let mut key = derive_argon2id_key(password, &salt, &envelope.kdf)?;
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| CoreError::InvalidPassword)?;
    Ok(Some(plaintext))
}

// =========================================================================
// Legacy raw-binary PBKDF2 envelope (read-only)
// =========================================================================

/// Derive a 256-bit AES key from a password via PBKDF2-HMAC-SHA256 with the
/// supplied iteration count.
pub fn derive_key_with_iterations(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> [u8; AES_256_KEY_SIZE] {
    let mut key = [0u8; AES_256_KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

/// Convenience wrapper around [`derive_key_with_iterations`] using
/// [`PBKDF2_ITERATIONS`] (current OWASP-recommended count).
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; AES_256_KEY_SIZE] {
    derive_key_with_iterations(password, salt, PBKDF2_ITERATIONS)
}

// =========================================================================
// Top-level encrypt / decrypt entry points
// =========================================================================

/// Encrypt `private_key` under `password`. Always emits the V2 JSON
/// envelope (Argon2id). No password strength check is performed — that is
/// the native facade's job.
pub fn encrypt_private_key(private_key: &[u8], password: &str) -> Result<Vec<u8>, CoreError> {
    encrypt_v2_envelope(private_key, password)
}

/// Decrypt an encrypted private key. Sniffs the input and dispatches to
/// either the V2 JSON envelope reader or the legacy raw-binary PBKDF2
/// reader (with the 100k iteration fallback).
///
/// Returns `CoreError::InvalidPassword` for AEAD-tag mismatches,
/// `CoreError::MalformedEnvelope` for structural problems,
/// `CoreError::UnsupportedAlgorithm` for unknown envelope versions or
/// ciphers, and `CoreError::DecryptionFailed` for KDF errors.
pub fn decrypt_private_key(
    encrypted_key_with_salt_and_nonce: &[u8],
    password: &str,
) -> Result<ZeroizingVec, CoreError> {
    if let Some(decrypted) = decrypt_v2_envelope(encrypted_key_with_salt_and_nonce, password)? {
        return Ok(ZeroizingVec::new(decrypted));
    }

    if encrypted_key_with_salt_and_nonce.len() < MIN_ENCRYPTED_HEADER_SIZE {
        return Err(CoreError::MalformedEnvelope(format!(
            "envelope is truncated: expected at least {} bytes, got {}",
            MIN_ENCRYPTED_HEADER_SIZE,
            encrypted_key_with_salt_and_nonce.len()
        )));
    }

    let (salt, rest) = encrypted_key_with_salt_and_nonce.split_at(PBKDF2_SALT_SIZE);
    let (nonce, encrypted_data) = rest.split_at(AES_GCM_NONCE_SIZE);
    let nonce_slice = Nonce::from_slice(nonce);

    // Try current iteration count first.
    let mut key = derive_key_from_password(password, salt);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();
    if let Ok(decrypted) = cipher.decrypt(nonce_slice, encrypted_data) {
        return Ok(ZeroizingVec::new(decrypted));
    }

    // Fall back to legacy 100k iterations (pre-0.6.0 keys).
    let mut legacy_key = derive_key_with_iterations(password, salt, PBKDF2_ITERATIONS_LEGACY);
    let legacy_cipher_key = Key::<Aes256Gcm>::from_slice(&legacy_key);
    let legacy_cipher = Aes256Gcm::new(legacy_cipher_key);
    legacy_key.zeroize();
    let decrypted = legacy_cipher
        .decrypt(nonce_slice, encrypted_data)
        .map_err(|_| CoreError::InvalidPassword)?;
    Ok(ZeroizingVec::new(decrypted))
}
