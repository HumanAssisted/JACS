//! Signing algorithms and the `DetachedSigner` trait.
//!
//! `jacs-core::sign` exposes the protocol-layer signing primitives used
//! by both the native `jacs` facade and the browser-side `jacs-wasm`
//! wrapper. The `DetachedSigner` trait abstracts over Ed25519 and ML-DSA-87
//! (FIPS-204, marketed as `pq2025` in JACS) so future signing backends —
//! for example a `WebCryptoSigner` driven by a non-extractable browser
//! `CryptoKey` — can drop in without changing the agent surface.
//!
//! See PRD §4.2 and §4.5.

use crate::CoreError;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =========================================================================
// Ed25519 constants
// =========================================================================

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Convenience module exposing the Ed25519 constants under a stable path.
pub mod ed25519_consts {
    pub use super::{ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE};
}

// =========================================================================
// pq2025 (ML-DSA-87) constants — single source of truth for jacs and
// jacs-wasm. The native `jacs::crypt::constants` module re-exports these
// in Task 011.
// =========================================================================

/// ML-DSA-87 private key size in bytes.
pub const ML_DSA_87_PRIVATE_KEY_SIZE: usize = 4896;
/// ML-DSA-87 public key size in bytes.
pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2592;
/// ML-DSA-87 signature size in bytes.
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

/// Convenience module exposing the pq2025 constants under a stable path
/// (`jacs_core::sign::pq2025_consts`). Used by Task 011 to delegate the
/// native `jacs::crypt::constants` re-exports.
pub mod pq2025_consts {
    pub use super::{
        ML_DSA_87_PRIVATE_KEY_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE,
    };
}

// =========================================================================
// SigningAlgorithm
// =========================================================================

/// JACS signing algorithm. The wire form is the lowercase string
/// (`"ed25519"`, `"pq2025"`, `"es256"`) — that is what the JS API surfaces and what
/// the `jacsSignature.signingAlgorithm` field stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgorithm {
    /// Ed25519 (RFC 8032) — implemented by `Ed25519DalekSigner` in Task 010.
    Ed25519,
    /// ML-DSA-87 (FIPS-204) — implemented by `Pq2025Signer`.
    Pq2025,
    /// ECDSA P-256 with SHA-256, canonical SEC1 public keys and P1363 signatures.
    Es256,
}

impl SigningAlgorithm {
    /// Stable wire identifier (`"ed25519"`, `"pq2025"`, or `"es256"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::Ed25519 => "ed25519",
            SigningAlgorithm::Pq2025 => "pq2025",
            SigningAlgorithm::Es256 => "es256",
        }
    }

    /// Parse the wire identifier. Accepts both the jacs-core form
    /// (`"ed25519"`, `"pq2025"`, `"es256"`) and the native `jacs` form (`"ring-Ed25519"`)
    /// so verification accepts signed documents from either platform. The
    /// canonical wire form for *newly signed* documents is always the
    /// lowercase short name; the native alias is read-only.
    pub fn from_wire_str(raw: &str) -> Option<Self> {
        match raw {
            "ed25519" | "ring-Ed25519" => Some(SigningAlgorithm::Ed25519),
            "pq2025" => Some(SigningAlgorithm::Pq2025),
            "es256" | "ES256" => Some(SigningAlgorithm::Es256),
            _ => None,
        }
    }
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// =========================================================================
// DetachedSigner trait
// =========================================================================

/// Abstract signer surface. One concrete impl per algorithm.
///
/// `sign` is fallible because the signer may be in the `Locked` state
/// (private key cleared via `clear_secrets`); in that case it returns
/// `CoreError::Locked` rather than panicking.
pub trait DetachedSigner: Send + Sync {
    /// The algorithm this signer implements.
    fn algorithm(&self) -> SigningAlgorithm;
    /// The public key bytes (raw, algorithm-specific encoding).
    fn public_key(&self) -> &[u8];
    /// Produce a detached signature over `message`. Returns
    /// `CoreError::Locked` if the private key has been cleared.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError>;
    /// Idempotent secret eviction. After this call:
    /// - `sign` returns `CoreError::Locked`.
    /// - `public_key` continues to work.
    /// - `algorithm` continues to work.
    fn clear_secrets(&mut self);
    /// Export the held private-key bytes in the same shape the matching
    /// `from_*` constructor accepts. Used by
    /// `CoreAgent::export_encrypted_material` to round-trip an unlocked
    /// agent through the encrypted-envelope storage path (HAIAI_WASM
    /// Issue 003).
    ///
    /// - `Ed25519` returns the PKCS#8 v2 DER bytes (what
    ///   `Ed25519DalekSigner::export_pkcs8_v2` produces, which
    ///   `from_pkcs8` round-trips).
    /// - `Pq2025` returns the 4896-byte ML-DSA-87 private key (what
    ///   `Pq2025Signer::export_private_bytes` produces, which
    ///   `from_private_bytes` round-trips).
    ///
    /// Hardware-backed implementations use the default `NotExportable` result.
    /// ES256 software signers return a 32-byte big-endian private scalar.
    /// Returns `CoreError::Locked` if an exportable signer has been cleared. The
    /// returned `Vec<u8>` MUST be treated as a secret — callers should
    /// encrypt it immediately and zeroize any intermediate buffers.
    fn export_private_key_bytes(&self) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::NotExportable)
    }
}

// =========================================================================
// Pq2025Signer (ML-DSA-87 / FIPS-204)
// =========================================================================

/// ML-DSA-87 signer. Holds the private key inside an `Option` so
/// `clear_secrets` can drop it deterministically without leaving a stale
/// reference.
pub struct Pq2025Signer {
    /// `None` after `clear_secrets`. The private-key bytes are zeroized
    /// on drop via `ZeroizingPq2025Private`.
    private_key: Option<ZeroizingPq2025Private>,
    /// Cached public-key bytes — survive `clear_secrets` so verification
    /// from a previously-unlocked agent keeps working.
    public_key: Vec<u8>,
}

/// Newtype around the ML-DSA-87 private-key bytes that zeroizes on drop.
/// Wrapping the bytes (rather than the `PrivateKey` itself) keeps us out
/// of `fips204`'s internal representation while still ensuring the
/// secret material is wiped from memory.
struct ZeroizingPq2025Private {
    bytes: [u8; ML_DSA_87_PRIVATE_KEY_SIZE],
}

impl Zeroize for ZeroizingPq2025Private {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for ZeroizingPq2025Private {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZeroizingPq2025Private {}

impl Pq2025Signer {
    /// Generate a fresh ML-DSA-87 keypair.
    pub fn generate() -> Result<Self, CoreError> {
        let (pk, sk) = ml_dsa_87::KG::try_keygen().map_err(|e| {
            CoreError::EncryptionFailed(format!("ML-DSA-87 key generation failed: {e}"))
        })?;
        let sk_bytes_arr = sk.into_bytes();
        let pk_bytes_vec = pk.into_bytes().to_vec();
        Ok(Self {
            private_key: Some(ZeroizingPq2025Private {
                bytes: sk_bytes_arr,
            }),
            public_key: pk_bytes_vec,
        })
    }

    /// Reconstruct a signer from existing private-key bytes (e.g. after
    /// decrypting a stored envelope).
    pub fn from_private_bytes(private_key: &[u8]) -> Result<Self, CoreError> {
        if private_key.len() != ML_DSA_87_PRIVATE_KEY_SIZE {
            return Err(CoreError::MalformedKey(format!(
                "ML-DSA-87 private key: expected {} bytes, got {}",
                ML_DSA_87_PRIVATE_KEY_SIZE,
                private_key.len()
            )));
        }
        let mut bytes = [0u8; ML_DSA_87_PRIVATE_KEY_SIZE];
        bytes.copy_from_slice(private_key);
        // Derive the public key by running the private key through fips204.
        let sk = ml_dsa_87::PrivateKey::try_from_bytes(bytes).map_err(|e| {
            CoreError::MalformedKey(format!("ML-DSA-87 private key deserialization failed: {e}"))
        })?;
        let pk = sk.get_public_key();
        let public_key = pk.into_bytes().to_vec();
        Ok(Self {
            private_key: Some(ZeroizingPq2025Private { bytes }),
            public_key,
        })
    }

    /// Export the held private-key bytes. Used by the native facade
    /// (`jacs::crypt::pq2025::generate_keys`) to preserve the historical
    /// `(private_bytes, public_bytes)` contract. The caller is
    /// responsible for storing the bytes securely; the buffer is a
    /// plain `Vec<u8>` so callers can encrypt + persist as needed.
    /// Returns `CoreError::Locked` if the signer has been cleared.
    pub fn export_private_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let inner = self.private_key.as_ref().ok_or(CoreError::Locked)?;
        Ok(inner.bytes.to_vec())
    }

    /// Static verify entry point — does not require holding a signer.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        if public_key.len() != ML_DSA_87_PUBLIC_KEY_SIZE {
            return Err(CoreError::MalformedKey(format!(
                "ML-DSA-87 public key: expected {} bytes, got {}",
                ML_DSA_87_PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }
        if signature.len() != ML_DSA_87_SIGNATURE_SIZE {
            return Err(CoreError::SignatureInvalid(format!(
                "ML-DSA-87 signature: expected {} bytes, got {}",
                ML_DSA_87_SIGNATURE_SIZE,
                signature.len()
            )));
        }
        let mut pk_arr = [0u8; ML_DSA_87_PUBLIC_KEY_SIZE];
        pk_arr.copy_from_slice(public_key);
        let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_arr).map_err(|e| {
            CoreError::MalformedKey(format!("ML-DSA-87 public key deserialization failed: {e}"))
        })?;
        let mut sig_arr = [0u8; ML_DSA_87_SIGNATURE_SIZE];
        sig_arr.copy_from_slice(signature);
        // Empty context — matches the native `jacs::crypt::pq2025` path so
        // existing fixtures verify unchanged.
        if pk.verify(message, &sig_arr, b"") {
            Ok(())
        } else {
            Err(CoreError::SignatureInvalid(
                "ML-DSA-87 verification failed".into(),
            ))
        }
    }
}

impl std::fmt::Debug for Pq2025Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pq2025Signer")
            .field("algorithm", &SigningAlgorithm::Pq2025)
            .field("public_key_len", &self.public_key.len())
            .field("unlocked", &self.private_key.is_some())
            .finish()
    }
}

impl DetachedSigner for Pq2025Signer {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Pq2025
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let priv_bytes = self.private_key.as_ref().ok_or(CoreError::Locked)?.bytes;
        let sk = ml_dsa_87::PrivateKey::try_from_bytes(priv_bytes).map_err(|e| {
            CoreError::MalformedKey(format!("ML-DSA-87 private key deserialization failed: {e}"))
        })?;
        let sig = sk
            .try_sign(message, b"")
            .map_err(|e| CoreError::EncryptionFailed(format!("ML-DSA-87 signing failed: {e}")))?;
        Ok(sig.to_vec())
    }

    fn clear_secrets(&mut self) {
        // Drop the wrapped private key; the impl above zeroizes on drop.
        self.private_key = None;
    }

    fn export_private_key_bytes(&self) -> Result<Vec<u8>, CoreError> {
        // Delegate to the concrete method so the wire format is the
        // 4896-byte ML-DSA-87 private key the `from_private_bytes`
        // constructor accepts. See the trait doc for the round-trip
        // contract.
        self.export_private_bytes()
    }
}

// =========================================================================
// Ed25519DalekSigner (ed25519-dalek 2.x, pkcs8 v1/v2 compatible)
// =========================================================================

/// Ed25519 signer backed by `ed25519-dalek`. Replaces the `ring`-based
/// path in `jacs::crypt::ringwrapper` for the protocol layer.
///
/// PKCS#8 v1 and v2 byte formats are both accepted — the `ring` path
/// emits v2 (with the optional public-key field), and historical native
/// keys round-trip unchanged because Ed25519 is deterministic: the same
/// 32-byte private scalar over the same message produces the exact same
/// 64-byte signature regardless of whether `ring` or `ed25519-dalek`
/// performs the operation.
pub struct Ed25519DalekSigner {
    /// `None` after `clear_secrets`. `SigningKey` already zeroizes on
    /// drop via the `ed25519-dalek` `zeroize` feature.
    signing_key: Option<SigningKey>,
    /// Cached raw public-key bytes; survive `clear_secrets`.
    public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
}

impl Ed25519DalekSigner {
    /// Generate a fresh Ed25519 keypair using a cryptographically secure
    /// system RNG.
    pub fn generate() -> Result<Self, CoreError> {
        use rand::TryRng;
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::SysRng
            .try_fill_bytes(secret.as_mut())
            .map_err(|_| CoreError::EncryptionFailed("secure randomness unavailable".into()))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key().to_bytes();
        Ok(Self {
            signing_key: Some(signing_key),
            public_key,
        })
    }

    /// Import a signer from PKCS#8 v1 or v2 bytes. `ring` emits v2 (with
    /// the optional public-key field carried inline); ed25519-dalek
    /// 2.x's `pkcs8` feature accepts both.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, CoreError> {
        let signing_key = SigningKey::from_pkcs8_der(pkcs8_bytes)
            .map_err(|e| CoreError::MalformedKey(format!("Ed25519 PKCS#8 decode failed: {e}")))?;
        let public_key = signing_key.verifying_key().to_bytes();
        Ok(Self {
            signing_key: Some(signing_key),
            public_key,
        })
    }

    /// Import a signer from the raw 32-byte private scalar. Used by
    /// CoreAgent in Task 012 when reconstructing from a decrypted
    /// envelope that does not carry PKCS#8 wrapping.
    pub fn from_private_scalar(scalar: &[u8]) -> Result<Self, CoreError> {
        if scalar.len() != 32 {
            return Err(CoreError::MalformedKey(format!(
                "Ed25519 private scalar: expected 32 bytes, got {}",
                scalar.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(scalar);
        let signing_key = SigningKey::from_bytes(&arr);
        // wipe stack copy
        arr.zeroize();
        let public_key = signing_key.verifying_key().to_bytes();
        Ok(Self {
            signing_key: Some(signing_key),
            public_key,
        })
    }

    /// Static verify entry point — does not require holding a signer.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(CoreError::MalformedKey(format!(
                "Ed25519 public key: expected {} bytes, got {}",
                ED25519_PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }
        if signature.len() != ED25519_SIGNATURE_SIZE {
            return Err(CoreError::SignatureInvalid(format!(
                "Ed25519 signature: expected {} bytes, got {}",
                ED25519_SIGNATURE_SIZE,
                signature.len()
            )));
        }
        let mut pk_arr = [0u8; ED25519_PUBLIC_KEY_SIZE];
        pk_arr.copy_from_slice(public_key);
        let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
            CoreError::MalformedKey(format!("Ed25519 public key deserialization failed: {e}"))
        })?;
        let mut sig_arr = [0u8; ED25519_SIGNATURE_SIZE];
        sig_arr.copy_from_slice(signature);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(message, &sig)
            .map_err(|e| CoreError::SignatureInvalid(format!("Ed25519 verification failed: {e}")))
    }

    /// Export the held private key as PKCS#8 v2 DER bytes — the exact
    /// shape `ring::Ed25519KeyPair::generate_pkcs8` produces, so storage
    /// code that round-trips through this function reads + writes the
    /// same on-disk format as the legacy ring path. Returns
    /// `CoreError::Locked` if the signer has been cleared.
    pub fn export_pkcs8_v2(&self) -> Result<Vec<u8>, CoreError> {
        let key = self.signing_key.as_ref().ok_or(CoreError::Locked)?;
        let der = key.to_pkcs8_der().map_err(|e| {
            CoreError::EncryptionFailed(format!("Ed25519 PKCS#8 export failed: {e}"))
        })?;
        Ok(der.as_bytes().to_vec())
    }
}

impl std::fmt::Debug for Ed25519DalekSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519DalekSigner")
            .field("algorithm", &SigningAlgorithm::Ed25519)
            .field("public_key_len", &self.public_key.len())
            .field("unlocked", &self.signing_key.is_some())
            .finish()
    }
}

impl DetachedSigner for Ed25519DalekSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let key = self.signing_key.as_ref().ok_or(CoreError::Locked)?;
        let sig = key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn clear_secrets(&mut self) {
        // `SigningKey` zeroizes its scalar on drop (via the `zeroize`
        // feature). Dropping the `Option` here is sufficient.
        self.signing_key = None;
    }

    fn export_private_key_bytes(&self) -> Result<Vec<u8>, CoreError> {
        // PKCS#8 v2 DER — the shape `Ed25519DalekSigner::from_pkcs8`
        // round-trips and what the native `ring::Ed25519KeyPair::
        // generate_pkcs8` path emits. See trait doc.
        self.export_pkcs8_v2()
    }
}

// =========================================================================
// ES256 (ECDSA P-256 / SHA-256)
// =========================================================================

/// Software P-256 signer with the same wire format as portable hardware signers.
///
/// Public keys are exactly 65-byte uncompressed SEC1 points (`04 || X || Y`).
/// Signatures are exactly 64-byte IEEE-P1363 `r || s`, normalized to low-S, over
/// SHA-256 of the message. Platform adapters must convert DER signatures and
/// normalize S before returning a signature. Private exports are the 32-byte
/// big-endian scalar, never an OS key handle. Hardware signers should implement
/// `DetachedSigner` directly and retain its `NotExportable` default.
pub struct P256Signer {
    signing_key: Option<p256::ecdsa::SigningKey>,
    public_key: Vec<u8>,
}

impl P256Signer {
    pub fn generate() -> Result<Self, CoreError> {
        use p256::elliptic_curve::Generate;
        let key = p256::ecdsa::SigningKey::try_generate_from_rng(&mut rand::rngs::SysRng)
            .map_err(|_| CoreError::EncryptionFailed("secure randomness unavailable".into()))?;
        Ok(Self::from_key(key))
    }

    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != 32 {
            return Err(CoreError::MalformedKey(
                "ES256 private scalar must be exactly 32 bytes".into(),
            ));
        }
        let key = p256::ecdsa::SigningKey::from_slice(bytes)
            .map_err(|error| CoreError::MalformedKey(format!("ES256 private scalar: {error}")))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: p256::ecdsa::SigningKey) -> Self {
        let public_key = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Self {
            signing_key: Some(key),
            public_key,
        }
    }

    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        // Shares canonical encoding and low-S checks with identity profiles.
        crate::identity::verify_signature("es256", public_key, message, signature)
    }
}

impl std::fmt::Debug for P256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256Signer")
            .field("algorithm", &SigningAlgorithm::Es256)
            .field("unlocked", &self.signing_key.is_some())
            .finish()
    }
}

impl DetachedSigner for P256Signer {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        use p256::ecdsa::signature::Signer as _;
        let key = self.signing_key.as_ref().ok_or(CoreError::Locked)?;
        let signature: p256::ecdsa::Signature = key.sign(message);
        let signature = signature.normalize_s();
        Ok(signature.to_bytes().to_vec())
    }

    fn clear_secrets(&mut self) {
        // p256 SigningKey zeroizes its secret scalar on drop.
        self.signing_key = None;
    }

    fn export_private_key_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let key = self.signing_key.as_ref().ok_or(CoreError::Locked)?;
        let mut bytes = key.to_bytes();
        let exported = bytes.to_vec();
        bytes.zeroize();
        Ok(exported)
    }
}

/// Native-compatible public key representation for HAI registration.
///
/// Ed25519 and pq2025 preserve the historical JACS PUBLIC KEY armor over raw
/// algorithm key bytes (not SPKI). ES256 uses standard DER SubjectPublicKeyInfo
/// inside PUBLIC KEY armor, matching the native ES256 implementation. Internal
/// signatures and key pinning always use the canonical raw bytes, not this text.
pub fn public_key_pem(public_key: &[u8], algorithm: SigningAlgorithm) -> Result<String, CoreError> {
    use base64::Engine as _;
    crate::identity::canonical_key_id(algorithm.as_str(), public_key)?;
    let encoded = match algorithm {
        SigningAlgorithm::Ed25519 | SigningAlgorithm::Pq2025 => public_key.to_vec(),
        SigningAlgorithm::Es256 => {
            use p256::pkcs8::EncodePublicKey;
            let key = p256::PublicKey::from_sec1_bytes(public_key)
                .map_err(|error| CoreError::MalformedKey(error.to_string()))?;
            key.to_public_key_der()
                .map_err(|error| CoreError::MalformedKey(error.to_string()))?
                .as_bytes()
                .to_vec()
        }
    };
    let base64 = base64::engine::general_purpose::STANDARD.encode(encoded);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Ok(pem)
}
