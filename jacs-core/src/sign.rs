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
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
/// (`"ed25519"`, `"pq2025"`) — that is what the JS API surfaces and what
/// the `jacsSignature.signingAlgorithm` field stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgorithm {
    /// Ed25519 (RFC 8032) — implemented by `Ed25519DalekSigner` in Task 010.
    Ed25519,
    /// ML-DSA-87 (FIPS-204) — implemented by `Pq2025Signer`.
    Pq2025,
}

impl SigningAlgorithm {
    /// Stable wire identifier (`"ed25519"` or `"pq2025"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::Ed25519 => "ed25519",
            SigningAlgorithm::Pq2025 => "pq2025",
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
            Err(CoreError::SignatureInvalid("ML-DSA-87 verification failed".into()))
        }
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
        let priv_bytes = self
            .private_key
            .as_ref()
            .ok_or(CoreError::Locked)?
            .bytes;
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
}
