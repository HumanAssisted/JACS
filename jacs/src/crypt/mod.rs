use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::ExposeSecret;
pub mod hash;
pub mod pq;
pub mod private_key;
pub mod ringwrapper;
pub mod rsawrapper;
pub mod aes_encrypt;
pub mod kem;
pub mod pq2025; // ML-DSA signatures // ML-KEM encryption

use crate::agent::Agent;
use std::str::FromStr;

use strum_macros::{AsRefStr, Display, EnumString};

use crate::keystore::{FsEncryptedStore, KeySpec, KeyStore};

#[derive(Debug, AsRefStr, Display, EnumString, Clone)]
pub enum CryptoSigningAlgorithm {
    #[strum(serialize = "RSA-PSS")]
    RsaPss,
    #[strum(serialize = "ring-Ed25519")]
    RingEd25519,
    #[strum(serialize = "pq-dilithium")]
    PqDilithium,
    #[strum(serialize = "pq-dilithium-alt")]
    PqDilithiumAlt, // Alternative version with different signature size
    #[strum(serialize = "pq2025")]
    Pq2025, // ML-DSA-87 (FIPS-204)
}

pub const JACS_AGENT_PRIVATE_KEY_FILENAME: &str = "JACS_AGENT_PRIVATE_KEY_FILENAME";
pub const JACS_AGENT_PUBLIC_KEY_FILENAME: &str = "JACS_AGENT_PUBLIC_KEY_FILENAME";

/// Detects the algorithm type based on the public key format.
///
/// **DEPRECATED**: This function uses heuristics that could potentially be fooled.
/// Prefer using the explicit `signingAlgorithm` field from the signature document.
/// This function should only be used as a fallback for legacy documents.
///
/// Each algorithm has unique characteristics in their public keys:
/// - Ed25519: Fixed length of 32 bytes, contains non-ASCII characters
/// - RSA-PSS: Typically longer (512+ bytes), mostly ASCII-compatible and starts with specific ASN.1 DER encoding
/// - Dilithium: Has a specific binary format with non-ASCII characters and varying lengths based on the parameter set
/// - Pq2025 (ML-DSA-87): 2592-byte public keys
pub fn detect_algorithm_from_public_key(
    public_key: &[u8],
) -> Result<CryptoSigningAlgorithm, Box<dyn std::error::Error>> {
    // Count non-ASCII bytes in the key
    let non_ascii_count = public_key.iter().filter(|&&b| b > 127).count();
    let non_ascii_ratio = non_ascii_count as f32 / public_key.len() as f32;

    // Ed25519 public keys are exactly 32 bytes and typically contain non-ASCII characters
    if public_key.len() == 32 && non_ascii_ratio > 0.5 {
        return Ok(CryptoSigningAlgorithm::RingEd25519);
    }

    // RSA keys are typically longer, mostly ASCII-compatible, and often start with specific ASN.1 DER encoding
    if public_key.len() > 100 && public_key.starts_with(&[0x30]) && non_ascii_ratio < 0.2 {
        return Ok(CryptoSigningAlgorithm::RsaPss);
    }

    // ML-DSA-87 (Pq2025) has exactly 2592 byte public keys
    if public_key.len() == 2592 {
        return Ok(CryptoSigningAlgorithm::Pq2025);
    }

    // PQ Dilithium keys have specific formats with many non-ASCII characters and larger sizes
    if public_key.len() > 1000 && non_ascii_ratio > 0.3 {
        return Ok(CryptoSigningAlgorithm::PqDilithium);
    }

    // If we have a high proportion of non-ASCII characters but don't match other criteria,
    // it's more likely to be Ed25519 or PQ Dilithium than RSA
    if non_ascii_ratio > 0.5 {
        if public_key.len() > 500 {
            return Ok(CryptoSigningAlgorithm::PqDilithium);
        } else {
            return Ok(CryptoSigningAlgorithm::RingEd25519);
        }
    }

    Err("Could not determine the algorithm from the public key format".into())
}

/// Detects which algorithm to use based on signature length and other characteristics
/// This helps handle version differences in the same algorithm family (like different PQ versions)
pub fn detect_algorithm_from_signature(
    signature_bytes: &[u8],
    detected_algo: &CryptoSigningAlgorithm,
) -> CryptoSigningAlgorithm {
    match detected_algo {
        CryptoSigningAlgorithm::PqDilithium => {
            // Handle different Dilithium signature lengths
            if signature_bytes.len() > 4640 && signature_bytes.len() < 4650 {
                // This appears to be the newer version with ~4644 byte signatures
                CryptoSigningAlgorithm::PqDilithiumAlt
            } else {
                // Stick with the original detection
                CryptoSigningAlgorithm::PqDilithium
            }
        }
        // For other algorithms, just return the detected algorithm as-is
        _ => detected_algo.clone(),
    }
}

pub trait KeyManager {
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn sign_string(&mut self, data: &str) -> Result<String, Box<dyn std::error::Error>>;
    fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

impl KeyManager for Agent {
    /// this necessatates updateding the version of the agent
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.as_ref().ok_or("Agent config not initialized")?;
        let key_algorithm = config.get_key_algorithm()?;
        let ks = FsEncryptedStore;
        let spec = KeySpec {
            algorithm: key_algorithm.clone(),
            key_id: None,
        };
        let (private_key, public_key) = ks.generate(&spec)?;
        self.set_keys(private_key, public_key, &key_algorithm)?;
        Ok(())
    }

    fn sign_string(&mut self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let config = self.config.as_ref().ok_or("Agent config not initialized")?;
        let key_algorithm = config.get_key_algorithm()?;
        // Validate algorithm is known (result unused but validates early)
        let _algo = CryptoSigningAlgorithm::from_str(&key_algorithm)
            .map_err(|_| format!("Unknown signing algorithm: {}", key_algorithm))?;
        {
            // Delegate to keystore; we expect detached signature bytes, return base64
            let ks = FsEncryptedStore;
            let binding = self.get_private_key()?;
            // Use secure decryption - ZeroizingVec will be zeroized when it goes out of scope
            let decrypted =
                crate::crypt::aes_encrypt::decrypt_private_key_secure(binding.expose_secret())?;
            let sig_bytes = ks.sign_detached(decrypted.as_slice(), data.as_bytes(), &key_algorithm)?;
            Ok(STANDARD.encode(sig_bytes))
        }
    }

    fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get the signature bytes for analysis
        let signature_bytes = STANDARD.decode(signature_base64)?;

        // Determine the algorithm type
        let algo = match public_key_enc_type {
            Some(public_key_enc_type) => CryptoSigningAlgorithm::from_str(&public_key_enc_type)?,
            None => {
                // Try to auto-detect the algorithm type from the public key
                match detect_algorithm_from_public_key(&public_key) {
                    Ok(detected_algo) => {
                        // Further refine detection based on signature
                        detect_algorithm_from_signature(&signature_bytes, &detected_algo)
                    }
                    Err(_) => {
                        // Fall back to the agent's configured algorithm if auto-detection fails
                        let config = self.config.as_ref()
                            .ok_or("Agent config not initialized for algorithm fallback")?;
                        let key_algorithm = config.get_key_algorithm()?;
                        CryptoSigningAlgorithm::from_str(&key_algorithm)?
                    }
                }
            }
        };

        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                rsawrapper::verify_string(public_key, data, signature_base64)
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                ringwrapper::verify_string(public_key, data, signature_base64)
            }
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                // Try the standard PQ verification first
                let result = pq::verify_string(public_key.clone(), data, signature_base64);

                if result.is_ok() {
                    return Ok(());
                }

                // If we encounter a signature length error and we're using PqDilithiumAlt,
                // we could implement a special handling here for the alternative format
                if let Err(e) = &result
                    && e.to_string().contains("BadLength")
                    && matches!(algo, CryptoSigningAlgorithm::PqDilithiumAlt)
                {
                    // Here we would add special handling for the alternative format
                    // For now, we'll just log it and fail with a more descriptive error
                    return Err(format!("Detected PQ-Dilithium version mismatch. Signature length {} bytes is not compatible with the current implementation. Error: {}", 
                            signature_bytes.len(), e).into());
                }

                // Return the original error
                result
            }
            CryptoSigningAlgorithm::Pq2025 => {
                pq2025::verify_string(public_key, data, signature_base64)
            }
        }
    }
}
