use secrecy::ExposeSecret;
pub mod hash;
pub mod pq;
pub mod ringwrapper;
pub mod rsawrapper;
// pub mod private_key;
pub mod aes_encrypt;

use crate::agent::Agent;
use std::str::FromStr;

#[cfg(not(target_arch = "wasm32"))]
use crate::agent::loaders::FileLoader;
use strum_macros::{AsRefStr, Display, EnumString};

use crate::crypt::aes_encrypt::decrypt_private_key;

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
}

pub const JACS_AGENT_PRIVATE_KEY_FILENAME: &str = "JACS_AGENT_PRIVATE_KEY_FILENAME";
pub const JACS_AGENT_PUBLIC_KEY_FILENAME: &str = "JACS_AGENT_PUBLIC_KEY_FILENAME";

/// Detects the algorithm type based on the public key format.
///
/// Each algorithm has unique characteristics in their public keys:
/// - Ed25519: Fixed length of 32 bytes, contains non-ASCII characters
/// - RSA-PSS: Typically longer (512+ bytes), mostly ASCII-compatible and starts with specific ASN.1 DER encoding
/// - Dilithium: Has a specific binary format with non-ASCII characters and varying lengths based on the parameter set
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
    fn sign_string(&mut self, data: &String) -> Result<String, Box<dyn std::error::Error>>;
    fn verify_string(
        &self,
        data: &String,
        signature_base64: &String,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

impl KeyManager for Agent {
    /// this necessatates updateding the version of the agent
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let key_algorithm = self.config.as_ref().unwrap().get_key_algorithm()?;
        let (mut private_key, mut public_key) = (Vec::new(), Vec::new());
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                (private_key, public_key) =
                    rsawrapper::generate_keys().map_err(|e| e.to_string())?;
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                (private_key, public_key) =
                    ringwrapper::generate_keys().map_err(|e| e.to_string())?;
            }
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                (private_key, public_key) = pq::generate_keys().map_err(|e| e.to_string())?;
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }

        let _ = self.set_keys(private_key, public_key, &key_algorithm);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = self.fs_save_keys();

        Ok(())
    }

    fn sign_string(&mut self, data: &String) -> Result<String, Box<dyn std::error::Error>> {
        let key_algorithm = self.config.as_ref().unwrap().get_key_algorithm()?;
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                let binding = self.get_private_key()?;
                let key_vec = decrypt_private_key(binding.expose_secret())?;
                return rsawrapper::sign_string(key_vec, data);
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                let binding = self.get_private_key()?;
                let key_vec = decrypt_private_key(binding.expose_secret())?;
                return ringwrapper::sign_string(key_vec, data);
            }
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                let binding = self.get_private_key()?;
                let key_vec = decrypt_private_key(binding.expose_secret())?;
                return pq::sign_string(key_vec, data);
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }
    }

    fn verify_string(
        &self,
        data: &String,
        signature_base64: &String,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get the signature bytes for analysis
        let signature_bytes = base64::decode(signature_base64)?;

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
                        let key_algorithm = self.config.as_ref().unwrap().get_key_algorithm()?;
                        CryptoSigningAlgorithm::from_str(&key_algorithm)?
                    }
                }
            }
        };

        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                return rsawrapper::verify_string(public_key, data, signature_base64);
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                return ringwrapper::verify_string(public_key, data, signature_base64);
            }
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                // Try the standard PQ verification first
                let result = pq::verify_string(public_key.clone(), data, signature_base64);

                if result.is_ok() {
                    return Ok(());
                }

                // If we encounter a signature length error and we're using PqDilithiumAlt,
                // we could implement a special handling here for the alternative format
                if let Err(e) = &result {
                    if e.to_string().contains("BadLength")
                        && matches!(algo, CryptoSigningAlgorithm::PqDilithiumAlt)
                    {
                        // Here we would add special handling for the alternative format
                        // For now, we'll just log it and fail with a more descriptive error
                        return Err(format!("Detected PQ-Dilithium version mismatch. Signature length {} bytes is not compatible with the current implementation. Error: {}", 
                            signature_bytes.len(), e).into());
                    }
                }

                // Return the original error
                result
            }
            _ => {
                return Err(format!("{} is not a known or implemented algorithm.", algo).into());
            }
        }
    }
}
