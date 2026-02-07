use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::ExposeSecret;
pub mod aes_encrypt;
pub mod constants;
pub mod hash;
pub mod kem;
pub mod pq;
pub mod pq2025;
pub mod private_key;
pub mod ringwrapper;
pub mod rsawrapper; // ML-DSA signatures // ML-KEM encryption

use constants::{
    DILITHIUM_ALT_SIG_SIZE_MAX, DILITHIUM_ALT_SIG_SIZE_MIN, DILITHIUM_MIN_KEY_LENGTH,
    DILITHIUM_NON_ASCII_RATIO, ED25519_NON_ASCII_RATIO, ED25519_PUBLIC_KEY_SIZE,
    ML_DSA_87_PUBLIC_KEY_SIZE, PQ_SMALL_KEY_THRESHOLD, RSA_MIN_KEY_LENGTH, RSA_NON_ASCII_RATIO,
};

use crate::agent::Agent;
use crate::error::JacsError;
use std::str::FromStr;
use tracing::{debug, info, trace, warn};

// ============================================================================
// Centralized Base64 Helpers
// ============================================================================
// All base64 operations in JACS use the STANDARD engine for consistency.
// For JWK/JWT operations that require URL-safe encoding, use the dedicated
// functions in src/a2a/keys.rs which correctly use URL_SAFE_NO_PAD per spec.

/// Encode bytes to base64 using the standard engine.
#[inline]
pub fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 string to bytes using the standard engine.
#[inline]
#[must_use = "decoded bytes must be used"]
pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, JacsError> {
    STANDARD
        .decode(encoded)
        .map_err(|e| JacsError::CryptoError(format!("Invalid base64: {}", e)))
}

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
    trace!(
        public_key_len = public_key.len(),
        "Detecting algorithm from public key"
    );
    // Count non-ASCII bytes in the key
    let non_ascii_count = public_key.iter().filter(|&&b| b > 127).count();
    let non_ascii_ratio = non_ascii_count as f32 / public_key.len() as f32;

    // Ed25519 public keys are exactly 32 bytes and typically contain non-ASCII characters
    if public_key.len() == ED25519_PUBLIC_KEY_SIZE && non_ascii_ratio > ED25519_NON_ASCII_RATIO {
        debug!(
            algorithm = "RingEd25519",
            "Detected Ed25519 from public key format"
        );
        return Ok(CryptoSigningAlgorithm::RingEd25519);
    }

    // RSA keys are typically longer, mostly ASCII-compatible, and often start with specific ASN.1 DER encoding
    if public_key.len() > RSA_MIN_KEY_LENGTH
        && public_key.starts_with(&[0x30])
        && non_ascii_ratio < RSA_NON_ASCII_RATIO
    {
        debug!(
            algorithm = "RSA-PSS",
            "Detected RSA-PSS from public key format"
        );
        return Ok(CryptoSigningAlgorithm::RsaPss);
    }

    // ML-DSA-87 (Pq2025) has exactly 2592 byte public keys
    if public_key.len() == ML_DSA_87_PUBLIC_KEY_SIZE {
        debug!(
            algorithm = "pq2025",
            "Detected ML-DSA-87 from public key format"
        );
        return Ok(CryptoSigningAlgorithm::Pq2025);
    }

    // PQ Dilithium keys have specific formats with many non-ASCII characters and larger sizes
    if public_key.len() > DILITHIUM_MIN_KEY_LENGTH && non_ascii_ratio > DILITHIUM_NON_ASCII_RATIO {
        debug!(
            algorithm = "pq-dilithium",
            "Detected PQ-Dilithium from public key format"
        );
        warn!(
            "DEPRECATED: Detected 'pq-dilithium' algorithm from public key. \
            'pq-dilithium' is deprecated; use 'pq2025' (ML-DSA-87, FIPS-204) for new agents."
        );
        return Ok(CryptoSigningAlgorithm::PqDilithium);
    }

    // If we have a high proportion of non-ASCII characters but don't match other criteria,
    // it's more likely to be Ed25519 or PQ Dilithium than RSA
    if non_ascii_ratio > ED25519_NON_ASCII_RATIO {
        if public_key.len() > PQ_SMALL_KEY_THRESHOLD {
            debug!(
                algorithm = "pq-dilithium",
                "Detected PQ-Dilithium from public key format (fallback)"
            );
            return Ok(CryptoSigningAlgorithm::PqDilithium);
        } else {
            debug!(
                algorithm = "RingEd25519",
                "Detected Ed25519 from public key format (fallback)"
            );
            return Ok(CryptoSigningAlgorithm::RingEd25519);
        }
    }

    warn!(
        public_key_len = public_key.len(),
        non_ascii_ratio = non_ascii_ratio,
        "Could not determine algorithm from public key format"
    );
    Err(JacsError::CryptoError(
        "Could not determine the algorithm from the public key format".to_string(),
    )
    .into())
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
            if signature_bytes.len() > DILITHIUM_ALT_SIG_SIZE_MIN
                && signature_bytes.len() < DILITHIUM_ALT_SIG_SIZE_MAX
            {
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

    /// Signs multiple strings in a batch operation.
    ///
    /// This is more efficient than calling `sign_string` repeatedly when signing
    /// multiple messages because it amortizes the overhead of key decryption and
    /// algorithm lookup across all messages.
    ///
    /// # Arguments
    ///
    /// * `messages` - A slice of string references to sign
    ///
    /// # Returns
    ///
    /// A vector of base64-encoded signatures, one for each input message, in the
    /// same order as the input slice.
    ///
    /// # Errors
    ///
    /// Returns an error if signing any message fails. In case of failure, no
    /// signatures are returned (all-or-nothing semantics).
    fn sign_batch(&mut self, messages: &[&str]) -> Result<Vec<String>, Box<dyn std::error::Error>>;
}

impl KeyManager for Agent {
    /// this necessatates updateding the version of the agent
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.as_ref().ok_or("Agent config not initialized")?;
        let key_algorithm = config.get_key_algorithm()?;
        info!(algorithm = %key_algorithm, "Generating new keypair");
        let ks = FsEncryptedStore;
        let spec = KeySpec {
            algorithm: key_algorithm.clone(),
            key_id: None,
        };
        let (private_key, public_key) = ks.generate(&spec)?;
        self.set_keys(private_key, public_key, &key_algorithm)?;
        info!(algorithm = %key_algorithm, "Keypair generated successfully");
        Ok(())
    }

    fn sign_string(&mut self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let config = self.config.as_ref().ok_or(
            "Document signing failed: agent configuration not initialized. \
            Call load() with a valid config file or create() to initialize the agent first.",
        )?;
        let key_algorithm = config.get_key_algorithm().map_err(|e| {
            format!(
                "Document signing failed: could not determine signing algorithm. \
                Ensure 'jacs_agent_key_algorithm' is set in your config file. Error: {}",
                e
            )
        })?;
        trace!(
            algorithm = %key_algorithm,
            data_len = data.len(),
            "Signing data"
        );
        // Validate algorithm is known (result unused but validates early)
        let _algo = CryptoSigningAlgorithm::from_str(&key_algorithm).map_err(|_| {
            format!(
                "Document signing failed: unknown signing algorithm '{}'. \
                Supported algorithms: ring-Ed25519, RSA-PSS, pq-dilithium, pq2025.",
                key_algorithm
            )
        })?;
        {
            // Delegate to keystore; we expect detached signature bytes, return base64
            let ks = FsEncryptedStore;
            let binding = self.get_private_key().map_err(|e| {
                format!(
                    "Document signing failed: private key not loaded. \
                    Ensure the agent has valid keys in the configured key directory. Error: {}",
                    e
                )
            })?;
            // Use secure decryption - ZeroizingVec will be zeroized when it goes out of scope
            let decrypted =
                crate::crypt::aes_encrypt::decrypt_private_key_secure(binding.expose_secret())
                    .map_err(|e| {
                        format!(
                            "Document signing failed: could not decrypt private key. \
                            Check that the password is correct. Error: {}",
                            e
                        )
                    })?;
            let sig_bytes = ks
                .sign_detached(decrypted.as_slice(), data.as_bytes(), &key_algorithm)
                .map_err(|e| {
                    format!(
                        "Document signing failed: cryptographic signing operation failed. \
                        This may indicate a corrupted key or algorithm mismatch. Error: {}",
                        e
                    )
                })?;
            debug!(
                algorithm = %key_algorithm,
                signature_len = sig_bytes.len(),
                "Signing completed successfully"
            );
            Ok(STANDARD.encode(sig_bytes))
        }
    }

    fn sign_batch(&mut self, messages: &[&str]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }

        let config = self.config.as_ref().ok_or(
            "Batch signing failed: agent configuration not initialized. \
            Call load() with a valid config file or create() to initialize the agent first.",
        )?;
        let key_algorithm = config.get_key_algorithm().map_err(|e| {
            format!(
                "Batch signing failed: could not determine signing algorithm. \
                Ensure 'jacs_agent_key_algorithm' is set in your config file. Error: {}",
                e
            )
        })?;

        info!(
            algorithm = %key_algorithm,
            batch_size = messages.len(),
            "Signing batch of messages"
        );

        // Validate algorithm is known
        let _algo = CryptoSigningAlgorithm::from_str(&key_algorithm).map_err(|_| {
            format!(
                "Batch signing failed: unknown signing algorithm '{}'. \
                Supported algorithms: ring-Ed25519, RSA-PSS, pq-dilithium, pq2025.",
                key_algorithm
            )
        })?;

        // Decrypt the private key once for all signatures
        let ks = FsEncryptedStore;
        let binding = self.get_private_key().map_err(|e| {
            format!(
                "Batch signing failed: private key not loaded. \
                Ensure the agent has valid keys in the configured key directory. Error: {}",
                e
            )
        })?;
        let decrypted =
            crate::crypt::aes_encrypt::decrypt_private_key_secure(binding.expose_secret())
                .map_err(|e| {
                    format!(
                        "Batch signing failed: could not decrypt private key. \
                        Check that the password is correct. Error: {}",
                        e
                    )
                })?;

        // Sign all messages with the same decrypted key
        let mut signatures = Vec::with_capacity(messages.len());
        for (index, data) in messages.iter().enumerate() {
            trace!(
                algorithm = %key_algorithm,
                batch_index = index,
                data_len = data.len(),
                "Signing batch item"
            );
            let sig_bytes =
                ks.sign_detached(decrypted.as_slice(), data.as_bytes(), &key_algorithm)?;
            signatures.push(STANDARD.encode(sig_bytes));
        }

        debug!(
            algorithm = %key_algorithm,
            batch_size = messages.len(),
            "Batch signing completed successfully"
        );

        Ok(signatures)
    }

    fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        trace!(
            data_len = data.len(),
            signature_len = signature_base64.len(),
            public_key_len = public_key.len(),
            explicit_algorithm = ?public_key_enc_type,
            "Verifying signature"
        );
        // Get the signature bytes for analysis
        let signature_bytes = STANDARD.decode(signature_base64)?;

        // Determine the algorithm type
        let algo = match public_key_enc_type {
            Some(ref enc_type) => {
                debug!(algorithm = %enc_type, "Using explicit algorithm from signature");
                CryptoSigningAlgorithm::from_str(enc_type)?
            }
            None => {
                warn!(
                    "SECURITY: signingAlgorithm not provided for verification. \
                    Auto-detection is deprecated and may be removed in a future version. \
                    Set JACS_REQUIRE_EXPLICIT_ALGORITHM=true to enforce explicit algorithms."
                );

                // Check if strict mode is enabled
                let strict = std::env::var("JACS_REQUIRE_EXPLICIT_ALGORITHM")
                    .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                    .unwrap_or(false);
                if strict {
                    return Err(
                        "Signature verification requires explicit signingAlgorithm field. \
                        Re-sign the document to include the signingAlgorithm field."
                            .into(),
                    );
                }

                // Try to auto-detect the algorithm type from the public key
                match detect_algorithm_from_public_key(&public_key) {
                    Ok(detected_algo) => {
                        // Further refine detection based on signature
                        let refined =
                            detect_algorithm_from_signature(&signature_bytes, &detected_algo);
                        debug!(detected = %refined, "Auto-detected algorithm from public key");
                        refined
                    }
                    Err(_) => {
                        // Fall back to the agent's configured algorithm if auto-detection fails
                        let config = self
                            .config
                            .as_ref()
                            .ok_or("Agent config not initialized for algorithm fallback")?;
                        let key_algorithm = config.get_key_algorithm()?;
                        debug!(fallback = %key_algorithm, "Using config fallback for algorithm detection");
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
