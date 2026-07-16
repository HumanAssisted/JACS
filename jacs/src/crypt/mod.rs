use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;
pub mod aes_encrypt;
pub mod constants;
// Public module, but only for its SANCTIONED verification/encoding helpers
// (see the module docs in es256.rs). Keygen (`generate_es256_keypair`) and
// signing (`sign_es256_jose`) stay pub(crate) per P2 §9.6 / FR25.
pub mod es256;
pub mod hash;
pub mod kem;
pub mod pq2025;
pub mod private_key;
pub mod ringwrapper;

use constants::{ED25519_PUBLIC_KEY_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE};

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

fn armor_pem_block(data: &[u8], block_type: &str) -> String {
    let encoded = base64_encode(data);
    let mut pem = String::with_capacity(encoded.len() + block_type.len() * 2 + 64);
    pem.push_str("-----BEGIN ");
    pem.push_str(block_type);
    pem.push_str("-----\n");

    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is valid ascii"));
        pem.push('\n');
    }

    pem.push_str("-----END ");
    pem.push_str(block_type);
    pem.push_str("-----\n");
    pem
}

/// Convert raw public-key bytes into canonical PEM text for external APIs.
///
/// Internally, JACS stores public keys as raw algorithm-specific bytes for
/// Ed25519 and pq2025. This helper preserves existing PEM blocks and otherwise
/// ASCII-armors the exact bytes without lossy decoding.
#[must_use = "public key PEM must be used"]
pub fn normalize_public_key_pem(public_key: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(public_key) {
        let trimmed = text.trim();
        if trimmed.contains("BEGIN PUBLIC KEY") {
            let mut normalized = trimmed.replace("\r\n", "\n").replace('\r', "\n");
            if !normalized.ends_with('\n') {
                normalized.push('\n');
            }
            return normalized;
        }
    }

    armor_pem_block(public_key, "PUBLIC KEY")
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

use crate::keystore::{KeySpec, KeyStore};

#[derive(Debug, AsRefStr, Display, EnumString, Clone)]
pub enum CryptoSigningAlgorithm {
    #[strum(serialize = "ring-Ed25519")]
    RingEd25519,
    #[strum(serialize = "pq2025")]
    Pq2025, // ML-DSA-87 (FIPS-204)
}

/// Returns the list of verification algorithms actually implemented in JACS.
pub fn supported_verification_algorithms() -> Vec<&'static str> {
    vec!["ring-Ed25519", "pq2025"]
}

/// Returns the list of algorithms still permitted for new private-key use.
pub fn supported_private_key_algorithms() -> Vec<&'static str> {
    vec!["ring-Ed25519", "pq2025"]
}

/// Returns the list of post-quantum algorithms actually implemented in JACS.
pub fn supported_pq_algorithms() -> Vec<&'static str> {
    vec!["pq2025"]
}

/// Verify a detached JACS signature with an explicitly declared algorithm.
///
/// This stateless entry point is for trust boundaries that already possess a
/// trusted public key. It deliberately does not infer an algorithm from key
/// shape and does not require constructing an unrelated [`Agent`].
pub fn verify_string_with_algorithm(
    public_key: Vec<u8>,
    data: &str,
    signature_base64: &str,
    algorithm: &str,
) -> Result<(), JacsError> {
    let algorithm = CryptoSigningAlgorithm::from_str(algorithm)
        .map_err(|_| JacsError::CryptoError(format!("Unknown signing algorithm: {algorithm}")))?;

    match algorithm {
        CryptoSigningAlgorithm::RingEd25519 => {
            ringwrapper::verify_string(public_key, data, signature_base64)
        }
        CryptoSigningAlgorithm::Pq2025 => pq2025::verify_string(public_key, data, signature_base64),
    }
}

fn rsa_private_key_operations_disabled(algorithm: &str) -> bool {
    matches!(
        algorithm.trim().to_ascii_lowercase().as_str(),
        "rsa" | "rsa-pss"
    )
}

/// Reject RSA private-key operations.
pub fn ensure_private_key_operation_allowed(
    algorithm: &str,
    operation: &str,
) -> Result<(), JacsError> {
    if rsa_private_key_operations_disabled(algorithm) {
        let allowed = supported_private_key_algorithms().join(", ");
        return Err(JacsError::CryptoError(format!(
            "RSA private-key {} is not supported by this JACS build. Use one of [{}].",
            operation, allowed
        )));
    }
    Ok(())
}

/// Resolve the signing algorithm for a new agent without substitution.
///
/// `pq2025` remains the default. Explicit Ed25519 aliases create genuine
/// Ed25519 keys, so the requested label, returned metadata, public-key shape,
/// and emitted signature algorithm agree. Unknown algorithms are a typed
/// error. Loading and verification retain the same two-algorithm support.
///
/// Lives in `crypt` (next to `ensure_private_key_operation_allowed`) so the
/// low-level `Agent` creation paths and the `simple`/binding layers all
/// apply the identical policy; re-exported as
/// `jacs::simple::core::resolve_new_agent_algorithm` for binding layers.
pub fn resolve_new_agent_algorithm(requested: &str) -> Result<String, JacsError> {
    match requested {
        "" | "pq2025" => Ok("pq2025".to_string()),
        "ed25519" | "ring-Ed25519" => Ok("ring-Ed25519".to_string()),
        other => Err(JacsError::ConfigError(format!(
            "Unsupported algorithm '{}' for new agent creation. Use pq2025 (default) or ed25519.",
            other
        ))),
    }
}

/// Resolve a rotation target from the authenticated current algorithm.
///
/// Rotation without an override preserves the current algorithm. An Ed25519
/// identity may explicitly upgrade to `pq2025`; a `pq2025` identity may not
/// downgrade to Ed25519. This keeps routine key replacement compatible while
/// making a security-level change deliberate and one-way.
pub fn resolve_rotation_algorithm(
    current: &str,
    requested: Option<&str>,
) -> Result<String, JacsError> {
    fn canonical(label: &str) -> Option<&'static str> {
        match label {
            "ed25519" | "ring-Ed25519" => Some("ring-Ed25519"),
            "pq2025" => Some("pq2025"),
            _ => None,
        }
    }

    let current = canonical(current).ok_or_else(|| {
        JacsError::ConfigError(format!(
            "Cannot rotate an agent with unsupported current algorithm '{}'.",
            current
        ))
    })?;
    let target = match requested {
        None | Some("") => current,
        Some(label) => canonical(label).ok_or_else(|| {
            JacsError::ConfigError(format!(
                "Unsupported key rotation algorithm '{}'. Use ed25519 or pq2025.",
                label
            ))
        })?,
    };

    if current == "pq2025" && target == "ring-Ed25519" {
        return Err(JacsError::ConfigError(
            "Refusing post-quantum to Ed25519 key rotation downgrade; keep pq2025.".to_string(),
        ));
    }

    Ok(target.to_string())
}

pub const JACS_AGENT_PRIVATE_KEY_FILENAME: &str = "JACS_AGENT_PRIVATE_KEY_FILENAME";
pub const JACS_AGENT_PUBLIC_KEY_FILENAME: &str = "JACS_AGENT_PUBLIC_KEY_FILENAME";

/// Detects the algorithm type based on the public key format.
///
/// **DEPRECATED**: This function uses heuristics that could potentially be fooled.
/// Prefer using the explicit `signingAlgorithm` field from the signature document.
/// This function should only be used as a fallback for legacy documents.
///
/// Each supported algorithm has a distinct public-key length:
/// - Ed25519: exactly 32 bytes (every byte string is possible)
/// - Pq2025 (ML-DSA-87): 2592-byte public keys
pub fn detect_algorithm_from_public_key(
    public_key: &[u8],
) -> Result<CryptoSigningAlgorithm, JacsError> {
    trace!(
        public_key_len = public_key.len(),
        "Detecting algorithm from public key"
    );
    // Ed25519 encodes an arbitrary group element as exactly 32 bytes. A
    // content heuristic (such as a minimum non-ASCII ratio) rejects valid
    // randomly generated keys and cannot add authenticity; cryptographic
    // verification remains the validity check.
    if public_key.len() == ED25519_PUBLIC_KEY_SIZE {
        debug!(
            algorithm = "RingEd25519",
            "Detected Ed25519 from public key format"
        );
        return Ok(CryptoSigningAlgorithm::RingEd25519);
    }

    // ML-DSA-87 (Pq2025) has exactly 2592 byte public keys
    if public_key.len() == ML_DSA_87_PUBLIC_KEY_SIZE {
        debug!(
            algorithm = "pq2025",
            "Detected ML-DSA-87 from public key format"
        );
        return Ok(CryptoSigningAlgorithm::Pq2025);
    }

    warn!(
        public_key_len = public_key.len(),
        "Could not determine algorithm from public key format"
    );
    Err(JacsError::CryptoError(
        "Could not determine the algorithm from the public key format".to_string(),
    ))
}

/// Detects which algorithm to use based on signature length and other characteristics
/// This helps handle version differences in the same algorithm family (like different PQ versions)
pub fn detect_algorithm_from_signature(
    _signature_bytes: &[u8],
    detected_algo: &CryptoSigningAlgorithm,
) -> CryptoSigningAlgorithm {
    detected_algo.clone()
}

pub trait KeyManager {
    fn generate_keys(&mut self) -> Result<(), JacsError>;
    fn sign_string(&mut self, data: &str) -> Result<String, JacsError>;
    fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), JacsError>;

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
    fn sign_batch(&mut self, messages: &[&str]) -> Result<Vec<String>, JacsError>;
}

impl Agent {
    /// Sign raw bytes and return the base64-encoded signature.
    ///
    /// This is the byte-level equivalent of `sign_string`. Used by
    /// the email signing module where the payload is binary.
    pub fn sign_bytes(&mut self, data: &[u8]) -> Result<Vec<u8>, JacsError> {
        let config = self
            .config
            .as_ref()
            .ok_or("Byte signing failed: agent configuration not initialized.")?;
        let key_algorithm = config.get_key_algorithm().map_err(|e| {
            format!(
                "Byte signing failed: could not determine signing algorithm: {}",
                e
            )
        })?;
        ensure_private_key_operation_allowed(&key_algorithm, "signing")?;

        let binding = self
            .get_private_key()
            .map_err(|e| format!("Byte signing failed: private key not loaded: {}", e))?;

        let is_ephemeral = self.is_ephemeral();
        let has_key_store = self.get_key_store().is_some();
        let stored_algo = self.get_key_algorithm().cloned();
        let (key_bytes, ks_box): (Zeroizing<Vec<u8>>, Box<dyn KeyStore>) = if is_ephemeral {
            let raw = binding.expose_secret().clone();
            let ks: Box<dyn KeyStore> = if has_key_store {
                let algo = stored_algo.as_deref().unwrap_or("pq2025");
                Box::new(crate::keystore::InMemoryKeyStore::new(algo))
            } else {
                Box::new(self.build_fs_store()?)
            };
            (Zeroizing::new(raw), ks)
        } else {
            let decrypted = crate::agent::decrypt_with_agent_password(
                binding.expose_secret(),
                self.password(),
                self.id.as_deref(),
            )
            .map_err(|e| format!("Byte signing failed: could not decrypt private key: {}", e))?;
            (
                Zeroizing::new(decrypted.as_slice().to_vec()),
                Box::new(self.build_fs_store()?) as Box<dyn KeyStore>,
            )
        };

        let sig_bytes = ks_box
            .sign_detached(key_bytes.as_slice(), data, &key_algorithm)
            .map_err(|e| {
                format!(
                    "Byte signing failed: cryptographic signing operation failed: {}",
                    e
                )
            })?;

        Ok(sig_bytes)
    }

    /// Generate keys using a specific KeyStore implementation.
    /// For ephemeral agents, uses set_keys_raw (no AES encryption).
    /// For persistent agents, uses set_keys (AES-encrypts private key).
    ///
    /// Resolve new key material without substitution. `pq2025` is the
    /// default; an explicit Ed25519 request mints Ed25519 keys. The config is
    /// updated only when a canonical alias differs from the requested label.
    pub fn generate_keys_with_store(&mut self, ks: &dyn KeyStore) -> Result<(), JacsError> {
        let config = self.config.as_ref().ok_or("Agent config not initialized")?;
        let requested_algorithm = config.get_key_algorithm()?;
        ensure_private_key_operation_allowed(&requested_algorithm, "key generation")?;
        let key_algorithm = if self.legacy_ed25519_keygen_allowed() {
            // Fixture-only hatch (see Agent::allow_legacy_ed25519_keygen_for_fixtures).
            requested_algorithm.clone()
        } else {
            resolve_new_agent_algorithm(&requested_algorithm)?
        };
        if key_algorithm != requested_algorithm
            && let Some(cfg) = self.config.as_mut()
        {
            // Keep the config consistent with the keys actually minted so
            // subsequent signing dispatches on the right algorithm.
            cfg.set_key_algorithm(key_algorithm.clone())?;
        }
        info!(algorithm = %key_algorithm, "Generating new keypair");
        let spec = KeySpec {
            algorithm: key_algorithm.clone(),
            key_id: None,
        };
        let (private_key, public_key) = ks.generate(&spec)?;
        if self.is_ephemeral() {
            self.set_keys_raw(private_key, public_key, &key_algorithm);
        } else {
            self.set_keys(private_key, public_key, &key_algorithm)?;
        }
        info!(algorithm = %key_algorithm, "Keypair generated successfully");
        Ok(())
    }
}

impl KeyManager for Agent {
    /// this necessatates updateding the version of the agent
    fn generate_keys(&mut self) -> Result<(), JacsError> {
        self.generate_keys_with_store(&self.build_fs_store()?)
    }

    fn sign_string(&mut self, data: &str) -> Result<String, JacsError> {
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
        ensure_private_key_operation_allowed(&key_algorithm, "signing")?;
        trace!(
            algorithm = %key_algorithm,
            data_len = data.len(),
            "Signing data"
        );
        let sign_start = std::time::Instant::now();
        // Validate algorithm is known (result unused but validates early)
        let _algo = CryptoSigningAlgorithm::from_str(&key_algorithm).map_err(|_| {
            format!(
                "Document signing failed: unknown signing algorithm '{}'. \
                Supported algorithms: ring-Ed25519, pq2025.",
                key_algorithm
            )
        })?;
        {
            let binding = self.get_private_key().map_err(|e| {
                format!(
                    "Document signing failed: private key not loaded. \
                    Ensure the agent has valid keys in the configured key directory. Error: {}",
                    e
                )
            })?;

            // Ephemeral agents: raw key, no AES decryption needed
            // Persistent agents: AES-encrypted key, must decrypt first
            let is_ephemeral = self.is_ephemeral();
            let has_key_store = self.get_key_store().is_some();
            let stored_algo = self.get_key_algorithm().cloned();
            let (key_bytes, ks_box): (Zeroizing<Vec<u8>>, Box<dyn KeyStore>) = if is_ephemeral {
                let raw = binding.expose_secret().clone();
                let ks: Box<dyn KeyStore> = if has_key_store {
                    let algo = stored_algo.as_deref().unwrap_or("pq2025");
                    Box::new(crate::keystore::InMemoryKeyStore::new(algo))
                } else {
                    Box::new(self.build_fs_store()?)
                };
                (Zeroizing::new(raw), ks)
            } else {
                let decrypted = crate::agent::decrypt_with_agent_password(
                    binding.expose_secret(),
                    self.password(),
                    self.id.as_deref(),
                )
                .map_err(|e| {
                    format!(
                        "Document signing failed: could not decrypt private key. \
                                Check that the password is correct. Error: {}",
                        e
                    )
                })?;
                (
                    Zeroizing::new(decrypted.as_slice().to_vec()),
                    Box::new(self.build_fs_store()?) as Box<dyn KeyStore>,
                )
            };

            let sig_bytes = ks_box
                .sign_detached(key_bytes.as_slice(), data.as_bytes(), &key_algorithm)
                .map_err(|e| {
                    format!(
                        "Document signing failed: cryptographic signing operation failed. \
                        This may indicate a corrupted key or algorithm mismatch. Error: {}",
                        e
                    )
                })?;
            let sign_duration_ms = sign_start.elapsed().as_millis() as u64;
            debug!(
                algorithm = %key_algorithm,
                signature_len = sig_bytes.len(),
                "Signing completed successfully"
            );
            info!(
                event = "document_signed",
                algorithm = %key_algorithm,
                duration_ms = sign_duration_ms,
                "Document signed"
            );
            Ok(STANDARD.encode(sig_bytes))
        }
    }

    fn sign_batch(&mut self, messages: &[&str]) -> Result<Vec<String>, JacsError> {
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
        ensure_private_key_operation_allowed(&key_algorithm, "signing")?;

        let batch_start = std::time::Instant::now();
        info!(
            algorithm = %key_algorithm,
            batch_size = messages.len(),
            "Signing batch of messages"
        );

        // Validate algorithm is known
        let _algo = CryptoSigningAlgorithm::from_str(&key_algorithm).map_err(|_| {
            format!(
                "Batch signing failed: unknown signing algorithm '{}'. \
                Supported algorithms: ring-Ed25519, pq2025.",
                key_algorithm
            )
        })?;

        let binding = self.get_private_key().map_err(|e| {
            format!(
                "Batch signing failed: private key not loaded. \
                Ensure the agent has valid keys in the configured key directory. Error: {}",
                e
            )
        })?;

        // Ephemeral: raw key, no AES. Persistent: decrypt first.
        let is_ephemeral = self.is_ephemeral();
        let has_key_store = self.get_key_store().is_some();
        let stored_algo = self.get_key_algorithm().cloned();
        let (key_bytes, ks_box): (Zeroizing<Vec<u8>>, Box<dyn KeyStore>) = if is_ephemeral {
            let raw = binding.expose_secret().clone();
            let ks: Box<dyn KeyStore> = if has_key_store {
                let algo = stored_algo.as_deref().unwrap_or("pq2025");
                Box::new(crate::keystore::InMemoryKeyStore::new(algo))
            } else {
                Box::new(self.build_fs_store()?)
            };
            (Zeroizing::new(raw), ks)
        } else {
            let decrypted = crate::agent::decrypt_with_agent_password(
                binding.expose_secret(),
                self.password(),
                self.id.as_deref(),
            )
            .map_err(|e| {
                format!(
                    "Batch signing failed: could not decrypt private key. \
                            Check that the password is correct. Error: {}",
                    e
                )
            })?;
            (
                Zeroizing::new(decrypted.as_slice().to_vec()),
                Box::new(self.build_fs_store()?) as Box<dyn KeyStore>,
            )
        };

        // Sign all messages with the same key
        let mut signatures = Vec::with_capacity(messages.len());
        for (index, data) in messages.iter().enumerate() {
            trace!(
                algorithm = %key_algorithm,
                batch_index = index,
                data_len = data.len(),
                "Signing batch item"
            );
            let sig_bytes =
                ks_box.sign_detached(key_bytes.as_slice(), data.as_bytes(), &key_algorithm)?;
            signatures.push(STANDARD.encode(sig_bytes));
        }

        let batch_duration_ms = batch_start.elapsed().as_millis() as u64;
        debug!(
            algorithm = %key_algorithm,
            batch_size = messages.len(),
            "Batch signing completed successfully"
        );
        info!(
            event = "batch_signed",
            algorithm = %key_algorithm,
            batch_size = messages.len(),
            duration_ms = batch_duration_ms,
            "Batch signing complete"
        );

        Ok(signatures)
    }

    fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), JacsError> {
        trace!(
            data_len = data.len(),
            signature_len = signature_base64.len(),
            public_key_len = public_key.len(),
            explicit_algorithm = ?public_key_enc_type,
            "Verifying signature"
        );
        let verify_start = std::time::Instant::now();
        // Get the signature bytes for analysis
        let signature_bytes = STANDARD
            .decode(signature_base64)
            .map_err(|e| JacsError::CryptoError(format!("Invalid base64 signature: {}", e)))?;

        // Determine the algorithm type
        let algo = match public_key_enc_type {
            Some(ref enc_type) => {
                debug!(algorithm = %enc_type, "Using explicit algorithm from signature");
                CryptoSigningAlgorithm::from_str(enc_type).map_err(|_| {
                    JacsError::CryptoError(format!("Unknown signing algorithm: {}", enc_type))
                })?
            }
            None => {
                let allow_legacy_detection = crate::storage::jenv::get_env_var(
                    "JACS_ALLOW_LEGACY_ALGORITHM_DETECTION",
                    false,
                )
                .ok()
                .flatten()
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
                if !allow_legacy_detection {
                    return Err(
                        "Signature verification requires explicit signingAlgorithm field. \
                        Re-sign the document to include the signingAlgorithm field, or set \
                        JACS_ALLOW_LEGACY_ALGORITHM_DETECTION=true to verify legacy documents."
                            .into(),
                    );
                }
                warn!(
                    "SECURITY: signingAlgorithm not provided for verification. \
                    Legacy auto-detection is enabled by JACS_ALLOW_LEGACY_ALGORITHM_DETECTION."
                );

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
                        CryptoSigningAlgorithm::from_str(&key_algorithm).map_err(|_| {
                            JacsError::CryptoError(format!(
                                "Unknown signing algorithm: {}",
                                key_algorithm
                            ))
                        })?
                    }
                }
            }
        };

        let algo_str = algo.to_string();
        let result = verify_string_with_algorithm(public_key, data, signature_base64, &algo_str);

        let verify_duration_ms = verify_start.elapsed().as_millis() as u64;
        let valid = result.is_ok();
        info!(
            event = "signature_verified",
            algorithm = %algo_str,
            valid = valid,
            duration_ms = verify_duration_ms,
            "Signature verification complete"
        );

        result
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CryptoSigningAlgorithm, detect_algorithm_from_public_key, normalize_public_key_pem,
        resolve_rotation_algorithm,
    };

    #[test]
    fn rotation_policy_preserves_or_upgrades_without_downgrading() {
        assert_eq!(
            resolve_rotation_algorithm("ring-Ed25519", None).unwrap(),
            "ring-Ed25519"
        );
        assert_eq!(
            resolve_rotation_algorithm("ring-Ed25519", Some("ed25519")).unwrap(),
            "ring-Ed25519"
        );
        assert_eq!(
            resolve_rotation_algorithm("ring-Ed25519", Some("pq2025")).unwrap(),
            "pq2025"
        );
        assert_eq!(
            resolve_rotation_algorithm("pq2025", None).unwrap(),
            "pq2025"
        );
        assert_eq!(
            resolve_rotation_algorithm("pq2025", Some("pq2025")).unwrap(),
            "pq2025"
        );

        let downgrade = resolve_rotation_algorithm("pq2025", Some("ed25519"))
            .expect_err("PQ to Ed25519 rotation must be rejected");
        assert!(downgrade.to_string().contains("downgrade"));
        assert!(resolve_rotation_algorithm("pq2025", Some("rsa-pss")).is_err());
    }

    #[test]
    fn detects_every_exact_length_ed25519_public_key() {
        // Ed25519 public keys are arbitrary 32-byte strings. Requiring a
        // particular proportion of non-ASCII bytes rejects valid keys based
        // on random key material; this low-high-bit fixture reproduces the
        // committed cross-language provenance key that exposed the bug.
        let key = [0x41_u8; 32];
        assert!(matches!(
            detect_algorithm_from_public_key(&key).expect("32-byte Ed25519 key"),
            CryptoSigningAlgorithm::RingEd25519,
        ));
    }

    #[test]
    fn rejects_unknown_key_lengths_even_when_bytes_are_non_ascii() {
        assert!(detect_algorithm_from_public_key(&[0xff_u8; 64]).is_err());
    }

    #[test]
    fn normalize_public_key_pem_wraps_raw_bytes() {
        let pem = normalize_public_key_pem(&[0x34, 0x9e, 0x74, 0xd9, 0xd1, 0x60]);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(pem.contains("NJ502dFg"));
    }

    #[test]
    fn normalize_public_key_pem_preserves_existing_pem() {
        let pem = normalize_public_key_pem(
            b"-----BEGIN PUBLIC KEY-----\r\nQUJD\n-----END PUBLIC KEY-----\r\n",
        );
        assert_eq!(
            pem,
            "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n"
        );
    }
}
