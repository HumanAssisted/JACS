//! Trust store management for JACS agents.
//!
//! This module provides functions for managing trusted agents,
//! enabling P2P key exchange and verification without a central authority.

use crate::crypt::hash::hash_public_key;
use crate::crypt::{CryptoSigningAlgorithm, detect_algorithm_from_public_key};
use crate::error::JacsError;
use crate::paths::trust_store_dir;
use crate::schema::utils::ValueExt;
use crate::time_utils;
use crate::validation::validate_agent_id;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use tracing::{info, warn};

/// Validates an agent ID is safe for use in filesystem paths.
///
/// This checks that the agent ID:
/// 1. Is a valid JACS agent ID (UUID:UUID format)
/// 2. Does not contain path traversal sequences
///
/// This is a security boundary function -- all trust store operations that
/// construct file paths from agent IDs MUST call this first.
fn validate_agent_id_for_path(agent_id: &str) -> Result<(), JacsError> {
    // Primary defense: validate UUID:UUID format (rejects all special characters)
    validate_agent_id(agent_id)?;

    // Secondary defense: explicitly reject path traversal patterns
    if agent_id.contains("..") || agent_id.contains('/') || agent_id.contains('\\') || agent_id.contains('\0') {
        return Err(JacsError::ValidationError(format!(
            "Agent ID '{}' contains unsafe path characters",
            agent_id
        )));
    }

    Ok(())
}

/// Validates that a constructed path is within the trust store directory.
///
/// Defense-in-depth: even after agent ID validation, verify the resolved
/// path doesn't escape the trust store.
fn validate_path_within_trust_dir(path: &Path, trust_dir: &Path) -> Result<(), JacsError> {
    // For existing files, canonicalize and check containment
    if path.exists() {
        let canonical_path = path.canonicalize().map_err(|e| JacsError::Internal {
            message: format!("Failed to canonicalize path: {}", e),
        })?;
        let canonical_trust = trust_dir.canonicalize().map_err(|e| JacsError::Internal {
            message: format!("Failed to canonicalize trust dir: {}", e),
        })?;
        if !canonical_path.starts_with(&canonical_trust) {
            return Err(JacsError::ValidationError(
                "Path traversal detected: resolved path is outside trust store".to_string(),
            ));
        }
    }
    Ok(())
}

/// Information about a trusted agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAgent {
    /// The agent's unique identifier.
    pub agent_id: String,
    /// The agent's human-readable name.
    pub name: Option<String>,
    /// The agent's public key in PEM format.
    pub public_key_pem: String,
    /// Hash of the public key for quick lookups.
    pub public_key_hash: String,
    /// When this agent was trusted.
    pub trusted_at: String,
}

/// Adds an agent to the local trust store.
///
/// The agent JSON must be a valid, self-signed JACS agent document.
/// The self-signature is verified before trusting.
///
/// # Arguments
///
/// * `agent_json` - The full agent JSON string
///
/// # Returns
///
/// The agent ID if successfully trusted.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::trust::trust_agent;
///
/// // Receive agent file from another party
/// let agent_json = std::fs::read_to_string("other-agent.json")?;
/// let agent_id = trust_agent(&agent_json)?;
/// println!("Now trusting agent: {}", agent_id);
/// ```
///
/// # Security
///
/// This function requires the public key to be provided separately via
/// `trust_agent_with_key` for proper signature verification. This version
/// attempts to load the public key from the trust store's key cache.
#[must_use = "trust operation result must be checked for errors"]
pub fn trust_agent(agent_json: &str) -> Result<String, JacsError> {
    // For backward compatibility, try to trust without a provided public key
    // This will fail if the public key isn't already in our key cache
    trust_agent_with_key(agent_json, None)
}

/// Adds an agent to the local trust store with explicit public key.
///
/// This is the preferred method for P2P trust establishment where you
/// receive both the agent document and their public key.
///
/// # Arguments
///
/// * `agent_json` - The full agent JSON string
/// * `public_key_pem` - Optional PEM-encoded public key. If not provided,
///   attempts to load from local key cache using the publicKeyHash.
///
/// # Returns
///
/// The agent ID if successfully trusted.
///
/// # Security
///
/// The self-signature is cryptographically verified before the agent is trusted.
/// If verification fails, the agent is NOT added to the trust store.
#[must_use = "trust operation result must be checked for errors"]
pub fn trust_agent_with_key(agent_json: &str, public_key_pem: Option<&str>) -> Result<String, JacsError> {
    // Parse the agent JSON
    let agent_value: Value = serde_json::from_str(agent_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "agent_json".to_string(),
            reason: e.to_string(),
        }
    })?;

    // Extract required fields
    let agent_id = agent_value.get_str_required("jacsId")?;

    // Validate agent ID is safe for filesystem paths (prevents path traversal)
    validate_agent_id_for_path(&agent_id)?;

    let name = agent_value.get_str("name");

    // Extract public key hash from signature
    let public_key_hash = agent_value.get_path_str_required(&["jacsSignature", "publicKeyHash"])?;

    // Extract signing algorithm from signature
    // Note: signingAlgorithm is now required in the schema, but we handle legacy documents
    // that may not have it by falling back to algorithm detection with a warning
    let signing_algorithm = agent_value.get_path_str(&["jacsSignature", "signingAlgorithm"]);

    if signing_algorithm.is_none() {
        warn!(
            agent_id = %agent_id,
            "SECURITY WARNING: Agent signature missing signingAlgorithm field. \
            Falling back to algorithm detection. This is insecure and deprecated. \
            Re-sign this agent document to include the signingAlgorithm field."
        );
    }

    // Get the public key bytes
    let public_key_bytes: Vec<u8> = match public_key_pem {
        Some(pem) => pem.as_bytes().to_vec(),
        None => {
            // Try to load from trust store key cache
            load_public_key_from_cache(&public_key_hash)?
        }
    };

    // Verify the public key hash matches
    let computed_hash = hash_public_key(public_key_bytes.clone());
    if computed_hash != public_key_hash {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "Public key hash mismatch for agent '{}': the provided public key (hash: '{}') \
                does not match the key hash in the agent's signature (expected: '{}'). \
                This could mean: (1) the wrong public key was provided, \
                (2) the agent document was modified after signing, or \
                (3) the agent's keys have been rotated. \
                Verify you have the correct public key for this agent.",
                agent_id, computed_hash, public_key_hash
            ),
        });
    }

    // Verify the self-signature
    verify_agent_self_signature(&agent_value, &public_key_bytes, signing_algorithm.as_deref())?;

    // Create trust store directory if it doesn't exist
    let trust_dir = trust_store_dir();
    fs::create_dir_all(&trust_dir).map_err(|e| JacsError::DirectoryCreateFailed {
        path: trust_dir.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;

    // Save the agent file
    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    fs::write(&agent_file, agent_json).map_err(|e| JacsError::FileWriteFailed {
        path: agent_file.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;

    // Save the public key to the key cache for future verifications
    save_public_key_to_cache(&public_key_hash, &public_key_bytes, signing_algorithm.as_deref())?;

    // Convert public key bytes to PEM string for metadata
    let public_key_pem_string = String::from_utf8(public_key_bytes.clone())
        .unwrap_or_else(|_| B64.encode(&public_key_bytes));

    // Also save a metadata file for quick lookups
    let trusted_agent = TrustedAgent {
        agent_id: agent_id.clone(),
        name,
        public_key_pem: public_key_pem_string,
        public_key_hash,
        trusted_at: time_utils::now_rfc3339(),
    };

    let metadata_file = trust_dir.join(format!("{}.meta.json", agent_id));
    let metadata_json = serde_json::to_string_pretty(&trusted_agent).map_err(|e| {
        JacsError::Internal {
            message: format!("Failed to serialize metadata: {}", e),
        }
    })?;
    fs::write(&metadata_file, metadata_json).map_err(|e| JacsError::Internal {
        message: format!("Failed to write metadata file: {}", e),
    })?;

    info!("Trusted agent {} added to trust store", agent_id);
    Ok(agent_id)
}

/// Lists all trusted agent IDs.
///
/// # Returns
///
/// A vector of agent IDs that are in the trust store.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::trust::list_trusted_agents;
///
/// let agents = list_trusted_agents()?;
/// for agent_id in agents {
///     println!("Trusted: {}", agent_id);
/// }
/// ```
#[must_use = "list of trusted agents must be used"]
pub fn list_trusted_agents() -> Result<Vec<String>, JacsError> {
    let trust_dir = trust_store_dir();

    if !trust_dir.exists() {
        return Ok(Vec::new());
    }

    let mut agents = Vec::new();

    let entries = fs::read_dir(&trust_dir).map_err(|e| JacsError::Internal {
        message: format!("Failed to read trust store directory: {}", e),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| JacsError::Internal {
            message: format!("Failed to read directory entry: {}", e),
        })?;

        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json")
            && !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".meta.json"))
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            agents.push(stem.to_string());
        }
    }

    Ok(agents)
}

/// Removes an agent from the trust store.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent to untrust
///
/// # Example
///
/// ```rust,ignore
/// use jacs::trust::untrust_agent;
///
/// untrust_agent("agent-123-uuid")?;
/// ```
#[must_use = "untrust operation result must be checked for errors"]
pub fn untrust_agent(agent_id: &str) -> Result<(), JacsError> {
    // Validate agent ID is safe for filesystem paths (prevents path traversal)
    validate_agent_id_for_path(agent_id)?;

    let trust_dir = trust_store_dir();

    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    let metadata_file = trust_dir.join(format!("{}.meta.json", agent_id));

    validate_path_within_trust_dir(&agent_file, &trust_dir)?;

    if !agent_file.exists() {
        return Err(JacsError::AgentNotTrusted {
            agent_id: agent_id.to_string(),
        });
    }

    // Remove both files
    if agent_file.exists() {
        fs::remove_file(&agent_file).map_err(|e| JacsError::Internal {
            message: format!("Failed to remove agent file: {}", e),
        })?;
    }

    if metadata_file.exists() {
        fs::remove_file(&metadata_file).map_err(|e| JacsError::Internal {
            message: format!("Failed to remove metadata file: {}", e),
        })?;
    }

    info!("Agent {} removed from trust store", agent_id);
    Ok(())
}

/// Retrieves a trusted agent's information.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent to look up
///
/// # Returns
///
/// The full agent JSON if the agent is trusted.
#[must_use = "trusted agent data must be used"]
pub fn get_trusted_agent(agent_id: &str) -> Result<String, JacsError> {
    // Validate agent ID is safe for filesystem paths (prevents path traversal)
    validate_agent_id_for_path(agent_id)?;

    let trust_dir = trust_store_dir();
    let agent_file = trust_dir.join(format!("{}.json", agent_id));

    validate_path_within_trust_dir(&agent_file, &trust_dir)?;

    if !agent_file.exists() {
        return Err(JacsError::TrustError(format!(
            "Agent '{}' is not in the trust store. Use trust_agent() or trust_agent_with_key() \
            to add the agent first. Use list_trusted_agents() to see currently trusted agents. \
            Expected file at: {}",
            agent_id,
            agent_file.to_string_lossy()
        )));
    }

    fs::read_to_string(&agent_file).map_err(|e| JacsError::FileReadFailed {
        path: agent_file.to_string_lossy().to_string(),
        reason: e.to_string(),
    })
}

/// Retrieves the public key for a trusted agent.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent
///
/// # Returns
///
/// The public key hash for looking up the actual key.
#[must_use = "public key hash must be used"]
pub fn get_trusted_public_key_hash(agent_id: &str) -> Result<String, JacsError> {
    // Validation is performed inside get_trusted_agent, but validate here too
    // for defense in depth in case the call chain changes
    validate_agent_id_for_path(agent_id)?;

    let agent_json = get_trusted_agent(agent_id)?;
    let agent_value: Value = serde_json::from_str(&agent_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "agent_json".to_string(),
            reason: e.to_string(),
        }
    })?;

    agent_value.get_path_str_required(&["jacsSignature", "publicKeyHash"])
}

/// Checks if an agent is in the trust store.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent to check
///
/// # Returns
///
/// `true` if the agent is trusted, `false` otherwise.
pub fn is_trusted(agent_id: &str) -> bool {
    // Validate agent ID is safe for filesystem paths; return false for invalid IDs
    if validate_agent_id_for_path(agent_id).is_err() {
        return false;
    }
    let trust_dir = trust_store_dir();
    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    agent_file.exists()
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

/// Loads a public key from the trust store's key cache.
fn load_public_key_from_cache(public_key_hash: &str) -> Result<Vec<u8>, JacsError> {
    // Validate hash doesn't contain path traversal characters
    if public_key_hash.contains("..") || public_key_hash.contains('/') || public_key_hash.contains('\\') || public_key_hash.contains('\0') {
        return Err(JacsError::ValidationError(format!(
            "Public key hash '{}' contains unsafe path characters",
            public_key_hash
        )));
    }

    let trust_dir = trust_store_dir();
    let keys_dir = trust_dir.join("keys");
    let key_file = keys_dir.join(format!("{}.pem", public_key_hash));

    if !key_file.exists() {
        return Err(JacsError::TrustError(format!(
            "Public key not found in trust store cache for hash '{}'. \
            To trust this agent, call trust_agent_with_key() and provide the agent's public key PEM. \
            Expected key at: {}",
            public_key_hash,
            key_file.to_string_lossy()
        )));
    }

    fs::read(&key_file).map_err(|e| JacsError::FileReadFailed {
        path: key_file.to_string_lossy().to_string(),
        reason: e.to_string(),
    })
}

/// Saves a public key to the trust store's key cache.
fn save_public_key_to_cache(
    public_key_hash: &str,
    public_key_bytes: &[u8],
    algorithm: Option<&str>,
) -> Result<(), JacsError> {
    // Validate hash doesn't contain path traversal characters
    if public_key_hash.contains("..") || public_key_hash.contains('/') || public_key_hash.contains('\\') || public_key_hash.contains('\0') {
        return Err(JacsError::ValidationError(format!(
            "Public key hash '{}' contains unsafe path characters",
            public_key_hash
        )));
    }

    let trust_dir = trust_store_dir();
    let keys_dir = trust_dir.join("keys");

    fs::create_dir_all(&keys_dir).map_err(|e| JacsError::DirectoryCreateFailed {
        path: keys_dir.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;

    // Save the public key
    let key_file = keys_dir.join(format!("{}.pem", public_key_hash));
    fs::write(&key_file, public_key_bytes).map_err(|e| JacsError::FileWriteFailed {
        path: key_file.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;

    // Save the algorithm type if provided
    if let Some(algo) = algorithm {
        let algo_file = keys_dir.join(format!("{}.algo", public_key_hash));
        fs::write(&algo_file, algo).map_err(|e| JacsError::FileWriteFailed {
            path: algo_file.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
    }

    Ok(())
}

/// Validates a signature timestamp using centralized time utilities.
///
/// This is a thin wrapper around `time_utils::validate_signature_timestamp`
/// for use within this module.
fn validate_signature_timestamp(timestamp_str: &str) -> Result<(), JacsError> {
    time_utils::validate_signature_timestamp(timestamp_str)
}

/// Verifies an agent's self-signature.
///
/// This function extracts the signature from the agent document and verifies it
/// against the provided public key. It also validates the signature timestamp.
fn verify_agent_self_signature(
    agent_value: &Value,
    public_key_bytes: &[u8],
    algorithm: Option<&str>,
) -> Result<(), JacsError> {
    // Extract and validate signature timestamp
    let signature_date = agent_value.get_path_str_required(&["jacsSignature", "date"])?;
    validate_signature_timestamp(&signature_date)?;

    // Extract signature components
    let signature_b64 = agent_value.get_path_str_required(&["jacsSignature", "signature"])?;
    let fields = agent_value.get_path_array_required(&["jacsSignature", "fields"])?;

    // Build the content that was signed, using deterministic field ordering
    let mut field_names: Vec<&str> = Vec::new();
    for field in fields {
        if let Some(name) = field.as_str() {
            field_names.push(name);
        }
    }
    // Sort fields alphabetically for deterministic content reconstruction
    field_names.sort();

    let mut content_parts: Vec<String> = Vec::new();
    for field_name in &field_names {
        if let Some(value) = agent_value.get(*field_name) {
            if let Some(str_val) = value.as_str() {
                content_parts.push(str_val.to_string());
            } else {
                // For non-string fields, use canonical JSON serialization
                content_parts.push(serde_json::to_string(value).unwrap_or_default());
            }
        }
    }

    if content_parts.is_empty() {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "No signed fields could be extracted from the agent document. \
                The 'fields' array in jacsSignature may reference non-existent fields.".to_string(),
        });
    }

    let signed_content = content_parts.join(" ");

    // Determine the algorithm
    let algo = match algorithm {
        Some(a) => CryptoSigningAlgorithm::from_str(a).map_err(|_| JacsError::SignatureVerificationFailed {
            reason: format!(
                "Unknown signing algorithm '{}'. Supported algorithms are: \
                'ring-Ed25519', 'RSA-PSS', 'pq-dilithium', 'pq-dilithium-alt', 'pq2025'. \
                The agent document may have been signed with an unsupported algorithm version.",
                a
            ),
        })?,
        None => {
            // Check if strict mode is enabled
            let strict = std::env::var("JACS_REQUIRE_EXPLICIT_ALGORITHM")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
            if strict {
                return Err(JacsError::SignatureVerificationFailed {
                    reason: "Signature missing signingAlgorithm field. \
                        Strict algorithm enforcement is enabled (JACS_REQUIRE_EXPLICIT_ALGORITHM=true). \
                        Re-sign the agent document to include the signingAlgorithm field.".to_string(),
                });
            }

            // Try to detect from the public key
            detect_algorithm_from_public_key(public_key_bytes).map_err(|e| {
                JacsError::SignatureVerificationFailed {
                    reason: format!(
                        "Could not detect signing algorithm from public key: {}. \
                        The agent document is missing the 'signingAlgorithm' field and \
                        automatic detection failed. Re-sign the agent document to include \
                        the signingAlgorithm field, or verify the public key format is correct.",
                        e
                    ),
                }
            })?
        }
    };

    // Verify the signature based on algorithm
    let verification_result = match algo {
        CryptoSigningAlgorithm::RsaPss => {
            crate::crypt::rsawrapper::verify_string(
                public_key_bytes.to_vec(),
                &signed_content,
                &signature_b64,
            )
        }
        CryptoSigningAlgorithm::RingEd25519 => {
            crate::crypt::ringwrapper::verify_string(
                public_key_bytes.to_vec(),
                &signed_content,
                &signature_b64,
            )
        }
        CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
            crate::crypt::pq::verify_string(
                public_key_bytes.to_vec(),
                &signed_content,
                &signature_b64,
            )
        }
        CryptoSigningAlgorithm::Pq2025 => {
            crate::crypt::pq2025::verify_string(
                public_key_bytes.to_vec(),
                &signed_content,
                &signature_b64,
            )
        }
    };

    verification_result.map_err(|e| JacsError::SignatureVerificationFailed {
        reason: format!(
            "Cryptographic signature verification failed using {} algorithm: {}. \
            This typically means: (1) the agent document was modified after signing, \
            (2) the wrong public key is being used, or (3) the signature is corrupted. \
            Verify the agent document integrity and ensure the correct public key is provided.",
            algo, e
        ),
    })?;

    info!("Agent self-signature verified successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time_utils::{now_rfc3339, now_utc};
    use serial_test::serial;
    use std::env;
    use tempfile::TempDir;

    /// RAII guard for test isolation that ensures HOME is restored even on panic.
    ///
    /// This struct:
    /// - Saves the original HOME environment variable
    /// - Creates a temporary directory and sets HOME to point to it
    /// - On drop (including panic unwinding): restores the original HOME
    /// - The TempDir is automatically cleaned up when dropped
    struct TrustTestGuard {
        _temp_dir: TempDir,
        original_home: Option<String>,
    }

    impl TrustTestGuard {
        /// Creates a new test guard that sets up an isolated trust store environment.
        ///
        /// # Panics
        ///
        /// Panics if the temporary directory cannot be created.
        fn new() -> Self {
            // Save original HOME before modifying
            let original_home = env::var("HOME").ok();

            let temp_dir = TempDir::new().expect("Failed to create temp directory for test");

            // SAFETY: `env::set_var` is unsafe in Rust 2024+ due to potential data races when
            // other threads read environment variables concurrently. This is safe here because:
            // 1. This function is only called from #[serial] tests which run single-threaded
            // 2. No other threads are spawned before this call completes
            // 3. The HOME variable is read only after this setup completes
            // 4. The TempDir lifetime ensures the path remains valid for the test duration
            // If these invariants are violated (e.g., parallel test execution), undefined
            // behavior could occur from concurrent env access.
            unsafe {
                env::set_var("HOME", temp_dir.path().to_str().unwrap());
            }

            Self {
                _temp_dir: temp_dir,
                original_home,
            }
        }
    }

    impl Drop for TrustTestGuard {
        fn drop(&mut self) {
            // Restore original HOME even during panic unwinding.
            // SAFETY: Same rationale as in new() - tests are #[serial] so no concurrent access.
            unsafe {
                match &self.original_home {
                    Some(home) => env::set_var("HOME", home),
                    None => env::remove_var("HOME"),
                }
            }
        }
    }

    /// Sets up an isolated trust store environment for testing.
    ///
    /// Returns a guard that must be kept alive for the duration of the test.
    /// When the guard is dropped (including on panic), the original HOME
    /// environment variable is restored.
    fn setup_test_trust_dir() -> TrustTestGuard {
        TrustTestGuard::new()
    }

    // ==================== Timestamp Validation Tests ====================

    #[test]
    fn test_valid_recent_timestamp() {
        // A timestamp from just now should be valid
        let now = now_rfc3339();
        let result = validate_signature_timestamp(&now);
        assert!(result.is_ok(), "Recent timestamp should be valid: {:?}", result);
    }

    #[test]
    fn test_valid_past_timestamp() {
        // A timestamp from 1 hour ago should be valid (within 90-day default expiry)
        let past = (now_utc() - chrono::Duration::hours(1)).to_rfc3339();
        let result = validate_signature_timestamp(&past);
        assert!(result.is_ok(), "Past timestamp within expiry should be valid: {:?}", result);
    }

    #[test]
    #[serial]
    fn test_valid_old_timestamp_with_expiry_disabled() {
        // A timestamp from a year ago should be valid when expiration is explicitly disabled
        unsafe { env::set_var("JACS_MAX_SIGNATURE_AGE_SECONDS", "0"); }
        let old = (now_utc() - chrono::Duration::days(365)).to_rfc3339();
        let result = validate_signature_timestamp(&old);
        unsafe { env::remove_var("JACS_MAX_SIGNATURE_AGE_SECONDS"); }
        assert!(result.is_ok(), "Old timestamp should be valid when expiration is disabled: {:?}", result);
    }

    #[test]
    fn test_old_timestamp_rejected_with_default_expiry() {
        // A timestamp from a year ago should be rejected with default 90-day expiry
        let old = (now_utc() - chrono::Duration::days(365)).to_rfc3339();
        let result = validate_signature_timestamp(&old);
        assert!(result.is_err(), "Year-old timestamp should be rejected with default expiry");
    }

    #[test]
    fn test_timestamp_slight_future_allowed() {
        // A timestamp a few seconds in the future should be allowed (clock drift)
        let slight_future = (now_utc() + chrono::Duration::seconds(30)).to_rfc3339();
        let result = validate_signature_timestamp(&slight_future);
        assert!(result.is_ok(), "Slight future timestamp should be allowed for clock drift: {:?}", result);
    }

    #[test]
    fn test_timestamp_far_future_rejected() {
        // A timestamp 10 minutes in the future should be rejected
        let far_future = (now_utc() + chrono::Duration::minutes(10)).to_rfc3339();
        let result = validate_signature_timestamp(&far_future);
        assert!(result.is_err(), "Far future timestamp should be rejected");
        if let Err(JacsError::SignatureVerificationFailed { reason }) = result {
            assert!(
                reason.contains("future"),
                "Error should mention future timestamp: {}",
                reason
            );
        } else {
            panic!("Expected SignatureVerificationFailed error");
        }
    }

    #[test]
    fn test_timestamp_invalid_format_rejected() {
        // Invalid timestamp formats should be rejected
        let invalid_timestamps = [
            "not-a-timestamp",
            "2024-13-01T00:00:00Z",  // Invalid month
            "2024-01-32T00:00:00Z",  // Invalid day
            "01/01/2024",            // Wrong format
            "",                       // Empty
        ];

        for invalid in invalid_timestamps {
            let result = validate_signature_timestamp(invalid);
            assert!(
                result.is_err(),
                "Invalid timestamp '{}' should be rejected",
                invalid
            );
            if let Err(JacsError::SignatureVerificationFailed { reason }) = result {
                assert!(
                    reason.contains("Invalid") || reason.contains("format"),
                    "Error should mention invalid format for '{}': {}",
                    invalid,
                    reason
                );
            }
        }
    }

    #[test]
    fn test_timestamp_various_valid_formats() {
        // Various valid RFC 3339 formats should work (use recent timestamps within 90-day window)
        let now = now_utc();
        let valid_timestamps = [
            (now - chrono::Duration::hours(1)).to_rfc3339(),
            (now - chrono::Duration::days(1)).to_rfc3339(),
            (now - chrono::Duration::days(30)).to_rfc3339(),
        ];

        for valid in &valid_timestamps {
            let result = validate_signature_timestamp(valid);
            assert!(
                result.is_ok(),
                "Valid timestamp format '{}' should be accepted: {:?}",
                valid,
                result
            );
        }
    }

    // ==================== Trust Store Tests ====================

    #[test]
    #[serial]
    fn test_list_empty_trust_store() {
        let _temp = setup_test_trust_dir();
        let agents = list_trusted_agents().unwrap();
        assert!(agents.is_empty());
    }

    #[test]
    #[serial]
    fn test_is_trusted_unknown() {
        let _temp = setup_test_trust_dir();
        assert!(!is_trusted("unknown-agent-id"));
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_missing_signature() {
        let _temp = setup_test_trust_dir();

        // Agent without jacsSignature should fail
        let agent_json = r#"{
            "jacsId": "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001",
            "name": "Test Agent"
        }"#;

        let result = trust_agent(agent_json);
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert!(field.contains("publicKeyHash"));
            }
            _ => panic!("Expected DocumentMalformed error, got: {:?}", result),
        }
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_invalid_public_key_hash() {
        let _temp = setup_test_trust_dir();

        // Agent with signature but wrong public key hash
        let agent_json = r#"{
            "jacsId": "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001",
            "name": "Test Agent",
            "jacsSignature": {
                "agentID": "test-agent-id",
                "agentVersion": "v1",
                "date": "2024-01-01T00:00:00Z",
                "signature": "dGVzdHNpZw==",
                "publicKeyHash": "wrong-hash",
                "signingAlgorithm": "ring-Ed25519",
                "fields": ["name"]
            }
        }"#;

        // This should fail because no public key exists for "wrong-hash"
        let result = trust_agent(agent_json);
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_save_and_load_public_key_cache() {
        let _temp = setup_test_trust_dir();

        let test_key = b"test-public-key-content";
        let hash = "test-hash-123";

        // Save the key
        let save_result = save_public_key_to_cache(hash, test_key, Some("ring-Ed25519"));
        assert!(save_result.is_ok());

        // Load it back
        let load_result = load_public_key_from_cache(hash);
        assert!(load_result.is_ok());
        assert_eq!(load_result.unwrap(), test_key);
    }

    #[test]
    #[serial]
    fn test_load_missing_public_key_cache() {
        let _temp = setup_test_trust_dir();

        let result = load_public_key_from_cache("nonexistent-hash");
        assert!(result.is_err());
        match result {
            Err(JacsError::TrustError(msg)) => {
                assert!(msg.contains("nonexistent-hash"), "Error should contain the hash");
                assert!(msg.contains("trust_agent_with_key"), "Error should suggest trust_agent_with_key");
            }
            _ => panic!("Expected TrustError error"),
        }
    }

    // ==================== Additional Negative Tests for Security ====================

    #[test]
    fn test_timestamp_empty_string_rejected() {
        let result = validate_signature_timestamp("");
        assert!(result.is_err(), "Empty timestamp should be rejected");
        if let Err(JacsError::SignatureVerificationFailed { reason }) = result {
            assert!(
                reason.contains("Invalid") || reason.contains("format"),
                "Error should mention invalid format: {}",
                reason
            );
        }
    }

    #[test]
    fn test_timestamp_whitespace_only_rejected() {
        let whitespace_timestamps = ["   ", "\t\t", "\n\n", "  \t\n  "];
        for ts in whitespace_timestamps {
            let result = validate_signature_timestamp(ts);
            assert!(
                result.is_err(),
                "Whitespace-only timestamp '{}' should be rejected",
                ts.escape_debug()
            );
        }
    }

    #[test]
    fn test_timestamp_extremely_far_future_rejected() {
        // Year 3000 - definitely too far in the future
        let far_future = "3000-01-01T00:00:00Z";
        let result = validate_signature_timestamp(far_future);
        assert!(
            result.is_err(),
            "Extremely far future timestamp should be rejected"
        );
    }

    #[test]
    fn test_timestamp_truly_invalid_formats_rejected() {
        // Formats that are definitely invalid for RFC 3339
        let invalid_timestamps = [
            "2024/01/01T00:00:00Z",    // Wrong date separator
            "Jan 01, 2024",            // Human readable format
            "1704067200",              // Unix timestamp
            "2024-W01",                // ISO week format
        ];

        for ts in invalid_timestamps {
            let result = validate_signature_timestamp(ts);
            assert!(
                result.is_err(),
                "Invalid timestamp format '{}' should be rejected",
                ts
            );
        }
    }

    #[test]
    fn test_timestamp_with_injection_attempt() {
        // Timestamps with potential injection characters
        let injection_attempts = [
            "2024-01-01T00:00:00Z; DROP TABLE users;",
            "2024-01-01T00:00:00Z<script>",
            "2024-01-01T00:00:00Z\x00null",
            "2024-01-01T00:00:00Z' OR '1'='1",
        ];

        for ts in injection_attempts {
            let result = validate_signature_timestamp(ts);
            assert!(
                result.is_err(),
                "Timestamp with injection attempt '{}' should be rejected",
                ts.escape_debug()
            );
        }
    }

    #[test]
    fn test_timestamp_unix_epoch_rejected_with_default_expiry() {
        // Unix epoch (1970-01-01) should be rejected with default 90-day expiry
        let epoch = "1970-01-01T00:00:00Z";
        let result = validate_signature_timestamp(epoch);
        assert!(
            result.is_err(),
            "Unix epoch should be rejected with default 90-day expiry"
        );
    }

    #[test]
    fn test_timestamp_y2k38_boundary() {
        // Test around the Y2K38 boundary (2038-01-19)
        let y2k38 = "2038-01-19T03:14:07Z";
        let result = validate_signature_timestamp(y2k38);
        // This should be valid (it's in the past from 2026 perspective when test runs,
        // or slightly in the future - either way, within normal bounds)
        // Just ensure it doesn't panic
        let _ = result;
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_invalid_json() {
        let _temp = setup_test_trust_dir();

        let invalid_json_cases = [
            "",                          // Empty
            "not json at all",           // Plain text
            "{",                         // Unclosed brace
            "[}",                        // Mismatched brackets
            "{'invalid': 'single quotes'}", // Single quotes
            "{\"incomplete\":",          // Incomplete
        ];

        for invalid_json in invalid_json_cases {
            let result = trust_agent(invalid_json);
            assert!(
                result.is_err(),
                "Invalid JSON '{}' should be rejected",
                invalid_json.escape_debug()
            );
        }
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_missing_jacs_id() {
        let _temp = setup_test_trust_dir();

        // Valid JSON but missing jacsId
        let agent_json = r#"{
            "name": "Test Agent",
            "jacsSignature": {
                "signature": "dGVzdA==",
                "publicKeyHash": "abc123",
                "date": "2024-01-01T00:00:00Z",
                "fields": ["name"]
            }
        }"#;

        let result = trust_agent(agent_json);
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert!(
                    field.contains("jacsId"),
                    "Error should mention jacsId: {}",
                    field
                );
            }
            _ => panic!("Expected DocumentMalformed error for missing jacsId"),
        }
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_null_fields() {
        let _temp = setup_test_trust_dir();

        // JSON with null values where strings expected
        let agent_json = r#"{
            "jacsId": null,
            "name": "Test Agent",
            "jacsSignature": {
                "signature": "dGVzdA==",
                "publicKeyHash": "abc123",
                "date": "2024-01-01T00:00:00Z",
                "fields": ["name"]
            }
        }"#;

        let result = trust_agent(agent_json);
        assert!(result.is_err(), "Null jacsId should be rejected");
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_wrong_type_fields() {
        let _temp = setup_test_trust_dir();

        // jacsId as number instead of string
        let agent_json = r#"{
            "jacsId": 12345,
            "name": "Test Agent",
            "jacsSignature": {
                "signature": "dGVzdA==",
                "publicKeyHash": "abc123",
                "date": "2024-01-01T00:00:00Z",
                "fields": ["name"]
            }
        }"#;

        let result = trust_agent(agent_json);
        assert!(result.is_err(), "Non-string jacsId should be rejected");
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_empty_signature() {
        let _temp = setup_test_trust_dir();

        let agent_json = r#"{
            "jacsId": "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001",
            "name": "Test Agent",
            "jacsSignature": {
                "signature": "",
                "publicKeyHash": "abc123",
                "date": "2024-01-01T00:00:00Z",
                "signingAlgorithm": "ring-Ed25519",
                "fields": ["name"]
            }
        }"#;

        let result = trust_agent(agent_json);
        // This will fail because empty signature can't be verified
        // and there's no public key for "abc123" hash
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_malformed_base64_signature() {
        let _temp = setup_test_trust_dir();

        let agent_json = r#"{
            "jacsId": "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001",
            "name": "Test Agent",
            "jacsSignature": {
                "signature": "!!!not-valid-base64!!!",
                "publicKeyHash": "abc123",
                "date": "2024-01-01T00:00:00Z",
                "signingAlgorithm": "ring-Ed25519",
                "fields": ["name"]
            }
        }"#;

        let result = trust_agent(agent_json);
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_untrust_nonexistent_agent() {
        let _temp = setup_test_trust_dir();

        let nonexistent_id = "550e8400-e29b-41d4-a716-446655440099:550e8400-e29b-41d4-a716-446655440098";
        let result = untrust_agent(nonexistent_id);
        assert!(result.is_err());
        match result {
            Err(JacsError::AgentNotTrusted { agent_id }) => {
                assert_eq!(agent_id, nonexistent_id, "Error should contain agent ID");
            }
            _ => panic!("Expected AgentNotTrusted error, got: {:?}", result),
        }
    }

    #[test]
    #[serial]
    fn test_get_trusted_agent_nonexistent() {
        let _temp = setup_test_trust_dir();

        let nonexistent_id = "550e8400-e29b-41d4-a716-446655440099:550e8400-e29b-41d4-a716-446655440098";
        let result = get_trusted_agent(nonexistent_id);
        assert!(result.is_err());
        match result {
            Err(JacsError::TrustError(msg)) => {
                assert!(msg.contains(nonexistent_id), "Error should contain agent ID");
                assert!(msg.contains("not in the trust store"), "Error should explain the issue");
                assert!(msg.contains("trust_agent"), "Error should suggest using trust_agent");
            }
            _ => panic!("Expected TrustError error, got: {:?}", result),
        }
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_future_signature_timestamp() {
        let _temp = setup_test_trust_dir();

        // Create test key and save it
        let test_key = b"test-public-key";
        let hash = "test-future-hash";
        save_public_key_to_cache(hash, test_key, Some("ring-Ed25519")).unwrap();

        // Agent with far future timestamp
        let far_future = (now_utc() + chrono::Duration::hours(1)).to_rfc3339();
        let agent_json = format!(r#"{{
            "jacsId": "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001",
            "name": "Test Agent",
            "jacsSignature": {{
                "signature": "dGVzdA==",
                "publicKeyHash": "{}",
                "date": "{}",
                "signingAlgorithm": "ring-Ed25519",
                "fields": ["name"]
            }}
        }}"#, hash, far_future);

        let result = trust_agent(&agent_json);
        // This should fail because the timestamp is too far in the future
        assert!(result.is_err());
    }

    #[test]
    fn test_algorithm_detection_with_empty_key() {
        use crate::crypt::detect_algorithm_from_public_key;

        let result = detect_algorithm_from_public_key(&[]);
        assert!(result.is_err(), "Empty public key should fail detection");
    }

    #[test]
    fn test_algorithm_detection_with_very_short_key() {
        use crate::crypt::detect_algorithm_from_public_key;

        let short_keys = [
            vec![0u8; 1],
            vec![0u8; 10],
            vec![0u8; 20],
        ];

        for key in short_keys {
            // These may succeed with Ed25519 detection or fail
            // The important thing is no panic
            let _ = detect_algorithm_from_public_key(&key);
        }
    }

    // ==================== Path Traversal Security Tests ====================

    #[test]
    #[serial]
    fn test_trust_agent_rejects_path_traversal_agent_id() {
        let _temp = setup_test_trust_dir();

        let path_traversal_ids = [
            "../../etc/passwd",
            "../../../etc/shadow",
            "valid-uuid:../../escape",
            "foo/bar",
            "foo\\bar",
            "foo\0bar:baz",
        ];

        for malicious_id in path_traversal_ids {
            let agent_json = format!(r#"{{
                "jacsId": "{}",
                "name": "Malicious Agent",
                "jacsSignature": {{
                    "signature": "dGVzdA==",
                    "publicKeyHash": "abc123",
                    "date": "2024-01-01T00:00:00Z",
                    "signingAlgorithm": "ring-Ed25519",
                    "fields": ["name"]
                }}
            }}"#, malicious_id);

            let result = trust_agent(&agent_json);
            assert!(
                result.is_err(),
                "Path traversal agent ID '{}' should be rejected",
                malicious_id.escape_debug()
            );
        }
    }

    #[test]
    #[serial]
    fn test_untrust_rejects_path_traversal() {
        let _temp = setup_test_trust_dir();

        let path_traversal_ids = [
            "../../etc/passwd",
            "../important-file",
            "foo/bar",
            "foo\\bar",
        ];

        for malicious_id in path_traversal_ids {
            let result = untrust_agent(malicious_id);
            assert!(
                result.is_err(),
                "Path traversal agent ID '{}' should be rejected by untrust_agent",
                malicious_id.escape_debug()
            );
        }
    }

    #[test]
    #[serial]
    fn test_get_trusted_agent_rejects_path_traversal() {
        let _temp = setup_test_trust_dir();

        let path_traversal_ids = [
            "../../etc/passwd",
            "../important-file",
            "foo/bar",
            "foo\\bar",
        ];

        for malicious_id in path_traversal_ids {
            let result = get_trusted_agent(malicious_id);
            assert!(
                result.is_err(),
                "Path traversal agent ID '{}' should be rejected by get_trusted_agent",
                malicious_id.escape_debug()
            );
        }
    }

    #[test]
    #[serial]
    fn test_is_trusted_rejects_path_traversal() {
        let _temp = setup_test_trust_dir();

        // is_trusted returns false for invalid IDs instead of error
        assert!(!is_trusted("../../etc/passwd"));
        assert!(!is_trusted("../important-file"));
        assert!(!is_trusted("foo/bar"));
        assert!(!is_trusted("foo\\bar"));
    }

    #[test]
    #[serial]
    fn test_public_key_cache_rejects_path_traversal_hash() {
        let _temp = setup_test_trust_dir();

        let malicious_hashes = [
            "../../etc/passwd",
            "../escape",
            "hash/with/slashes",
            "hash\\with\\backslashes",
        ];

        for malicious_hash in malicious_hashes {
            let save_result = save_public_key_to_cache(malicious_hash, b"key-data", Some("ring-Ed25519"));
            assert!(
                save_result.is_err(),
                "Path traversal hash '{}' should be rejected by save_public_key_to_cache",
                malicious_hash.escape_debug()
            );

            let load_result = load_public_key_from_cache(malicious_hash);
            assert!(
                load_result.is_err(),
                "Path traversal hash '{}' should be rejected by load_public_key_from_cache",
                malicious_hash.escape_debug()
            );
        }
    }
}
