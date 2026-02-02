//! Trust store management for JACS agents.
//!
//! This module provides functions for managing trusted agents,
//! enabling P2P key exchange and verification without a central authority.

use crate::crypt::hash::hash_public_key;
use crate::crypt::{CryptoSigningAlgorithm, detect_algorithm_from_public_key};
use crate::error::JacsError;
use crate::paths::trust_store_dir;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::str::FromStr;
use tracing::{info, warn};

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
pub fn trust_agent_with_key(agent_json: &str, public_key_pem: Option<&str>) -> Result<String, JacsError> {
    // Parse the agent JSON
    let agent_value: Value = serde_json::from_str(agent_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "agent_json".to_string(),
            reason: e.to_string(),
        }
    })?;

    // Extract required fields
    let agent_id = agent_value["jacsId"]
        .as_str()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsId".to_string(),
            reason: "Missing or invalid jacsId".to_string(),
        })?
        .to_string();

    let name = agent_value["name"].as_str().map(|s| s.to_string());

    // Extract public key hash from signature
    let public_key_hash = agent_value["jacsSignature"]["publicKeyHash"]
        .as_str()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature.publicKeyHash".to_string(),
            reason: "Missing public key hash".to_string(),
        })?
        .to_string();

    // Extract signing algorithm from signature
    // Note: signingAlgorithm is now required in the schema, but we handle legacy documents
    // that may not have it by falling back to algorithm detection with a warning
    let signing_algorithm = agent_value["jacsSignature"]["signingAlgorithm"]
        .as_str()
        .map(|s| s.to_string());

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
                "Public key hash mismatch: expected {}, got {}",
                public_key_hash, computed_hash
            ),
        });
    }

    // Verify the self-signature
    verify_agent_self_signature(&agent_value, &public_key_bytes, signing_algorithm.as_deref())?;

    // Create trust store directory if it doesn't exist
    let trust_dir = trust_store_dir();
    fs::create_dir_all(&trust_dir).map_err(|e| JacsError::Internal {
        message: format!("Failed to create trust store directory: {}", e),
    })?;

    // Save the agent file
    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    fs::write(&agent_file, agent_json).map_err(|e| JacsError::Internal {
        message: format!("Failed to write trusted agent file: {}", e),
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
        trusted_at: chrono::Utc::now().to_rfc3339(),
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
        if path.extension().map_or(false, |ext| ext == "json")
            && !path
                .file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |n| n.ends_with(".meta.json"))
        {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                agents.push(stem.to_string());
            }
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
pub fn untrust_agent(agent_id: &str) -> Result<(), JacsError> {
    let trust_dir = trust_store_dir();

    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    let metadata_file = trust_dir.join(format!("{}.meta.json", agent_id));

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
pub fn get_trusted_agent(agent_id: &str) -> Result<String, JacsError> {
    let trust_dir = trust_store_dir();
    let agent_file = trust_dir.join(format!("{}.json", agent_id));

    if !agent_file.exists() {
        return Err(JacsError::AgentNotTrusted {
            agent_id: agent_id.to_string(),
        });
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
pub fn get_trusted_public_key_hash(agent_id: &str) -> Result<String, JacsError> {
    let agent_json = get_trusted_agent(agent_id)?;
    let agent_value: Value = serde_json::from_str(&agent_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "agent_json".to_string(),
            reason: e.to_string(),
        }
    })?;

    agent_value["jacsSignature"]["publicKeyHash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature.publicKeyHash".to_string(),
            reason: "Missing public key hash".to_string(),
        })
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
    let trust_dir = trust_store_dir();
    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    agent_file.exists()
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

/// Loads a public key from the trust store's key cache.
fn load_public_key_from_cache(public_key_hash: &str) -> Result<Vec<u8>, JacsError> {
    let trust_dir = trust_store_dir();
    let keys_dir = trust_dir.join("keys");
    let key_file = keys_dir.join(format!("{}.pem", public_key_hash));

    if !key_file.exists() {
        return Err(JacsError::KeyNotFound {
            path: key_file.to_string_lossy().to_string(),
        });
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
    let trust_dir = trust_store_dir();
    let keys_dir = trust_dir.join("keys");

    fs::create_dir_all(&keys_dir).map_err(|e| JacsError::Internal {
        message: format!("Failed to create keys directory: {}", e),
    })?;

    // Save the public key
    let key_file = keys_dir.join(format!("{}.pem", public_key_hash));
    fs::write(&key_file, public_key_bytes).map_err(|e| JacsError::Internal {
        message: format!("Failed to write public key file: {}", e),
    })?;

    // Save the algorithm type if provided
    if let Some(algo) = algorithm {
        let algo_file = keys_dir.join(format!("{}.algo", public_key_hash));
        fs::write(&algo_file, algo).map_err(|e| JacsError::Internal {
            message: format!("Failed to write algorithm file: {}", e),
        })?;
    }

    Ok(())
}

/// Maximum clock drift tolerance for signature timestamps (in seconds).
/// Signatures dated more than 5 minutes in the future are rejected.
const MAX_FUTURE_TIMESTAMP_SECONDS: i64 = 300;

/// Optional maximum signature age (in seconds).
/// Set to 0 to disable expiration checking.
/// Default: 0 (no expiration - signatures don't expire)
const MAX_SIGNATURE_AGE_SECONDS: i64 = 0;

/// Validates a signature timestamp.
///
/// # Arguments
/// * `timestamp_str` - ISO 8601 / RFC 3339 formatted timestamp string
///
/// # Returns
/// Ok(()) if the timestamp is valid, or an error describing the issue.
///
/// # Validation Rules
/// 1. The timestamp must be a valid RFC 3339 / ISO 8601 format
/// 2. The timestamp must not be more than MAX_FUTURE_TIMESTAMP_SECONDS in the future
///    (allows for small clock drift between systems)
/// 3. If MAX_SIGNATURE_AGE_SECONDS > 0, the timestamp must not be older than that
fn validate_signature_timestamp(timestamp_str: &str) -> Result<(), JacsError> {
    use chrono::{DateTime, Utc};

    // Parse the timestamp
    let signature_time: DateTime<Utc> = timestamp_str
        .parse()
        .map_err(|e| JacsError::SignatureVerificationFailed {
            reason: format!("Invalid signature timestamp format '{}': {}", timestamp_str, e),
        })?;

    let now = Utc::now();

    // Check for future timestamps (with clock drift tolerance)
    let future_limit = now + chrono::Duration::seconds(MAX_FUTURE_TIMESTAMP_SECONDS);
    if signature_time > future_limit {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "Signature timestamp {} is too far in the future (max {} seconds allowed). \
                This may indicate clock skew or a forged signature.",
                timestamp_str, MAX_FUTURE_TIMESTAMP_SECONDS
            ),
        });
    }

    // Check for expired signatures (if expiration is enabled)
    if MAX_SIGNATURE_AGE_SECONDS > 0 {
        let expiry_limit = now - chrono::Duration::seconds(MAX_SIGNATURE_AGE_SECONDS);
        if signature_time < expiry_limit {
            return Err(JacsError::SignatureVerificationFailed {
                reason: format!(
                    "Signature timestamp {} is too old (max age {} seconds). \
                    The agent document may need to be re-signed.",
                    timestamp_str, MAX_SIGNATURE_AGE_SECONDS
                ),
            });
        }
    }

    Ok(())
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
    let signature_date = agent_value["jacsSignature"]["date"]
        .as_str()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature.date".to_string(),
            reason: "Missing signature timestamp".to_string(),
        })?;

    validate_signature_timestamp(signature_date)?;

    // Extract signature components
    let signature_b64 = agent_value["jacsSignature"]["signature"]
        .as_str()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature.signature".to_string(),
            reason: "Missing signature".to_string(),
        })?;

    let fields = agent_value["jacsSignature"]["fields"]
        .as_array()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature.fields".to_string(),
            reason: "Missing or invalid fields array".to_string(),
        })?;

    // Build the content that was signed
    let mut content_parts: Vec<String> = Vec::new();
    for field in fields {
        if let Some(field_name) = field.as_str() {
            if let Some(value) = agent_value.get(field_name) {
                if let Some(str_val) = value.as_str() {
                    content_parts.push(str_val.to_string());
                }
            }
        }
    }
    let signed_content = content_parts.join(" ");

    // Determine the algorithm
    let algo = match algorithm {
        Some(a) => CryptoSigningAlgorithm::from_str(a).map_err(|_| JacsError::SignatureVerificationFailed {
            reason: format!("Unknown signing algorithm: {}", a),
        })?,
        None => {
            // Try to detect from the public key
            detect_algorithm_from_public_key(public_key_bytes).map_err(|e| {
                JacsError::SignatureVerificationFailed {
                    reason: format!("Could not detect algorithm: {}", e),
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
                signature_b64,
            )
        }
        CryptoSigningAlgorithm::RingEd25519 => {
            crate::crypt::ringwrapper::verify_string(
                public_key_bytes.to_vec(),
                &signed_content,
                signature_b64,
            )
        }
        CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
            crate::crypt::pq::verify_string(
                public_key_bytes.to_vec(),
                &signed_content,
                signature_b64,
            )
        }
        CryptoSigningAlgorithm::Pq2025 => {
            crate::crypt::pq2025::verify_string(
                public_key_bytes.to_vec(),
                &signed_content,
                signature_b64,
            )
        }
    };

    verification_result.map_err(|e| JacsError::SignatureVerificationFailed {
        reason: format!("Signature verification failed: {}", e),
    })?;

    info!("Agent self-signature verified successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serial_test::serial;
    use std::env;
    use tempfile::TempDir;

    fn setup_test_trust_dir() -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        // Override the trust store location for tests
        // SAFETY: This is only used in single-threaded tests
        unsafe {
            env::set_var("HOME", temp_dir.path().to_str().unwrap());
        }
        temp_dir
    }

    // ==================== Timestamp Validation Tests ====================

    #[test]
    fn test_valid_recent_timestamp() {
        // A timestamp from just now should be valid
        let now = Utc::now().to_rfc3339();
        let result = validate_signature_timestamp(&now);
        assert!(result.is_ok(), "Recent timestamp should be valid: {:?}", result);
    }

    #[test]
    fn test_valid_past_timestamp() {
        // A timestamp from 1 hour ago should be valid (when expiration is disabled)
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let result = validate_signature_timestamp(&past);
        assert!(result.is_ok(), "Past timestamp should be valid when expiration is disabled: {:?}", result);
    }

    #[test]
    fn test_valid_old_timestamp() {
        // A timestamp from a year ago should be valid (when expiration is disabled)
        let old = (Utc::now() - chrono::Duration::days(365)).to_rfc3339();
        let result = validate_signature_timestamp(&old);
        assert!(result.is_ok(), "Old timestamp should be valid when expiration is disabled: {:?}", result);
    }

    #[test]
    fn test_timestamp_slight_future_allowed() {
        // A timestamp a few seconds in the future should be allowed (clock drift)
        let slight_future = (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
        let result = validate_signature_timestamp(&slight_future);
        assert!(result.is_ok(), "Slight future timestamp should be allowed for clock drift: {:?}", result);
    }

    #[test]
    fn test_timestamp_far_future_rejected() {
        // A timestamp 10 minutes in the future should be rejected
        let far_future = (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
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
        // Various valid RFC 3339 formats should work
        let valid_timestamps = [
            "2024-01-15T10:30:00Z",
            "2024-06-20T15:45:30+00:00",
            "2024-12-01T00:00:00.000Z",
        ];

        for valid in valid_timestamps {
            let result = validate_signature_timestamp(valid);
            // These are old timestamps but should still be valid if no expiration
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
            "jacsId": "test-agent-id",
            "name": "Test Agent"
        }"#;

        let result = trust_agent(agent_json);
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert!(field.contains("publicKeyHash"));
            }
            _ => panic!("Expected DocumentMalformed error"),
        }
    }

    #[test]
    #[serial]
    fn test_trust_agent_rejects_invalid_public_key_hash() {
        let _temp = setup_test_trust_dir();

        // Agent with signature but wrong public key hash
        let agent_json = r#"{
            "jacsId": "test-agent-id",
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
            Err(JacsError::KeyNotFound { .. }) => (),
            _ => panic!("Expected KeyNotFound error"),
        }
    }
}
