//! Provenance wrapping for A2A artifacts (v0.4.0)

use crate::a2a::{A2AArtifact, A2AMessage};
use crate::agent::{
    AGENT_SIGNATURE_FIELDNAME, Agent, boilerplate::BoilerPlate, document::DocumentTraits,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::error::Error;
use tracing::{info, warn};
use uuid::Uuid;

/// Verification status indicating whether and how a signature was verified
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Signature was cryptographically verified
    Verified,
    /// Signature is from the current agent (self-signed) and was verified
    SelfSigned,
    /// Signature is from a foreign agent and could not be verified because
    /// the public key is not available. The signature may or may not be valid.
    Unverified { reason: String },
    /// Signature verification failed - the signature is invalid
    Invalid { reason: String },
}

impl VerificationStatus {
    /// Returns true if the signature was cryptographically verified
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            VerificationStatus::Verified | VerificationStatus::SelfSigned
        )
    }

    /// Returns true if the signature could not be verified due to missing public key
    pub fn is_unverified(&self) -> bool {
        matches!(self, VerificationStatus::Unverified { .. })
    }

    /// Returns true if the signature was checked and found to be invalid
    pub fn is_invalid(&self) -> bool {
        matches!(self, VerificationStatus::Invalid { .. })
    }
}

/// Wrap an A2A artifact with JACS provenance signature
pub fn wrap_artifact_with_provenance(
    agent: &mut Agent,
    artifact: Value,
    artifact_type: &str,
    parent_signatures: Option<Vec<Value>>,
) -> Result<Value, Box<dyn Error>> {
    // Create a JACS header for the artifact
    let artifact_id = Uuid::new_v4().to_string();
    let artifact_version = Uuid::new_v4().to_string();

    let mut wrapped_artifact = json!({
        "jacsId": artifact_id,
        "jacsVersion": artifact_version,
        "jacsType": format!("a2a-{}", artifact_type),
        "jacsLevel": "artifact",
        "jacsPreviousVersion": null,
        "jacsVersionDate": chrono::Utc::now().to_rfc3339(),
        "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
        "a2aArtifact": artifact,
    });

    // Add parent signatures if this is part of a chain
    if let Some(parents) = parent_signatures {
        wrapped_artifact["jacsParentSignatures"] = json!(parents);
    }

    // Sign the wrapped artifact
    let signature = agent.signing_procedure(&wrapped_artifact, None, AGENT_SIGNATURE_FIELDNAME)?;
    wrapped_artifact[AGENT_SIGNATURE_FIELDNAME] = signature;

    // Add SHA256 hash
    let document_hash = agent.hash_doc(&wrapped_artifact)?;
    wrapped_artifact[crate::agent::SHA256_FIELDNAME] = json!(document_hash);

    info!("Successfully wrapped A2A artifact with JACS provenance");
    Ok(wrapped_artifact)
}

/// Wrap a typed A2A Artifact (v0.4.0) with JACS provenance signature.
pub fn wrap_a2a_artifact_with_provenance(
    agent: &mut Agent,
    artifact: &A2AArtifact,
    parent_signatures: Option<Vec<Value>>,
) -> Result<Value, Box<dyn Error>> {
    let artifact_value = serde_json::to_value(artifact)?;
    wrap_artifact_with_provenance(agent, artifact_value, "artifact", parent_signatures)
}

/// Wrap a typed A2A Message (v0.4.0) with JACS provenance signature.
pub fn wrap_a2a_message_with_provenance(
    agent: &mut Agent,
    message: &A2AMessage,
    parent_signatures: Option<Vec<Value>>,
) -> Result<Value, Box<dyn Error>> {
    let message_value = serde_json::to_value(message)?;
    wrap_artifact_with_provenance(agent, message_value, "message", parent_signatures)
}

/// Verify a JACS-wrapped A2A artifact
///
/// This function verifies the signature on a wrapped artifact. The verification
/// status indicates whether the signature could be verified:
///
/// - `Verified` or `SelfSigned`: The signature was cryptographically verified
/// - `Unverified`: The signature could not be verified because the public key
///   for the signing agent is not available (foreign agent, no registry lookup)
/// - `Invalid`: The signature was checked and found to be invalid
///
/// For foreign agents (agents other than the current agent), the public key
/// must be fetched from an agent registry or provided through another mechanism.
/// Currently, only self-signed verification is supported. Foreign signatures
/// will return `Unverified` status.
pub fn verify_wrapped_artifact(
    agent: &Agent,
    wrapped_artifact: &Value,
) -> Result<VerificationResult, Box<dyn Error>> {
    // First verify the hash
    if let Err(e) = agent.verify_hash(wrapped_artifact) {
        return Ok(VerificationResult {
            status: VerificationStatus::Invalid {
                reason: format!("Hash verification failed: {}", e),
            },
            valid: false,
            signer_id: String::new(),
            signer_version: String::new(),
            artifact_type: wrapped_artifact
                .get("jacsType")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            timestamp: wrapped_artifact
                .get("jacsVersionDate")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            parent_signatures_valid: false,
            parent_verification_results: vec![],
            original_artifact: wrapped_artifact
                .get("a2aArtifact")
                .cloned()
                .unwrap_or(Value::Null),
        });
    }

    // Get the signer's public key info
    let signature_info = wrapped_artifact
        .get(AGENT_SIGNATURE_FIELDNAME)
        .ok_or("No JACS signature found")?;

    let agent_id = signature_info
        .get("agentID")
        .and_then(|v| v.as_str())
        .ok_or("No agent ID in signature")?;

    let agent_version = signature_info
        .get("agentVersion")
        .and_then(|v| v.as_str())
        .ok_or("No agent version in signature")?;

    // Check if this is a self-signed document
    let current_agent_id = agent.get_id().ok();
    let is_self_signed = current_agent_id
        .as_ref()
        .map(|id| id == agent_id)
        .unwrap_or(false);

    // Determine verification status
    let (status, valid) = if is_self_signed {
        // Self-signed: we can verify with our own key
        let public_key = agent.get_public_key()?;
        match agent.signature_verification_procedure(
            wrapped_artifact,
            None,
            AGENT_SIGNATURE_FIELDNAME,
            public_key,
            agent.get_key_algorithm().cloned(),
            None,
            None,
        ) {
            Ok(_) => (VerificationStatus::SelfSigned, true),
            Err(e) => (
                VerificationStatus::Invalid {
                    reason: format!("Signature verification failed: {}", e),
                },
                false,
            ),
        }
    } else {
        // Foreign signature: we cannot verify without the signer's public key
        // In a production system, this would look up the public key from:
        // 1. A local cache of known agent public keys
        // 2. The hai.ai agent registry
        // 3. DNS-based discovery (/.well-known/jacs-pubkey.json)
        warn!(
            "Cannot verify foreign signature from agent {}: public key not available. \
             Implement registry lookup or DNS discovery to verify foreign signatures.",
            agent_id
        );
        (
            VerificationStatus::Unverified {
                reason: format!(
                    "Public key for agent {} not available. Cannot verify foreign signature.",
                    agent_id
                ),
            },
            false, // valid=false because we couldn't actually verify
        )
    };

    // Extract the original A2A artifact
    let original_artifact = wrapped_artifact
        .get("a2aArtifact")
        .ok_or("No A2A artifact found in wrapper")?;

    // Verify parent signatures if present
    let (parent_signatures_valid, parent_verification_results) =
        verify_parent_signatures(agent, wrapped_artifact)?;

    Ok(VerificationResult {
        status,
        valid,
        signer_id: agent_id.to_string(),
        signer_version: agent_version.to_string(),
        artifact_type: wrapped_artifact
            .get("jacsType")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        timestamp: wrapped_artifact
            .get("jacsVersionDate")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        parent_signatures_valid,
        parent_verification_results,
        original_artifact: original_artifact.clone(),
    })
}

/// Verify parent signatures in a chain of custody
///
/// Returns (all_valid, individual_results) where all_valid is true only if
/// all parent signatures were successfully verified.
fn verify_parent_signatures(
    agent: &Agent,
    wrapped_artifact: &Value,
) -> Result<(bool, Vec<ParentVerificationResult>), Box<dyn Error>> {
    let parents = match wrapped_artifact.get("jacsParentSignatures") {
        Some(Value::Array(arr)) => arr,
        Some(_) => return Err("jacsParentSignatures must be an array".into()),
        None => return Ok((true, vec![])), // No parents = valid chain
    };

    if parents.is_empty() {
        return Ok((true, vec![]));
    }

    let mut results = Vec::with_capacity(parents.len());
    let mut all_valid = true;

    for (index, parent) in parents.iter().enumerate() {
        let parent_id = parent
            .get("jacsId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let parent_signer = parent
            .get(AGENT_SIGNATURE_FIELDNAME)
            .and_then(|sig| sig.get("agentID"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Try to verify each parent signature
        // Note: This recursively calls verify_wrapped_artifact
        let verification = match verify_wrapped_artifact(agent, parent) {
            Ok(result) => {
                let status = result.status.clone();
                let verified = result.valid;
                if !verified {
                    all_valid = false;
                }
                ParentVerificationResult {
                    index,
                    artifact_id: parent_id,
                    signer_id: parent_signer,
                    status,
                    verified,
                }
            }
            Err(e) => {
                all_valid = false;
                ParentVerificationResult {
                    index,
                    artifact_id: parent_id,
                    signer_id: parent_signer,
                    status: VerificationStatus::Invalid {
                        reason: format!("Verification error: {}", e),
                    },
                    verified: false,
                }
            }
        };

        results.push(verification);
    }

    Ok((all_valid, results))
}

/// Result of parent signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentVerificationResult {
    /// Index in the parent signatures array
    pub index: usize,
    /// ID of the parent artifact
    pub artifact_id: String,
    /// ID of the agent that signed the parent
    pub signer_id: String,
    /// Verification status
    pub status: VerificationStatus,
    /// Whether the signature was verified (convenience field)
    pub verified: bool,
}

/// Result of artifact verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Detailed verification status
    pub status: VerificationStatus,
    /// Whether the signature was cryptographically verified.
    /// This is false for both Invalid and Unverified statuses.
    pub valid: bool,
    /// ID of the signing agent
    pub signer_id: String,
    /// Version of the signing agent
    pub signer_version: String,
    /// Type of the artifact (e.g., "a2a-task", "a2a-message")
    pub artifact_type: String,
    /// Timestamp when the artifact was signed
    pub timestamp: String,
    /// Whether all parent signatures in the chain are valid
    pub parent_signatures_valid: bool,
    /// Individual verification results for each parent signature
    pub parent_verification_results: Vec<ParentVerificationResult>,
    /// The original A2A artifact that was wrapped
    pub original_artifact: Value,
}

/// Create a chain of custody document for multi-agent workflows
pub fn create_chain_of_custody(artifacts: Vec<Value>) -> Result<Value, Box<dyn Error>> {
    let mut chain = Vec::new();

    for artifact in artifacts {
        if let Some(sig) = artifact.get(AGENT_SIGNATURE_FIELDNAME) {
            let entry = json!({
                "artifactId": artifact.get("jacsId"),
                "artifactType": artifact.get("jacsType"),
                "timestamp": artifact.get("jacsVersionDate"),
                "agentId": sig.get("agentID"),
                "agentVersion": sig.get("agentVersion"),
                "signatureHash": sig.get("publicKeyHash"),
            });
            chain.push(entry);
        }
    }

    Ok(json!({
        "chainOfCustody": chain,
        "created": chrono::Utc::now().to_rfc3339(),
        "totalArtifacts": chain.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_status_is_verified() {
        assert!(VerificationStatus::Verified.is_verified());
        assert!(VerificationStatus::SelfSigned.is_verified());
        assert!(
            !VerificationStatus::Unverified {
                reason: "test".to_string()
            }
            .is_verified()
        );
        assert!(
            !VerificationStatus::Invalid {
                reason: "test".to_string()
            }
            .is_verified()
        );
    }

    #[test]
    fn test_verification_status_is_unverified() {
        assert!(!VerificationStatus::Verified.is_unverified());
        assert!(!VerificationStatus::SelfSigned.is_unverified());
        assert!(
            VerificationStatus::Unverified {
                reason: "test".to_string()
            }
            .is_unverified()
        );
        assert!(
            !VerificationStatus::Invalid {
                reason: "test".to_string()
            }
            .is_unverified()
        );
    }

    #[test]
    fn test_verification_status_is_invalid() {
        assert!(!VerificationStatus::Verified.is_invalid());
        assert!(!VerificationStatus::SelfSigned.is_invalid());
        assert!(
            !VerificationStatus::Unverified {
                reason: "test".to_string()
            }
            .is_invalid()
        );
        assert!(
            VerificationStatus::Invalid {
                reason: "test".to_string()
            }
            .is_invalid()
        );
    }

    #[test]
    fn test_verification_result_creation() {
        let result = VerificationResult {
            status: VerificationStatus::SelfSigned,
            valid: true,
            signer_id: "test-agent".to_string(),
            signer_version: "v1".to_string(),
            artifact_type: "a2a-task".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            parent_signatures_valid: true,
            parent_verification_results: vec![],
            original_artifact: json!({"test": "data"}),
        };

        assert!(result.valid);
        assert!(result.status.is_verified());
        assert_eq!(result.signer_id, "test-agent");
    }

    #[test]
    fn test_create_chain_of_custody_empty() {
        let chain = create_chain_of_custody(vec![]).unwrap();
        assert_eq!(chain["totalArtifacts"], 0);
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            status: VerificationStatus::Unverified {
                reason: "No public key".to_string(),
            },
            valid: false,
            signer_id: "foreign-agent".to_string(),
            signer_version: "v2".to_string(),
            artifact_type: "a2a-message".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            parent_signatures_valid: true,
            parent_verification_results: vec![],
            original_artifact: json!({"message": "hello"}),
        };

        // Should be serializable to JSON
        let json = serde_json::to_string(&result).expect("serialization should succeed");
        assert!(json.contains("Unverified"));
        assert!(json.contains("foreign-agent"));
    }
}
