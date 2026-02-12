//! Provenance wrapping for A2A artifacts (v0.4.0)

use crate::a2a::{A2AArtifact, A2AMessage};
#[cfg(not(target_arch = "wasm32"))]
use crate::agent::loaders::fetch_public_key_from_hai;
use crate::agent::{
    AGENT_SIGNATURE_FIELDNAME, Agent, JACS_IGNORE_FIELDS, boilerplate::BoilerPlate,
    document::DocumentTraits, loaders::FileLoader,
};
use crate::config::{KeyResolutionSource, get_key_resolution_order};
use crate::crypt::{KeyManager, hash::hash_public_key};
use crate::schema::utils::ValueExt;
use crate::time_utils;
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

fn signature_fields(wrapped_artifact: &Value, signature_info: &Value) -> Vec<String> {
    if let Some(fields) = signature_info.get("fields").and_then(|v| v.as_array()) {
        return fields
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }

    wrapped_artifact
        .as_object()
        .map(|obj| {
            obj.keys()
                .filter(|key| {
                    *key != AGENT_SIGNATURE_FIELDNAME && !JACS_IGNORE_FIELDS.contains(&key.as_str())
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn build_signable_string(
    wrapped_artifact: &Value,
    fields: &[String],
    signature_key_from: &str,
) -> Result<String, String> {
    let mut result = String::new();

    for key in fields {
        if let Some(value) = wrapped_artifact.get(key)
            && let Some(str_value) = value.as_str()
        {
            if str_value == signature_key_from || JACS_IGNORE_FIELDS.contains(&str_value) {
                return Err(format!(
                    "Invalid signature field value '{}': reserved by JACS",
                    str_value
                ));
            }
            result.push_str(str_value);
            result.push(' ');
        }
    }

    Ok(result.trim().to_string())
}

fn resolve_foreign_public_key(
    agent: &Agent,
    signer_id: &str,
    signer_version: &str,
    public_key_hash: &str,
) -> Result<(Vec<u8>, String), String> {
    if public_key_hash.is_empty() {
        return Err("Missing publicKeyHash in signature".to_string());
    }

    let resolution_order = get_key_resolution_order();
    let mut last_error = "No key source attempted".to_string();

    for source in &resolution_order {
        match source {
            KeyResolutionSource::Local => match agent.fs_load_public_key(public_key_hash) {
                Ok(public_key) => match agent.fs_load_public_key_type(public_key_hash) {
                    Ok(enc_type) => {
                        return Ok((public_key, enc_type.trim().to_string()));
                    }
                    Err(e) => {
                        last_error = format!("Local key type lookup failed: {}", e);
                    }
                },
                Err(e) => {
                    last_error = format!("Local key lookup failed: {}", e);
                }
            },
            KeyResolutionSource::Dns => {
                // DNS can validate identity but does not return key material.
                last_error = "DNS source does not provide public key bytes".to_string();
            }
            KeyResolutionSource::Hai => {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    if signer_id.is_empty() || signer_version.is_empty() {
                        last_error =
                            "HAI lookup requires signer agent ID and version UUID".to_string();
                        continue;
                    }

                    match fetch_public_key_from_hai(signer_id, signer_version) {
                        Ok(key_info) => {
                            if !key_info.hash.is_empty() && key_info.hash != public_key_hash {
                                last_error = format!(
                                    "HAI key hash mismatch: expected {}..., got {}...",
                                    &public_key_hash[..public_key_hash.len().min(16)],
                                    &key_info.hash[..key_info.hash.len().min(16)]
                                );
                                continue;
                            }
                            return Ok((key_info.public_key, key_info.algorithm));
                        }
                        Err(e) => {
                            last_error = format!("HAI key lookup failed: {}", e);
                        }
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = signer_id;
                    let _ = signer_version;
                    last_error =
                        "HAI lookup is not available on wasm32 targets in this build".to_string();
                }
            }
        }
    }

    Err(format!(
        "Could not resolve signer key {}... using sources {:?}. Last error: {}",
        &public_key_hash[..public_key_hash.len().min(16)],
        resolution_order,
        last_error
    ))
}

fn verify_with_resolved_key(
    agent: &Agent,
    wrapped_artifact: &Value,
    signature_info: &Value,
    public_key: Vec<u8>,
    public_key_enc_type: String,
) -> Result<(), String> {
    let signature = signature_info
        .get_str("signature")
        .ok_or_else(|| "No signature found in jacsSignature".to_string())?;
    let signature_hash = signature_info
        .get_str("publicKeyHash")
        .ok_or_else(|| "No publicKeyHash found in jacsSignature".to_string())?;

    let computed_hash = hash_public_key(public_key.clone());
    if computed_hash != signature_hash {
        return Err(format!(
            "Resolved public key hash mismatch: expected {}..., got {}...",
            &signature_hash[..signature_hash.len().min(16)],
            &computed_hash[..computed_hash.len().min(16)]
        ));
    }

    let fields = signature_fields(wrapped_artifact, signature_info);
    let signable_data = build_signable_string(wrapped_artifact, &fields, AGENT_SIGNATURE_FIELDNAME)
        .map_err(|e| format!("Could not build signable payload: {}", e))?;

    let explicit_alg = if public_key_enc_type.is_empty() {
        signature_info
            .get_str("signingAlgorithm")
            .map(|s| s.to_string())
    } else {
        Some(public_key_enc_type)
    };

    agent
        .verify_string(&signable_data, &signature, public_key, explicit_alg)
        .map_err(|e| format!("Signature verification failed: {}", e))
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
        "jacsVersionDate": time_utils::now_rfc3339(),
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
/// is resolved via configured key resolution order (`local`, `dns`, `hai`).
/// DNS can validate identity but does not provide key bytes; practical signature
/// verification requires local key material or HAI key retrieval.
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
            artifact_type: wrapped_artifact.get_str_or("jacsType", "unknown"),
            timestamp: wrapped_artifact.get_str_or("jacsVersionDate", ""),
            parent_signatures_valid: false,
            parent_verification_results: vec![],
            original_artifact: wrapped_artifact
                .get("a2aArtifact")
                .cloned()
                .unwrap_or(Value::Null),
            trust_level: None,
            trust_assessment: None,
        });
    }

    // Get the signer's public key info
    let signature_info = wrapped_artifact
        .get(AGENT_SIGNATURE_FIELDNAME)
        .ok_or("No JACS signature found")?;

    let agent_id = signature_info
        .get_str("agentID")
        .ok_or("No agent ID in signature")?;
    let agent_version = signature_info
        .get_str("agentVersion")
        .ok_or("No agent version in signature")?;
    let public_key_hash = signature_info.get_str_or("publicKeyHash", "");

    // Check if this is a self-signed document
    let current_agent_id = agent.get_id().ok();
    let is_self_signed = current_agent_id
        .as_ref()
        .map(|id| id == &agent_id)
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
        match resolve_foreign_public_key(agent, &agent_id, &agent_version, &public_key_hash) {
            Ok((public_key, public_key_enc_type)) => match verify_with_resolved_key(
                agent,
                wrapped_artifact,
                signature_info,
                public_key,
                public_key_enc_type,
            ) {
                Ok(_) => (VerificationStatus::Verified, true),
                Err(e) => (
                    VerificationStatus::Invalid {
                        reason: format!("Foreign signature verification failed: {}", e),
                    },
                    false,
                ),
            },
            Err(reason) => {
                warn!(
                    "Could not resolve foreign signature key for agent {}: {}",
                    agent_id, reason
                );
                (VerificationStatus::Unverified { reason }, false)
            }
        }
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
        signer_id: agent_id.clone(),
        signer_version: agent_version.clone(),
        artifact_type: wrapped_artifact.get_str_or("jacsType", "unknown"),
        timestamp: wrapped_artifact.get_str_or("jacsVersionDate", ""),
        parent_signatures_valid,
        parent_verification_results,
        original_artifact: original_artifact.clone(),
        trust_level: None,
        trust_assessment: None,
    })
}

/// Verify a JACS-wrapped A2A artifact with trust policy enforcement.
///
/// This combines cryptographic signature verification with trust policy
/// evaluation. The remote agent's Agent Card is assessed against the
/// specified trust policy, and the trust level is included in the result.
///
/// # Arguments
///
/// * `agent` - The local agent performing the verification
/// * `wrapped_artifact` - The JACS-wrapped artifact to verify
/// * `remote_card` - The remote agent's A2A Agent Card
/// * `policy` - The trust policy to apply
///
/// # Returns
///
/// A `VerificationResult` with `trust_level` and `trust_assessment` populated.
/// If the trust policy rejects the agent, `valid` is set to `false` and
/// `status` reflects the rejection reason.
pub fn verify_wrapped_artifact_with_policy(
    agent: &Agent,
    wrapped_artifact: &Value,
    remote_card: &super::AgentCard,
    policy: super::trust::A2ATrustPolicy,
) -> Result<VerificationResult, Box<dyn Error>> {
    use super::trust::assess_a2a_agent;

    // First perform the trust assessment
    let assessment = assess_a2a_agent(agent, remote_card, policy);

    if !assessment.allowed {
        // Trust policy rejected the agent — short-circuit without crypto verification
        info!(
            policy = %policy,
            trust_level = %assessment.trust_level,
            reason = %assessment.reason,
            "A2A trust policy rejected remote agent"
        );
        return Ok(VerificationResult {
            status: VerificationStatus::Invalid {
                reason: assessment.reason.clone(),
            },
            valid: false,
            signer_id: assessment.agent_id.clone().unwrap_or_default(),
            signer_version: String::new(),
            artifact_type: wrapped_artifact.get_str_or("jacsType", "unknown"),
            timestamp: wrapped_artifact.get_str_or("jacsVersionDate", ""),
            parent_signatures_valid: false,
            parent_verification_results: vec![],
            original_artifact: wrapped_artifact
                .get("a2aArtifact")
                .cloned()
                .unwrap_or(Value::Null),
            trust_level: Some(assessment.trust_level),
            trust_assessment: Some(assessment),
        });
    }

    // Trust policy accepted the agent — proceed with cryptographic verification
    let mut result = verify_wrapped_artifact(agent, wrapped_artifact)?;

    // Enrich result with trust information
    result.trust_level = Some(assessment.trust_level);
    result.trust_assessment = Some(assessment);

    info!(
        policy = %policy,
        trust_level = ?result.trust_level,
        crypto_valid = result.valid,
        "A2A artifact verified with trust policy"
    );

    Ok(result)
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
        Some(_) => return Err("Invalid jacsParentSignatures: must be an array".into()),
        None => return Ok((true, vec![])), // No parents = valid chain
    };

    if parents.is_empty() {
        return Ok((true, vec![]));
    }

    let mut results = Vec::with_capacity(parents.len());
    let mut all_valid = true;

    for (index, parent) in parents.iter().enumerate() {
        let parent_id = parent.get_str_or("jacsId", "unknown");
        let parent_signer =
            parent.get_path_str_or(&[AGENT_SIGNATURE_FIELDNAME, "agentID"], "unknown");

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
    /// Trust level of the signing agent (set when policy-based verification is used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<super::trust::TrustLevel>,
    /// Trust policy assessment details (set when policy-based verification is used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_assessment: Option<super::trust::TrustAssessment>,
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
        "created": time_utils::now_rfc3339(),
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
            timestamp: time_utils::now_rfc3339(),
            parent_signatures_valid: true,
            parent_verification_results: vec![],
            original_artifact: json!({"test": "data"}),
            trust_level: None,
            trust_assessment: None,
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
            trust_level: None,
            trust_assessment: None,
        };

        // Should be serializable to JSON
        let json = serde_json::to_string(&result).expect("serialization should succeed");
        assert!(json.contains("Unverified"));
        assert!(json.contains("foreign-agent"));
    }

    // =========================================================================
    // verify_wrapped_artifact_with_policy tests
    // =========================================================================

    use crate::a2a::trust::{A2ATrustPolicy, TrustLevel};
    use crate::a2a::{
        AgentCapabilities, AgentCard, AgentExtension, AgentInterface, JACS_EXTENSION_URI,
        A2A_PROTOCOL_VERSION,
    };

    /// Create a minimal Agent Card for trust policy tests.
    fn make_test_card(
        name: &str,
        with_jacs_extension: bool,
        agent_id: Option<&str>,
        version: Option<&str>,
    ) -> AgentCard {
        let extensions = if with_jacs_extension {
            Some(vec![AgentExtension {
                uri: JACS_EXTENSION_URI.to_string(),
                description: Some("JACS provenance".to_string()),
                required: Some(false),
            }])
        } else {
            None
        };

        let metadata = match (agent_id, version) {
            (Some(id), Some(ver)) => Some(json!({
                "jacsId": id,
                "jacsVersion": ver,
            })),
            (Some(id), None) => Some(json!({ "jacsId": id })),
            _ => None,
        };

        AgentCard {
            name: name.to_string(),
            description: format!("Test agent: {}", name),
            version: "1.0".to_string(),
            protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            supported_interfaces: vec![AgentInterface {
                url: "https://test.example.com".to_string(),
                protocol_binding: "jsonrpc".to_string(),
                tenant: None,
            }],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            capabilities: AgentCapabilities {
                streaming: None,
                push_notifications: None,
                extended_agent_card: None,
                extensions,
            },
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security: None,
            signatures: None,
            metadata,
        }
    }

    /// Create a dummy wrapped artifact (not cryptographically valid).
    fn make_dummy_wrapped_artifact(artifact_type: &str, agent_id: &str) -> Value {
        json!({
            "jacsId": "artifact-test-001",
            "jacsVersion": "v1",
            "jacsType": format!("a2a-{}", artifact_type),
            "jacsLevel": "artifact",
            "jacsVersionDate": "2025-01-01T00:00:00Z",
            "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
            "a2aArtifact": { "test": "data" },
            "jacsSignature": {
                "agentID": agent_id,
                "agentVersion": "v1",
                "publicKeyHash": "abc123",
                "signature": "deadbeef",
            }
        })
    }

    #[test]
    fn test_policy_open_accepts_non_jacs_agent() {
        let agent = crate::get_empty_agent();
        let card = make_test_card("plain-agent", false, None, None);
        let artifact = make_dummy_wrapped_artifact("task", "foreign-agent");

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Open,
        )
        .unwrap();

        // Open policy always allows — trust level should be Untrusted
        assert_eq!(result.trust_level, Some(TrustLevel::Untrusted));
        assert!(result.trust_assessment.is_some());
        assert!(result.trust_assessment.as_ref().unwrap().allowed);
    }

    #[test]
    fn test_policy_open_accepts_jacs_agent() {
        let agent = crate::get_empty_agent();
        let card = make_test_card("jacs-agent", true, Some("agent-1"), Some("v1"));
        let artifact = make_dummy_wrapped_artifact("message", "agent-1");

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Open,
        )
        .unwrap();

        assert_eq!(result.trust_level, Some(TrustLevel::JacsVerified));
        assert!(result.trust_assessment.as_ref().unwrap().allowed);
    }

    #[test]
    fn test_policy_verified_rejects_non_jacs_agent() {
        let agent = crate::get_empty_agent();
        let card = make_test_card("plain-agent", false, Some("no-jacs"), Some("v1"));
        let artifact = make_dummy_wrapped_artifact("task", "no-jacs");

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Verified,
        )
        .unwrap();

        // Verified policy should reject non-JACS agent
        assert!(!result.valid);
        assert_eq!(result.trust_level, Some(TrustLevel::Untrusted));
        assert!(!result.trust_assessment.as_ref().unwrap().allowed);
        assert!(result
            .trust_assessment
            .as_ref()
            .unwrap()
            .reason
            .contains("does not declare JACS provenance"));
    }

    #[test]
    fn test_policy_verified_accepts_jacs_agent() {
        let agent = crate::get_empty_agent();
        let card = make_test_card("jacs-agent", true, Some("agent-2"), Some("v1"));
        let artifact = make_dummy_wrapped_artifact("task", "agent-2");

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Verified,
        )
        .unwrap();

        // Verified policy accepts JACS agents — trust check passes,
        // but crypto verification may fail (dummy artifact is not properly signed)
        assert_eq!(result.trust_level, Some(TrustLevel::JacsVerified));
        assert!(result.trust_assessment.as_ref().unwrap().allowed);
    }

    #[test]
    fn test_policy_strict_rejects_jacs_not_trusted_agent() {
        let agent = crate::get_empty_agent();
        let card = make_test_card(
            "jacs-not-trusted",
            true,
            Some("550e8400-e29b-41d4-a716-446655440077"),
            Some("550e8400-e29b-41d4-a716-446655440078"),
        );
        let artifact = make_dummy_wrapped_artifact(
            "task",
            "550e8400-e29b-41d4-a716-446655440077",
        );

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Strict,
        )
        .unwrap();

        // Strict policy rejects agents not in trust store
        assert!(!result.valid);
        assert_eq!(result.trust_level, Some(TrustLevel::JacsVerified));
        assert!(!result.trust_assessment.as_ref().unwrap().allowed);
        assert!(result
            .trust_assessment
            .as_ref()
            .unwrap()
            .reason
            .contains("not in the local trust store"));
    }

    #[test]
    fn test_policy_strict_rejects_non_jacs_agent() {
        let agent = crate::get_empty_agent();
        let card = make_test_card("plain-untrusted", false, None, None);
        let artifact = make_dummy_wrapped_artifact("task", "unknown");

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Strict,
        )
        .unwrap();

        assert!(!result.valid);
        assert_eq!(result.trust_level, Some(TrustLevel::Untrusted));
        assert!(!result.trust_assessment.as_ref().unwrap().allowed);
    }

    #[test]
    fn test_policy_rejection_preserves_artifact_type() {
        let agent = crate::get_empty_agent();
        let card = make_test_card("rejected-agent", false, Some("rej-1"), Some("v1"));
        let artifact = make_dummy_wrapped_artifact("message", "rej-1");

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Verified,
        )
        .unwrap();

        assert!(!result.valid);
        assert_eq!(result.artifact_type, "a2a-message");
        assert_eq!(
            result.original_artifact,
            json!({ "test": "data" })
        );
    }

    #[test]
    fn test_policy_open_proceeds_to_crypto_verification() {
        let agent = crate::get_empty_agent();
        let card = make_test_card("open-agent", false, Some("agent-open"), Some("v1"));
        // Dummy artifact with no valid hash — crypto verification will fail
        let artifact = make_dummy_wrapped_artifact("task", "agent-open");

        let result = verify_wrapped_artifact_with_policy(
            &agent,
            &artifact,
            &card,
            A2ATrustPolicy::Open,
        )
        .unwrap();

        // Trust check passes (Open), but crypto verification should fail
        // (dummy artifact doesn't have a real hash/signature)
        assert!(result.trust_assessment.as_ref().unwrap().allowed);
        assert_eq!(result.trust_level, Some(TrustLevel::Untrusted));
        // Crypto verification fails due to missing/invalid hash
        assert!(!result.valid);
    }

    #[test]
    fn test_verification_result_with_trust_serialization() {
        use crate::a2a::trust::TrustAssessment;

        let result = VerificationResult {
            status: VerificationStatus::Verified,
            valid: true,
            signer_id: "trusted-agent".to_string(),
            signer_version: "v1".to_string(),
            artifact_type: "a2a-task".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            parent_signatures_valid: true,
            parent_verification_results: vec![],
            original_artifact: json!({"data": "test"}),
            trust_level: Some(TrustLevel::JacsVerified),
            trust_assessment: Some(TrustAssessment {
                allowed: true,
                trust_level: TrustLevel::JacsVerified,
                reason: "Verified policy: agent has JACS provenance".to_string(),
                jacs_registered: true,
                agent_id: Some("trusted-agent".to_string()),
                policy: A2ATrustPolicy::Verified,
            }),
        };

        let json_str = serde_json::to_string(&result).expect("should serialize");
        assert!(json_str.contains("trust_level"));
        assert!(json_str.contains("trust_assessment"));
        assert!(json_str.contains("JacsVerified"));

        // Deserialize back
        let deserialized: VerificationResult =
            serde_json::from_str(&json_str).expect("should deserialize");
        assert_eq!(deserialized.trust_level, Some(TrustLevel::JacsVerified));
        assert!(deserialized.trust_assessment.unwrap().allowed);
    }

    #[test]
    fn test_verification_result_without_trust_omits_fields() {
        let result = VerificationResult {
            status: VerificationStatus::Verified,
            valid: true,
            signer_id: "agent".to_string(),
            signer_version: "v1".to_string(),
            artifact_type: "a2a-task".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            parent_signatures_valid: true,
            parent_verification_results: vec![],
            original_artifact: json!({}),
            trust_level: None,
            trust_assessment: None,
        };

        let json_str = serde_json::to_string(&result).expect("should serialize");
        // When None, these fields should be omitted (skip_serializing_if)
        assert!(!json_str.contains("trust_level"));
        assert!(!json_str.contains("trust_assessment"));
    }
}
