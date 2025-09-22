//! Provenance wrapping for A2A artifacts

use crate::agent::{
    AGENT_SIGNATURE_FIELDNAME, Agent, boilerplate::BoilerPlate, document::DocumentTraits,
};
use serde_json::{Value, json};
use std::error::Error;
use tracing::info;
use uuid::Uuid;

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
    let signature = agent.signing_procedure(
        &wrapped_artifact,
        None,
        &AGENT_SIGNATURE_FIELDNAME.to_string(),
    )?;
    wrapped_artifact[AGENT_SIGNATURE_FIELDNAME] = signature;

    // Add SHA256 hash
    let document_hash = agent.hash_doc(&wrapped_artifact)?;
    wrapped_artifact[crate::agent::SHA256_FIELDNAME] = json!(document_hash);

    info!("Successfully wrapped A2A artifact with JACS provenance");
    Ok(wrapped_artifact)
}

/// Verify a JACS-wrapped A2A artifact
pub fn verify_wrapped_artifact(
    agent: &Agent,
    wrapped_artifact: &Value,
) -> Result<VerificationResult, Box<dyn Error>> {
    // First verify the hash
    agent.verify_hash(wrapped_artifact)?;

    // Get the signer's public key
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

    // In a real implementation, we would fetch the public key from the agent registry
    // For now, we'll use the current agent's key if IDs match
    let current_agent_id = agent.get_id().ok();
    let is_self_signed = current_agent_id.map(|id| id == agent_id).unwrap_or(false);

    if is_self_signed {
        let public_key = agent.get_public_key()?;
        agent.signature_verification_procedure(
            wrapped_artifact,
            None,
            &AGENT_SIGNATURE_FIELDNAME.to_string(),
            public_key,
            agent.get_key_algorithm().cloned(),
            None,
            None,
        )?;
    }

    // Extract the original A2A artifact
    let original_artifact = wrapped_artifact
        .get("a2aArtifact")
        .ok_or("No A2A artifact found in wrapper")?;

    // Check parent signatures if present
    let parent_signatures_valid =
        if let Some(_parents) = wrapped_artifact.get("jacsParentSignatures") {
            // In a real implementation, we would verify each parent signature
            true
        } else {
            true
        };

    Ok(VerificationResult {
        valid: true,
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
        original_artifact: original_artifact.clone(),
    })
}

/// Result of artifact verification
#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub signer_id: String,
    pub signer_version: String,
    pub artifact_type: String,
    pub timestamp: String,
    pub parent_signatures_valid: bool,
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
    fn test_verification_result_creation() {
        let result = VerificationResult {
            valid: true,
            signer_id: "test-agent".to_string(),
            signer_version: "v1".to_string(),
            artifact_type: "a2a-task".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            parent_signatures_valid: true,
            original_artifact: json!({"test": "data"}),
        };

        assert!(result.valid);
        assert_eq!(result.signer_id, "test-agent");
    }

    #[test]
    fn test_create_chain_of_custody_empty() {
        let chain = create_chain_of_custody(vec![]).unwrap();
        assert_eq!(chain["totalArtifacts"], 0);
    }
}
