//! JACS extension management for A2A protocol (v0.4.0)

use crate::a2a::keys::{create_jwk_set, export_as_jwk, sign_jws};
use crate::a2a::{AgentCard, AgentCardSignature};
use crate::agent::{Agent, boilerplate::BoilerPlate};
use serde_json::{Value, json};
use std::error::Error;
use tracing::info;

/// Sign an A2A Agent Card using JWS and embed the signature.
///
/// Returns a clone of the AgentCard with the JWS signature appended to
/// its `signatures` field (per A2A v0.4.0).
pub fn sign_agent_card_jws(
    agent_card: &AgentCard,
    private_key: &[u8],
    algorithm: &str,
    key_id: &str,
) -> Result<String, Box<dyn Error>> {
    // Serialize the agent card to JSON
    let agent_card_json = serde_json::to_vec(agent_card)?;

    // Sign using JWS
    let jws = sign_jws(&agent_card_json, private_key, algorithm, key_id)?;

    info!("Successfully signed Agent Card with JWS");
    Ok(jws)
}

/// Embed a JWS signature into an AgentCard's `signatures` field (v0.4.0).
///
/// Returns a new AgentCard with the signature appended.
pub fn embed_signature_in_agent_card(
    agent_card: &AgentCard,
    jws_signature: &str,
    key_id: Option<&str>,
) -> AgentCard {
    let mut card = agent_card.clone();
    let sig = AgentCardSignature {
        jws: jws_signature.to_string(),
        key_id: key_id.map(|k| k.to_string()),
    };
    match card.signatures.as_mut() {
        Some(sigs) => sigs.push(sig),
        None => card.signatures = Some(vec![sig]),
    }
    card
}

/// Generate the .well-known endpoints for A2A integration
pub struct WellKnownEndpoints {
    pub agent_card_path: String,
    pub jwks_path: String,
    pub jacs_descriptor_path: String,
    pub jacs_pubkey_path: String,
}

impl Default for WellKnownEndpoints {
    fn default() -> Self {
        Self {
            agent_card_path: "/.well-known/agent-card.json".to_string(),
            jwks_path: "/.well-known/jwks.json".to_string(),
            jacs_descriptor_path: "/.well-known/jacs-agent.json".to_string(),
            jacs_pubkey_path: "/.well-known/jacs-pubkey.json".to_string(),
        }
    }
}

/// Generate all .well-known documents for A2A integration (v0.4.0).
///
/// The agent card is returned with the JWS signature embedded in its
/// `signatures` field rather than wrapped in a separate document.
pub fn generate_well_known_documents(
    agent: &Agent,
    agent_card: &AgentCard,
    a2a_public_key: &[u8],
    a2a_algorithm: &str,
    jws_signature: &str,
) -> Result<Vec<(String, Value)>, Box<dyn Error>> {
    let mut documents = Vec::new();
    let endpoints = WellKnownEndpoints::default();

    // 1. Agent Card with embedded signature (v0.4.0)
    let signed_card = embed_signature_in_agent_card(agent_card, jws_signature, None);
    let card_json = serde_json::to_value(&signed_card)?;
    documents.push((endpoints.agent_card_path, card_json));

    // 2. JWK Set for A2A
    let agent_id = agent.get_id()?;
    let jwk = export_as_jwk(a2a_public_key, a2a_algorithm, &agent_id)?;
    let jwk_set = create_jwk_set(vec![jwk]);
    documents.push((endpoints.jwks_path, jwk_set));

    // 3. JACS Agent Descriptor
    let jacs_descriptor = create_jacs_agent_descriptor(agent)?;
    documents.push((endpoints.jacs_descriptor_path, jacs_descriptor));

    // 4. JACS Public Key
    let jacs_pubkey_doc = create_jacs_pubkey_document(agent)?;
    documents.push((endpoints.jacs_pubkey_path, jacs_pubkey_doc));

    Ok(documents)
}

/// Create JACS agent descriptor document
fn create_jacs_agent_descriptor(agent: &Agent) -> Result<Value, Box<dyn Error>> {
    let agent_value = agent.get_value().ok_or("Agent value not loaded")?;

    let public_key = agent.get_public_key()?;
    let public_key_hash = crate::crypt::hash::hash_public_key(public_key.clone());

    let agent_id = agent.get_id()?;
    let agent_version = agent.get_version()?;
    let key_algorithm = agent.get_key_algorithm();

    Ok(json!({
        "jacsVersion": "1.0",
        "agentId": agent_id,
        "agentVersion": agent_version,
        "agentType": agent_value.get("jacsAgentType"),
        "publicKeyHash": public_key_hash,
        "keyAlgorithm": key_algorithm,
        "capabilities": {
            "signing": true,
            "verification": true,
            "postQuantum": key_algorithm
                .map(|alg| alg.contains("dilithium") || alg.contains("falcon") || alg.contains("sphincs"))
                .unwrap_or(false),
        },
        "schemas": {
            "agent": "https://hai.ai/schemas/agent/v1/agent.schema.json",
            "header": "https://hai.ai/schemas/header/v1/header.schema.json",
            "signature": "https://hai.ai/schemas/components/signature/v1/signature.schema.json",
        },
        "endpoints": {
            "verify": "/jacs/verify",
            "sign": "/jacs/sign",
            "agent": "/jacs/agent",
        }
    }))
}

/// Create JACS public key document
fn create_jacs_pubkey_document(agent: &Agent) -> Result<Value, Box<dyn Error>> {
    let public_key = agent.get_public_key()?;
    let public_key_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &public_key);
    let public_key_hash = crate::crypt::hash::hash_public_key(public_key.clone());

    let agent_id = agent.get_id()?;
    let agent_version = agent.get_version()?;

    Ok(json!({
        "publicKey": public_key_b64,
        "publicKeyHash": public_key_hash,
        "algorithm": agent.get_key_algorithm(),
        "agentId": agent_id,
        "agentVersion": agent_version,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_well_known_endpoints() {
        let endpoints = WellKnownEndpoints::default();
        assert_eq!(endpoints.agent_card_path, "/.well-known/agent-card.json");
        assert_eq!(endpoints.jwks_path, "/.well-known/jwks.json");
    }
}
