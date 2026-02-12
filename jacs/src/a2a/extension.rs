//! JACS extension management for A2A protocol (v0.4.0)

use crate::a2a::agent_card::create_extension_descriptor;
use crate::a2a::keys::{create_jwk_set, export_as_jwk, sign_jws};
use crate::a2a::{AgentCard, AgentCardSignature};
use crate::agent::{Agent, boilerplate::BoilerPlate};
use crate::crypt::supported_verification_algorithms;
use crate::time_utils;
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

/// Verify a JWS signature on an A2A Agent Card.
///
/// Checks the first (or specified) JWS signature in the card's `signatures`
/// field against the card's serialized content. The signature is verified by
/// serializing the card *without* signatures, then checking the JWS payload
/// matches and the cryptographic signature is valid.
///
/// # Arguments
///
/// * `agent_card` - The Agent Card to verify (must have at least one signature)
/// * `public_key` - The public key bytes for verification
/// * `algorithm` - The key algorithm (e.g., "rsa", "ring-Ed25519")
///
/// # Returns
///
/// `Ok(true)` if the signature is valid, or an error describing the failure.
pub fn verify_agent_card_jws(
    agent_card: &AgentCard,
    public_key: &[u8],
    algorithm: &str,
) -> Result<bool, Box<dyn Error>> {
    use crate::a2a::keys::verify_jws;

    // Get the first signature
    let signatures = agent_card
        .signatures
        .as_ref()
        .ok_or("Agent Card has no signatures")?;

    if signatures.is_empty() {
        return Err("Agent Card signatures array is empty".into());
    }

    let jws = &signatures[0].jws;

    // Serialize the card without signatures for comparison
    let mut card_without_sig = agent_card.clone();
    card_without_sig.signatures = None;
    let expected_payload = serde_json::to_vec(&card_without_sig)?;

    // Verify the JWS signature
    let verified_payload = verify_jws(jws, public_key, algorithm)?;

    // Compare payload content
    if verified_payload != expected_payload {
        return Err("JWS payload does not match the Agent Card content".into());
    }

    info!("Successfully verified Agent Card JWS signature");
    Ok(true)
}

/// Generate the .well-known endpoints for A2A integration
pub struct WellKnownEndpoints {
    pub agent_card_path: String,
    pub jwks_path: String,
    pub jacs_descriptor_path: String,
    pub jacs_pubkey_path: String,
    pub jacs_extension_path: String,
}

impl Default for WellKnownEndpoints {
    fn default() -> Self {
        Self {
            agent_card_path: "/.well-known/agent-card.json".to_string(),
            jwks_path: "/.well-known/jwks.json".to_string(),
            jacs_descriptor_path: "/.well-known/jacs-agent.json".to_string(),
            jacs_pubkey_path: "/.well-known/jacs-pubkey.json".to_string(),
            jacs_extension_path: "/.well-known/jacs-extension.json".to_string(),
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

    // 5. JACS Extension Descriptor
    let signing_algorithm = agent
        .get_key_algorithm()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let extension_descriptor = create_extension_descriptor(&signing_algorithm);
    documents.push((endpoints.jacs_extension_path, extension_descriptor));

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
            "verificationAlgorithms": supported_verification_algorithms(),
            "postQuantum": key_algorithm
                .map(|alg| alg.contains("dilithium") || alg.contains("pq2025"))
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
    let public_key_b64 = crate::crypt::base64_encode(&public_key);
    let public_key_hash = crate::crypt::hash::hash_public_key(public_key.clone());

    let agent_id = agent.get_id()?;
    let agent_version = agent.get_version()?;

    Ok(json!({
        "publicKey": public_key_b64,
        "publicKeyHash": public_key_hash,
        "algorithm": agent.get_key_algorithm(),
        "agentId": agent_id,
        "agentVersion": agent_version,
        "timestamp": time_utils::now_rfc3339(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::JACS_EXTENSION_URI;

    #[test]
    fn test_well_known_endpoints_has_all_five_paths() {
        let endpoints = WellKnownEndpoints::default();
        assert_eq!(endpoints.agent_card_path, "/.well-known/agent-card.json");
        assert_eq!(endpoints.jwks_path, "/.well-known/jwks.json");
        assert_eq!(
            endpoints.jacs_descriptor_path,
            "/.well-known/jacs-agent.json"
        );
        assert_eq!(endpoints.jacs_pubkey_path, "/.well-known/jacs-pubkey.json");
        assert_eq!(
            endpoints.jacs_extension_path,
            "/.well-known/jacs-extension.json"
        );
    }

    #[test]
    fn test_well_known_endpoints_all_under_well_known() {
        let endpoints = WellKnownEndpoints::default();
        let paths = [
            &endpoints.agent_card_path,
            &endpoints.jwks_path,
            &endpoints.jacs_descriptor_path,
            &endpoints.jacs_pubkey_path,
            &endpoints.jacs_extension_path,
        ];
        for path in &paths {
            assert!(
                path.starts_with("/.well-known/"),
                "Path {} should be under /.well-known/",
                path
            );
        }
    }

    #[test]
    fn test_extension_descriptor_via_well_known() {
        // Verify that create_extension_descriptor produces a valid document
        // that would be served at jacs_extension_path
        let descriptor = create_extension_descriptor("pq2025");
        assert_eq!(descriptor["uri"], JACS_EXTENSION_URI);
        assert_eq!(descriptor["name"], "JACS Document Provenance");
        assert!(descriptor["capabilities"].is_object());
        assert!(descriptor["capabilities"]["documentSigning"].is_object());
        assert!(descriptor["capabilities"]["documentVerification"].is_object());
        assert!(descriptor["capabilities"]["postQuantumCrypto"].is_object());
        assert!(descriptor["endpoints"].is_object());
    }

    #[test]
    fn test_embed_signature_in_agent_card() {
        use crate::a2a::{
            A2A_PROTOCOL_VERSION, AgentCapabilities, AgentInterface,
        };

        let card = AgentCard {
            name: "Test".to_string(),
            description: "Test agent".to_string(),
            version: "1.0".to_string(),
            protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            supported_interfaces: vec![AgentInterface {
                url: "https://example.com".to_string(),
                protocol_binding: "jsonrpc".to_string(),
                tenant: None,
            }],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            capabilities: AgentCapabilities {
                streaming: None,
                push_notifications: None,
                extended_agent_card: None,
                extensions: None,
            },
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security: None,
            signatures: None,
            metadata: None,
        };

        let signed = embed_signature_in_agent_card(&card, "fake.jws.signature", Some("key-1"));
        let sigs = signed.signatures.unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].jws, "fake.jws.signature");
        assert_eq!(sigs[0].key_id, Some("key-1".to_string()));
    }

    // =========================================================================
    // verify_agent_card_jws tests
    // =========================================================================

    fn make_test_card() -> AgentCard {
        use crate::a2a::{A2A_PROTOCOL_VERSION, AgentCapabilities, AgentInterface};

        AgentCard {
            name: "JWS Test Agent".to_string(),
            description: "Agent for JWS verification tests".to_string(),
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
                extensions: None,
            },
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security: None,
            signatures: None,
            metadata: None,
        }
    }

    #[test]
    fn test_sign_and_verify_agent_card_roundtrip_ed25519() {
        let card = make_test_card();

        // Generate Ed25519 keys
        let (private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");

        // Sign the card
        let jws =
            sign_agent_card_jws(&card, &private_key, "ring-Ed25519", "test-key-1").expect("sign");

        // Embed signature
        let signed_card = embed_signature_in_agent_card(&card, &jws, Some("test-key-1"));

        // Verify
        let result =
            verify_agent_card_jws(&signed_card, &public_key, "ring-Ed25519").expect("verify");
        assert!(result);
    }

    #[test]
    fn test_sign_and_verify_agent_card_roundtrip_rsa() {
        let card = make_test_card();

        // Generate RSA keys
        let (private_key, public_key) =
            crate::crypt::rsawrapper::generate_keys().expect("key gen");

        // Sign the card
        let jws = sign_agent_card_jws(&card, &private_key, "rsa", "rsa-key-1").expect("sign");

        // Embed signature
        let signed_card = embed_signature_in_agent_card(&card, &jws, Some("rsa-key-1"));

        // Verify
        let result = verify_agent_card_jws(&signed_card, &public_key, "rsa").expect("verify");
        assert!(result);
    }

    #[test]
    fn test_verify_tampered_agent_card_fails() {
        let card = make_test_card();

        // Generate keys and sign
        let (private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");
        let jws =
            sign_agent_card_jws(&card, &private_key, "ring-Ed25519", "test-key").expect("sign");

        // Embed signature, then tamper with the card
        let mut signed_card = embed_signature_in_agent_card(&card, &jws, Some("test-key"));
        signed_card.name = "TAMPERED NAME".to_string();

        // Verification should fail (payload mismatch)
        let result = verify_agent_card_jws(&signed_card, &public_key, "ring-Ed25519");
        assert!(
            result.is_err(),
            "Tampered card should fail verification"
        );
    }

    #[test]
    fn test_verify_missing_signature_fails() {
        let card = make_test_card(); // No signatures

        let (_private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");

        let result = verify_agent_card_jws(&card, &public_key, "ring-Ed25519");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no signatures"),
            "Error should mention missing signatures"
        );
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let card = make_test_card();

        // Sign with one key
        let (private_key, _public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");
        let jws =
            sign_agent_card_jws(&card, &private_key, "ring-Ed25519", "key-1").expect("sign");
        let signed_card = embed_signature_in_agent_card(&card, &jws, Some("key-1"));

        // Verify with a different key
        let (_private_key2, public_key2) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen 2");

        let result = verify_agent_card_jws(&signed_card, &public_key2, "ring-Ed25519");
        assert!(
            result.is_err(),
            "Verification with wrong key should fail"
        );
    }
}
