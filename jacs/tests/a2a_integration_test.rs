//! Integration tests for A2A protocol support in JACS

use jacs::a2a::{agent_card::*, extension::*, keys::*, provenance::*};
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use serde_json::json;
use std::env;

mod utils;
use utils::load_test_agent_one;

#[test]
fn test_export_agent_to_a2a_agent_card() {
    // Use the test agent from fixtures
    let agent = load_test_agent_one();

    // Export to A2A Agent Card
    let agent_card = export_agent_card(&agent).expect("Failed to export agent card");

    // Verify the agent card has required fields
    assert_eq!(agent_card.protocol_version, "1.0");
    assert!(!agent_card.url.is_empty());
    assert!(!agent_card.name.is_empty());
    assert!(!agent_card.skills.is_empty());
    assert!(!agent_card.security_schemes.is_empty());

    // Check JACS extension is present
    assert!(agent_card.capabilities.extensions.is_some());
    let extensions = agent_card.capabilities.extensions.as_ref().unwrap();
    assert!(
        extensions
            .iter()
            .any(|ext| ext.uri == "urn:hai.ai:jacs-provenance-v1")
    );
}

#[test]
fn test_dual_key_generation() {
    // No environment setup needed - keys are ephemeral
    let dual_keys = create_jwk_keys(Some("rsa"), Some("rsa")).expect("Failed to create dual keys");

    // Verify both keys were generated
    assert!(!dual_keys.jacs_private_key.is_empty());
    assert!(!dual_keys.jacs_public_key.is_empty());
    assert_eq!(dual_keys.jacs_algorithm, "rsa");

    assert!(!dual_keys.a2a_private_key.is_empty());
    assert!(!dual_keys.a2a_public_key.is_empty());
    assert_eq!(dual_keys.a2a_algorithm, "rsa");
}

#[test]
fn test_agent_card_jws_signing() {
    // Use the test agent from fixtures
    let agent = load_test_agent_one();

    // Export agent card
    let agent_card = export_agent_card(&agent).expect("Failed to export agent card");

    // Generate A2A-compatible keys (ephemeral - no env vars needed)
    let dual_keys = create_jwk_keys(Some("rsa"), Some("rsa")).expect("Failed to create keys");

    // Sign the agent card with JWS
    let jws_signature = sign_agent_card_jws(
        &agent_card,
        &dual_keys.a2a_private_key,
        &dual_keys.a2a_algorithm,
        "test-key-id",
    )
    .expect("Failed to sign agent card");

    // Verify JWS format (header.payload.signature)
    let parts: Vec<&str> = jws_signature.split('.').collect();
    assert_eq!(parts.len(), 3);
}

#[test]
fn test_wrap_a2a_artifact_with_provenance() {
    // Use the test agent from fixtures
    let mut agent = load_test_agent_one();

    // Create a sample A2A artifact (e.g., a task)
    let a2a_task = json!({
        "taskId": "task-123",
        "name": "Process Document",
        "description": "Extract entities from document",
        "status": "pending",
        "created": chrono::Utc::now().to_rfc3339(),
    });

    // Wrap with JACS provenance
    let wrapped = wrap_artifact_with_provenance(&mut agent, a2a_task.clone(), "task", None)
        .expect("Failed to wrap artifact");

    // Verify the wrapped artifact
    assert!(wrapped.get("jacsId").is_some());
    assert!(wrapped.get("jacsVersion").is_some());
    assert_eq!(
        wrapped.get("jacsType").and_then(|v| v.as_str()),
        Some("a2a-task")
    );
    assert!(wrapped.get("jacsSignature").is_some());
    assert!(wrapped.get("jacsSha256").is_some());
    assert_eq!(wrapped.get("a2aArtifact"), Some(&a2a_task));
}

#[test]
fn test_verify_wrapped_artifact() {
    // Use the test agent from fixtures
    let mut agent = load_test_agent_one();

    // Create and wrap an artifact
    let a2a_artifact = json!({
        "messageId": "msg-456",
        "content": "Hello from A2A",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let wrapped = wrap_artifact_with_provenance(&mut agent, a2a_artifact.clone(), "message", None)
        .expect("Failed to wrap artifact");

    // Verify the wrapped artifact
    let verification =
        verify_wrapped_artifact(&agent, &wrapped).expect("Failed to verify artifact");

    assert!(verification.valid);
    assert_eq!(verification.artifact_type, "a2a-message");
    assert_eq!(verification.original_artifact, a2a_artifact);
}

#[test]
fn test_create_chain_of_custody() {
    // Use the test agent from fixtures
    let mut agent = load_test_agent_one();

    // Create multiple artifacts
    let mut artifacts: Vec<serde_json::Value> = Vec::new();

    for i in 0..3 {
        let artifact = json!({
            "stepId": format!("step-{}", i),
            "action": format!("Process step {}", i),
        });

        let wrapped = wrap_artifact_with_provenance(
            &mut agent,
            artifact,
            "workflow-step",
            if i > 0 {
                Some(vec![artifacts.last().unwrap().clone()])
            } else {
                None
            },
        )
        .expect("Failed to wrap artifact");

        artifacts.push(wrapped);
    }

    // Create chain of custody
    let chain =
        create_chain_of_custody(artifacts.clone()).expect("Failed to create chain of custody");

    assert_eq!(chain["totalArtifacts"], 3);
    assert!(chain["chainOfCustody"].is_array());
}

#[test]
fn test_well_known_endpoints_generation() {
    // Use the test agent from fixtures
    let agent = load_test_agent_one();

    // Export agent card
    let agent_card = export_agent_card(&agent).expect("Failed to export agent card");

    // Generate dual keys (ephemeral - no env vars needed)
    let dual_keys = create_jwk_keys(Some("dilithium"), Some("rsa")).expect("Failed to create keys");

    // Sign agent card
    let jws_signature = sign_agent_card_jws(
        &agent_card,
        &dual_keys.a2a_private_key,
        &dual_keys.a2a_algorithm,
        "test-key",
    )
    .expect("Failed to sign agent card");

    // Generate well-known documents
    let documents = generate_well_known_documents(
        &agent,
        &agent_card,
        &dual_keys.a2a_public_key,
        &dual_keys.a2a_algorithm,
        &jws_signature,
    )
    .expect("Failed to generate well-known documents");

    // Verify all expected documents are present
    let paths: Vec<String> = documents.iter().map(|(path, _)| path.clone()).collect();
    assert!(paths.contains(&"/.well-known/agent.json".to_string()));
    assert!(paths.contains(&"/.well-known/jwks.json".to_string()));
    assert!(paths.contains(&"/.well-known/jacs-agent.json".to_string()));
    assert!(paths.contains(&"/.well-known/jacs-pubkey.json".to_string()));
}

#[test]
fn test_create_extension_descriptor() {
    let descriptor = create_extension_descriptor();

    // Verify descriptor structure
    assert_eq!(descriptor["uri"], "urn:hai.ai:jacs-provenance-v1");
    assert_eq!(descriptor["name"], "JACS Document Provenance");
    assert!(descriptor["capabilities"]["documentSigning"].is_object());
    assert!(descriptor["capabilities"]["postQuantumCrypto"].is_object());
    assert!(descriptor["endpoints"]["sign"].is_object());
    assert!(descriptor["endpoints"]["verify"].is_object());
}
