//! Integration tests for A2A protocol support in JACS (v0.4.0)

use jacs::a2a::{agent_card::*, extension::*, keys::*, provenance::*, *};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::hash::hash_public_key;
use serde_json::json;

mod utils;
use utils::{load_test_agent_one, load_test_agent_two};

#[test]
fn test_export_agent_to_a2a_agent_card() {
    // Use the test agent from fixtures
    let agent = load_test_agent_one();

    // Export to A2A Agent Card
    let agent_card = export_agent_card(&agent).expect("Failed to export agent card");

    // Verify the agent card has required fields (v0.4.0)
    assert!(agent_card.protocol_versions.contains(&"0.4.0".to_string()));
    assert!(!agent_card.name.is_empty());
    assert!(!agent_card.version.is_empty());
    assert!(!agent_card.supported_interfaces.is_empty());
    assert_eq!(
        agent_card.supported_interfaces[0].protocol_binding,
        "jsonrpc"
    );
    assert!(!agent_card.default_input_modes.is_empty());
    assert!(!agent_card.default_output_modes.is_empty());
    assert!(!agent_card.skills.is_empty());

    // Verify skills have required v0.4.0 fields
    for skill in &agent_card.skills {
        assert!(!skill.id.is_empty());
        assert!(!skill.name.is_empty());
        assert!(!skill.tags.is_empty());
    }

    // Verify security schemes is a map (not array)
    assert!(agent_card.security_schemes.is_some());
    let schemes = agent_card.security_schemes.as_ref().unwrap();
    assert!(schemes.contains_key("bearer-jwt"));
    assert!(schemes.contains_key("api-key"));

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
fn test_embed_signature_in_agent_card() {
    let agent = load_test_agent_one();
    let agent_card = export_agent_card(&agent).expect("Failed to export agent card");
    let dual_keys = create_jwk_keys(Some("rsa"), Some("rsa")).expect("Failed to create keys");

    let jws_signature = sign_agent_card_jws(
        &agent_card,
        &dual_keys.a2a_private_key,
        &dual_keys.a2a_algorithm,
        "test-key-id",
    )
    .expect("Failed to sign agent card");

    // Embed the signature (v0.4.0 approach)
    let signed_card =
        embed_signature_in_agent_card(&agent_card, &jws_signature, Some("test-key-id"));

    assert!(signed_card.signatures.is_some());
    let sigs = signed_card.signatures.as_ref().unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].jws, jws_signature);
    assert_eq!(sigs[0].key_id, Some("test-key-id".to_string()));
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
    assert!(matches!(
        verification.status,
        VerificationStatus::SelfSigned
    ));
    assert_eq!(verification.artifact_type, "a2a-message");
    assert_eq!(verification.original_artifact, a2a_artifact);
}

#[test]
fn test_verify_foreign_wrapped_artifact_with_local_key_resolution() {
    let mut signer = load_test_agent_one();
    let verifier = load_test_agent_two();

    let a2a_artifact = json!({
        "messageId": "msg-foreign-001",
        "content": "Hello from foreign agent",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let wrapped = wrap_artifact_with_provenance(&mut signer, a2a_artifact.clone(), "message", None)
        .expect("Failed to wrap artifact");

    // Ensure verifier has signer key material available in local trust store.
    let signer_public_key = signer.get_public_key().expect("signer public key");
    let signer_public_key_hash = hash_public_key(signer_public_key.clone());
    verifier
        .fs_save_remote_public_key(&signer_public_key_hash, &signer_public_key, b"RSA-PSS")
        .expect("cache signer key in verifier trust store");

    let verification =
        verify_wrapped_artifact(&verifier, &wrapped).expect("Failed to verify foreign artifact");

    assert!(verification.valid);
    assert!(matches!(verification.status, VerificationStatus::Verified));
    assert_eq!(verification.original_artifact, a2a_artifact);
}

#[test]
fn test_verify_foreign_wrapped_artifact_without_key_is_unverified() {
    let mut signer = load_test_agent_one();
    let verifier = load_test_agent_two();

    let wrapped = wrap_artifact_with_provenance(
        &mut signer,
        json!({
            "messageId": "msg-foreign-002",
            "content": "Unresolvable key test",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }),
        "message",
        None,
    )
    .expect("Failed to wrap artifact");

    let mut foreign_unresolvable = wrapped.clone();
    foreign_unresolvable["jacsSignature"]["publicKeyHash"] = json!("not-a-real-public-key-hash");
    let updated_hash = verifier
        .hash_doc(&foreign_unresolvable)
        .expect("updated hash after signature metadata mutation");
    foreign_unresolvable["jacsSha256"] = json!(updated_hash);

    let verification = verify_wrapped_artifact(&verifier, &foreign_unresolvable)
        .expect("Verification should return status, not error");

    assert!(!verification.valid);
    assert!(matches!(
        verification.status,
        VerificationStatus::Unverified { .. }
    ));
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

    // Verify all expected documents are present (v0.4.0 path)
    let paths: Vec<String> = documents.iter().map(|(path, _)| path.clone()).collect();
    assert!(paths.contains(&"/.well-known/agent-card.json".to_string()));
    assert!(paths.contains(&"/.well-known/jwks.json".to_string()));
    assert!(paths.contains(&"/.well-known/jacs-agent.json".to_string()));
    assert!(paths.contains(&"/.well-known/jacs-pubkey.json".to_string()));

    // Verify the agent card document has embedded signatures
    let card_doc = documents
        .iter()
        .find(|(p, _)| p == "/.well-known/agent-card.json")
        .unwrap();
    assert!(card_doc.1.get("signatures").is_some());
    assert!(card_doc.1.get("protocolVersions").is_some());
}

#[test]
fn test_create_extension_descriptor() {
    let descriptor = create_extension_descriptor();

    // Verify descriptor structure
    assert_eq!(descriptor["uri"], "urn:hai.ai:jacs-provenance-v1");
    assert_eq!(descriptor["name"], "JACS Document Provenance");
    assert_eq!(descriptor["a2aProtocolVersion"], "0.4.0");
    assert!(descriptor["capabilities"]["documentSigning"].is_object());
    assert!(descriptor["capabilities"]["postQuantumCrypto"].is_object());
    assert!(descriptor["endpoints"]["sign"].is_object());
    assert!(descriptor["endpoints"]["verify"].is_object());
}

#[test]
fn test_agent_card_json_shape() {
    let agent = load_test_agent_one();
    let agent_card = export_agent_card(&agent).expect("Failed to export agent card");

    // Serialize to JSON and verify the shape matches A2A v0.4.0
    let json_value = serde_json::to_value(&agent_card).unwrap();

    // Required fields exist
    assert!(json_value.get("name").is_some());
    assert!(json_value.get("description").is_some());
    assert!(json_value.get("version").is_some());
    assert!(json_value.get("protocolVersions").is_some());
    assert!(json_value.get("supportedInterfaces").is_some());
    assert!(json_value.get("defaultInputModes").is_some());
    assert!(json_value.get("defaultOutputModes").is_some());
    assert!(json_value.get("capabilities").is_some());
    assert!(json_value.get("skills").is_some());

    // Removed fields do NOT exist
    assert!(json_value.get("url").is_none());
    assert!(json_value.get("protocolVersion").is_none());

    // protocolVersions is an array
    assert!(json_value["protocolVersions"].is_array());

    // supportedInterfaces items have url and protocolBinding
    let iface = &json_value["supportedInterfaces"][0];
    assert!(iface.get("url").is_some());
    assert!(iface.get("protocolBinding").is_some());

    // securitySchemes is a map (object), not an array
    assert!(json_value["securitySchemes"].is_object());

    // Skills have id and tags
    let skill = &json_value["skills"][0];
    assert!(skill.get("id").is_some());
    assert!(skill.get("name").is_some());
    assert!(skill.get("tags").is_some());
    assert!(skill["tags"].is_array());
}
