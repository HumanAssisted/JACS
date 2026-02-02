//! Integration tests for full agent lifecycle.
//!
//! These tests exercise the complete workflow of creating agents, signing documents,
//! establishing trust, and managing agreements.
//!
//! Note: Tests that use SimpleAgent::create are marked as #[ignore] because they require
//! specific file system setup. Run them with: cargo test --test lifecycle_tests -- --ignored

use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use jacs::agent::agreement::Agreement;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::trust;
use serde_json::json;
use serial_test::serial;
use std::env;
use std::fs;
use tempfile::TempDir;

mod utils;
use utils::{
    create_agent_v1, load_local_document, load_test_agent_one, load_test_agent_two,
    raw_fixture, set_min_test_env_vars, DOCTESTFILECONFIG, TEST_PASSWORD,
};

// =============================================================================
// Test Helpers
// =============================================================================

/// Stores the original HOME for restoration.
static ORIGINAL_HOME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Gets or initializes the original HOME directory.
fn get_original_home() -> &'static str {
    ORIGINAL_HOME.get_or_init(|| {
        env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
    })
}

/// Sets up a test trust directory and returns the TempDir guard.
/// IMPORTANT: Always use `cleanup_trust_test_env()` in tests that call this.
fn setup_trust_test_env() -> TempDir {
    // Ensure we capture original HOME before modifying
    let _ = get_original_home();

    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    // SAFETY: These tests run serially via #[serial] attribute
    unsafe {
        env::set_var("HOME", temp_dir.path());
    }
    temp_dir
}

/// Cleans up trust test environment by restoring HOME.
fn cleanup_trust_test_env() {
    let original = get_original_home();
    unsafe {
        env::set_var("HOME", original);
    }
}

/// Cleans up test environment variables.
fn cleanup_test_env() {
    let vars = [
        "JACS_KEY_DIRECTORY",
        "JACS_DATA_DIRECTORY",
        "JACS_PRIVATE_KEY_PASSWORD",
        "JACS_USE_SECURITY",
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        "JACS_AGENT_KEY_ALGORITHM",
        "JACS_AGENT_ID_AND_VERSION",
    ];
    for var in vars {
        let _ = jacs::storage::jenv::clear_env_var(var);
        unsafe {
            env::remove_var(var);
        }
    }
}

// =============================================================================
// 1. Agent Creation Flow Tests
// =============================================================================

#[test]
#[serial]
fn test_agent_creation_with_low_level_api() {
    set_min_test_env_vars();

    // Create agent using the low-level API
    let mut agent = create_agent_v1().expect("Failed to create agent schema");
    let json_data = fs::read_to_string(raw_fixture("myagent.new.json"))
        .expect("Failed to read agent fixture");

    // Create agent and verify it loads
    let result = agent.create_agent_and_load(&json_data, false, None);
    assert!(result.is_ok(), "Failed to create agent: {:?}", result.err());

    // Verify agent has ID and version
    let agent_id = agent.get_id();
    assert!(agent_id.is_ok(), "Agent should have an ID");
    assert!(!agent_id.unwrap().is_empty(), "Agent ID should not be empty");

    let agent_version = agent.get_version();
    assert!(agent_version.is_ok(), "Agent should have a version");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_agent_creation_with_keys() {
    set_min_test_env_vars();

    let mut agent = create_agent_v1().expect("Failed to create agent schema");
    let json_data = fs::read_to_string(raw_fixture("myagent.new.json"))
        .expect("Failed to read agent fixture");

    // Create agent with auto-generated keys using ed25519
    let result = agent.create_agent_and_load(&json_data, true, Some("ed25519"));
    assert!(result.is_ok(), "Failed to create agent with keys: {:?}", result.err());

    // Verify self-signature
    let verify_result = agent.verify_self_signature();
    assert!(verify_result.is_ok(), "Self-signature verification failed: {:?}", verify_result.err());

    cleanup_test_env();
}

#[test]
#[serial]
fn test_agent_load_by_id() {
    set_min_test_env_vars();

    // Load existing test agent
    let agent = load_test_agent_one();

    // Verify agent is properly loaded
    let id = agent.get_id().expect("Agent should have ID");
    let version = agent.get_version().expect("Agent should have version");

    assert!(!id.is_empty(), "Agent ID should not be empty");
    assert!(!version.is_empty(), "Agent version should not be empty");

    cleanup_test_env();
}

// =============================================================================
// 2. Document Signing Flow Tests
// =============================================================================

#[test]
#[serial]
fn test_document_signing_and_verification() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();

    // Create a simple document
    let doc_json = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": {
            "message": "Hello, World!",
            "value": 42
        }
    });

    // Sign the document
    let doc_result = agent.create_document_and_load(&doc_json.to_string(), None, None);
    assert!(doc_result.is_ok(), "Failed to create signed document: {:?}", doc_result.err());

    let doc = doc_result.unwrap();
    let doc_key = doc.getkey();

    // Verify the signature
    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(verify_result.is_ok(), "Signature verification failed: {:?}", verify_result.err());

    cleanup_test_env();
}

#[test]
#[serial]
fn test_document_hash_verification() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();

    // Load existing signed document
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string())
        .expect("Failed to load test document");

    let document = agent.load_document(&document_string).expect("Failed to load document");

    // Verify hash
    let hash_result = agent.verify_hash(&document.value);
    assert!(hash_result.is_ok(), "Hash verification failed: {:?}", hash_result.err());

    cleanup_test_env();
}

#[test]
#[serial]
fn test_tampered_document_fails_verification() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();

    // Load a signed document
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string())
        .expect("Failed to load test document");

    // Tamper with the content (change a value in the document)
    let tampered = document_string.replace("\"favorite-snack\"", "\"tampered-snack\"");

    // Load the tampered document
    let load_result = agent.load_document(&tampered);

    // Either loading should fail (invalid JSON/schema) or verification should fail
    if let Ok(doc) = load_result {
        let verify_result = agent.verify_hash(&doc.value);
        // Hash verification should fail for tampered document
        assert!(verify_result.is_err(), "Tampered document hash should fail verification");
    }
    // If loading failed, that's also acceptable - the document is invalid

    cleanup_test_env();
}

#[test]
#[serial]
fn test_multiple_documents_signing() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();

    // Sign multiple documents
    let mut doc_keys = Vec::new();
    for i in 0..3 {
        let doc_json = json!({
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": {
                "document_number": i,
                "data": format!("Test document {}", i)
            }
        });

        let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
            .expect(&format!("Failed to create document {}", i));

        doc_keys.push(doc.getkey());
    }

    // Verify all documents
    for (i, key) in doc_keys.iter().enumerate() {
        let verify_result = agent.verify_document_signature(key, None, None, None, None);
        assert!(verify_result.is_ok(), "Document {} signature verification failed", i);
    }

    cleanup_test_env();
}

// =============================================================================
// 3. Agreement Workflow Tests
// =============================================================================

#[test]
#[serial]
fn test_agreement_creation() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();

    let agent_ids = vec![
        agent.get_id().expect("Failed to get agent one ID"),
        agent_two.get_id().expect("Failed to get agent two ID"),
    ];

    // Load base document
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string())
        .expect("Failed to load document");
    let document = agent.load_document(&document_string).expect("Failed to load document");
    let document_key = document.getkey();

    // Create agreement
    let agreement_result = agent.create_agreement(
        &document_key,
        &agent_ids,
        None,
        None,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );

    assert!(agreement_result.is_ok(), "Failed to create agreement: {:?}", agreement_result.err());

    let agreement_doc = agreement_result.unwrap();

    // Verify requested agents
    let requested = agreement_doc
        .agreement_requested_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("Failed to get requested agents");
    assert_eq!(requested.len(), 2, "Should have 2 requested agents");

    // Verify unsigned agents
    let unsigned = agreement_doc
        .agreement_unsigned_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("Failed to get unsigned agents");
    assert_eq!(unsigned.len(), 2, "All agents should be unsigned initially");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_agreement_signing_workflow() {
    set_min_test_env_vars();

    let mut agent_one = load_test_agent_one();
    let mut agent_two = load_test_agent_two();

    let agent_ids = vec![
        agent_one.get_id().expect("Failed to get agent one ID"),
        agent_two.get_id().expect("Failed to get agent two ID"),
    ];

    // Load and create agreement
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string())
        .expect("Failed to load document");
    let document = agent_one.load_document(&document_string).expect("Failed to load document");
    let document_key = document.getkey();

    let unsigned_doc = agent_one
        .create_agreement(
            &document_key,
            &agent_ids,
            None,
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("Failed to create agreement");

    let unsigned_key = unsigned_doc.getkey();

    // Agent one signs
    let one_signed = agent_one
        .sign_agreement(&unsigned_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("Agent one failed to sign");

    let one_signed_str = serde_json::to_string(&one_signed.value).expect("Serialize failed");

    // Agent two loads and signs
    agent_two.load_document(&one_signed_str).expect("Agent two failed to load");
    let both_signed = agent_two
        .sign_agreement(&one_signed.getkey(), Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("Agent two failed to sign");

    // Verify agreement is complete
    let unsigned_after = both_signed
        .agreement_unsigned_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("Failed to get unsigned agents");
    assert!(unsigned_after.is_empty(), "All agents should have signed");

    let signed_agents = both_signed
        .agreement_signed_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("Failed to get signed agents");
    assert_eq!(signed_agents.len(), 2, "Both agents should have signed");

    // Verify the complete agreement
    let check_result = agent_two.check_agreement(
        &both_signed.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(check_result.is_ok(), "Agreement check failed: {:?}", check_result.err());

    cleanup_test_env();
}

#[test]
#[serial]
fn test_incomplete_agreement_fails_check() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();

    let agent_ids = vec![
        agent.get_id().expect("Failed to get agent one ID"),
        agent_two.get_id().expect("Failed to get agent two ID"),
    ];

    // Load and create agreement
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string())
        .expect("Failed to load document");
    let document = agent.load_document(&document_string).expect("Failed to load document");

    let unsigned_doc = agent
        .create_agreement(
            &document.getkey(),
            &agent_ids,
            None,
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("Failed to create agreement");

    // Only one agent signs
    let one_signed = agent
        .sign_agreement(&unsigned_doc.getkey(), Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("Agent one failed to sign");

    // Check should fail - not all agents have signed
    let check_result = agent.check_agreement(
        &one_signed.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(check_result.is_err(), "Incomplete agreement check should fail");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_agreement_get_question_and_context() {
    set_min_test_env_vars();

    let mut agent_one = load_test_agent_one();
    let mut agent_two = load_test_agent_two();

    let agent_ids = vec![
        agent_one.get_id().unwrap(),
        agent_two.get_id().unwrap(),
    ];

    // Create a complete agreement
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent_one.load_document(&document_string).unwrap();

    let unsigned_doc = agent_one
        .create_agreement(
            &document.getkey(),
            &agent_ids,
            None,
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .unwrap();

    // Sign with both agents
    let one_signed = agent_one
        .sign_agreement(&unsigned_doc.getkey(), Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .unwrap();

    let one_signed_str = serde_json::to_string(&one_signed.value).unwrap();
    agent_two.load_document(&one_signed_str).unwrap();

    let both_signed = agent_two
        .sign_agreement(&one_signed.getkey(), Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .unwrap();

    // Get question and context
    let both_signed_str = serde_json::to_string(&both_signed.value).unwrap();
    agent_one.load_document(&both_signed_str).unwrap();

    let result = agent_one.agreement_get_question_and_context(
        &both_signed.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );

    assert!(result.is_ok(), "Should be able to get question and context");

    cleanup_test_env();
}

// =============================================================================
// 4. Trust Store Integration Tests
// =============================================================================

#[test]
#[serial]
fn test_trust_store_empty_initially() {
    let _temp = setup_trust_test_env();

    // Trust store should be empty
    let trusted = trust::list_trusted_agents().expect("Failed to list trusted agents");
    assert!(trusted.is_empty(), "Trust store should start empty");

    cleanup_trust_test_env();
}

#[test]
#[serial]
fn test_is_trusted_returns_false_for_unknown() {
    let _temp = setup_trust_test_env();

    assert!(!trust::is_trusted("unknown-agent-id"));
    assert!(!trust::is_trusted("another-unknown-id"));

    cleanup_trust_test_env();
}

#[test]
#[serial]
fn test_untrust_nonexistent_agent_fails() {
    let _temp = setup_trust_test_env();

    let result = trust::untrust_agent("nonexistent-agent-id");
    assert!(result.is_err(), "Untrusting non-existent agent should fail");

    match result {
        Err(jacs::JacsError::AgentNotTrusted { agent_id }) => {
            assert_eq!(agent_id, "nonexistent-agent-id");
        }
        _ => panic!("Expected AgentNotTrusted error"),
    }

    cleanup_trust_test_env();
}

#[test]
#[serial]
fn test_get_trusted_agent_nonexistent_fails() {
    let _temp = setup_trust_test_env();

    let result = trust::get_trusted_agent("nonexistent-agent-id");
    assert!(result.is_err(), "Getting non-existent agent should fail");

    cleanup_trust_test_env();
}

// =============================================================================
// 5. Key Operations Tests
// =============================================================================

#[test]
#[serial]
fn test_key_generation_ed25519() {
    set_min_test_env_vars();

    let mut agent = create_agent_v1().expect("Failed to create agent");
    let json_data = fs::read_to_string(raw_fixture("myagent.new.json"))
        .expect("Failed to read agent fixture");

    // Create agent with ed25519 keys
    let result = agent.create_agent_and_load(&json_data, true, Some("ed25519"));
    assert!(result.is_ok(), "Failed to create agent with ed25519: {:?}", result.err());

    // Verify we can sign
    let doc_json = json!({
        "jacsType": "test",
        "jacsLevel": "raw",
        "content": "test data"
    });

    let doc_result = agent.create_document_and_load(&doc_json.to_string(), None, None);
    assert!(doc_result.is_ok(), "Should be able to sign with ed25519 keys");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_signature_includes_agent_info() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();

    // Create a signed document
    let doc_json = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": "test"
    });

    let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
        .expect("Failed to create document");

    // Check that the document has signature information
    let signature = doc.value.get("jacsSignature");
    assert!(signature.is_some(), "Document should have jacsSignature");

    let sig = signature.unwrap();
    assert!(sig.get("agentID").is_some(), "Signature should have agentID");
    assert!(sig.get("signature").is_some(), "Signature should have signature value");
    assert!(sig.get("date").is_some(), "Signature should have date");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_agent_self_signature_verification() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();

    // Verify the agent's self-signature
    let result = agent.verify_self_signature();
    assert!(result.is_ok(), "Agent self-signature should be valid: {:?}", result.err());

    // Also verify the hash
    let hash_result = agent.verify_self_hash();
    assert!(hash_result.is_ok(), "Agent self-hash should be valid: {:?}", hash_result.err());

    cleanup_test_env();
}

// =============================================================================
// End-to-End Workflow Test
// =============================================================================

#[test]
#[serial]
fn test_full_document_lifecycle() {
    set_min_test_env_vars();

    let mut agent = load_test_agent_one();

    // 1. Create initial document
    let initial_doc = json!({
        "jacsType": "contract",
        "jacsLevel": "raw",
        "content": {
            "title": "Test Contract",
            "version": 1,
            "status": "draft"
        }
    });

    let doc = agent.create_document_and_load(&initial_doc.to_string(), None, None)
        .expect("Failed to create initial document");

    let doc_key = doc.getkey();
    let doc_id = doc.id.clone();

    // 2. Verify signature
    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(verify_result.is_ok(), "Initial document signature should be valid");

    // 3. Update the document
    let updated_content = json!({
        "jacsType": "contract",
        "jacsLevel": "raw",
        "content": {
            "title": "Test Contract",
            "version": 2,
            "status": "active"
        }
    });

    let updated_doc = agent.update_document(&doc_key, &updated_content.to_string(), None, None)
        .expect("Failed to update document");

    // 4. Verify the updated document has a new version
    let new_version = updated_doc.version.clone();
    assert_ne!(doc.version, new_version, "Updated document should have new version");

    // 5. Verify new signature is valid
    let new_doc_key = updated_doc.getkey();
    let verify_updated = agent.verify_document_signature(&new_doc_key, None, None, None, None);
    assert!(verify_updated.is_ok(), "Updated document signature should be valid");

    // 6. Document ID should remain the same
    assert_eq!(doc_id, updated_doc.id, "Document ID should remain the same after update");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_cross_agent_document_verification() {
    set_min_test_env_vars();

    let mut agent_one = load_test_agent_one();
    let mut agent_two = load_test_agent_two();

    // Agent one creates and signs a document
    let doc_json = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "from": agent_one.get_id().unwrap(),
        "to": agent_two.get_id().unwrap(),
        "content": "Hello from agent one!"
    });

    let doc = agent_one.create_document_and_load(&doc_json.to_string(), None, None)
        .expect("Agent one failed to create document");

    // Serialize the document for transfer
    let doc_string = serde_json::to_string(&doc.value).expect("Failed to serialize");

    // Agent two loads the document
    let loaded_doc = agent_two.load_document(&doc_string)
        .expect("Agent two failed to load document");

    // Agent two should be able to verify the hash (but not signature without agent one's key)
    let hash_result = agent_two.verify_hash(&loaded_doc.value);
    assert!(hash_result.is_ok(), "Hash verification should work cross-agent");

    cleanup_test_env();
}
