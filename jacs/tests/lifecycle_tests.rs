//! Integration tests for full agent lifecycle.
//!
//! These tests exercise the complete workflow of creating agents, signing documents,
//! establishing trust, and managing agreements.
//!
//! Note: These tests create fresh agents rather than relying on pre-existing fixtures
//! to ensure test isolation and avoid fixture staleness issues.

use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::trust;
use serde_json::json;
use serial_test::serial;
use std::env;
use std::fs;
use tempfile::TempDir;

mod utils;
use utils::{create_agent_v1, raw_fixture, set_min_test_env_vars};

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
fn setup_trust_test_env() -> TempDir {
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

/// Sets up environment for lifecycle tests with unique key filenames.
/// This prevents overwriting the shared fixture keys used by other tests.
fn set_lifecycle_test_env_vars() {
    let fixtures_dir = utils::fixtures_dir_string();
    let keys_dir = utils::fixtures_keys_dir_string();
    unsafe {
        env::set_var(utils::PASSWORD_ENV_VAR, utils::TEST_PASSWORD_LEGACY);
        env::set_var("JACS_KEY_DIRECTORY", &keys_dir);
        // Use unique key filenames for lifecycle tests to avoid overwriting shared fixtures
        env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "lifecycle-test.private.pem");
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "lifecycle-test.public.pem");
        env::set_var("JACS_DATA_DIRECTORY", &fixtures_dir);
    }
}

/// Creates a fresh test agent with auto-generated keys.
/// Returns the agent ready for use.
fn create_fresh_agent() -> jacs::agent::Agent {
    set_lifecycle_test_env_vars();
    let mut agent = create_agent_v1().expect("Failed to create agent schema");
    let json_data = fs::read_to_string(raw_fixture("myagent.new.json"))
        .expect("Failed to read agent fixture");

    agent.create_agent_and_load(&json_data, true, Some("ed25519"))
        .expect("Failed to create agent with keys");
    agent
}

// =============================================================================
// 1. Agent Creation Flow Tests
// =============================================================================

#[test]
#[serial]
fn test_agent_creation_with_low_level_api() {
    set_min_test_env_vars();

    let mut agent = create_agent_v1().expect("Failed to create agent schema");
    let json_data = fs::read_to_string(raw_fixture("myagent.new.json"))
        .expect("Failed to read agent fixture");

    // Create agent without keys (just validates schema)
    let result = agent.create_agent_and_load(&json_data, false, None);
    assert!(result.is_ok(), "Failed to create agent: {:?}", result.err());

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
    // Use lifecycle-specific env vars to avoid overwriting shared fixture keys
    set_lifecycle_test_env_vars();

    let mut agent = create_agent_v1().expect("Failed to create agent schema");
    let json_data = fs::read_to_string(raw_fixture("myagent.new.json"))
        .expect("Failed to read agent fixture");

    // Create agent with ed25519 keys
    let result = agent.create_agent_and_load(&json_data, true, Some("ed25519"));
    assert!(result.is_ok(), "Failed to create agent with keys: {:?}", result.err());

    // Verify self-signature
    let verify_result = agent.verify_self_signature();
    assert!(verify_result.is_ok(), "Self-signature verification failed: {:?}", verify_result.err());

    cleanup_test_env();
}

#[test]
#[serial]
fn test_agent_has_required_fields() {
    let agent = create_fresh_agent();

    // Verify agent has all required fields
    let id = agent.get_id().expect("Should have ID");
    let version = agent.get_version().expect("Should have version");

    assert!(!id.is_empty(), "ID should not be empty");
    assert!(!version.is_empty(), "Version should not be empty");

    // Check value contains expected fields
    let value = agent.get_value().expect("Should have value");
    assert!(value.get("name").is_some(), "Should have name");
    assert!(value.get("jacsId").is_some(), "Should have jacsId");
    assert!(value.get("jacsVersion").is_some(), "Should have jacsVersion");
    assert!(value.get("jacsSignature").is_some(), "Should have signature");

    cleanup_test_env();
}

// =============================================================================
// 2. Document Signing Flow Tests
// =============================================================================

#[test]
#[serial]
fn test_document_signing_and_verification() {
    let mut agent = create_fresh_agent();

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
fn test_document_has_signature_fields() {
    let mut agent = create_fresh_agent();

    let doc_json = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": "test"
    });

    let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
        .expect("Failed to create document");

    // Check signature fields
    let signature = doc.value.get("jacsSignature");
    assert!(signature.is_some(), "Document should have jacsSignature");

    let sig = signature.unwrap();
    assert!(sig.get("agentID").is_some(), "Signature should have agentID");
    assert!(sig.get("signature").is_some(), "Signature should have signature value");
    assert!(sig.get("date").is_some(), "Signature should have date");
    assert!(sig.get("publicKeyHash").is_some(), "Signature should have publicKeyHash");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_document_hash_verification() {
    let mut agent = create_fresh_agent();

    // Create and sign a document
    let doc_json = json!({
        "jacsType": "test",
        "jacsLevel": "raw",
        "content": "hash test"
    });

    let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
        .expect("Failed to create document");

    // Verify hash
    let hash_result = agent.verify_hash(&doc.value);
    assert!(hash_result.is_ok(), "Hash verification failed: {:?}", hash_result.err());

    cleanup_test_env();
}

#[test]
#[serial]
fn test_tampered_document_fails_hash_verification() {
    let mut agent = create_fresh_agent();

    // Create and sign a document
    let doc_json = json!({
        "jacsType": "test",
        "jacsLevel": "raw",
        "content": "original"
    });

    let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
        .expect("Failed to create document");

    // Tamper with the value
    let mut tampered_value = doc.value.clone();
    tampered_value["content"] = json!("tampered");

    // Hash verification should fail
    let hash_result = agent.verify_hash(&tampered_value);
    assert!(hash_result.is_err(), "Tampered document hash verification should fail");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_multiple_documents_signing() {
    let mut agent = create_fresh_agent();

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

// Note: Document update tests require the updated content to include the original
// document's jacsId. This is covered in the document_tests.rs test file.
// See test_load_custom_schema_and_custom_document_and_update_and_verify_signature

// =============================================================================
// 3. Agreement Workflow Tests
// =============================================================================
//
// Note: Full agreement workflow tests require multiple agents with valid key pairs.
// The agreement_test.rs file contains comprehensive agreement tests that use
// pre-configured test agents (load_test_agent_one, load_test_agent_two).
// Those fixtures require matching key pairs that are set up in the fixtures directory.
//
// For a working agreement test, see:
// - test_sign_agreement in agreement_test.rs (multi-party signing)
// - test_create_agreement in agreement_test.rs (agreement creation)
// - test_add_and_remove_agents in agreement_test.rs (agent management)

// =============================================================================
// 4. Trust Store Integration Tests
// =============================================================================

#[test]
#[serial]
fn test_trust_store_empty_initially() {
    let _temp = setup_trust_test_env();

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

    let fake_id = "00000000-0000-0000-0000-000000000000:00000000-0000-0000-0000-000000000001";
    let result = trust::untrust_agent(fake_id);
    assert!(result.is_err(), "Untrusting non-existent agent should fail");

    match result {
        Err(jacs::JacsError::AgentNotTrusted { agent_id }) => {
            assert_eq!(agent_id, fake_id);
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
// 5. Key and Signature Tests
// =============================================================================

#[test]
#[serial]
fn test_agent_self_signature_verification() {
    let mut agent = create_fresh_agent();

    // Verify the agent's self-signature
    let sig_result = agent.verify_self_signature();
    assert!(sig_result.is_ok(), "Agent self-signature should be valid: {:?}", sig_result.err());

    // Also verify the hash
    let hash_result = agent.verify_self_hash();
    assert!(hash_result.is_ok(), "Agent self-hash should be valid: {:?}", hash_result.err());

    cleanup_test_env();
}

#[test]
#[serial]
fn test_document_id_uniqueness() {
    let mut agent = create_fresh_agent();

    let mut doc_ids = Vec::new();
    for _ in 0..5 {
        let doc_json = json!({
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": "same content"
        });

        let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
            .expect("Failed to create document");

        doc_ids.push(doc.id.clone());
    }

    // All IDs should be unique
    let unique_ids: std::collections::HashSet<_> = doc_ids.iter().collect();
    assert_eq!(unique_ids.len(), doc_ids.len(), "All document IDs should be unique");

    cleanup_test_env();
}

#[test]
#[serial]
fn test_signature_timestamp_present() {
    let mut agent = create_fresh_agent();

    let doc_json = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": "timestamp test"
    });

    let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
        .expect("Failed to create document");

    // Check timestamp is present and valid format
    let signature = doc.value.get("jacsSignature").expect("Should have signature");
    let timestamp = signature.get("date").expect("Should have date");

    assert!(timestamp.is_string(), "Timestamp should be a string");
    let ts_str = timestamp.as_str().unwrap();
    assert!(!ts_str.is_empty(), "Timestamp should not be empty");

    // Should be a valid RFC 3339 timestamp
    let parsed: Result<chrono::DateTime<chrono::Utc>, _> = ts_str.parse();
    assert!(parsed.is_ok(), "Timestamp should be valid RFC 3339: {}", ts_str);

    cleanup_test_env();
}

// =============================================================================
// End-to-End Workflow Test
// =============================================================================

// =============================================================================
// End-to-End Workflow Test
// =============================================================================

#[test]
#[serial]
fn test_full_signing_workflow() {
    let mut agent = create_fresh_agent();

    // 1. Create a document
    let doc_json = json!({
        "jacsType": "contract",
        "jacsLevel": "raw",
        "content": {
            "title": "Test Contract",
            "version": 1,
            "status": "draft"
        }
    });

    let doc = agent.create_document_and_load(&doc_json.to_string(), None, None)
        .expect("Failed to create initial document");

    let doc_key = doc.getkey();

    // 2. Verify signature
    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(verify_result.is_ok(), "Document signature should be valid");

    // 3. Verify hash
    let hash_result = agent.verify_hash(&doc.value);
    assert!(hash_result.is_ok(), "Document hash should be valid");

    // 4. Document should have all required fields
    assert!(!doc.id.is_empty(), "Document should have ID");
    assert!(!doc.version.is_empty(), "Document should have version");
    assert!(doc.value.get("jacsSignature").is_some(), "Document should have signature");

    // 5. Agent should be able to verify itself
    let self_sig = agent.verify_self_signature();
    assert!(self_sig.is_ok(), "Agent self-signature should be valid");

    let self_hash = agent.verify_self_hash();
    assert!(self_hash.is_ok(), "Agent self-hash should be valid");

    cleanup_test_env();
}
