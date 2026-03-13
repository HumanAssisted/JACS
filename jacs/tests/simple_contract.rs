//! Characterization tests for the narrow SimpleAgent contract.
//!
//! These tests cover the 17 methods defined in Section 4.1.2 of
//! docs/ARCHITECTURE_UPGRADE.md as the narrow simple contract:
//!
//!   create, create_with_params, load, ephemeral, verify_self,
//!   sign_message, sign_file, verify, verify_with_key, verify_by_id,
//!   export_agent, get_public_key_pem, get_agent_id, key_id,
//!   diagnostics, is_strict, config_path
//!
//! These tests form the behavioral baseline that MUST pass before
//! any refactoring begins. If a later refactor breaks any of these,
//! it has violated the narrow contract.

use jacs::simple::{CreateAgentParams, SimpleAgent};
use serde_json::{Value, json};
use serial_test::serial;
use std::fs;
use tempfile::TempDir;

// =============================================================================
// Helper: create an ephemeral agent for tests that don't need disk
// =============================================================================

fn ephemeral_ed25519() -> (SimpleAgent, jacs::simple::AgentInfo) {
    SimpleAgent::ephemeral(Some("ed25519")).expect("ephemeral(ed25519) should succeed")
}

fn ephemeral_default() -> (SimpleAgent, jacs::simple::AgentInfo) {
    SimpleAgent::ephemeral(None).expect("ephemeral(default/pq2025) should succeed")
}

// =============================================================================
// Helper: create a persistent agent in a temp directory
// =============================================================================

/// Maps user-friendly algorithm names to internal JACS names.
/// SimpleAgent::ephemeral() does this mapping internally, but
/// create_with_params() takes the raw internal algorithm name.
fn internal_algorithm(friendly: &str) -> &str {
    match friendly {
        "ed25519" => "ring-Ed25519",
        "rsa-pss" | "rsa" => "RSA-PSS",
        "pq2025" => "pq2025",
        other => other,
    }
}

const TEST_PASSWORD: &str = "TestP@ss123!#";

fn persistent_agent_in(dir: &TempDir, algorithm: &str) -> (SimpleAgent, jacs::simple::AgentInfo) {
    let data_dir = dir.path().join("jacs_data");
    let key_dir = dir.path().join("jacs_keys");
    let config_path = dir.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("test-agent")
        .password(TEST_PASSWORD)
        .algorithm(internal_algorithm(algorithm))
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .description("Test agent for narrow contract characterization")
        .build();

    // create_with_params sets env vars inside a mutex guard and restores them
    // on return. The persistent agent needs JACS_PRIVATE_KEY_PASSWORD to be
    // set for subsequent sign operations, so we set it after creation.
    let result =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    // Re-set password env var so signing can decrypt the private key.
    // Also re-set key/data directories so the agent can find its files.
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
        std::env::set_var("JACS_DATA_DIRECTORY", data_dir.to_str().unwrap());
        std::env::set_var("JACS_KEY_DIRECTORY", key_dir.to_str().unwrap());
    }

    result
}

// =============================================================================
// 1. SimpleAgent::create()
// =============================================================================

#[test]
#[serial]
fn test_create_returns_agent_and_info() {
    // create() writes to CWD (./jacs_keys, ./jacs_data, ./jacs.config.json),
    // so we must run it from a temp directory to avoid polluting the repo.
    let tmp = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();

    // Set env vars that create() needs — it reads from env for key config
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
        std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "agent.private.pem.enc");
        std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "agent.public.pem");
    }

    let result = SimpleAgent::create("create-test", None, Some("ed25519"));

    // Restore CWD and clean up env vars that create() doesn't need globally.
    // These leak into subsequent #[serial] tests otherwise.
    std::env::set_current_dir(&original_dir).unwrap();
    unsafe {
        std::env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
        std::env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
    }

    let (agent, info) = result.expect("create() should succeed");

    assert!(!info.agent_id.is_empty(), "agent_id should be non-empty");
    assert_eq!(info.name, "create-test");
    assert!(!info.version.is_empty(), "version should be non-empty");

    // create() should have written files in the temp directory
    assert!(
        tmp.path().join("jacs_keys").exists(),
        "create() should create jacs_keys directory"
    );
    assert!(
        tmp.path().join("jacs_data").exists(),
        "create() should create jacs_data directory"
    );
    assert!(
        tmp.path().join("jacs.config.json").exists(),
        "create() should create jacs.config.json"
    );

    // Agent should be usable for signing
    let signed = agent.sign_message(&json!({"test": true}));
    assert!(
        signed.is_ok(),
        "newly created agent should be able to sign: {:?}",
        signed.err()
    );
}

// =============================================================================
// 2. SimpleAgent::create_with_params()
// =============================================================================

#[test]
#[serial]
fn test_create_with_params_respects_all_fields() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("custom_data");
    let key_dir = tmp.path().join("custom_keys");
    let config_path = tmp.path().join("custom.config.json");

    let params = CreateAgentParams::builder()
        .name("params-test-agent")
        .password(TEST_PASSWORD)
        .algorithm(internal_algorithm("ed25519"))
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .description("A custom test agent")
        .agent_type("ai")
        .build();

    let (_agent, info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    assert_eq!(info.name, "params-test-agent");
    assert!(
        info.data_directory.contains("custom_data"),
        "data_directory should reflect param: got {}",
        info.data_directory
    );
    assert!(
        info.key_directory.contains("custom_keys"),
        "key_directory should reflect param: got {}",
        info.key_directory
    );
    assert!(
        info.config_path.contains("custom.config.json"),
        "config_path should reflect param: got {}",
        info.config_path
    );
    // Config file should exist on disk
    assert!(
        std::path::Path::new(&info.config_path).exists(),
        "config file should be created at {}",
        info.config_path
    );
}

#[test]
#[serial]
fn test_create_with_params_ed25519() {
    let tmp = TempDir::new().unwrap();
    let (agent, info) = persistent_agent_in(&tmp, "ed25519");
    assert!(
        info.algorithm.contains("ed25519") || info.algorithm.contains("Ed25519"),
        "algorithm should be ed25519 variant, got: {}",
        info.algorithm
    );
    let signed = agent.sign_message(&json!({"algo": "ed25519"}));
    assert!(signed.is_ok(), "ed25519 agent should sign successfully");
}

#[test]
#[serial]
fn test_create_with_params_pq2025() {
    let tmp = TempDir::new().unwrap();
    let (agent, info) = persistent_agent_in(&tmp, "pq2025");
    assert!(
        info.algorithm.contains("pq2025"),
        "algorithm should be pq2025, got: {}",
        info.algorithm
    );
    let signed = agent.sign_message(&json!({"algo": "pq2025"}));
    assert!(
        signed.is_ok(),
        "pq2025 agent should sign successfully: {:?}",
        signed.err()
    );
}

// =============================================================================
// 3. SimpleAgent::load()
// =============================================================================

#[test]
#[serial]
fn test_load_roundtrips_with_create() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("load-roundtrip-agent")
        .password(TEST_PASSWORD)
        .algorithm(internal_algorithm("ed25519"))
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .build();

    let (_agent, info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    // Set env vars so load() can find the agent files and decrypt the key.
    // create_with_params restores env vars on return, so we must re-set them.
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
        std::env::set_var("JACS_DATA_DIRECTORY", data_dir.to_str().unwrap());
        std::env::set_var("JACS_KEY_DIRECTORY", key_dir.to_str().unwrap());
    }

    let loaded = SimpleAgent::load(Some(&info.config_path), None);
    assert!(
        loaded.is_ok(),
        "load() should succeed for a created agent: {:?}",
        loaded.err()
    );

    let loaded_agent = loaded.unwrap();
    // The loaded agent should be able to verify itself
    let verify_result = loaded_agent.verify_self();
    assert!(
        verify_result.is_ok(),
        "loaded agent should verify_self: {:?}",
        verify_result.err()
    );
    assert!(
        verify_result.unwrap().valid,
        "loaded agent self-verification should be valid"
    );
}

#[test]
fn test_load_nonexistent_config_fails() {
    let result = SimpleAgent::load(Some("/nonexistent/path/jacs.config.json"), None);
    assert!(
        result.is_err(),
        "load() should fail for a nonexistent config path"
    );
}

// =============================================================================
// 4. SimpleAgent::ephemeral()
// =============================================================================

#[test]
fn test_ephemeral_creates_agent_no_disk_writes() {
    let tmp = TempDir::new().unwrap();
    let before_count = fs::read_dir(tmp.path()).unwrap().count();

    let (agent, info) = SimpleAgent::ephemeral(Some("ed25519")).expect("ephemeral should succeed");

    let after_count = fs::read_dir(tmp.path()).unwrap().count();
    assert_eq!(
        before_count, after_count,
        "ephemeral should not write to disk"
    );

    assert!(
        !info.agent_id.is_empty(),
        "ephemeral agent_id should be non-empty"
    );
    assert_eq!(info.name, "ephemeral");
    assert!(
        info.config_path.is_empty(),
        "ephemeral agent should have no config_path"
    );

    // Should be usable
    let signed = agent.sign_message(&json!({"ephemeral": true}));
    assert!(signed.is_ok(), "ephemeral agent should be able to sign");
}

#[test]
fn test_ephemeral_default_algorithm() {
    let (agent, info) = ephemeral_default();
    assert!(!info.agent_id.is_empty());
    assert!(
        info.algorithm.contains("pq2025"),
        "default ephemeral should use pq2025, got: {}",
        info.algorithm
    );
    let signed = agent.sign_message(&json!({"default": true}));
    assert!(signed.is_ok());
}

#[test]
fn test_ephemeral_ed25519() {
    let (agent, info) = ephemeral_ed25519();
    assert!(!info.agent_id.is_empty());
    assert!(
        info.algorithm.contains("Ed25519") || info.algorithm.contains("ed25519"),
        "ed25519 ephemeral should use ed25519, got: {}",
        info.algorithm
    );
    let signed = agent.sign_message(&json!({"ed25519": true}));
    assert!(signed.is_ok());
}

#[test]
fn test_ephemeral_rsa() {
    let (agent, info) =
        SimpleAgent::ephemeral(Some("rsa-pss")).expect("ephemeral rsa-pss should succeed");
    assert!(!info.agent_id.is_empty());
    assert!(
        info.algorithm.contains("RSA") || info.algorithm.contains("rsa"),
        "rsa-pss ephemeral should use RSA variant, got: {}",
        info.algorithm
    );
    let signed = agent.sign_message(&json!({"rsa": true}));
    assert!(signed.is_ok());
}

// =============================================================================
// 5. SimpleAgent::verify_self()
// =============================================================================

#[test]
fn test_verify_self_on_fresh_ephemeral() {
    let (agent, _info) = ephemeral_ed25519();
    let result = agent.verify_self().expect("verify_self should not error");
    assert!(
        result.valid,
        "fresh ephemeral agent should verify_self as valid"
    );
    assert!(result.errors.is_empty(), "no errors expected");
    assert!(
        !result.signer_id.is_empty(),
        "signer_id should be populated"
    );
}

#[test]
#[serial]
fn test_verify_self_on_persistent_agent() {
    let tmp = TempDir::new().unwrap();
    let (agent, _info) = persistent_agent_in(&tmp, "ed25519");
    let result = agent.verify_self().expect("verify_self should not error");
    assert!(result.valid, "persistent agent should verify_self as valid");
}

// =============================================================================
// 6. SimpleAgent::sign_message()
// =============================================================================

#[test]
fn test_sign_message_produces_verifiable_output() {
    let (agent, _info) = ephemeral_ed25519();
    let data = json!({"action": "test", "value": 42});
    let signed = agent
        .sign_message(&data)
        .expect("sign_message should succeed");

    assert!(!signed.raw.is_empty(), "signed.raw should be non-empty");
    assert!(
        !signed.document_id.is_empty(),
        "document_id should be non-empty"
    );
    assert!(!signed.agent_id.is_empty(), "agent_id should be non-empty");
    assert!(
        !signed.timestamp.is_empty(),
        "timestamp should be non-empty"
    );

    // The raw JSON should be parseable
    let parsed: Value = serde_json::from_str(&signed.raw).expect("signed.raw should be valid JSON");
    assert!(
        parsed.get("jacsSignature").is_some(),
        "signed document should have jacsSignature"
    );
}

#[test]
fn test_sign_message_different_data_different_ids() {
    let (agent, _info) = ephemeral_ed25519();
    let signed1 = agent.sign_message(&json!({"msg": 1})).unwrap();
    let signed2 = agent.sign_message(&json!({"msg": 2})).unwrap();
    assert_ne!(
        signed1.document_id, signed2.document_id,
        "different messages should produce different document IDs"
    );
}

// =============================================================================
// 7. SimpleAgent::sign_file()
// =============================================================================

#[test]
fn test_sign_file_embed_true() {
    let tmp = TempDir::new().unwrap();
    let test_file = tmp.path().join("test.txt");
    fs::write(&test_file, "Hello, JACS!").unwrap();

    let (agent, _info) = ephemeral_ed25519();
    let signed = agent
        .sign_file(test_file.to_str().unwrap(), true)
        .expect("sign_file(embed=true) should succeed");

    assert!(!signed.raw.is_empty());
    assert!(!signed.document_id.is_empty());

    let parsed: Value = serde_json::from_str(&signed.raw).unwrap();
    assert!(
        parsed.get("jacsSignature").is_some(),
        "signed file doc should have jacsSignature"
    );
}

#[test]
fn test_sign_file_embed_false() {
    let tmp = TempDir::new().unwrap();
    let test_file = tmp.path().join("test.txt");
    fs::write(&test_file, "Hello, JACS!").unwrap();

    let (agent, _info) = ephemeral_ed25519();
    let signed = agent
        .sign_file(test_file.to_str().unwrap(), false)
        .expect("sign_file(embed=false) should succeed");

    assert!(!signed.raw.is_empty());
    assert!(!signed.document_id.is_empty());
}

#[test]
fn test_sign_file_nonexistent_fails() {
    let (agent, _info) = ephemeral_ed25519();
    let result = agent.sign_file("/nonexistent/file.txt", true);
    assert!(result.is_err(), "sign_file on nonexistent file should fail");
}

// =============================================================================
// 8. SimpleAgent::verify()
// =============================================================================

#[test]
fn test_verify_accepts_valid_document() {
    let (agent, _info) = ephemeral_ed25519();
    let signed = agent.sign_message(&json!({"data": "valid"})).unwrap();

    let result = agent.verify(&signed.raw).expect("verify should not error");
    assert!(
        result.valid,
        "verify should return valid for a valid document"
    );
    assert!(result.errors.is_empty(), "no errors on valid document");
}

#[test]
fn test_verify_rejects_tampered_document() {
    let (agent, _info) = ephemeral_ed25519();
    let signed = agent.sign_message(&json!({"data": "original"})).unwrap();

    // Tamper with the content
    let mut parsed: Value = serde_json::from_str(&signed.raw).unwrap();
    parsed["content"] = json!({"data": "tampered"});
    let tampered = serde_json::to_string(&parsed).unwrap();

    // Verification should detect the tampering
    let result = agent.verify(&tampered);
    // In non-strict mode, verify returns Ok with valid=false
    // In strict mode or load failure, it may return Err
    match result {
        Ok(vr) => assert!(!vr.valid, "tampered document should not verify as valid"),
        Err(_) => {} // Also acceptable — strict mode or load rejection
    }
}

#[test]
fn test_verify_rejects_garbage_input() {
    let (agent, _info) = ephemeral_ed25519();
    let result = agent.verify("not-json-at-all");
    assert!(result.is_err(), "garbage input should fail verification");
}

// =============================================================================
// 9. SimpleAgent::verify_with_key()
// =============================================================================

#[test]
fn test_verify_with_key_correct_key() {
    let (agent, _info) = ephemeral_ed25519();
    let signed = agent.sign_message(&json!({"key_test": true})).unwrap();

    // Get the agent's public key
    let pubkey = agent
        .get_public_key()
        .expect("get_public_key should succeed");

    let result = agent
        .verify_with_key(&signed.raw, pubkey)
        .expect("verify_with_key should not error");
    assert!(
        result.valid,
        "verify_with_key with correct key should be valid"
    );
}

#[test]
fn test_verify_with_key_wrong_key() {
    let (agent_a, _) = ephemeral_ed25519();
    let (agent_b, _) = ephemeral_ed25519();

    let signed = agent_a.sign_message(&json!({"from": "a"})).unwrap();

    // Get agent_b's key (wrong key for agent_a's document)
    let wrong_key = agent_b.get_public_key().unwrap();

    let result = agent_a.verify_with_key(&signed.raw, wrong_key);
    // Should either return Ok(valid=false) or Err
    match result {
        Ok(vr) => assert!(!vr.valid, "wrong key should not verify as valid"),
        Err(_) => {} // Also acceptable
    }
}

// =============================================================================
// 10. SimpleAgent::verify_by_id() — requires stored document
// =============================================================================

#[test]
fn test_verify_by_id_on_signed_message() {
    // verify_by_id needs the document to be stored in the agent's storage.
    // For ephemeral agents, sign_message stores in memory.
    let (agent, _info) = ephemeral_ed25519();
    let signed = agent.sign_message(&json!({"stored": true})).unwrap();

    // verify_by_id requires "uuid:version" format, NOT just the UUID.
    // SignedDocument.document_id is only the UUID, so we must construct
    // the key from jacsId + jacsVersion in the raw signed JSON.
    let signed_value: Value = serde_json::from_str(&signed.raw).expect("parse signed document");
    let document_key = format!(
        "{}:{}",
        signed_value["jacsId"]
            .as_str()
            .expect("jacsId should exist"),
        signed_value["jacsVersion"]
            .as_str()
            .expect("jacsVersion should exist")
    );

    let result = agent
        .verify_by_id(&document_key)
        .expect("verify_by_id should succeed for a document stored in memory");
    assert!(
        result.valid,
        "verify_by_id should return valid for stored doc: {:?}",
        result.errors
    );
}

#[test]
fn test_verify_by_id_rejects_uuid_only() {
    // Passing just a UUID (without :version) should fail with a format error.
    let (agent, _info) = ephemeral_ed25519();
    let signed = agent.sign_message(&json!({"stored": true})).unwrap();

    let result = agent.verify_by_id(&signed.document_id);
    assert!(
        result.is_err(),
        "verify_by_id should reject UUID-only format"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("uuid:version"),
        "error should mention expected format, got: {}",
        msg
    );
}

// =============================================================================
// 11. SimpleAgent::export_agent()
// =============================================================================

#[test]
fn test_export_agent_returns_valid_json() {
    let (agent, info) = ephemeral_ed25519();
    let exported = agent.export_agent().expect("export_agent should succeed");

    assert!(!exported.is_empty(), "exported agent should be non-empty");

    let parsed: Value =
        serde_json::from_str(&exported).expect("exported agent should be valid JSON");

    // Should contain the agent ID
    let jacs_id = parsed.get("jacsId").and_then(|v| v.as_str());
    assert!(jacs_id.is_some(), "exported agent should have jacsId");
    assert_eq!(
        jacs_id.unwrap(),
        info.agent_id,
        "exported jacsId should match info.agent_id"
    );
}

// =============================================================================
// 12. SimpleAgent::get_public_key_pem()
// =============================================================================

#[test]
fn test_get_public_key_pem_returns_pem_format() {
    let (agent, _info) = ephemeral_ed25519();
    let pem = agent
        .get_public_key_pem()
        .expect("get_public_key_pem should succeed");

    assert!(!pem.is_empty(), "PEM should be non-empty");
    // PEM format should have standard markers
    assert!(
        pem.contains("-----BEGIN") || pem.contains("PUBLIC KEY"),
        "PEM should contain standard PEM markers, got: {}",
        &pem[..pem.len().min(100)]
    );
}

#[test]
fn test_get_public_key_pem_rsa() {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("rsa-pss")).expect("ephemeral rsa-pss should succeed");
    let pem = agent
        .get_public_key_pem()
        .expect("get_public_key_pem should succeed");
    assert!(
        pem.contains("-----BEGIN") || pem.contains("PUBLIC KEY"),
        "RSA PEM should have standard markers"
    );
}

// =============================================================================
// 13. SimpleAgent::get_agent_id()
// =============================================================================

#[test]
fn test_get_agent_id_returns_non_empty() {
    let (agent, _info) = ephemeral_ed25519();

    // get_agent_id() looks for "jacsId" (canonical) in the exported agent JSON.
    // If this test fails, it means get_agent_id() regressed — both the core and
    // binding-core contracts expect success here.
    let result = agent.get_agent_id();
    match result {
        Ok(agent_id) => {
            assert!(!agent_id.is_empty(), "agent_id should be non-empty");
        }
        Err(e) => {
            // If get_agent_id fails, verify key_id still works as fallback,
            // but flag the failure clearly so it doesn't hide a regression.
            let kid = agent.key_id().expect("key_id should succeed");
            assert!(!kid.is_empty(), "key_id should be non-empty as fallback");
            panic!(
                "get_agent_id() failed but key_id() succeeds — \
                get_agent_id() may be looking for wrong field. Error: {}",
                e
            );
        }
    }
}

// =============================================================================
// 14. SimpleAgent::key_id()
// =============================================================================

#[test]
fn test_key_id_returns_non_empty() {
    let (agent, _info) = ephemeral_ed25519();
    let kid = agent.key_id().expect("key_id should succeed");
    assert!(!kid.is_empty(), "key_id should be non-empty");
}

// =============================================================================
// 15. SimpleAgent::diagnostics()
// =============================================================================

#[test]
fn test_diagnostics_returns_expected_fields() {
    let (agent, _info) = ephemeral_ed25519();
    let diag = agent.diagnostics();

    // Should have these fields (from the standalone diagnostics + agent additions)
    assert!(
        diag.get("jacs_version").is_some(),
        "diagnostics should have jacs_version"
    );
    assert!(diag.get("os").is_some(), "diagnostics should have os");
    assert!(diag.get("arch").is_some(), "diagnostics should have arch");
    assert!(
        diag.get("agent_loaded").is_some(),
        "diagnostics should have agent_loaded"
    );

    // For a loaded agent, agent_loaded should be true
    let agent_loaded = diag["agent_loaded"].as_bool();
    assert_eq!(
        agent_loaded,
        Some(true),
        "agent_loaded should be true for a loaded agent"
    );
}

#[test]
fn test_standalone_diagnostics() {
    // The standalone diagnostics() function doesn't require an agent
    let diag = jacs::simple::diagnostics();
    assert!(diag.get("jacs_version").is_some());
    assert!(diag.get("os").is_some());
    assert!(diag.get("arch").is_some());
    assert_eq!(
        diag["agent_loaded"].as_bool(),
        Some(false),
        "standalone diagnostics should show agent_loaded=false"
    );
}

// =============================================================================
// 16. SimpleAgent::is_strict()
// =============================================================================

#[test]
fn test_is_strict_default_false() {
    let (agent, _info) = ephemeral_ed25519();
    // Default strict mode should be false (unless JACS_STRICT_MODE env is set)
    // We don't set it, so it should be false
    assert!(!agent.is_strict(), "default strict mode should be false");
}

// =============================================================================
// 17. SimpleAgent::config_path()
// =============================================================================

#[test]
fn test_config_path_ephemeral_is_none() {
    let (agent, _info) = ephemeral_ed25519();
    assert!(
        agent.config_path().is_none(),
        "ephemeral agent should have no config_path"
    );
}

#[test]
#[serial]
fn test_config_path_persistent_is_some() {
    let tmp = TempDir::new().unwrap();
    let (agent, info) = persistent_agent_in(&tmp, "ed25519");
    let path = agent.config_path();
    assert!(path.is_some(), "persistent agent should have a config_path");
    assert_eq!(
        path.unwrap(),
        info.config_path,
        "config_path should match info.config_path"
    );
}

// =============================================================================
// Integration: Sign-then-verify roundtrip with ed25519
// =============================================================================

#[test]
fn test_sign_verify_roundtrip_ed25519() {
    let (agent, _info) = ephemeral_ed25519();
    let data = json!({"roundtrip": "ed25519", "number": 123});

    let signed = agent.sign_message(&data).expect("sign should succeed");
    let result = agent.verify(&signed.raw).expect("verify should succeed");

    assert!(result.valid, "roundtrip verification should be valid");
    // The data should be recoverable from the verification result
    assert_eq!(
        result.data.get("roundtrip"),
        Some(&json!("ed25519")),
        "verified data should contain original content"
    );
}

// =============================================================================
// Integration: Sign-then-verify roundtrip with RSA
// =============================================================================

#[test]
fn test_sign_verify_roundtrip_rsa() {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("rsa-pss")).expect("ephemeral rsa-pss should succeed");
    let data = json!({"roundtrip": "rsa", "value": true});

    let signed = agent.sign_message(&data).expect("sign should succeed");
    let result = agent.verify(&signed.raw).expect("verify should succeed");

    assert!(result.valid, "RSA roundtrip verification should be valid");
}

// =============================================================================
// Integration: Cross-agent verification (A signs, B verifies with exported key)
// =============================================================================

#[test]
fn test_cross_agent_verification() {
    let (agent_a, _info_a) = ephemeral_ed25519();
    let (agent_b, _info_b) = ephemeral_ed25519();

    // Agent A signs a message
    let signed = agent_a
        .sign_message(&json!({"from": "agent_a", "msg": "hello"}))
        .expect("agent_a sign should succeed");

    // Get agent A's public key
    let pubkey_a = agent_a
        .get_public_key()
        .expect("get_public_key should succeed");

    // Agent B verifies with agent A's key
    let result = agent_b
        .verify_with_key(&signed.raw, pubkey_a)
        .expect("verify_with_key should not error");

    assert!(
        result.valid,
        "agent B should verify agent A's document with agent A's public key"
    );
}

// =============================================================================
// Integration: Sign-then-verify roundtrip with pq2025
// =============================================================================

#[test]
fn test_sign_verify_roundtrip_pq2025() {
    let (agent, _info) = ephemeral_default(); // pq2025
    let data = json!({"roundtrip": "pq2025"});

    let signed = agent.sign_message(&data).expect("sign should succeed");
    let result = agent.verify(&signed.raw).expect("verify should succeed");

    assert!(
        result.valid,
        "pq2025 roundtrip verification should be valid"
    );
}
