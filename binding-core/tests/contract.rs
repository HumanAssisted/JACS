//! Binding-core contract tests for the SimpleAgent narrow API.
//!
//! These tests mirror the narrow simple contract (Section 4.1.2 of
//! docs/ARCHITECTURE_UPGRADE.md) and verify that AgentWrapper correctly
//! marshals operations through the FFI bridge.
//!
//! ## Mapping: AgentWrapper method -> SimpleAgent narrow contract method
//!
//! | AgentWrapper method         | SimpleAgent narrow contract method |
//! |-----------------------------|-----------------------------------|
//! | ephemeral(algo)             | ephemeral(algorithm)              |
//! | create_document(...)        | sign_message(data) [via agent]    |
//! | verify_signature(doc, None) | verify(signed_document)           |
//! | verify_document(doc)        | verify(signed_document)           |
//! | get_agent_json()            | export_agent()                    |
//! | get_agent_id()              | get_agent_id()                    |
//! | diagnostics()               | diagnostics()                     |
//! | sign_string(data)           | sign_message (low-level)          |
//!
//! ## Extended surface (tested separately below, NOT part of narrow contract):
//! | sign_batch(messages)        | sign_messages_batch (batch)       |
//!
//! Note: Some narrow contract methods (load, create, create_with_params,
//! config_path, is_strict) are not exposed through AgentWrapper because
//! binding-core uses a different lifecycle (new() + load()/ephemeral()).

use jacs_binding_core::AgentWrapper;
use serde_json::{Value, json};
use serial_test::serial;
use std::path::{Path, PathBuf};

struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    fn change_to(path: &Path) -> Self {
        let original = std::env::current_dir().expect("current dir should be available");
        std::env::set_current_dir(path).expect("should change current dir");
        Self { original }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

fn canonical_display(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn assert_same_path(actual: &Value, expected: &Path) {
    let actual_path = actual.as_str().expect("path value should be a string");
    assert_eq!(
        canonical_display(Path::new(actual_path)),
        canonical_display(expected)
    );
}

// =============================================================================
// Helper: create an ephemeral wrapper for tests
// =============================================================================

fn create_ephemeral_wrapper() -> AgentWrapper {
    // New agent creation is PQ-only (P2 Task 001): the "ed25519" request
    // resolves to pq2025 with a WARN. The helper keeps the historical call
    // shape to prove the alias path still succeeds.
    let wrapper = AgentWrapper::new();
    wrapper
        .ephemeral(Some("ed25519"))
        .expect("ephemeral(ed25519) should succeed (resolved to pq2025)");
    wrapper
}

#[test]
#[serial]
fn test_load_with_info_returns_canonical_metadata() {
    let tmp = tempfile::TempDir::new().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();
    let config_dir = tmp_path.join("nested");
    let data_dir = config_dir.join("jacs_data");
    let key_dir = config_dir.join("jacs_keys");
    let config_path = config_dir.join("jacs.config.json");

    let params = jacs::simple::CreateAgentParams::builder()
        .name("binding-agent-wrapper")
        .password("TestP@ss123!#")
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .domain("binding-wrapper.example.com")
        .build();

    let (_agent, created_info) =
        jacs::simple::SimpleAgent::create_with_params(params).expect("create should succeed");

    let _cwd_guard = CwdGuard::change_to(&tmp_path);
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#");
    }

    let wrapper = AgentWrapper::new();
    let info_json = wrapper
        .load_with_info("./nested/jacs.config.json".to_string())
        .expect("load_with_info should succeed");
    let info: Value = serde_json::from_str(&info_json).expect("info should be valid JSON");

    assert_eq!(info["agent_id"], created_info.agent_id);
    assert_eq!(info["version"], created_info.version);
    assert_eq!(info["algorithm"], created_info.algorithm);
    assert_same_path(&info["config_path"], &config_path);
    assert_same_path(&info["data_directory"], &data_dir);
    assert_same_path(&info["key_directory"], &key_dir);

    unsafe {
        std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
    }
}

#[test]
#[serial]
fn test_load_with_info_prefers_wrapper_password_and_restores_process_env() {
    let tmp = tempfile::TempDir::new().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();
    let config_path = tmp_path.join("jacs.config.json");
    let data_dir = tmp_path.join("jacs_data");
    let key_dir = tmp_path.join("jacs_keys");

    let params = jacs::simple::CreateAgentParams::builder()
        .name("binding-password-store")
        .password("CorrectP@ss123!#")
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .domain("binding-password.example.com")
        .build();

    let (_agent, created_info) =
        jacs::simple::SimpleAgent::create_with_params(params).expect("create should succeed");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "WrongEnvP@ss123!#");
    }

    let wrapper = AgentWrapper::new();
    wrapper
        .set_private_key_password(Some("CorrectP@ss123!#".to_string()))
        .expect("setting wrapper password should succeed");

    let info_json = wrapper
        .load_with_info(config_path.to_string_lossy().to_string())
        .expect("load_with_info should succeed with wrapper password");
    let info: Value = serde_json::from_str(&info_json).expect("info should be valid JSON");

    assert_eq!(info["agent_id"], created_info.agent_id);
    assert_eq!(
        std::env::var("JACS_PRIVATE_KEY_PASSWORD").ok().as_deref(),
        Some("WrongEnvP@ss123!#")
    );

    unsafe {
        std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
    }
}

#[cfg(feature = "pq-tests")]
fn create_ephemeral_wrapper_pq() -> AgentWrapper {
    let wrapper = AgentWrapper::new();
    wrapper
        .ephemeral(None) // defaults to pq2025
        .expect("ephemeral(pq2025) should succeed");
    wrapper
}

// =============================================================================
// 1. Create agent via AgentWrapper (maps to: create/ephemeral)
// =============================================================================

#[test]
fn test_create_agent_via_wrapper_valid_json() {
    let wrapper = AgentWrapper::new();
    let info_json = wrapper
        .ephemeral(Some("ed25519"))
        .expect("ephemeral should succeed");

    // The returned string should be valid JSON with agent info
    let info: Value = serde_json::from_str(&info_json).expect("ephemeral should return valid JSON");
    assert!(
        info.get("agent_id").is_some(),
        "agent info should have agent_id"
    );
    let agent_id = info["agent_id"].as_str().unwrap_or("");
    assert!(!agent_id.is_empty(), "agent_id should be non-empty");
    assert!(
        info.get("algorithm").is_some(),
        "agent info should have algorithm"
    );
}

#[cfg(feature = "pq-tests")]
#[test]
fn test_create_agent_pq2025() {
    let wrapper = AgentWrapper::new();
    let info_json = wrapper
        .ephemeral(None)
        .expect("ephemeral(pq2025) should succeed");

    let info: Value = serde_json::from_str(&info_json).unwrap();
    let algo = info["algorithm"].as_str().unwrap_or("");
    assert!(
        algo.contains("pq2025"),
        "default algorithm should be pq2025, got: {}",
        algo
    );
}

// =============================================================================
// P2 Task 001 — new agent creation is PQ-only; rotation always resolves to
// pq2025. Existing Ed25519-rooted agents are grandfathered (load-and-sign),
// which is covered by jacs/tests/config_signing_integration.rs.
// =============================================================================

#[test]
fn new_public_agent_creation_rejects_ed25519_algorithm_selection() {
    // "Rejects" = the selection is not honored: an Ed25519 request resolves
    // to pq2025 (with a WARN) rather than minting a new Ed25519 root.
    let wrapper = AgentWrapper::new();
    let info_json = wrapper
        .ephemeral(Some("ed25519"))
        .expect("ephemeral(ed25519) resolves instead of erroring");
    let info: Value = serde_json::from_str(&info_json).unwrap();
    assert!(
        info["algorithm"].as_str().unwrap_or("").contains("pq2025"),
        "ed25519 request must resolve to pq2025 for NEW agents, got: {}",
        info["algorithm"]
    );
}

#[test]
fn new_public_agent_creation_rejects_es256_algorithm_selection() {
    // ES256 is an ecosystem compatibility key, never a native signing
    // algorithm — creation requests are a typed error.
    let wrapper = AgentWrapper::new();
    for bad in ["es256", "ES256", "ring-ES256"] {
        let err = wrapper
            .ephemeral(Some(bad))
            .expect_err("es256 creation must be rejected");
        assert!(
            err.to_string().contains("pq2025"),
            "error should steer to pq2025, got: {err}"
        );
    }
}

fn create_persistent_wrapper_for_rotation(
    name: &str,
) -> (AgentWrapper, tempfile::TempDir, CwdGuard) {
    let tmp = tempfile::TempDir::new().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();
    let config_path = tmp_path.join("jacs.config.json");

    let params = jacs::simple::CreateAgentParams::builder()
        .name(name)
        .password("TestP@ss123!#")
        .data_directory(tmp_path.join("jacs_data").to_str().unwrap())
        .key_directory(tmp_path.join("jacs_keys").to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .domain("rotation-wall.example.com")
        .build();
    let (_agent, _info) =
        jacs::simple::SimpleAgent::create_with_params(params).expect("create should succeed");

    let guard = CwdGuard::change_to(&tmp_path);
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#");
    }
    let wrapper = AgentWrapper::new();
    wrapper
        .load_with_info(config_path.to_string_lossy().to_string())
        .expect("load should succeed");
    (wrapper, tmp, guard)
}

#[test]
#[serial]
fn create_with_params_returns_pq_root_and_compatibility_key_metadata() {
    // P2 Task 002: creation via params JSON eagerly mints the ES256
    // compat key and surfaces its metadata through AgentInfo.
    let tmp = tempfile::TempDir::new().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();

    let params_json = serde_json::json!({
        "name": "binding-compat-key",
        "password": "TestP@ss123!#",
        "data_directory": tmp_path.join("jacs_data").to_str().unwrap(),
        "key_directory": tmp_path.join("jacs_keys").to_str().unwrap(),
        "config_path": tmp_path.join("jacs.config.json").to_str().unwrap(),
    })
    .to_string();

    let (_wrapper, info_json) =
        jacs_binding_core::SimpleAgentWrapper::create_with_params(&params_json)
            .expect("create with params");
    let info: Value = serde_json::from_str(&info_json).unwrap();
    assert!(
        info["algorithm"].as_str().unwrap_or("").contains("pq2025"),
        "native root is pq2025"
    );
    assert_eq!(info["ecosystem_algorithm"], "ES256");
    assert!(
        !info["ecosystem_kid"].as_str().unwrap_or("").is_empty(),
        "compat kid surfaces through the binding info"
    );
}

#[test]
#[serial]
fn add_compat_key_json_migrates_existing_agent() {
    // P2 Task 002: a pre-P2-style agent (created with the opt-out) gains
    // the compat key only through the explicit migration method.
    let tmp = tempfile::TempDir::new().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();

    let params_json = serde_json::json!({
        "name": "binding-compat-migrate",
        "password": "TestP@ss123!#",
        "data_directory": tmp_path.join("jacs_data").to_str().unwrap(),
        "key_directory": tmp_path.join("jacs_keys").to_str().unwrap(),
        "config_path": tmp_path.join("jacs.config.json").to_str().unwrap(),
        "no_compat_key": true,
    })
    .to_string();

    let (wrapper, info_json) =
        jacs_binding_core::SimpleAgentWrapper::create_with_params(&params_json)
            .expect("create with opt-out");
    let info: Value = serde_json::from_str(&info_json).unwrap();
    assert!(
        info["ecosystem_kid"].as_str().unwrap_or("").is_empty(),
        "opt-out agent starts without a compat key"
    );

    let compat_json = wrapper
        .add_compat_key_json()
        .expect("explicit migration succeeds");
    let compat: Value = serde_json::from_str(&compat_json).unwrap();
    assert_eq!(compat["role"], "ecosystem_signing");
    assert_eq!(compat["algorithm"], "ES256");

    let err = wrapper
        .add_compat_key_json()
        .expect_err("duplicate migration is a typed error");
    assert!(err.to_string().contains("already") || err.to_string().contains("exists"));
    // PRD §9.7: the duplicate guard is a validation failure on existing
    // kinds — never KeyNotFound (the key exists) and never a new variant.
    assert_eq!(
        err.kind,
        jacs_binding_core::ErrorKind::Validation,
        "duplicate compat key must map to Validation, got {:?}",
        err.kind
    );
}

#[test]
#[serial]
fn export_compatibility_jwks_missing_key_maps_to_key_not_found() {
    // PRD §9.7 (Issue 012): a missing ES256 compatibility key surfaces as
    // ErrorKind::KeyNotFound across the binding surface, so Python/Node/Go
    // callers can distinguish "run add-compat-key" from bad input.
    let tmp = tempfile::TempDir::new().unwrap();
    let tmp_path = tmp.path().canonicalize().unwrap();

    let params_json = serde_json::json!({
        "name": "binding-compat-missing-key",
        "password": "TestP@ss123!#",
        "data_directory": tmp_path.join("jacs_data").to_str().unwrap(),
        "key_directory": tmp_path.join("jacs_keys").to_str().unwrap(),
        "config_path": tmp_path.join("jacs.config.json").to_str().unwrap(),
        "no_compat_key": true,
    })
    .to_string();

    let (wrapper, _info_json) =
        jacs_binding_core::SimpleAgentWrapper::create_with_params(&params_json)
            .expect("create with opt-out");

    let err = wrapper
        .export_compatibility_jwks_json()
        .expect_err("agent without compat key cannot export JWKS");
    assert_eq!(
        err.kind,
        jacs_binding_core::ErrorKind::KeyNotFound,
        "missing compat key must map to KeyNotFound, got {:?}: {}",
        err.kind,
        err
    );
    assert!(
        err.to_string().contains("add-compat-key") || err.to_string().contains("add_compat_key"),
        "error should steer to the explicit migration command, got: {err}"
    );
}

#[test]
#[serial]
fn rotate_keys_rejects_ed25519_selection() {
    let (wrapper, _tmp, _guard) = create_persistent_wrapper_for_rotation("rotate-wall-reject");
    for bad in ["ring-Ed25519", "ed25519"] {
        let err = wrapper
            .rotate_keys(Some(bad))
            .expect_err("rotation to Ed25519 must be a typed error");
        assert!(
            err.to_string().contains("pq2025"),
            "rotation error should steer to pq2025, got: {err}"
        );
    }
    unsafe {
        std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
    }
}

#[test]
#[serial]
fn rotate_keys_defaults_to_pq2025() {
    let (wrapper, _tmp, _guard) = create_persistent_wrapper_for_rotation("rotate-wall-default");
    let result_json = wrapper
        .rotate_keys(None)
        .expect("no-argument rotation succeeds and resolves to pq2025");
    let result: Value = serde_json::from_str(&result_json).expect("rotation result JSON");
    assert!(
        result.get("new_version").is_some(),
        "rotation result should carry new_version"
    );
    // The config on disk must be stamped pq2025 after rotation (rotation is
    // the Ed25519->PQ migration path; it never re-mints from config).
    let config: Value =
        serde_json::from_str(&std::fs::read_to_string("./jacs.config.json").expect("read config"))
            .expect("parse config");
    assert_eq!(
        config["jacs_agent_key_algorithm"].as_str(),
        Some("pq2025"),
        "rotation must stamp the config algorithm to pq2025"
    );
    unsafe {
        std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
    }
}

// =============================================================================
// 2. Sign message via AgentWrapper (maps to: sign_message)
// =============================================================================

#[test]
fn test_sign_message_output_has_signature_fields() {
    let wrapper = create_ephemeral_wrapper();

    let content = json!({
        "jacsType": "document",
        "jacsLevel": "raw",
        "content": {"action": "test", "value": 42}
    });

    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    assert!(!signed.is_empty(), "signed document should not be empty");

    let parsed: Value =
        serde_json::from_str(&signed).expect("signed document should be valid JSON");

    // Should have JACS signature fields
    assert!(
        parsed.get("jacsSignature").is_some(),
        "signed document should have jacsSignature"
    );
    assert!(
        parsed.get("jacsId").is_some() || parsed.get("id").is_some(),
        "signed document should have an ID field"
    );
}

// =============================================================================
// 3. Verify signed message via AgentWrapper (maps to: verify)
// =============================================================================

#[test]
fn test_verify_valid_returns_success() {
    let wrapper = create_ephemeral_wrapper();

    let content = json!({
        "jacsType": "document",
        "jacsLevel": "raw",
        "content": {"hello": "verify-test"}
    });

    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature should succeed");
    assert!(valid, "valid document should verify successfully");
}

// =============================================================================
// 4. Verify rejects tampered message (maps to: verify)
// =============================================================================

#[test]
fn test_verify_rejects_tampered() {
    let wrapper = create_ephemeral_wrapper();

    let content = json!({
        "jacsType": "document",
        "jacsLevel": "raw",
        "content": {"original": true}
    });

    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    // Tamper with the content
    let mut parsed: Value = serde_json::from_str(&signed).unwrap();
    if let Some(content_field) = parsed.get_mut("content") {
        *content_field = json!({"original": false, "tampered": true});
    }
    let tampered = serde_json::to_string(&parsed).unwrap();

    // Verification should fail
    let result = wrapper.verify_document(&tampered);
    assert!(
        result.is_err(),
        "tampered document should fail verification"
    );
}

#[test]
fn test_verify_rejects_garbage() {
    let wrapper = create_ephemeral_wrapper();
    let result = wrapper.verify_document("not-valid-json");
    assert!(result.is_err(), "garbage input should fail verification");
}

// =============================================================================
// 5. Export agent via AgentWrapper (maps to: export_agent)
// =============================================================================

#[test]
fn test_export_agent_json_valid() {
    let wrapper = create_ephemeral_wrapper();
    let agent_json = wrapper
        .get_agent_json()
        .expect("get_agent_json should succeed");

    assert!(!agent_json.is_empty(), "agent JSON should not be empty");

    let parsed: Value = serde_json::from_str(&agent_json).expect("agent JSON should be valid JSON");
    assert!(
        parsed.get("jacsId").is_some(),
        "agent JSON should have jacsId"
    );
    assert!(
        parsed.get("jacsSignature").is_some(),
        "agent JSON should have jacsSignature (it's a signed agent document)"
    );
}

// =============================================================================
// 6. Get agent ID via AgentWrapper (maps to: get_agent_id)
// =============================================================================

#[test]
fn test_get_agent_id_non_empty() {
    let wrapper = create_ephemeral_wrapper();
    let agent_id = wrapper.get_agent_id().expect("get_agent_id should succeed");
    assert!(!agent_id.is_empty(), "agent_id should be non-empty");
}

#[test]
fn test_get_agent_id_consistent_with_ephemeral_info() {
    let wrapper = AgentWrapper::new();
    let info_json = wrapper
        .ephemeral(Some("ed25519"))
        .expect("ephemeral should succeed");

    let info: Value = serde_json::from_str(&info_json).unwrap();
    let info_agent_id = info["agent_id"].as_str().unwrap_or("");

    let wrapper_agent_id = wrapper.get_agent_id().expect("get_agent_id should succeed");

    assert_eq!(
        info_agent_id, wrapper_agent_id,
        "agent_id from ephemeral info should match get_agent_id()"
    );
}

// =============================================================================
// 7. Diagnostics via AgentWrapper (maps to: diagnostics)
// =============================================================================

#[test]
fn test_diagnostics_returns_json_with_expected_keys() {
    let wrapper = create_ephemeral_wrapper();
    let diag_str = wrapper.diagnostics();

    assert!(!diag_str.is_empty(), "diagnostics should not be empty");

    let diag: Value = serde_json::from_str(&diag_str).expect("diagnostics should be valid JSON");

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

    // For a loaded ephemeral agent, agent_loaded should be true
    assert_eq!(
        diag["agent_loaded"].as_bool(),
        Some(true),
        "agent_loaded should be true for loaded agent"
    );
}

#[test]
fn test_diagnostics_standalone_returns_valid_json() {
    let diag_str = jacs_binding_core::diagnostics_standalone();
    assert!(!diag_str.is_empty());
    let diag: Value =
        serde_json::from_str(&diag_str).expect("standalone diagnostics should be valid JSON");
    assert!(diag.get("jacs_version").is_some());
    assert_eq!(
        diag["agent_loaded"].as_bool(),
        Some(false),
        "standalone diagnostics should show agent_loaded=false"
    );
}

// =============================================================================
// 8. Full roundtrip: create -> sign -> verify (integration)
// =============================================================================

#[test]
fn test_full_roundtrip_create_sign_verify_ed25519_alias() {
    let wrapper = create_ephemeral_wrapper();

    // Sign a document
    let content = json!({
        "jacsType": "document",
        "jacsLevel": "raw",
        "content": {"roundtrip": "ed25519", "step": 1}
    });

    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    // Verify via verify_signature
    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature should succeed");
    assert!(valid, "roundtrip document should verify successfully");
}

#[test]
fn test_full_roundtrip_create_sign_verify_ed25519() {
    let wrapper = AgentWrapper::new();
    wrapper
        .ephemeral(Some("ed25519"))
        .expect("ephemeral(ed25519) should succeed");
    let signed = wrapper
        .create_document(
            &serde_json::json!({"curve": "ed25519"}).to_string(),
            None,
            None,
            true,
            None,
            None,
        )
        .expect("create_document should succeed");
    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature should succeed");
    assert!(valid, "ed25519 roundtrip document should verify");
}

#[cfg(feature = "pq-tests")]
#[test]
fn test_full_roundtrip_create_sign_verify_pq2025() {
    let wrapper = create_ephemeral_wrapper_pq();

    let content = json!({
        "jacsType": "document",
        "jacsLevel": "raw",
        "content": {"roundtrip": "pq2025", "step": 1}
    });

    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature should succeed");
    assert!(valid, "pq2025 roundtrip should verify successfully");
}

// =============================================================================
// 9. Sign string (low-level, maps to: sign_message at string level)
// =============================================================================

#[test]
fn test_sign_string_returns_non_empty() {
    let wrapper = create_ephemeral_wrapper();
    let sig = wrapper
        .sign_string("hello world")
        .expect("sign_string should succeed");
    assert!(!sig.is_empty(), "signature should be non-empty");
}

#[test]
fn test_sign_string_different_data_different_sigs() {
    let wrapper = create_ephemeral_wrapper();
    let sig1 = wrapper.sign_string("message one").unwrap();
    let sig2 = wrapper.sign_string("message two").unwrap();
    assert_ne!(
        sig1, sig2,
        "different messages should produce different signatures"
    );
}

// =============================================================================
// 10. Batch signing — EXTENDED SURFACE (not part of narrow contract)
//
// sign_batch/sign_messages_batch will move off SimpleAgent in TASK_030-032.
// These tests verify binding-core's current behavior but are NOT part of
// the narrow contract baseline. A future removal of sign_batch from
// AgentWrapper is expected and should not be treated as a regression.
// =============================================================================

#[test]
fn test_sign_batch_returns_correct_count() {
    let wrapper = create_ephemeral_wrapper();
    let messages = vec![
        "batch-msg-1".to_string(),
        "batch-msg-2".to_string(),
        "batch-msg-3".to_string(),
    ];
    let sigs = wrapper
        .sign_batch(messages.clone())
        .expect("sign_batch should succeed");
    assert_eq!(
        sigs.len(),
        messages.len(),
        "should return one signature per message"
    );
    for sig in &sigs {
        assert!(!sig.is_empty(), "each signature should be non-empty");
    }
}

#[test]
fn test_sign_batch_empty_input() {
    let wrapper = create_ephemeral_wrapper();
    let sigs = wrapper
        .sign_batch(vec![])
        .expect("sign_batch with empty input should succeed");
    assert!(sigs.is_empty(), "empty input should return empty output");
}

// =============================================================================
// 11. Agent not loaded guard
// =============================================================================

#[test]
fn test_get_agent_id_before_load_fails() {
    let wrapper = AgentWrapper::new();
    // No ephemeral() or load() called — agent is not loaded
    let result = wrapper.get_agent_id();
    assert!(
        result.is_err(),
        "get_agent_id should fail when agent is not loaded"
    );
}

#[test]
fn test_get_agent_json_before_load_fails() {
    let wrapper = AgentWrapper::new();
    let result = wrapper.get_agent_json();
    assert!(
        result.is_err(),
        "get_agent_json should fail when agent is not loaded"
    );
}

// =============================================================================
// 12. P2 Task 006 — surface guardrails: no generic projection surface.
//
// P2 ships ONLY named, targeted exporters (JWKS, compat key binding, A2A
// card, AP2 mandate, Agreement-v2 VC). These source-scan tests (same
// include_str! pattern as agreement_v2_json.rs) prove the old broad
// "project any document into any envelope/algorithm" design did not creep
// back onto the public binding surface. Source scan is feature-independent:
// cfg(a2a) / cfg(agreements) methods are visible in the raw source.
// =============================================================================

const SIMPLE_WRAPPER_SRC: &str = include_str!("../src/simple_wrapper.rs");

#[test]
fn simple_wrapper_has_no_generic_sign_jws_method() {
    assert!(
        !SIMPLE_WRAPPER_SRC.contains("fn sign_jws"),
        "SimpleAgentWrapper must not expose a generic sign_jws method; \
         ES256 JWS signing is internal (pub(crate) sign_es256_jose) and \
         only reachable through the named exporters"
    );
}

#[test]
fn simple_wrapper_has_no_generic_sign_es256_method() {
    for forbidden in ["fn sign_es256", "fn sign_with_algorithm"] {
        assert!(
            !SIMPLE_WRAPPER_SRC.contains(forbidden),
            "SimpleAgentWrapper must not expose `{forbidden}`; the ES256 \
             compatibility key never signs arbitrary caller-chosen payloads"
        );
    }
}

#[test]
fn simple_wrapper_has_no_generic_sign_data_integrity_method() {
    for forbidden in [
        "fn sign_data_integrity",
        "fn issue_w3c_vc",
        "fn export_dsse_document",
    ] {
        assert!(
            !SIMPLE_WRAPPER_SRC.contains(forbidden),
            "SimpleAgentWrapper must not expose `{forbidden}`; Data \
             Integrity / VC / DSSE projections exist only as the named, \
             scope-gated exporters"
        );
    }
}

/// Extract every `pub fn` in simple_wrapper.rs as `(name, [param names])`,
/// handling multi-line parameter lists.
fn simple_wrapper_public_fn_signatures() -> Vec<(String, Vec<String>)> {
    let src = SIMPLE_WRAPPER_SRC;
    let mut signatures = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = src[cursor..].find("pub fn ") {
        let name_start = cursor + rel + "pub fn ".len();
        let rest = &src[name_start..];
        let open = rest.find('(').expect("pub fn should have a parameter list");
        let name = rest[..open]
            .split('<')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();

        // Walk to the matching close paren (param types may nest parens).
        let mut depth = 0usize;
        let mut close = open;
        for (i, c) in rest[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(close > open, "unbalanced parameter list for pub fn {name}");

        let params: Vec<String> = rest[open + 1..close]
            .split(',')
            .filter_map(|piece| piece.split_once(':'))
            .map(|(param, _ty)| param.trim().trim_start_matches("mut ").trim().to_string())
            .filter(|param| {
                !param.is_empty() && param.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
            .collect();

        signatures.push((name, params));
        cursor = name_start + close;
    }
    assert!(
        signatures.len() > 30,
        "source scan should see the full SimpleAgentWrapper surface, found only {}",
        signatures.len()
    );
    signatures
}

#[test]
fn no_public_method_accepts_arbitrary_document_plus_algorithm_or_suite() {
    // A method that takes BOTH a document/JSON payload AND an
    // algorithm/cryptosuite selector is the generic-projection shape P2
    // deliberately closed (callers must not choose the envelope). Methods
    // may take one or the other: rotate_keys/create/ephemeral take an
    // algorithm but no document; sign_message_json takes a document but
    // no algorithm; verify_with_key_json takes a document + key but no
    // algorithm selector today.
    //
    // Exemptions:
    // - verify_* methods: an algorithm parameter for VERIFICATION does
    //   not let a caller mint signatures, so it is allowed.
    // - ALLOWLIST: any future deliberate exception must be named here
    //   with a justification (currently empty).
    const ALLOWLIST: [&str; 0] = [];

    let doc_like = |param: &str| {
        ["document", "json", "payload", "data", "content", "message"]
            .iter()
            .any(|marker| param.contains(marker))
    };
    let algorithm_like = |param: &str| {
        param.contains("algorithm")
            || param.contains("suite")
            || param.split('_').any(|segment| segment == "alg")
    };

    let violations: Vec<String> = simple_wrapper_public_fn_signatures()
        .into_iter()
        .filter(|(name, _)| !name.starts_with("verify") && !ALLOWLIST.contains(&name.as_str()))
        .filter(|(_, params)| {
            params.iter().any(|p| doc_like(p)) && params.iter().any(|p| algorithm_like(p))
        })
        .map(|(name, params)| format!("pub fn {name}({})", params.join(", ")))
        .collect();

    assert!(
        violations.is_empty(),
        "generic projection surface detected on SimpleAgentWrapper — a public \
         method takes BOTH a document/JSON payload AND an algorithm/cryptosuite \
         selector. Either remove the method or add it to the ALLOWLIST in this \
         test with a written justification:\n{}",
        violations.join("\n")
    );
}

#[test]
fn named_targeted_export_methods_exist() {
    // The narrow P2 surface: these exact named exporters, nothing broader.
    // export_a2a_agent_card_json (cfg a2a) and export_agreement_v2_as_vc_json
    // (cfg agreements) are checked via source scan so this test passes under
    // any feature combination.
    for method in [
        "pub fn add_compat_key_json",
        "pub fn export_compatibility_jwks_json",
        "pub fn export_compatibility_key_binding_json",
        "pub fn export_ap2_mandate_json",
        "pub fn export_a2a_agent_card_json",
        "pub fn export_agreement_v2_as_vc_json",
    ] {
        assert!(
            SIMPLE_WRAPPER_SRC.contains(method),
            "named targeted exporter `{method}` is missing from \
             SimpleAgentWrapper — P2 exports must stay named, not generic"
        );
    }
}
