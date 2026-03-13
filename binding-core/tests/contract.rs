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

// =============================================================================
// Helper: create an ephemeral wrapper for tests
// =============================================================================

fn create_ephemeral_wrapper() -> AgentWrapper {
    let wrapper = AgentWrapper::new();
    wrapper
        .ephemeral(Some("ed25519"))
        .expect("ephemeral(ed25519) should succeed");
    wrapper
}

fn create_ephemeral_wrapper_rsa() -> AgentWrapper {
    let wrapper = AgentWrapper::new();
    wrapper
        .ephemeral(Some("rsa-pss"))
        .expect("ephemeral(rsa-pss) should succeed");
    wrapper
}

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

#[test]
fn test_create_agent_rsa() {
    let wrapper = AgentWrapper::new();
    let info_json = wrapper
        .ephemeral(Some("rsa-pss"))
        .expect("ephemeral(rsa-pss) should succeed");

    let info: Value = serde_json::from_str(&info_json).unwrap();
    let algo = info["algorithm"].as_str().unwrap_or("");
    assert!(
        algo.contains("RSA") || algo.contains("rsa"),
        "algorithm should be RSA variant, got: {}",
        algo
    );
}

// =============================================================================
// 2. Sign message via AgentWrapper (maps to: sign_message)
// =============================================================================

#[test]
fn test_sign_message_output_has_signature_fields() {
    let wrapper = create_ephemeral_wrapper();

    let content = json!({
        "jacsType": "message",
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
        "jacsType": "message",
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
        "jacsType": "message",
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
fn test_full_roundtrip_create_sign_verify_ed25519() {
    let wrapper = create_ephemeral_wrapper();

    // Sign a document
    let content = json!({
        "jacsType": "message",
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
fn test_full_roundtrip_create_sign_verify_rsa() {
    let wrapper = create_ephemeral_wrapper_rsa();

    let content = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": {"roundtrip": "rsa", "step": 1}
    });

    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature should succeed");
    assert!(valid, "RSA roundtrip should verify successfully");
}

#[test]
fn test_full_roundtrip_create_sign_verify_pq2025() {
    let wrapper = create_ephemeral_wrapper_pq();

    let content = json!({
        "jacsType": "message",
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
