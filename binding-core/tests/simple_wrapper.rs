//! Tests for `SimpleAgentWrapper` — the narrow-contract FFI adapter.
//!
//! These tests verify that `SimpleAgentWrapper` correctly wraps
//! `jacs::simple::SimpleAgent` with FFI-safe marshaling (String in/out,
//! `BindingResult` errors). Zero business logic — pure delegation.

use jacs_binding_core::{BindingCoreError, SimpleAgentWrapper};
use serde_json::{Value, json};

// =============================================================================
// Helper
// =============================================================================

fn ephemeral_wrapper() -> SimpleAgentWrapper {
    let (wrapper, _info) =
        SimpleAgentWrapper::ephemeral(Some("ed25519")).expect("ephemeral should succeed");
    wrapper
}

// =============================================================================
// 1. SimpleAgentWrapper::create()
// =============================================================================

#[test]
fn test_create_returns_wrapper_and_info_json() {
    let tmp = tempfile::TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#");
        std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "agent.private.pem.enc");
        std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "agent.public.pem");
    }

    let result = SimpleAgentWrapper::create("test-agent", None, Some("ed25519"));
    std::env::set_current_dir(&original_dir).unwrap();

    unsafe {
        std::env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
        std::env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
    }

    let (wrapper, info_json) = result.expect("create should succeed");

    // info_json should be valid JSON with agent_id
    let info: Value = serde_json::from_str(&info_json).expect("info should be valid JSON");
    assert!(
        info.get("agent_id").is_some(),
        "info should contain agent_id"
    );
    assert!(
        !info["agent_id"].as_str().unwrap_or("").is_empty(),
        "agent_id should be non-empty"
    );

    // Wrapper should be usable
    let signed = wrapper.sign_message_json(r#"{"test": true}"#);
    assert!(signed.is_ok(), "wrapper from create should be able to sign");
}

// =============================================================================
// 2. SimpleAgentWrapper::load() roundtrips with create
// =============================================================================

#[test]
fn test_load_roundtrips_with_create() {
    // Use unique key filenames to avoid env var pollution from parallel tests.
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = jacs::simple::CreateAgentParams::builder()
        .name("load-test")
        .password("TestP@ss123!#")
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .build();

    let (_agent, _info) =
        jacs::simple::SimpleAgent::create_with_params(params).expect("create should succeed");

    // Set env vars only for the load step (load reads them for key/data dirs).
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#");
        std::env::set_var("JACS_DATA_DIRECTORY", data_dir.to_str().unwrap());
        std::env::set_var("JACS_KEY_DIRECTORY", key_dir.to_str().unwrap());
    }

    let wrapper = SimpleAgentWrapper::load(Some(config_path.to_str().unwrap()), None)
        .expect("load should succeed");

    // Clean up env vars immediately.
    unsafe {
        std::env::remove_var("JACS_DATA_DIRECTORY");
        std::env::remove_var("JACS_KEY_DIRECTORY");
    }

    let diag = wrapper.diagnostics();
    let diag_value: Value = serde_json::from_str(&diag).expect("diagnostics should be JSON");
    assert_eq!(diag_value["agent_loaded"], true);
}

// =============================================================================
// 3. SimpleAgentWrapper::ephemeral()
// =============================================================================

#[test]
fn test_ephemeral_creates_wrapper() {
    let (wrapper, info_json) =
        SimpleAgentWrapper::ephemeral(Some("ed25519")).expect("ephemeral should succeed");

    let info: Value = serde_json::from_str(&info_json).expect("info should be valid JSON");
    assert!(!info["agent_id"].as_str().unwrap_or("").is_empty());

    // Should be usable for signing
    let signed = wrapper.sign_message_json(r#"{"ephemeral": true}"#);
    assert!(signed.is_ok());
}

#[test]
fn test_ephemeral_default_algorithm() {
    let (wrapper, info_json) =
        SimpleAgentWrapper::ephemeral(None).expect("ephemeral(None) should succeed");

    let info: Value = serde_json::from_str(&info_json).expect("info should be valid JSON");
    assert!(
        info["algorithm"].as_str().unwrap_or("").contains("pq2025"),
        "default should be pq2025"
    );

    let signed = wrapper.sign_message_json(r#"{"pq": true}"#);
    assert!(signed.is_ok());
}

// =============================================================================
// 4. sign_message + verify roundtrip
// =============================================================================

#[test]
fn test_sign_message_json_and_verify_roundtrip() {
    let wrapper = ephemeral_wrapper();
    let data = r#"{"action": "test", "value": 42}"#;

    let signed_json = wrapper
        .sign_message_json(data)
        .expect("sign_message_json should succeed");

    // signed_json should be a valid JSON string
    let signed: Value =
        serde_json::from_str(&signed_json).expect("signed output should be valid JSON");
    assert!(signed.get("jacsSignature").is_some());

    // Verify the signed document
    let verify_json = wrapper
        .verify_json(&signed_json)
        .expect("verify_json should succeed");
    let result: Value =
        serde_json::from_str(&verify_json).expect("verify result should be valid JSON");
    assert_eq!(result["valid"], true, "verification should succeed");
}

// =============================================================================
// 5. export_agent
// =============================================================================

#[test]
fn test_export_agent_returns_valid_json() {
    let wrapper = ephemeral_wrapper();
    let exported = wrapper.export_agent().expect("export_agent should succeed");

    let parsed: Value =
        serde_json::from_str(&exported).expect("exported agent should be valid JSON");
    assert!(parsed.get("jacsId").is_some(), "should have jacsId");
}

// =============================================================================
// 6. get_public_key_pem
// =============================================================================

#[test]
fn test_get_public_key_pem_returns_pem() {
    let wrapper = ephemeral_wrapper();
    let pem = wrapper
        .get_public_key_pem()
        .expect("get_public_key_pem should succeed");

    assert!(!pem.is_empty());
    assert!(
        pem.contains("-----BEGIN") || pem.contains("PUBLIC KEY"),
        "should be PEM format"
    );
}

// =============================================================================
// 7. diagnostics
// =============================================================================

#[test]
fn test_diagnostics_returns_json() {
    let wrapper = ephemeral_wrapper();
    let diag = wrapper.diagnostics();

    let parsed: Value = serde_json::from_str(&diag).expect("diagnostics should be valid JSON");
    assert!(parsed.get("jacs_version").is_some());
    assert_eq!(parsed["agent_loaded"], true);
}

// =============================================================================
// 8. Thread safety: Send + Sync
// =============================================================================

#[test]
fn test_simple_agent_wrapper_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SimpleAgentWrapper>();
}

// =============================================================================
// 9. get_agent_id
// =============================================================================

#[test]
fn test_get_agent_id() {
    let wrapper = ephemeral_wrapper();
    let agent_id = wrapper.get_agent_id().expect("get_agent_id should succeed");
    assert!(!agent_id.is_empty());
}

// =============================================================================
// 10. get_public_key (raw bytes as base64)
// =============================================================================

#[test]
fn test_get_public_key_returns_base64() {
    let wrapper = ephemeral_wrapper();
    let key_b64 = wrapper
        .get_public_key_base64()
        .expect("get_public_key_base64 should succeed");
    assert!(!key_b64.is_empty());

    // Should be valid base64
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&key_b64)
        .expect("should be valid base64");
    assert!(!decoded.is_empty(), "decoded key should be non-empty");
}

// =============================================================================
// 11. verify_self
// =============================================================================

#[test]
fn test_verify_self() {
    let wrapper = ephemeral_wrapper();
    let result_json = wrapper.verify_self().expect("verify_self should succeed");
    let result: Value =
        serde_json::from_str(&result_json).expect("verify_self result should be JSON");
    assert_eq!(result["valid"], true);
}

// =============================================================================
// 12. key_id
// =============================================================================

#[test]
fn test_key_id() {
    let wrapper = ephemeral_wrapper();
    let kid = wrapper.key_id().expect("key_id should succeed");
    assert!(!kid.is_empty());
}

// =============================================================================
// 13. is_strict and config_path
// =============================================================================

#[test]
fn test_is_strict_default() {
    let wrapper = ephemeral_wrapper();
    assert!(!wrapper.is_strict());
}

#[test]
fn test_config_path_ephemeral() {
    let wrapper = ephemeral_wrapper();
    assert!(wrapper.config_path().is_none());
}

// =============================================================================
// 14. sign_raw_bytes
// =============================================================================

#[test]
fn test_sign_raw_bytes() {
    let wrapper = ephemeral_wrapper();
    let sig_b64 = wrapper
        .sign_raw_bytes_base64(b"hello world")
        .expect("sign_raw_bytes_base64 should succeed");
    assert!(!sig_b64.is_empty());

    // Should be valid base64
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&sig_b64)
        .expect("signature should be valid base64");
}

// =============================================================================
// 15. JSON helper for Go FFI
// =============================================================================

#[test]
fn test_sign_message_json_ffi() {
    let wrapper = ephemeral_wrapper();
    let signed = jacs_binding_core::sign_message_json(&wrapper, r#"{"go_ffi": true}"#)
        .expect("sign_message_json should succeed");
    let parsed: Value = serde_json::from_str(&signed).expect("should be valid JSON");
    assert!(parsed.get("jacsSignature").is_some());
}
