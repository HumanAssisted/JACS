//! Parity tests for the SimpleAgentWrapper narrow contract.
//!
//! These tests define the *reference behavior* that ALL language bindings
//! (Python/PyO3, Node/NAPI, Go/CGo) must match. They use shared fixture
//! inputs from `tests/fixtures/parity_inputs.json` and verify:
//!
//! 1. **Structural parity**: signed documents contain the same field names/types
//! 2. **Cross-verify parity**: a document signed by one algorithm can be verified
//! 3. **Roundtrip parity**: sign -> verify succeeds for all fixture inputs
//! 4. **Error parity**: all bindings reject the same invalid inputs
//!
//! Note: Exact crypto output bytes differ per invocation (nonce/randomness),
//! so we verify structure and verifiability, not byte-equality.

use base64::Engine;
use jacs_binding_core::SimpleAgentWrapper;
use serde_json::Value;

// =============================================================================
// Load shared fixtures
// =============================================================================

fn load_parity_inputs() -> Value {
    let fixture_bytes = include_bytes!("fixtures/parity_inputs.json");
    serde_json::from_slice(fixture_bytes).expect("parity_inputs.json should be valid JSON")
}

fn ephemeral(algo: &str) -> SimpleAgentWrapper {
    let (wrapper, _info) =
        SimpleAgentWrapper::ephemeral(Some(algo)).expect("ephemeral should succeed");
    wrapper
}

// =============================================================================
// 1. Structural parity: signed documents have required fields
// =============================================================================

#[test]
fn test_parity_signed_document_structure_ed25519() {
    parity_signed_document_structure("ed25519");
}

#[test]
fn test_parity_signed_document_structure_pq2025() {
    parity_signed_document_structure("pq2025");
}

fn parity_signed_document_structure(algo: &str) {
    let fixtures = load_parity_inputs();
    let wrapper = ephemeral(algo);
    let required_top = &fixtures["expected_signed_document_fields"]["required_top_level"];
    let required_sig = &fixtures["expected_signed_document_fields"]["required_signature_fields"];

    for input in fixtures["sign_message_inputs"].as_array().unwrap() {
        let name = input["name"].as_str().unwrap();
        let data = &input["data"];
        let data_json = serde_json::to_string(data).unwrap();

        let signed_json = wrapper
            .sign_message_json(&data_json)
            .unwrap_or_else(|e| panic!("[{}] sign_message_json failed for '{}': {}", algo, name, e));

        let signed: Value = serde_json::from_str(&signed_json)
            .unwrap_or_else(|e| panic!("[{}] signed output for '{}' is not valid JSON: {}", algo, name, e));

        // Check required top-level fields
        for field in required_top.as_array().unwrap() {
            let field_name = field.as_str().unwrap();
            assert!(
                signed.get(field_name).is_some(),
                "[{}] signed document for '{}' missing required field '{}'",
                algo,
                name,
                field_name
            );
        }

        // Check required signature fields
        let sig_obj = signed
            .get("jacsSignature")
            .expect("jacsSignature should exist");
        for field in required_sig.as_array().unwrap() {
            let field_name = field.as_str().unwrap();
            assert!(
                sig_obj.get(field_name).is_some(),
                "[{}] jacsSignature for '{}' missing required field '{}'",
                algo,
                name,
                field_name
            );
        }
    }
}

// =============================================================================
// 2. Roundtrip parity: sign -> verify succeeds for all fixture inputs
// =============================================================================

#[test]
fn test_parity_sign_verify_roundtrip_ed25519() {
    parity_sign_verify_roundtrip("ed25519");
}

#[test]
fn test_parity_sign_verify_roundtrip_pq2025() {
    parity_sign_verify_roundtrip("pq2025");
}

fn parity_sign_verify_roundtrip(algo: &str) {
    let fixtures = load_parity_inputs();
    let wrapper = ephemeral(algo);

    for input in fixtures["sign_message_inputs"].as_array().unwrap() {
        let name = input["name"].as_str().unwrap();
        let data = &input["data"];
        let data_json = serde_json::to_string(data).unwrap();

        let signed_json = wrapper
            .sign_message_json(&data_json)
            .unwrap_or_else(|e| panic!("[{}] sign failed for '{}': {}", algo, name, e));

        let verify_result_json = wrapper
            .verify_json(&signed_json)
            .unwrap_or_else(|e| panic!("[{}] verify failed for '{}': {}", algo, name, e));

        let result: Value = serde_json::from_str(&verify_result_json)
            .expect("verify result should be valid JSON");

        assert_eq!(
            result["valid"], true,
            "[{}] roundtrip verification failed for '{}'",
            algo, name
        );
    }
}

// =============================================================================
// 3. Cross-algorithm verify: sign with ed25519, verify structure is consistent
// =============================================================================

#[test]
fn test_parity_cross_algorithm_structure_consistency() {
    let fixtures = load_parity_inputs();
    let input = &fixtures["sign_message_inputs"][0]; // simple_message
    let data_json = serde_json::to_string(&input["data"]).unwrap();

    let ed_wrapper = ephemeral("ed25519");
    let pq_wrapper = ephemeral("pq2025");

    let ed_signed: Value = serde_json::from_str(
        &ed_wrapper.sign_message_json(&data_json).unwrap(),
    )
    .unwrap();

    let pq_signed: Value = serde_json::from_str(
        &pq_wrapper.sign_message_json(&data_json).unwrap(),
    )
    .unwrap();

    // Both should have the same top-level field names (structure parity)
    let ed_keys: Vec<&str> = ed_signed
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    let pq_keys: Vec<&str> = pq_signed
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();

    // Both should have jacsId and jacsSignature at minimum
    assert!(
        ed_keys.contains(&"jacsId"),
        "ed25519 signed doc should have jacsId"
    );
    assert!(
        pq_keys.contains(&"jacsId"),
        "pq2025 signed doc should have jacsId"
    );
    assert!(
        ed_keys.contains(&"jacsSignature"),
        "ed25519 signed doc should have jacsSignature"
    );
    assert!(
        pq_keys.contains(&"jacsSignature"),
        "pq2025 signed doc should have jacsSignature"
    );

    // Signature objects should have the same field names
    let ed_sig_keys: std::collections::BTreeSet<&str> = ed_signed["jacsSignature"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    let pq_sig_keys: std::collections::BTreeSet<&str> = pq_signed["jacsSignature"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();

    assert_eq!(
        ed_sig_keys, pq_sig_keys,
        "jacsSignature fields should be identical across algorithms"
    );
}

// =============================================================================
// 4. Verify with explicit key parity
// =============================================================================

#[test]
fn test_parity_verify_with_key_ed25519() {
    parity_verify_with_key("ed25519");
}

#[test]
fn test_parity_verify_with_key_pq2025() {
    parity_verify_with_key("pq2025");
}

fn parity_verify_with_key(algo: &str) {
    let fixtures = load_parity_inputs();
    let wrapper = ephemeral(algo);
    let key_b64 = wrapper.get_public_key_base64().unwrap();

    let input = &fixtures["sign_message_inputs"][0];
    let data_json = serde_json::to_string(&input["data"]).unwrap();

    let signed_json = wrapper.sign_message_json(&data_json).unwrap();

    let result_json = wrapper
        .verify_with_key_json(&signed_json, &key_b64)
        .unwrap_or_else(|e| panic!("[{}] verify_with_key failed: {}", algo, e));

    let result: Value = serde_json::from_str(&result_json).unwrap();
    assert_eq!(
        result["valid"], true,
        "[{}] verify with explicit key should succeed",
        algo
    );
}

// =============================================================================
// 5. Sign raw bytes parity
// =============================================================================

#[test]
fn test_parity_sign_raw_bytes_ed25519() {
    parity_sign_raw_bytes("ed25519");
}

#[test]
fn test_parity_sign_raw_bytes_pq2025() {
    parity_sign_raw_bytes("pq2025");
}

fn parity_sign_raw_bytes(algo: &str) {
    let fixtures = load_parity_inputs();
    let wrapper = ephemeral(algo);

    for input in fixtures["sign_raw_bytes_inputs"].as_array().unwrap() {
        let name = input["name"].as_str().unwrap();
        let data_b64 = input["data_base64"].as_str().unwrap();
        let data_bytes = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .unwrap_or_else(|e| panic!("fixture '{}' has invalid base64: {}", name, e));

        let sig_b64 = wrapper
            .sign_raw_bytes_base64(&data_bytes)
            .unwrap_or_else(|e| panic!("[{}] sign_raw_bytes failed for '{}': {}", algo, name, e));

        // Result should be valid base64
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap_or_else(|e| {
                panic!(
                    "[{}] sign_raw_bytes result for '{}' is not valid base64: {}",
                    algo, name, e
                )
            });
        assert!(
            !sig_bytes.is_empty(),
            "[{}] signature for '{}' should be non-empty",
            algo,
            name
        );
    }
}

// =============================================================================
// 6. Identity parity: agent_id, key_id, public_key, diagnostics
// =============================================================================

#[test]
fn test_parity_identity_methods_ed25519() {
    parity_identity_methods("ed25519");
}

#[test]
fn test_parity_identity_methods_pq2025() {
    parity_identity_methods("pq2025");
}

fn parity_identity_methods(algo: &str) {
    let wrapper = ephemeral(algo);

    // get_agent_id: non-empty string
    let agent_id = wrapper
        .get_agent_id()
        .unwrap_or_else(|e| panic!("[{}] get_agent_id failed: {}", algo, e));
    assert!(
        !agent_id.is_empty(),
        "[{}] agent_id should be non-empty",
        algo
    );

    // key_id: non-empty string
    let key_id = wrapper
        .key_id()
        .unwrap_or_else(|e| panic!("[{}] key_id failed: {}", algo, e));
    assert!(!key_id.is_empty(), "[{}] key_id should be non-empty", algo);

    // get_public_key_pem: valid PEM
    let pem = wrapper
        .get_public_key_pem()
        .unwrap_or_else(|e| panic!("[{}] get_public_key_pem failed: {}", algo, e));
    assert!(
        pem.contains("-----BEGIN") || pem.contains("PUBLIC KEY"),
        "[{}] should return PEM format",
        algo
    );

    // get_public_key_base64: valid base64
    let key_b64 = wrapper
        .get_public_key_base64()
        .unwrap_or_else(|e| panic!("[{}] get_public_key_base64 failed: {}", algo, e));
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&key_b64)
        .unwrap_or_else(|e| panic!("[{}] public key base64 is invalid: {}", algo, e));
    assert!(
        !decoded.is_empty(),
        "[{}] decoded public key should be non-empty",
        algo
    );

    // export_agent: valid JSON with jacsId
    let exported = wrapper
        .export_agent()
        .unwrap_or_else(|e| panic!("[{}] export_agent failed: {}", algo, e));
    let parsed: Value = serde_json::from_str(&exported)
        .unwrap_or_else(|e| panic!("[{}] export_agent output is not JSON: {}", algo, e));
    assert!(
        parsed.get("jacsId").is_some(),
        "[{}] exported agent should have jacsId",
        algo
    );

    // diagnostics: valid JSON with expected keys
    let diag = wrapper.diagnostics();
    let diag_v: Value = serde_json::from_str(&diag)
        .unwrap_or_else(|e| panic!("[{}] diagnostics is not JSON: {}", algo, e));
    assert!(
        diag_v.get("jacs_version").is_some(),
        "[{}] diagnostics should have jacs_version",
        algo
    );
    assert_eq!(
        diag_v["agent_loaded"], true,
        "[{}] diagnostics should show agent_loaded=true",
        algo
    );

    // verify_self: should succeed
    let self_result_json = wrapper
        .verify_self()
        .unwrap_or_else(|e| panic!("[{}] verify_self failed: {}", algo, e));
    let self_result: Value = serde_json::from_str(&self_result_json)
        .unwrap_or_else(|e| panic!("[{}] verify_self result is not JSON: {}", algo, e));
    assert_eq!(
        self_result["valid"], true,
        "[{}] verify_self should be valid",
        algo
    );

    // is_strict: ephemeral agents default to non-strict
    assert!(
        !wrapper.is_strict(),
        "[{}] ephemeral agent should not be strict",
        algo
    );

    // config_path: ephemeral has no config
    assert!(
        wrapper.config_path().is_none(),
        "[{}] ephemeral agent should have no config_path",
        algo
    );
}

// =============================================================================
// 7. Error parity: all bindings must reject these inputs
// =============================================================================

#[test]
fn test_parity_verify_rejects_invalid_json() {
    let wrapper = ephemeral("ed25519");
    let result = wrapper.verify_json("not-valid-json{{{");
    assert!(
        result.is_err(),
        "verify_json should reject invalid JSON input"
    );
}

#[test]
fn test_parity_verify_rejects_tampered_document() {
    let wrapper = ephemeral("ed25519");

    let signed_json = wrapper
        .sign_message_json(r#"{"original": true}"#)
        .unwrap();

    // Tamper with the content
    let mut parsed: Value = serde_json::from_str(&signed_json).unwrap();
    if let Some(content) = parsed.get_mut("content") {
        *content = serde_json::json!({"original": false, "tampered": true});
    }
    let tampered = serde_json::to_string(&parsed).unwrap();

    // Verification should return valid=false (not an error, but invalid)
    // or return an error -- either is acceptable parity behavior
    match wrapper.verify_json(&tampered) {
        Ok(result_json) => {
            let result: Value = serde_json::from_str(&result_json).unwrap();
            assert_eq!(
                result["valid"], false,
                "tampered document should verify as invalid"
            );
        }
        Err(_) => {
            // Also acceptable: returning an error for tampered input
        }
    }
}

#[test]
fn test_parity_sign_message_rejects_invalid_json() {
    let wrapper = ephemeral("ed25519");
    let result = wrapper.sign_message_json("not valid json {{");
    assert!(
        result.is_err(),
        "sign_message_json should reject invalid JSON"
    );
}

#[test]
fn test_parity_verify_by_id_rejects_bad_format() {
    let wrapper = ephemeral("ed25519");
    let result = wrapper.verify_by_id_json("not-a-valid-id");
    assert!(
        result.is_err(),
        "verify_by_id should reject malformed document ID"
    );
}

#[test]
fn test_parity_verify_with_key_rejects_invalid_base64() {
    let wrapper = ephemeral("ed25519");
    let signed = wrapper
        .sign_message_json(r#"{"test": 1}"#)
        .unwrap();
    let result = wrapper.verify_with_key_json(&signed, "not-valid-base64!!!");
    assert!(
        result.is_err(),
        "verify_with_key should reject invalid base64 key"
    );
}

// =============================================================================
// 8. Sign file parity
// =============================================================================

#[test]
fn test_parity_sign_file_ed25519() {
    parity_sign_file("ed25519");
}

#[test]
fn test_parity_sign_file_pq2025() {
    parity_sign_file("pq2025");
}

fn parity_sign_file(algo: &str) {
    let tmp = tempfile::TempDir::new().unwrap();
    let file_path = tmp.path().join("parity_test_file.txt");
    std::fs::write(&file_path, b"parity test content").unwrap();

    let wrapper = ephemeral(algo);
    let signed_json = wrapper
        .sign_file_json(file_path.to_str().unwrap(), true)
        .unwrap_or_else(|e| panic!("[{}] sign_file failed: {}", algo, e));

    let signed: Value = serde_json::from_str(&signed_json)
        .unwrap_or_else(|e| panic!("[{}] sign_file output is not JSON: {}", algo, e));

    assert!(
        signed.get("jacsSignature").is_some(),
        "[{}] signed file should have jacsSignature",
        algo
    );
    assert!(
        signed.get("jacsId").is_some(),
        "[{}] signed file should have jacsId",
        algo
    );

    // Verify the signed file
    let verify_json = wrapper
        .verify_json(&signed_json)
        .unwrap_or_else(|e| panic!("[{}] verify signed file failed: {}", algo, e));
    let result: Value = serde_json::from_str(&verify_json).unwrap();
    assert_eq!(
        result["valid"], true,
        "[{}] signed file should verify",
        algo
    );
}

// =============================================================================
// 9. Verification result structure parity
// =============================================================================

#[test]
fn test_parity_verification_result_structure() {
    let fixtures = load_parity_inputs();
    let wrapper = ephemeral("ed25519");
    let required_fields = &fixtures["expected_verification_result_fields"]["required"];

    let signed = wrapper
        .sign_message_json(r#"{"structure_test": true}"#)
        .unwrap();
    let verify_json = wrapper.verify_json(&signed).unwrap();
    let result: Value = serde_json::from_str(&verify_json).unwrap();

    for field in required_fields.as_array().unwrap() {
        let field_name = field.as_str().unwrap();
        assert!(
            result.get(field_name).is_some(),
            "verification result missing required field '{}'",
            field_name
        );
    }
}

// =============================================================================
// 10. create_with_params parity
// =============================================================================

#[test]
fn test_parity_create_with_params() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().join("data");
    let key_dir = tmp.path().join("keys");
    let config_path = tmp.path().join("config.json");

    // Set password env var for the signing step (SimpleAgent reads it for key decryption)
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#");
    }

    let params_json = serde_json::json!({
        "name": "parity-agent",
        "password": "TestP@ss123!#",
        "algorithm": "ring-Ed25519",
        "data_directory": data_dir.to_str().unwrap(),
        "key_directory": key_dir.to_str().unwrap(),
        "config_path": config_path.to_str().unwrap()
    })
    .to_string();

    let (wrapper, info_json) = SimpleAgentWrapper::create_with_params(&params_json)
        .expect("create_with_params should succeed");

    // info_json should be valid JSON with agent_id
    let info: Value = serde_json::from_str(&info_json).unwrap();
    assert!(
        !info["agent_id"].as_str().unwrap_or("").is_empty(),
        "agent_id from create_with_params should be non-empty"
    );

    // Agent should be functional
    let signed = wrapper
        .sign_message_json(r#"{"params_parity": true}"#)
        .expect("agent from create_with_params should be able to sign");
    assert!(!signed.is_empty());

    // And verifiable
    let verify_json = wrapper.verify_json(&signed).expect("should verify");
    let result: Value = serde_json::from_str(&verify_json).unwrap();
    assert_eq!(result["valid"], true);

    // Clean up env var
    unsafe {
        std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
    }
}
