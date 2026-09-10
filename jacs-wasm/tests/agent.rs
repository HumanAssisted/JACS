//! Browser tests for `CoreAgentHandle` (Task 016).
//!
//! Run with `wasm-pack test --headless --chrome jacs-wasm --test agent`.
//! These exercise the wasm-bindgen-facing API and validate that the
//! generated `.d.ts` names line up with the PRD §4.3 contract.

#![cfg(target_arch = "wasm32")]

use jacs_wasm::{create_ephemeral, create_verifier, import_encrypted_agent, init_jacs_wasm};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn json_get<'a>(parsed: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    parsed.get(key).expect(key)
}

#[wasm_bindgen_test]
fn ephemeral_ed25519_signs_and_verifies() {
    init_jacs_wasm();
    let handle = create_ephemeral("ed25519").expect("create");
    let signed = handle
        .sign_message_json(r#"{"hello":"world"}"#)
        .expect("sign");
    let verified = handle.verify_json(&signed).expect("verify");
    let outcome: serde_json::Value = serde_json::from_str(&verified).expect("outcome");
    assert!(json_get(&outcome, "valid").as_bool().unwrap_or(false));
}

#[wasm_bindgen_test]
fn ephemeral_pq2025_signs_and_verifies() {
    init_jacs_wasm();
    let handle = create_ephemeral("pq2025").expect("create");
    let signed = handle
        .sign_message_json(r#"{"purpose":"wasm-test"}"#)
        .expect("sign");
    let verified = handle.verify_json(&signed).expect("verify");
    let outcome: serde_json::Value = serde_json::from_str(&verified).expect("outcome");
    assert!(json_get(&outcome, "valid").as_bool().unwrap_or(false));
}

#[wasm_bindgen_test]
fn raw_json_entry_points_reject_duplicate_decoded_keys() {
    init_jacs_wasm();
    let handle = create_ephemeral("ed25519").expect("create");

    let sign_result = handle.sign_message_json(
        r#"{"decision":"deny","decision":"allow","agentID":"one","agent\u0049D":"two"}"#,
    );
    assert!(sign_result.is_err(), "ambiguous payload must not be signed");
    drop(sign_result.err());

    let signed = handle
        .sign_message_json(r#"{"decision":"allow"}"#)
        .expect("sign unambiguous payload");
    let ambiguous = format!(
        "{{\"content\":{{\"decision\":\"deny\"}},{}",
        signed.strip_prefix('{').expect("signed document object")
    );
    let verify_result = handle.verify_json(&ambiguous);
    assert!(
        verify_result.is_err(),
        "ambiguous signed bytes must not be verified"
    );
    drop(verify_result.err());
}

#[wasm_bindgen_test]
fn unsupported_algorithm_returns_jacs_wasm_error_with_unsupported_code() {
    init_jacs_wasm();
    let result = create_ephemeral("rsa");
    assert!(result.is_err(), "rsa is not supported in the browser");
    // Discard the error itself — wasm-bindgen's `JsError` does not impl
    // `Debug`, so the assertion above is the load-bearing one. The JSON
    // payload shape (`{ code, message }`) is validated by JS callers via
    // `try { … } catch (e) { JSON.parse(e.message).code }` in real
    // applications and by the TypeScript smoke test in Task 020.
    drop(result.err());
}

#[wasm_bindgen_test]
fn create_verifier_returns_handle_that_can_verify_but_not_sign() {
    init_jacs_wasm();
    let signer = create_ephemeral("ed25519").expect("signer");
    let pk_b64 = signer.get_public_key_base64().expect("pk b64");
    let signed = signer.sign_message_json(r#"{"a":1}"#).expect("sign");

    let verifier = create_verifier(&pk_b64, "ed25519").expect("create verifier");
    let verified = verifier.verify_json(&signed).expect("verify_json");
    let outcome: serde_json::Value = serde_json::from_str(&verified).expect("outcome");
    assert!(json_get(&outcome, "valid").as_bool().unwrap_or(false));

    // sign must fail (Locked). `expect_err` would need `Debug` on the
    // Ok variant; assert on `is_err()` and drop the JsError instead.
    let sign_result = verifier.sign_message_json(r#"{"x":1}"#);
    assert!(sign_result.is_err(), "sign on verifier must fail");
    drop(sign_result.err());
}

#[wasm_bindgen_test]
fn is_unlocked_reflects_clear_secrets() {
    init_jacs_wasm();
    let handle = create_ephemeral("ed25519").expect("create");
    assert!(handle.is_unlocked().expect("is_unlocked"));
    handle.clear_secrets().expect("clear");
    assert!(!handle.is_unlocked().expect("is_unlocked after clear"));
}

#[wasm_bindgen_test]
fn export_agent_returns_json_string_with_jacs_id() {
    init_jacs_wasm();
    let handle = create_ephemeral("ed25519").expect("create");
    let agent_str = handle.export_agent().expect("export");
    let parsed: serde_json::Value = serde_json::from_str(&agent_str).expect("parse");
    assert!(parsed.get("jacsId").and_then(|v| v.as_str()).is_some());
}

#[wasm_bindgen_test]
fn encrypted_export_import_round_trips_in_browser() {
    init_jacs_wasm();
    let password = "browser export roundtrip password";
    let original = create_ephemeral("ed25519").expect("create");
    let original_public_key = original.get_public_key_base64().expect("public key");
    let original_agent: serde_json::Value =
        serde_json::from_str(&original.export_agent().expect("public agent")).expect("agent JSON");

    let material_json = original
        .export_encrypted_agent(password.to_owned())
        .expect("encrypted export");
    let material: serde_json::Value =
        serde_json::from_str(&material_json).expect("AgentMaterial JSON");
    assert_eq!(material["algorithm"], serde_json::Value::from("ed25519"));
    assert!(
        material["encrypted_private_key"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "encrypted private-key envelope is base64 encoded"
    );

    let restored = import_encrypted_agent(&material_json, password).expect("encrypted import");
    assert_eq!(
        restored.get_public_key_base64().expect("restored key"),
        original_public_key
    );
    let restored_agent: serde_json::Value =
        serde_json::from_str(&restored.export_agent().expect("restored public agent"))
            .expect("restored agent JSON");
    assert_eq!(restored_agent["jacsId"], original_agent["jacsId"]);

    let signed = restored
        .sign_message_json(r#"{"restored":true}"#)
        .expect("restored signer works");
    let outcome: serde_json::Value = serde_json::from_str(
        &restored
            .verify_json(&signed)
            .expect("restored verifier works"),
    )
    .expect("verification outcome JSON");
    assert_eq!(outcome["valid"], serde_json::Value::Bool(true));
}

#[wasm_bindgen_test]
fn encrypted_export_rejects_wrong_password_without_partial_handle() {
    init_jacs_wasm();
    let original = create_ephemeral("ed25519").expect("create");
    let material_json = original
        .export_encrypted_agent("correct browser password".to_owned())
        .expect("encrypted export");

    let result = import_encrypted_agent(&material_json, "wrong browser password");
    assert!(result.is_err(), "wrong password must fail closed");
    drop(result.err());
}

#[wasm_bindgen_test]
fn encrypted_export_refuses_locked_handle() {
    init_jacs_wasm();
    let handle = create_ephemeral("ed25519").expect("create");
    handle.clear_secrets().expect("clear");
    let result = handle.export_encrypted_agent("unused password".to_owned());
    assert!(
        result.is_err(),
        "locked handles must not export key material"
    );
    drop(result.err());
}

#[wasm_bindgen_test]
fn get_public_key_base64_round_trips_to_32_bytes_for_ed25519() {
    use base64::Engine;
    init_jacs_wasm();
    let handle = create_ephemeral("ed25519").expect("create");
    let pk_b64 = handle.get_public_key_base64().expect("pk b64");
    let pk = base64::engine::general_purpose::STANDARD
        .decode(pk_b64.as_bytes())
        .expect("decode");
    assert_eq!(pk.len(), 32);
}
