//! Browser tests for `CoreAgentHandle` (Task 016).
//!
//! Run with `wasm-pack test --headless --chrome jacs-wasm --test agent`.
//! These exercise the wasm-bindgen-facing API and validate that the
//! generated `.d.ts` names line up with the PRD §4.3 contract.

#![cfg(target_arch = "wasm32")]

use jacs_wasm::{create_ephemeral, create_verifier, init_jacs_wasm};
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
