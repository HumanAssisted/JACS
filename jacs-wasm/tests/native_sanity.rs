//! Native sanity tests for jacs-wasm. These exercise the wasm-bindgen
//! wrapper code paths that **do not** require `target_arch = "wasm32"` —
//! i.e. the pure Rust logic of `CoreAgentHandle` and its constructors.
//! The same handle types are exercised under `wasm-pack test --headless
//! --chrome` (tests/web.rs) once the toolchain ships a matching
//! chromedriver in CI; running them here keeps a Rust-only regression
//! suite green during local development.

#![cfg(not(target_arch = "wasm32"))]

use jacs_wasm::{
    CoreAgentHandle, create_ephemeral, create_verifier,
};
use serde_json::Value;

#[allow(dead_code)]
fn extract_code(err: &wasm_bindgen::JsError) -> Option<String> {
    // wasm-bindgen's JsError stores the message; we can't introspect it
    // without a wasm context. For the native test surface we settle for
    // round-tripping through `format!` and parsing the JSON, which
    // matches the shape `map_core_err` writes.
    let msg = format!("{:?}", err);
    let start = msg.find("{")?;
    let end = msg.rfind("}")? + 1;
    let json_part = &msg[start..end];
    let v: Value = serde_json::from_str(json_part).ok()?;
    v.get("code").and_then(|c| c.as_str()).map(str::to_string)
}

#[test]
fn create_ephemeral_ed25519_signs_and_verifies_via_handle() {
    let handle = create_ephemeral("ed25519").expect("create ephemeral");
    let signed = handle
        .sign_message_json(r#"{"hello":"world"}"#)
        .expect("sign");
    let verified = handle.verify_json(&signed).expect("verify");
    let outcome: Value = serde_json::from_str(&verified).expect("verify json parse");
    assert_eq!(outcome["valid"], Value::Bool(true));
}

#[test]
fn create_ephemeral_pq2025_signs_and_verifies_via_handle() {
    let handle = create_ephemeral("pq2025").expect("create ephemeral");
    let signed = handle
        .sign_message_json(r#"{"purpose":"test"}"#)
        .expect("sign");
    let verified = handle.verify_json(&signed).expect("verify");
    let outcome: Value = serde_json::from_str(&verified).expect("verify json parse");
    assert_eq!(outcome["valid"], Value::Bool(true));
}

// NOTE: The error-returning constructor paths build `JsError` values via
// `wasm-bindgen` imports that panic on non-wasm targets (see
// `wasm-bindgen-0.2`'s `lib.rs:1196`). The behavior they exercise is
// validated under `wasm-pack test` in `tests/web.rs`; we skip them on the
// native test runner to keep `cargo test -p jacs-wasm` green.
#[test]
#[ignore = "JsError construction panics on native targets; covered by web.rs under wasm-pack test"]
fn create_ephemeral_unknown_algorithm_returns_unsupported_error() {
    let result = create_ephemeral("rsa");
    let err = result.err().expect("must fail");
    let code = extract_code(&err).expect("code present");
    assert_eq!(code, "UnsupportedAlgorithm", "got code: {}", code);
}

#[test]
fn is_unlocked_reflects_clear_secrets() {
    let handle = create_ephemeral("ed25519").expect("create ephemeral");
    assert!(handle.is_unlocked().expect("is_unlocked"));
    handle.clear_secrets().expect("clear");
    assert!(!handle.is_unlocked().expect("is_unlocked after clear"));
}

#[test]
#[ignore = "JsError construction panics on native targets; covered by web.rs under wasm-pack test"]
fn sign_after_clear_secrets_returns_locked_error() {
    let handle = create_ephemeral("ed25519").expect("create ephemeral");
    handle.clear_secrets().expect("clear");
    let err = handle
        .sign_message_json(r#"{"x":1}"#)
        .expect_err("sign after clear must error");
    let code = extract_code(&err).expect("code present");
    assert_eq!(code, "Locked", "got code: {}", code);
}

#[test]
fn verify_with_key_works_without_unlocking() {
    let signer = create_ephemeral("ed25519").expect("create");
    let pk_b64 = signer.get_public_key_base64().expect("pk b64");
    let signed = signer.sign_message_json(r#"{"a":1}"#).expect("sign");

    // Make a verifier-only handle and use verifyWithKeyJson (static path).
    let verifier = create_verifier(&pk_b64, "ed25519").expect("create verifier");
    let outcome_json = verifier
        .verify_with_key_json(&signed, &pk_b64, "ed25519")
        .expect("verify_with_key");
    let outcome: Value = serde_json::from_str(&outcome_json).unwrap();
    assert_eq!(outcome["valid"], Value::Bool(true));
}

#[test]
#[ignore = "JsError construction panics on native targets; covered by web.rs under wasm-pack test"]
fn create_verifier_handle_cannot_sign() {
    let signer = create_ephemeral("ed25519").expect("create");
    let pk_b64 = signer.get_public_key_base64().expect("pk b64");
    let verifier = create_verifier(&pk_b64, "ed25519").expect("create verifier");

    let err = verifier
        .sign_message_json(r#"{"x":1}"#)
        .expect_err("sign on verifier handle must error");
    let code = extract_code(&err).expect("code present");
    assert_eq!(code, "Locked", "got code: {}", code);
}

#[test]
fn create_verifier_advertises_override_public_key_and_algorithm() {
    let signer = create_ephemeral("pq2025").expect("create");
    let pk_b64 = signer.get_public_key_base64().expect("pk b64");
    let verifier = create_verifier(&pk_b64, "pq2025").expect("create verifier");
    assert_eq!(verifier.get_public_key_base64().expect("pk b64"), pk_b64);
    assert_eq!(verifier.algorithm().expect("algo"), "pq2025");
}

#[test]
fn export_agent_returns_json_with_jacs_id() {
    let handle: CoreAgentHandle = create_ephemeral("ed25519").expect("create");
    let agent_str = handle.export_agent().expect("export");
    let agent: Value = serde_json::from_str(&agent_str).expect("agent json parse");
    assert!(agent["jacsId"].as_str().is_some(), "jacsId present");
}

#[test]
fn get_public_key_base64_decodes_to_32_bytes_for_ed25519() {
    use base64::Engine;
    let handle = create_ephemeral("ed25519").expect("create");
    let pk_b64 = handle.get_public_key_base64().expect("pk b64");
    let pk = base64::engine::general_purpose::STANDARD
        .decode(pk_b64.as_bytes())
        .expect("decode");
    assert_eq!(pk.len(), 32);
}
