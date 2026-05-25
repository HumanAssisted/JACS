//! Native sanity tests for jacs-wasm. These exercise the wasm-bindgen
//! wrapper code paths that **do not** require `target_arch = "wasm32"` —
//! i.e. the pure Rust logic of `CoreAgentHandle` and its constructors.
//! The same handle types are exercised under `wasm-pack test --headless
//! --chrome` (tests/web.rs) once the toolchain ships a matching
//! chromedriver in CI; running them here keeps a Rust-only regression
//! suite green during local development.

#![cfg(not(target_arch = "wasm32"))]

use jacs_wasm::{CoreAgentHandle, create_ephemeral, create_verifier};
use serde_json::{Value, json};
use std::path::Path;

const AGREEMENT_V2_SCENARIO: &str =
    include_str!("../../binding-core/tests/fixtures/agreement_v2_scenarios.json");

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
fn agreement_v2_create_sign_verify_round_trips_on_wasm_handle() {
    let handle = create_ephemeral("ed25519").expect("create");
    let agent_id = wasm_agent_id(&handle);

    let created = handle
        .create_agreement_v2_json(&wasm_agreement_v2_input(&agent_id).to_string())
        .expect("create agreement v2");
    let signed = handle
        .sign_agreement_v2_json(&created, "signer")
        .expect("sign agreement v2");
    let report_json = handle
        .verify_agreement_v2_json(&signed)
        .expect("verify agreement v2");
    let report: Value = serde_json::from_str(&report_json).unwrap();
    assert_eq!(report["valid"], Value::Bool(true));
    assert_eq!(report["status"], Value::String("final".to_string()));
    assert_eq!(report["signerCount"], Value::from(1));
}

fn wasm_agent_id(handle: &CoreAgentHandle) -> String {
    let agent: Value = serde_json::from_str(&handle.export_agent().expect("agent")).unwrap();
    agent["jacsId"].as_str().unwrap().to_string()
}

fn wasm_agreement_v2_fixture() -> Value {
    serde_json::from_str(AGREEMENT_V2_SCENARIO).expect("agreement v2 scenario fixture")
}

fn wasm_agreement_v2_input(agent_id: &str) -> Value {
    let scenario = wasm_agreement_v2_fixture();
    let mut input = scenario["base_input"].clone();
    input["parties"] = json!([
        {"agentId": agent_id, "agentType": "ai", "role": "signer"}
    ]);
    input["controllers"] = json!([agent_id]);
    input
}

fn wasm_transcript_ref(name: &str) -> Value {
    wasm_agreement_v2_fixture()["transcript_refs"][name].clone()
}

fn wasm_terms(name: &str) -> String {
    wasm_agreement_v2_fixture()["terms_conflict"][name]
        .as_str()
        .expect("terms conflict value")
        .to_string()
}

#[test]
fn agreement_v2_declared_wasm_surface_tracks_canonical_fixture() {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../binding-core/tests/fixtures/method_parity.json");
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path).unwrap()).unwrap();
    let declarations =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("jacs_wasm.d.ts"))
            .unwrap();
    let mapping = [
        ("create_agreement_v2_json", "createAgreementV2Json"),
        ("apply_agreement_v2_json", "applyAgreementV2Json"),
        ("sign_agreement_v2_json", "signAgreementV2Json"),
        ("verify_agreement_v2_json", "verifyAgreementV2Json"),
        (
            "detect_agreement_v2_branch_conflict_json",
            "detectAgreementV2BranchConflictJson",
        ),
        (
            "merge_agreement_v2_transcript_branches_json",
            "mergeAgreementV2TranscriptBranchesJson",
        ),
        (
            "resolve_agreement_v2_branch_conflict_json",
            "resolveAgreementV2BranchConflictJson",
        ),
    ];
    let agreement_methods = fixture["feature_gated_methods"]["agreements"]
        .as_array()
        .expect("agreement methods");

    for method in agreement_methods {
        let rust_name = method.as_str().expect("method name");
        let wasm_name = mapping
            .iter()
            .find_map(|(rust, wasm)| (*rust == rust_name).then_some(*wasm))
            .unwrap_or_else(|| panic!("missing wasm mapping for {rust_name}"));
        assert!(
            declarations.contains(&format!("{wasm_name}(")),
            "missing {wasm_name} declaration for {rust_name}"
        );
    }
}

#[test]
fn agreement_v2_notary_and_branch_methods_round_trip_on_wasm_handle() {
    let handle = create_ephemeral("ed25519").expect("create");
    let agent_id = wasm_agent_id(&handle);
    let base = handle
        .create_agreement_v2_json(&wasm_agreement_v2_input(&agent_id).to_string())
        .expect("create agreement v2");
    let left = handle
        .apply_agreement_v2_json(
            &base,
            &json!({"type": "appendTranscript", "entry": wasm_transcript_ref("left")}).to_string(),
        )
        .expect("left transcript");
    let right = handle
        .apply_agreement_v2_json(
            &base,
            &json!({"type": "appendTranscript", "entry": wasm_transcript_ref("right")}).to_string(),
        )
        .expect("right transcript");

    let analysis: Value = serde_json::from_str(
        &handle
            .detect_agreement_v2_branch_conflict_json(&base, &left, &right)
            .expect("detect branch conflict"),
    )
    .unwrap();
    assert_eq!(analysis["autoMergeable"], Value::Bool(true));

    let merged: Value = serde_json::from_str(
        &handle
            .merge_agreement_v2_transcript_branches_json(&base, &left, &right)
            .expect("merge transcript branches"),
    )
    .unwrap();
    assert_eq!(merged["transcript"].as_array().unwrap().len(), 2);

    let left_terms = handle
        .apply_agreement_v2_json(
            &base,
            &json!({"type": "updateTerms", "terms": wasm_terms("left")}).to_string(),
        )
        .expect("left terms");
    let right_terms = handle
        .apply_agreement_v2_json(
            &base,
            &json!({"type": "updateTerms", "terms": wasm_terms("right")}).to_string(),
        )
        .expect("right terms");
    let resolved: Value = serde_json::from_str(
        &handle
            .resolve_agreement_v2_branch_conflict_json(
                &base,
                &left_terms,
                &right_terms,
                &json!({"type": "updateTerms", "terms": wasm_terms("resolved")}).to_string(),
            )
            .expect("resolve branch conflict"),
    )
    .unwrap();
    let right_terms_doc: Value = serde_json::from_str(&right_terms).unwrap();
    assert_eq!(resolved["terms"], Value::String(wasm_terms("resolved")));
    assert_eq!(
        resolved["links"][0],
        json!({
            "jacsId": right_terms_doc["jacsId"],
            "jacsVersion": right_terms_doc["jacsVersion"]
        })
    );

    let notary = create_ephemeral("ed25519").expect("notary");
    let notary_id = wasm_agent_id(&notary);
    let mut input = wasm_agreement_v2_input(&agent_id);
    input["parties"] = json!([
        {"agentId": agent_id, "agentType": "ai", "role": "signer"},
        {"agentId": notary_id, "agentType": "ai", "role": "notary"}
    ]);
    input["signaturePolicy"]["notaryRequired"] = json!(1);
    let created = handle
        .create_agreement_v2_json(&input.to_string())
        .expect("create notary agreement");
    let notarized: Value = serde_json::from_str(
        &notary
            .sign_agreement_v2_json(&created, "notary")
            .expect("notary sign"),
    )
    .unwrap();
    assert_eq!(
        notarized["agreementSignatures"][0]["role"],
        Value::String("notary".to_string())
    );
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

// ---------------------------------------------------------------------------
// Issue 006 / Task 031 — metrics() + JACS_WASM_DEBUG behaviour
// ---------------------------------------------------------------------------

#[test]
fn metrics_starts_at_zero_and_increments_on_sign_and_verify() {
    let handle = create_ephemeral("ed25519").expect("create");

    let initial: Value =
        serde_json::from_str(&handle.metrics_json().expect("metrics")).expect("metrics json parse");
    assert_eq!(initial["signCount"], Value::from(0));
    assert_eq!(initial["verifyCount"], Value::from(0));
    assert_eq!(initial["lastSignDurationMs"], Value::from(0.0));
    assert_eq!(initial["lastVerifyDurationMs"], Value::from(0.0));

    let signed = handle.sign_message_json(r#"{"x":1}"#).expect("sign");
    let _ = handle.verify_json(&signed).expect("verify");
    let _ = handle.verify_json(&signed).expect("verify-2");

    let after: Value =
        serde_json::from_str(&handle.metrics_json().expect("metrics")).expect("metrics json parse");
    assert_eq!(after["signCount"], Value::from(1));
    assert_eq!(after["verifyCount"], Value::from(2));
    // Durations are non-negative (we can't assert > 0 reliably because
    // the native fallback uses real time and can round to 0 on a fast
    // run).
    assert!(after["lastSignDurationMs"].as_f64().unwrap() >= 0.0);
    assert!(after["lastVerifyDurationMs"].as_f64().unwrap() >= 0.0);
}

#[test]
fn metrics_are_per_handle_independent() {
    let h1 = create_ephemeral("ed25519").expect("h1");
    let h2 = create_ephemeral("ed25519").expect("h2");

    let _ = h1.sign_message_json(r#"{"k":"a"}"#).expect("h1 sign");
    let _ = h1.sign_message_json(r#"{"k":"b"}"#).expect("h1 sign 2");

    let m1: Value = serde_json::from_str(&h1.metrics_json().expect("m1")).expect("m1 parse");
    let m2: Value = serde_json::from_str(&h2.metrics_json().expect("m2")).expect("m2 parse");
    assert_eq!(m1["signCount"], Value::from(2));
    assert_eq!(m2["signCount"], Value::from(0));
}

#[test]
fn metrics_verifier_handle_increments_verify_count() {
    use base64::Engine;
    let signer = create_ephemeral("ed25519").expect("signer");
    let signed = signer
        .sign_message_json(r#"{"hello":"world"}"#)
        .expect("sign");
    let pk_b64 = signer.get_public_key_base64().expect("pk");

    let verifier = create_verifier(&pk_b64, "ed25519").expect("verifier");
    let _ = verifier.verify_json(&signed).expect("verify");
    let _ = verifier
        .verify_with_key_json(&signed, &pk_b64, "ed25519")
        .expect("verify-with-key");

    let m: Value = serde_json::from_str(&verifier.metrics_json().expect("m")).expect("m parse");
    assert_eq!(m["verifyCount"], Value::from(2));
    assert_eq!(m["signCount"], Value::from(0));

    // Discard base64 binding so unused-import lint doesn't fire.
    let _ = base64::engine::general_purpose::STANDARD.encode([0u8]);
}
