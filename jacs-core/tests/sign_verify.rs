//! Tests for `CoreAgent::sign_message`, `verify`, and `verify_with_key` (Task 013).
//!
//! All tests run natively; cross-compat with `jacs` is tested in
//! `jacs/tests/wasm_compat_cross.rs`.

use jacs_core::{CoreAgent, CoreError, SigningAlgorithm};
use serde_json::json;

// -----------------------------------------------------------------------------
// sign_message wrapper shape (jacsType / jacsLevel / content)
// -----------------------------------------------------------------------------

#[test]
fn core_agent_sign_message_produces_expected_shape() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let signed = agent
        .sign_message(&json!({ "hello": "world" }))
        .expect("sign");

    assert!(signed.is_object(), "signed doc is a JSON object");
    assert_eq!(signed.get("jacsType").and_then(|v| v.as_str()), Some("message"));
    assert_eq!(signed.get("jacsLevel").and_then(|v| v.as_str()), Some("raw"));
    assert_eq!(
        signed.pointer("/content/hello").and_then(|v| v.as_str()),
        Some("world")
    );

    let sig = signed.get("jacsSignature").expect("jacsSignature present");
    for field in [
        "agentID",
        "agentVersion",
        "date",
        "iat",
        "jti",
        "signature",
        "publicKeyHash",
        "signingAlgorithm",
        "fields",
        "signatureContentVersion",
    ] {
        assert!(
            sig.get(field).is_some(),
            "jacsSignature.{} is present",
            field
        );
    }
    assert_eq!(
        sig.get("signingAlgorithm").and_then(|v| v.as_str()),
        Some("ed25519")
    );
    assert_eq!(
        sig.get("signatureContentVersion").and_then(|v| v.as_str()),
        Some("jacs-signature-v2")
    );
    assert!(
        sig.get("signature").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty()),
        "signature is a non-empty string"
    );
}

// -----------------------------------------------------------------------------
// sign + verify round-trip
// -----------------------------------------------------------------------------

#[test]
fn core_agent_sign_then_verify_roundtrip() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let signed = agent
        .sign_message(&json!({ "n": 42, "list": [1, 2, 3] }))
        .expect("sign");

    let outcome = agent.verify(&signed).expect("verify");
    assert!(outcome.valid, "verify outcome must be valid");
    assert!(!outcome.signer_id.is_empty(), "signer_id is populated");
    assert!(outcome.errors.is_empty(), "no errors on success");
}

#[test]
fn core_agent_sign_then_verify_pq2025_roundtrip() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).expect("ephemeral");
    let signed = agent
        .sign_message(&json!({ "purpose": "test" }))
        .expect("sign");

    let outcome = agent.verify(&signed).expect("verify");
    assert!(outcome.valid);
}

// -----------------------------------------------------------------------------
// verify_with_key — verify-only path (no unlock)
// -----------------------------------------------------------------------------

#[test]
fn core_agent_verify_with_key_works_without_unlock() {
    let mut signer_agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let pk = signer_agent.public_key().to_vec();
    let signed = signer_agent
        .sign_message(&json!({ "msg": "verify-with-key" }))
        .expect("sign");

    // Static path — no agent state needed.
    let outcome = CoreAgent::verify_with_key(&signed, &pk, SigningAlgorithm::Ed25519)
        .expect("verify_with_key");
    assert!(outcome.valid);
}

// -----------------------------------------------------------------------------
// Negative tests
// -----------------------------------------------------------------------------

#[test]
fn core_agent_verify_rejects_tampered_content() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let mut signed = agent
        .sign_message(&json!({ "key": "untampered" }))
        .expect("sign");

    // Flip the content.
    *signed
        .pointer_mut("/content/key")
        .expect("content.key exists") = json!("TAMPERED");

    let outcome = agent.verify(&signed).expect("verify call");
    assert!(!outcome.valid, "tampered doc must not verify");
    assert!(!outcome.errors.is_empty(), "errors populated on tamper");
}

#[test]
fn core_agent_verify_rejects_algorithm_mismatch() {
    let mut pq_agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).expect("ephemeral");
    let signed = pq_agent.sign_message(&json!({ "x": 1 })).expect("sign");
    let ed_agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");

    // ed_agent (Ed25519) tries to verify a Pq2025-signed document.
    let result = ed_agent.verify(&signed);
    match result {
        Err(CoreError::AlgorithmMismatch { .. }) => {}
        other => panic!("expected AlgorithmMismatch, got {:?}", other),
    }
}

#[test]
fn core_agent_clear_secrets_blocks_sign_allows_verify() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let signed = agent
        .sign_message(&json!({ "before": "lock" }))
        .expect("sign before lock");

    agent.clear_secrets();

    // Sign must fail with Locked.
    let sign_after = agent.sign_message(&json!({ "after": "lock" }));
    match sign_after {
        Err(CoreError::Locked) => {}
        other => panic!("expected Locked, got {:?}", other),
    }

    // Verify must continue to work.
    let outcome = agent.verify(&signed).expect("verify after lock");
    assert!(outcome.valid);
}
