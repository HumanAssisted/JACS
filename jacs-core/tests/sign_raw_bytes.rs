//! Tests for `CoreAgent::sign_raw_bytes` and `verify_raw_bytes_with_key`.
//!
//! Motivation: the JACS message wrapper that `sign_message` builds is the
//! right shape for protocol-layer signed documents, but auth-header
//! signing (HAIAI `Authorization: JACS <id>:<ts>:<nonce>:<sig>`) signs
//! exact bytes — the verifier reproduces the same byte string from the
//! header fields and compares signatures. Wrapping those bytes in a
//! JACS message before signing produces a different signature contract
//! and forces every verifier to reconstruct the wrapper. These tests
//! lock the raw-bytes primitive so wasm + native produce identical
//! signatures for identical byte inputs.

use jacs_core::{CoreAgent, CoreError, SigningAlgorithm};

// -----------------------------------------------------------------------------
// round-trip
// -----------------------------------------------------------------------------

#[test]
fn sign_raw_bytes_then_verify_roundtrips_ed25519() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let message = b"JACS abc:123:nonce:body-hash";

    let signature = agent.sign_raw_bytes(message).expect("sign");
    let ok = CoreAgent::verify_raw_bytes_with_key(
        agent.public_key(),
        SigningAlgorithm::Ed25519,
        message,
        &signature,
    )
    .expect("verify");
    assert!(ok, "verifier accepts signature over identical bytes");
}

#[test]
fn sign_raw_bytes_then_verify_roundtrips_pq2025() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).expect("ephemeral");
    let message = b"JACS abc:123:nonce:body-hash";

    let signature = agent.sign_raw_bytes(message).expect("sign");
    let ok = CoreAgent::verify_raw_bytes_with_key(
        agent.public_key(),
        SigningAlgorithm::Pq2025,
        message,
        &signature,
    )
    .expect("verify");
    assert!(ok, "verifier accepts signature over identical bytes");
}

// -----------------------------------------------------------------------------
// tamper detection
// -----------------------------------------------------------------------------

#[test]
fn verify_raw_bytes_rejects_modified_message() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let signature = agent.sign_raw_bytes(b"original").expect("sign");
    let ok = CoreAgent::verify_raw_bytes_with_key(
        agent.public_key(),
        SigningAlgorithm::Ed25519,
        b"tampered",
        &signature,
    )
    .expect("verify");
    assert!(!ok, "verifier rejects signature when message differs");
}

#[test]
fn verify_raw_bytes_rejects_bad_signature_bytes() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let mut signature = agent.sign_raw_bytes(b"msg").expect("sign");
    // Flip a bit in the signature; verification must fail without panicking.
    signature[0] ^= 0xFF;
    let ok = CoreAgent::verify_raw_bytes_with_key(
        agent.public_key(),
        SigningAlgorithm::Ed25519,
        b"msg",
        &signature,
    )
    .expect("verify");
    assert!(!ok, "tampered signature must not verify");
}

// -----------------------------------------------------------------------------
// locked agent rejection
// -----------------------------------------------------------------------------

#[test]
fn sign_raw_bytes_returns_locked_after_clear_secrets() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    agent.clear_secrets();
    let err = agent.sign_raw_bytes(b"msg").expect_err("locked");
    assert!(
        matches!(err, CoreError::Locked),
        "expected Locked after clear_secrets, got {err:?}"
    );
}

// -----------------------------------------------------------------------------
// determinism (Ed25519 is deterministic; pq2025 is randomized so skip)
// -----------------------------------------------------------------------------

#[test]
fn sign_raw_bytes_ed25519_is_deterministic() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let a = agent.sign_raw_bytes(b"same bytes").expect("sign a");
    let b = agent.sign_raw_bytes(b"same bytes").expect("sign b");
    assert_eq!(a, b, "ed25519 sign is deterministic on identical input");
}
