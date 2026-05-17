//! Wave 5 / Task 010 — `Ed25519DalekSigner` tests.
//!
//! The byte-exact signature match against the Task 001 fixture
//! (`ed25519_dalek_signature_matches_ring_fixture`) is the load-bearing
//! oracle: Ed25519 is deterministic, so if `ed25519-dalek` produces
//! different bytes than `ring` over the same canonical payload + same
//! key, the entire native → wasm migration fails. Any mismatch is a
//! blocker, not something to patch around.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use jacs_core::CoreError;
use jacs_core::sign::{DetachedSigner, Ed25519DalekSigner, SigningAlgorithm};

const FIXTURE_PKCS8: &[u8] = include_bytes!("../../jacs/tests/fixtures/wasm_compat/ed25519.pkcs8.bin");
const FIXTURE_PUBLIC: &[u8] = include_bytes!("../../jacs/tests/fixtures/wasm_compat/ed25519.public.bin");
const FIXTURE_SIGNED_JSON: &str =
    include_str!("../../jacs/tests/fixtures/wasm_compat/ed25519.signed.json");

#[test]
fn ed25519_dalek_imports_ring_pkcs8() {
    let signer = Ed25519DalekSigner::from_pkcs8(FIXTURE_PKCS8)
        .expect("ring-generated PKCS#8 must import");
    assert_eq!(
        signer.public_key(),
        FIXTURE_PUBLIC,
        "imported PKCS#8 public key must match the fixture's public bytes"
    );
    assert_eq!(signer.algorithm(), SigningAlgorithm::Ed25519);
}

#[test]
fn ed25519_dalek_signature_matches_ring_fixture() {
    // Ed25519 is deterministic: signing the same message with the same
    // key always produces the same 64-byte signature. The fixture
    // captures (canonical payload, ring-produced signature); the
    // ed25519-dalek path must produce byte-identical output.
    let signer = Ed25519DalekSigner::from_pkcs8(FIXTURE_PKCS8).expect("import");
    let parsed: serde_json::Value =
        serde_json::from_str(FIXTURE_SIGNED_JSON).expect("fixture JSON");
    let canonical = parsed["canonical"].as_str().expect("canonical field");
    let expected_sig =
        B64.decode(parsed["signature_b64"].as_str().expect("sig field")).expect("base64");
    let produced_sig = signer.sign(canonical.as_bytes()).expect("sign");
    assert_eq!(
        produced_sig, expected_sig,
        "ed25519-dalek signature must byte-equal the ring fixture signature"
    );
}

#[test]
fn ed25519_dalek_verify_existing_signature() {
    let parsed: serde_json::Value =
        serde_json::from_str(FIXTURE_SIGNED_JSON).expect("fixture JSON");
    let canonical = parsed["canonical"].as_str().expect("canonical");
    let sig = B64.decode(parsed["signature_b64"].as_str().expect("sig")).expect("base64");
    Ed25519DalekSigner::verify(FIXTURE_PUBLIC, canonical.as_bytes(), &sig)
        .expect("Task 001 ed25519 fixture must verify via jacs-core");
}

#[test]
fn ed25519_dalek_wrong_message_rejected() {
    let signer = Ed25519DalekSigner::generate().expect("keygen");
    let sig = signer.sign(b"original").expect("sign");
    let err = Ed25519DalekSigner::verify(signer.public_key(), b"tampered", &sig)
        .expect_err("must reject tampered message");
    assert!(matches!(err, CoreError::SignatureInvalid(_)), "got {err:?}");
}

#[test]
fn ed25519_dalek_generate_then_sign_verify_roundtrip() {
    let signer = Ed25519DalekSigner::generate().expect("keygen");
    let sig = signer.sign(b"roundtrip").expect("sign");
    Ed25519DalekSigner::verify(signer.public_key(), b"roundtrip", &sig).expect("verify");
}

#[test]
fn ed25519_dalek_clear_secrets_blocks_sign() {
    let mut signer = Ed25519DalekSigner::generate().expect("keygen");
    signer.sign(b"before clear").expect("sign before clear");
    signer.clear_secrets();
    let err = signer.sign(b"after clear").expect_err("must fail when locked");
    assert!(matches!(err, CoreError::Locked), "got {err:?}");
    // Idempotent.
    signer.clear_secrets();
    // Public key still accessible.
    assert!(!signer.public_key().is_empty(), "public key survives clear");
}

#[test]
fn ed25519_dalek_malformed_pkcs8_rejected() {
    let err = Ed25519DalekSigner::from_pkcs8(b"garbage")
        .expect_err("garbage PKCS#8 must be rejected");
    assert!(matches!(err, CoreError::MalformedKey(_)), "got {err:?}");
}

#[test]
fn ed25519_dalek_malformed_public_key_length_rejected() {
    let err = Ed25519DalekSigner::verify(b"short", b"msg", &[0u8; 64])
        .expect_err("must fail");
    assert!(matches!(err, CoreError::MalformedKey(_)), "got {err:?}");
}

#[test]
fn ed25519_dalek_malformed_signature_length_rejected() {
    let signer = Ed25519DalekSigner::generate().expect("keygen");
    let err = Ed25519DalekSigner::verify(signer.public_key(), b"msg", &[0u8; 10])
        .expect_err("must fail");
    assert!(matches!(err, CoreError::SignatureInvalid(_)), "got {err:?}");
}

#[test]
fn ed25519_dalek_from_private_scalar_matches_pkcs8_import() {
    // PKCS#8 v2 carries a 32-byte private scalar inside the wrapping.
    // Pulling it out manually and feeding it to from_private_scalar
    // must produce a signer that signs identically to the PKCS#8 import
    // (same key, same deterministic signature).
    //
    // The v2 wire format here is:
    //   30 51 02 01 01 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes priv>
    //   ...
    // So bytes [16..48] are the raw scalar.
    let scalar = &FIXTURE_PKCS8[16..48];
    let signer_a = Ed25519DalekSigner::from_pkcs8(FIXTURE_PKCS8).expect("pkcs8");
    let signer_b = Ed25519DalekSigner::from_private_scalar(scalar).expect("scalar");
    assert_eq!(
        signer_a.public_key(),
        signer_b.public_key(),
        "PKCS#8 and raw-scalar paths must reconstruct the same public key"
    );
    let msg = b"agreement";
    assert_eq!(
        signer_a.sign(msg).expect("a"),
        signer_b.sign(msg).expect("b"),
        "deterministic signatures must match across import paths"
    );
}
