//! Wave 6 / Task 011 — delegation tests.
//!
//! After ringwrapper + pq2025 delegate to jacs-core::sign, their wire
//! outputs must be byte-identical to the underlying jacs-core path
//! (Ed25519 is deterministic; pq2025 fixture is the oracle).

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use jacs::crypt::{pq2025, ringwrapper};
use jacs_core::sign::{DetachedSigner, Ed25519DalekSigner, Pq2025Signer};

const FIXTURE_PKCS8: &[u8] =
    include_bytes!("../../jacs/tests/fixtures/wasm_compat/ed25519.pkcs8.bin");
const FIXTURE_ED25519_SIGNED: &str =
    include_str!("../../jacs/tests/fixtures/wasm_compat/ed25519.signed.json");
const FIXTURE_PQ2025_PUBLIC: &[u8] =
    include_bytes!("../../jacs/tests/fixtures/wasm_compat/pq2025.public.bin");
const FIXTURE_PQ2025_SIGNED: &str =
    include_str!("../../jacs/tests/fixtures/wasm_compat/pq2025.signed.json");

#[test]
fn delegation_preserves_ring_output() {
    // The wrapper signs through jacs-core; bytes must equal what calling
    // Ed25519DalekSigner directly produces (same key, same message —
    // deterministic).
    let parsed: serde_json::Value =
        serde_json::from_str(FIXTURE_ED25519_SIGNED).expect("fixture JSON");
    let canonical = parsed["canonical"].as_str().expect("canonical").to_string();

    let wrapper_sig =
        ringwrapper::sign_string(FIXTURE_PKCS8.to_vec(), &canonical).expect("ringwrapper sign");
    let wrapper_sig_bytes = B64.decode(&wrapper_sig).expect("decode wrapper sig");

    let direct = Ed25519DalekSigner::from_pkcs8(FIXTURE_PKCS8).expect("direct import");
    let direct_sig = direct.sign(canonical.as_bytes()).expect("direct sign");

    assert_eq!(
        wrapper_sig_bytes, direct_sig,
        "ringwrapper sign_string must produce bytes identical to Ed25519DalekSigner::sign"
    );

    // And the same bytes as the ring-era fixture.
    let fixture_sig = B64
        .decode(parsed["signature_b64"].as_str().expect("sig_b64"))
        .expect("base64");
    assert_eq!(
        wrapper_sig_bytes, fixture_sig,
        "ringwrapper sign_string must produce bytes identical to the ring fixture"
    );
}

#[test]
fn delegation_preserves_pq2025_verify() {
    // Static verify on the Task 001 fixture must succeed through the
    // jacs::crypt::pq2025 wrapper now that it delegates to jacs-core.
    let parsed: serde_json::Value =
        serde_json::from_str(FIXTURE_PQ2025_SIGNED).expect("fixture JSON");
    let canonical = parsed["canonical"].as_str().expect("canonical");
    let sig_b64 = parsed["signature_b64"].as_str().expect("sig_b64");
    pq2025::verify_string(FIXTURE_PQ2025_PUBLIC.to_vec(), canonical, sig_b64)
        .expect("pq2025::verify_string must accept the Task 001 fixture after delegation");
    // And via the jacs-core static path.
    let sig = B64.decode(sig_b64).expect("base64");
    Pq2025Signer::verify(FIXTURE_PQ2025_PUBLIC, canonical.as_bytes(), &sig)
        .expect("Pq2025Signer::verify must accept the Task 001 fixture");
}

#[test]
fn delegation_preserves_ring_generate_pkcs8_format() {
    // Generated PKCS#8 must round-trip through the wrapper. The
    // historical contract is (pkcs8_bytes, raw_public_bytes); the
    // wrapper must keep emitting bytes that the wrapper itself can
    // re-import and sign with.
    let (private_key, public_key) = ringwrapper::generate_keys().expect("generate");
    assert_eq!(public_key.len(), 32, "Ed25519 public key is 32 bytes");
    assert!(
        private_key.len() >= 48,
        "PKCS#8 v2 wrapping is at least 48 bytes, got {}",
        private_key.len()
    );
    let sig =
        ringwrapper::sign_string(private_key, &"hello".to_string()).expect("sign after generate");
    ringwrapper::verify_string(public_key, "hello", &sig).expect("verify after generate");
}

#[test]
fn delegation_preserves_pq2025_generate_format() {
    let (private_key, public_key) = pq2025::generate_keys().expect("generate");
    assert_eq!(
        private_key.len(),
        4896,
        "ML-DSA-87 private key is 4896 bytes"
    );
    assert_eq!(public_key.len(), 2592, "ML-DSA-87 public key is 2592 bytes");
    let sig = pq2025::sign_string(private_key, &"hello".to_string()).expect("sign after generate");
    pq2025::verify_string(public_key, "hello", &sig).expect("verify after generate");
}
