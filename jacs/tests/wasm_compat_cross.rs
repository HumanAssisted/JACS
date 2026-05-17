//! Cross-compat tests between native `jacs` and `jacs_core` (Task 013).
//!
//! These exercise the **signature reconstruction contract**: jacs and
//! jacs-core build the same canonical bytes from the same document +
//! metadata, so a signature produced by one verifies under the other.
//!
//! The tests deliberately use ephemeral agents (raw keys on the native
//! side) so the `publicKeyHash` baked into the signed payload is computed
//! from the same byte sequence on both sides (jacs-core uses pure SHA-256
//! over the raw bytes; native's `hash_public_key` uses encoding_rs UTF-8
//! lossy decode + sha256 — they differ for arbitrary binary, but
//! jacs-core's verification reads the publicKeyHash string straight out of
//! the signed metadata, not by recomputing it, so the actual canonical
//! bytes match).

use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use jacs_core::{CoreAgent, SigningAlgorithm};
use serde_json::{Value, json};

// -----------------------------------------------------------------------------
// Helpers: produce a native ephemeral agent with a freshly-generated keypair.
// -----------------------------------------------------------------------------

/// Build a native ephemeral Ed25519 agent that already has keys.
///
/// `Agent::ephemeral` does not set `key_paths`, so the default
/// `generate_keys` (which builds an fs key store) blows up. Use
/// `generate_keys_with_store` with an in-memory store instead — that
/// is the same code path `SimpleAgent::ephemeral` ends up running.
fn native_ephemeral_ed25519() -> Agent {
    let mut agent = Agent::ephemeral("ring-Ed25519").expect("ephemeral agent");
    let ks = jacs::keystore::InMemoryKeyStore::new("ring-Ed25519");
    agent.generate_keys_with_store(&ks).expect("generate keys");
    agent
}

// -----------------------------------------------------------------------------
// Test A: native-signed payload verifies via jacs_core::CoreAgent::verify_with_key
// -----------------------------------------------------------------------------

#[test]
fn native_signed_doc_verifies_via_core() {
    let mut native = native_ephemeral_ed25519();
    let pk = native.get_public_key().expect("public key");

    // Native signing_procedure returns the signature object; embed it into
    // a document under `jacsSignature`. The canonical bytes that the
    // native signer signed over are derived from this document.
    let mut document: Value = json!({
        "content": { "hello": "world" },
        "jacsLevel": "raw",
        "jacsType": "message",
    });
    let signature = native
        .signing_procedure(&document, None, "jacsSignature")
        .expect("native signing_procedure");
    document
        .as_object_mut()
        .unwrap()
        .insert("jacsSignature".into(), signature);

    // jacs-core verifies the same document with the raw public key and the
    // matching algorithm tag.
    let outcome =
        CoreAgent::verify_with_key(&document, &pk, SigningAlgorithm::Ed25519).expect("verify");
    assert!(
        outcome.valid,
        "native-signed doc must verify in jacs-core; errors: {:?}",
        outcome.errors
    );
}

// -----------------------------------------------------------------------------
// Test B: jacs_core-signed payload verifies via native Agent::verify_string
// -----------------------------------------------------------------------------

#[test]
fn core_signed_doc_verifies_via_native() {
    let mut core_agent =
        CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral core agent");
    let pk = core_agent.public_key().to_vec();

    let signed = core_agent
        .sign_message(&json!({ "cross": "compat" }))
        .expect("sign");

    // Native verify_string takes (data, sig_b64, public_key, algorithm).
    // Rebuild the canonical payload exactly as jacs_core's signer did.
    let sig_obj = signed
        .get("jacsSignature")
        .expect("jacsSignature exists")
        .clone();
    let sig_b64 = sig_obj["signature"].as_str().expect("signature str");
    let fields: Vec<String> = sig_obj["fields"]
        .as_array()
        .expect("fields array")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let canonical = jacs_core::verify::build_signature_content_v2(
        &signed,
        &fields,
        "jacsSignature",
        &sig_obj,
    )
    .expect("canonical");

    let native = Agent::ephemeral("ring-Ed25519").expect("ephemeral");
    native
        .verify_string(&canonical, sig_b64, pk, Some("ring-Ed25519".to_string()))
        .expect("native verify_string must accept jacs-core's signature");
}
