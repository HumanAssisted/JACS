//! Tests for `jacs_core::CoreAgent` and `AgentMaterial` (Task 012).
//!
//! Covers ephemeral key generation, encrypted-material import with
//! password and raw-key unlocks, idempotent `clear_secrets`, and the
//! serde round-trip for `AgentMaterial`.

use jacs_core::envelope::encrypt_v2_envelope;
use jacs_core::{
    AgentMaterial, CoreAgent, CoreError, DetachedSigner, SigningAlgorithm, UnlockSecret,
    ed25519_signer_for_tests,
};
use secrecy::SecretBox;
use serde_json::json;

// -----------------------------------------------------------------------------
// Test helpers: build encrypted ephemeral fixtures inline so the tests do not
// rely on the wasm_compat fixture files (which target a later cross-compat
// task). We need exact byte parity with the production decrypt path; the
// envelope writer used here is the same `encrypt_v2_envelope` that native
// `jacs::crypt::aes_encrypt` calls into.
// -----------------------------------------------------------------------------

/// Generate an Ed25519 ephemeral keypair and return
/// (encrypted_private_key_envelope_bytes, raw_pkcs8_v2_bytes, public_key_bytes).
fn make_encrypted_ed25519(password: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let signer = ed25519_signer_for_tests();
    let pkcs8 = signer.export_pkcs8_v2().expect("export pkcs8");
    let pk = signer.public_key().to_vec();
    let envelope = encrypt_v2_envelope(&pkcs8, password).expect("encrypt envelope");
    (envelope, pkcs8, pk)
}

// -----------------------------------------------------------------------------
// AgentMaterial serde round-trip
// -----------------------------------------------------------------------------

#[test]
fn agent_material_serde_roundtrip() {
    let material = AgentMaterial {
        config: json!({ "schema": "v1", "name": "test-agent" }),
        agent: json!({ "jacsId": "abc", "jacsVersion": "v1" }),
        public_key: vec![1, 2, 3, 4],
        encrypted_private_key: vec![5, 6, 7, 8, 9],
        algorithm: SigningAlgorithm::Ed25519,
    };

    let serialized = serde_json::to_string(&material).expect("serialize");
    let restored: AgentMaterial = serde_json::from_str(&serialized).expect("deserialize");

    assert_eq!(restored.config, material.config);
    assert_eq!(restored.agent, material.agent);
    assert_eq!(restored.public_key, material.public_key);
    assert_eq!(restored.encrypted_private_key, material.encrypted_private_key);
    assert_eq!(restored.algorithm, material.algorithm);
}

// -----------------------------------------------------------------------------
// CoreAgent::ephemeral
// -----------------------------------------------------------------------------

#[test]
fn core_agent_ephemeral_pq2025_works() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).expect("ephemeral pq2025");
    assert_eq!(agent.algorithm(), SigningAlgorithm::Pq2025);
    assert!(!agent.public_key().is_empty());
    assert!(agent.is_unlocked());
    // The exported agent must be a JSON object with a `jacsId` field.
    let exported = agent.export_agent();
    assert!(exported.is_object(), "export_agent returns a JSON object");
    assert!(
        exported.get("jacsId").and_then(|v| v.as_str()).is_some(),
        "export_agent embeds jacsId"
    );
}

#[test]
fn core_agent_ephemeral_ed25519_works() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral ed25519");
    assert_eq!(agent.algorithm(), SigningAlgorithm::Ed25519);
    assert_eq!(agent.public_key().len(), 32);
    assert!(agent.is_unlocked());
}

// -----------------------------------------------------------------------------
// CoreAgent::from_encrypted_material — password path
// -----------------------------------------------------------------------------

#[test]
fn core_agent_from_encrypted_material_wrong_password_fails() {
    let (encrypted, _pkcs8, pk) = make_encrypted_ed25519("correct horse battery staple");
    let material = AgentMaterial {
        config: json!({}),
        agent: json!({ "jacsId": "ephemeral-test", "jacsVersion": "v1" }),
        public_key: pk,
        encrypted_private_key: encrypted,
        algorithm: SigningAlgorithm::Ed25519,
    };

    let result = CoreAgent::from_encrypted_material(material, UnlockSecret::Password("wrong"));

    match result {
        Err(CoreError::InvalidPassword) => {}
        other => panic!("expected InvalidPassword, got {:?}", other),
    }
}

#[test]
fn core_agent_from_encrypted_material_correct_password_unlocks() {
    let password = "another secure phrase";
    let (encrypted, _pkcs8, pk) = make_encrypted_ed25519(password);
    let material = AgentMaterial {
        config: json!({}),
        agent: json!({ "jacsId": "ephemeral-test", "jacsVersion": "v1" }),
        public_key: pk.clone(),
        encrypted_private_key: encrypted,
        algorithm: SigningAlgorithm::Ed25519,
    };

    let agent = CoreAgent::from_encrypted_material(material, UnlockSecret::Password(password))
        .expect("unlock with correct password");

    assert_eq!(agent.algorithm(), SigningAlgorithm::Ed25519);
    assert_eq!(agent.public_key(), pk.as_slice());
    assert!(agent.is_unlocked());
}

// -----------------------------------------------------------------------------
// CoreAgent::from_encrypted_material — raw private key bypass
// -----------------------------------------------------------------------------

#[test]
fn core_agent_raw_private_key_unlock_works() {
    let (_encrypted, pkcs8, pk) = make_encrypted_ed25519("password-not-needed");
    let material = AgentMaterial {
        config: json!({}),
        agent: json!({ "jacsId": "raw-key-test", "jacsVersion": "v1" }),
        public_key: pk.clone(),
        // `encrypted_private_key` is irrelevant for the RawPrivateKey unlock
        // path — it must not be touched.
        encrypted_private_key: vec![],
        algorithm: SigningAlgorithm::Ed25519,
    };

    let secret = SecretBox::new(Box::new(pkcs8));
    let agent = CoreAgent::from_encrypted_material(material, UnlockSecret::RawPrivateKey(secret))
        .expect("unlock with raw private key");

    assert!(agent.is_unlocked());
    assert_eq!(agent.public_key(), pk.as_slice());
}

// -----------------------------------------------------------------------------
// clear_secrets semantics
// -----------------------------------------------------------------------------

#[test]
fn core_agent_clear_secrets_sets_is_unlocked_false() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    assert!(agent.is_unlocked());
    agent.clear_secrets();
    assert!(!agent.is_unlocked());
    // Public key still readable after clear.
    assert_eq!(agent.public_key().len(), 32);
}

#[test]
fn core_agent_clear_secrets_idempotent() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).expect("ephemeral");
    agent.clear_secrets();
    agent.clear_secrets(); // must not panic
    assert!(!agent.is_unlocked());
}
