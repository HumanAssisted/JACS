use jacs_core::transfer::*;
use jacs_core::{CoreAgent, SigningAlgorithm, UnlockSecret};
use serde_json::json;

#[test]
fn six_generated_words_are_from_fixed_vocabulary() {
    let words: std::collections::HashSet<_> =
        include_str!("../src/transfer-words.txt").lines().collect();
    assert_eq!(words.len(), 2048);
    let code = generate_transfer_code().unwrap();
    assert_eq!(code.split_whitespace().count(), 6);
    assert!(code.split_whitespace().all(|word| words.contains(word)));
    assert_eq!(TRANSFER_CODE_ENTROPY_BITS, 66);
}

#[test]
fn all_algorithms_transfer_rewrap_unlock_and_sign() {
    for algorithm in [
        SigningAlgorithm::Ed25519,
        SigningAlgorithm::Pq2025,
        SigningAlgorithm::Es256,
    ] {
        let sender = CoreAgent::ephemeral(algorithm).unwrap();
        let id = sender.export_agent()["jacsId"].as_str().unwrap().to_owned();
        let code = generate_transfer_code().unwrap();
        let material = sender.export_encrypted_material(&code).unwrap();
        validate_transfer_material(&material).unwrap();
        let destination = reencrypt_transferred_material(
            material,
            &code,
            &id,
            sender.public_key(),
            algorithm,
            "destination-secret-from-password-or-prf",
        )
        .unwrap();
        assert!(
            CoreAgent::from_encrypted_material(destination.clone(), UnlockSecret::Password(&code))
                .is_err()
        );
        let mut receiver = CoreAgent::from_encrypted_material(
            destination,
            UnlockSecret::Password("destination-secret-from-password-or-prf"),
        )
        .unwrap();
        let message = receiver.sign_message(&json!({"from":"receiver"})).unwrap();
        assert!(sender.verify(&message).unwrap().valid);
        receiver.clear_secrets();
        assert!(receiver.sign_message(&json!({})).is_err());
    }
}

#[test]
fn transfer_rejects_substitution_unsigned_identity_and_plaintext() {
    let sender = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let id = sender.export_agent()["jacsId"].as_str().unwrap().to_owned();
    let material = sender.export_encrypted_material("transfer-secret").unwrap();
    assert!(
        import_transferred_agent(
            material.clone(),
            "transfer-secret",
            "another-agent",
            sender.public_key(),
            sender.algorithm()
        )
        .is_err()
    );
    assert!(
        import_transferred_agent(
            material.clone(),
            "transfer-secret",
            &id,
            &[0; 32],
            sender.algorithm()
        )
        .is_err()
    );
    assert!(
        import_transferred_agent(
            material.clone(),
            "transfer-secret",
            &id,
            sender.public_key(),
            SigningAlgorithm::Es256
        )
        .is_err()
    );
    assert!(
        reencrypt_transferred_material(
            material.clone(),
            "transfer-secret",
            &id,
            sender.public_key(),
            sender.algorithm(),
            "transfer-secret"
        )
        .is_err()
    );
    let mut altered = material.clone();
    altered.agent["name"] = json!("substituted");
    assert!(validate_transfer_material(&altered).is_err());
    altered = material.clone();
    altered
        .agent
        .as_object_mut()
        .unwrap()
        .remove("jacsSignature");
    assert!(validate_transfer_material(&altered).is_err());
    altered = material.clone();
    altered.encrypted_private_key = vec![42; 32];
    assert!(validate_transfer_material(&altered).is_err());
    altered = material;
    altered.config = json!({"password":"do-not-relay"});
    assert!(validate_transfer_material(&altered).is_err());
}

#[test]
fn hostile_kdf_rejected_without_derivation() {
    let sender = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let mut material = sender.export_encrypted_material("transfer-secret").unwrap();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&material.encrypted_private_key).unwrap();
    envelope["kdf"]["m_cost_kib"] = json!(u32::MAX);
    material.encrypted_private_key = serde_json::to_vec(&envelope).unwrap();
    assert!(validate_transfer_material(&material).is_err());
}

#[test]
fn unknown_material_fields_cannot_hide_plaintext_secrets_from_relay_validation() {
    let sender = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let material = sender.export_encrypted_material("transfer-secret").unwrap();
    let mut wire = serde_json::to_value(material).unwrap();
    wire["private_key"] = json!("accidental-plaintext-must-not-be-relayed");
    assert!(serde_json::from_value::<jacs_core::AgentMaterial>(wire).is_err());
}
