use jacs_core::sign::P256Signer;
use jacs_core::{CoreAgent, DetachedSigner, SigningAlgorithm};
use jacs_mobile::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[test]
fn portable_material_roundtrip_and_locked_lifecycle() {
    for algorithm in [
        MobileAlgorithm::Ed25519,
        MobileAlgorithm::Pq2025,
        MobileAlgorithm::Es256,
    ] {
        let sender = MobileAgent::create(algorithm).unwrap();
        let code = generate_transfer_code().unwrap();
        assert_eq!(code.split(' ').count(), 6);
        let encrypted = sender.export_encrypted_agent(code.clone()).unwrap();
        let material_json = material_to_json(encrypted.clone()).unwrap();
        // Portable core consumes EXACTLY the wire JSON emitted by mobile.
        let core_material: jacs_core::AgentMaterial = serde_json::from_str(&material_json).unwrap();
        let core = CoreAgent::from_encrypted_material(
            core_material,
            jacs_core::UnlockSecret::Password(&code),
        )
        .unwrap();
        let agent_id = core.export_agent()["jacsId"].as_str().unwrap().to_string();
        let restored = MobileAgent::import_pinned(
            material_from_json(material_json).unwrap(),
            code.clone(),
            agent_id.clone(),
            sender.public_key().unwrap(),
            algorithm,
        )
        .unwrap();
        let signed = restored
            .sign_message_json(r#"{"hello":"mobile"}"#.into())
            .unwrap();
        assert!(sender.verify_json(signed.clone()).unwrap().valid);
        assert!(
            core.verify(&serde_json::from_str(&signed).unwrap())
                .unwrap()
                .valid
        );
        assert!(
            MobileAgent::import_encrypted_agent(encrypted.clone(), "wrong-password".into())
                .is_err()
        );
        assert!(
            MobileAgent::import_pinned(
                encrypted.clone(),
                code.clone(),
                "wrong-id".into(),
                sender.public_key().unwrap(),
                algorithm
            )
            .is_err()
        );
        let saved = reencrypt_transferred_material(
            encrypted,
            code,
            agent_id,
            sender.public_key().unwrap(),
            algorithm,
            "long-destination-secret".into(),
        )
        .unwrap();
        assert!(
            MobileAgent::import_encrypted_agent(saved, "long-destination-secret".into()).is_ok()
        );
        restored.clear_secrets().unwrap();
        restored.clear_secrets().unwrap();
        assert!(!restored.is_unlocked().unwrap());
        assert!(restored.sign_message_json("{}".into()).is_err());
        assert!(restored.export_encrypted_agent("password".into()).is_err());
        assert!(restored.verify_json(signed).unwrap().valid);
    }
}

struct FakeHardware {
    signer: P256Signer,
    cleared: Arc<AtomicBool>,
    denied: Arc<AtomicBool>,
}
impl PlatformSigner for FakeHardware {
    fn algorithm(&self) -> MobileAlgorithm {
        MobileAlgorithm::Es256
    }
    fn public_key(&self) -> Result<Vec<u8>, PlatformSignerError> {
        Ok(self.signer.public_key().to_vec())
    }
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, PlatformSignerError> {
        if self.denied.load(Ordering::SeqCst) {
            return Err(PlatformSignerError::Cancelled);
        }
        self.signer
            .sign(&message)
            .map_err(|e| PlatformSignerError::Failed {
                detail: e.to_string(),
            })
    }
    fn clear_secrets(&self) {
        self.cleared.store(true, Ordering::SeqCst);
    }
}

#[test]
fn callback_signer_cannot_export_and_identity_updates_remain_signed() {
    let template = CoreAgent::ephemeral(SigningAlgorithm::Es256).unwrap();
    let mut identity = template.export_agent();
    identity.as_object_mut().unwrap().remove("jacsSignature");
    identity.as_object_mut().unwrap().remove("jacsSha256");
    // from_signer fills/replaces the public key binding for unsigned identities.
    identity
        .as_object_mut()
        .unwrap()
        .remove("jacsPublicKeyHash");
    identity.as_object_mut().unwrap().remove("publicKey");
    let cleared = Arc::new(AtomicBool::new(false));
    let denied = Arc::new(AtomicBool::new(false));
    let callback = FakeHardware {
        signer: P256Signer::generate().unwrap(),
        cleared: cleared.clone(),
        denied: denied.clone(),
    };
    let agent =
        MobileAgent::from_platform_signer(Box::new(callback), identity.to_string()).unwrap();
    let signed = agent.sign_message_json("{\"x\":1}".into()).unwrap();
    assert!(agent.verify_json(signed).unwrap().valid);
    match agent.export_encrypted_agent("secret".into()).unwrap_err() {
        MobileError::Core { code, .. } => assert_eq!(code, "NotExportable"),
        e => panic!("unexpected error: {e}"),
    }
    let prior = agent.export_agent_json().unwrap();
    let updated = agent
        .update_agent("{\"jacsName\":\"Phone\"}".into())
        .unwrap();
    assert_ne!(
        serde_json::from_str::<serde_json::Value>(&prior).unwrap()["jacsVersion"],
        serde_json::from_str::<serde_json::Value>(&updated).unwrap()["jacsVersion"]
    );
    assert!(agent.verify_json(updated.clone()).unwrap().valid);
    denied.store(true, Ordering::SeqCst);
    assert!(
        agent
            .update_agent("{\"jacsName\":\"Denied\"}".into())
            .is_err()
    );
    assert_eq!(agent.export_agent_json().unwrap(), updated);
    agent.clear_secrets().unwrap();
    assert!(cleared.load(Ordering::SeqCst));
}

#[test]
fn strict_json_rejects_duplicate_keys() {
    let agent = MobileAgent::create_default().unwrap();
    assert!(agent.sign_message_json("{\"x\":1,\"x\":2}".into()).is_err());
}

#[test]
fn staged_update_preserves_active_identity_until_commit() {
    let agent = MobileAgent::create_default().unwrap();
    let original = agent.export_agent_json().unwrap();
    let candidate = agent
        .prepare_agent_update_json(r#"{"jacsName":"Phone"}"#.into())
        .unwrap();
    assert_eq!(agent.export_agent_json().unwrap(), original);
    assert!(agent.verify_json(candidate.clone()).unwrap().valid);
    let signed = agent.sign_message_json("{}".into()).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&signed).unwrap()["jacsSignature"]["agentVersion"],
        serde_json::from_str::<serde_json::Value>(&original).unwrap()["jacsVersion"]
    );
    let committed = agent.commit_agent_update_json(candidate.clone()).unwrap();
    assert_eq!(committed, candidate);
    assert_eq!(agent.export_agent_json().unwrap(), candidate);
}

#[test]
fn default_creation_is_post_quantum() {
    assert_eq!(MobileAlgorithm::default(), MobileAlgorithm::Pq2025);
    let agent = MobileAgent::create_default().unwrap();
    assert_eq!(agent.algorithm().unwrap(), MobileAlgorithm::Pq2025);
    assert!(
        agent
            .verify_json(agent.sign_message_json("{}".into()).unwrap())
            .unwrap()
            .valid
    );
}

#[test]
fn hardware_high_s_signatures_are_normalized_and_verified_before_release() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::sync::Mutex;

    struct HighSHardware {
        signer: P256Signer,
        returned_signature: Arc<Mutex<Vec<u8>>>,
    }
    impl PlatformSigner for HighSHardware {
        fn algorithm(&self) -> MobileAlgorithm {
            MobileAlgorithm::Es256
        }
        fn public_key(&self) -> Result<Vec<u8>, PlatformSignerError> {
            Ok(self.signer.public_key().to_vec())
        }
        fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, PlatformSignerError> {
            // Hardware ECDSA commonly returns either S representative. Force
            // n-s using public curve metadata, independently of normalize_s.
            const ORDER: [u8; 32] = [
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
                0xfc, 0x63, 0x25, 0x51,
            ];
            let mut signature = self.signer.sign(&message).unwrap();
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let difference = i16::from(ORDER[i]) - i16::from(signature[32 + i]) - borrow;
                signature[32 + i] = difference as u8;
                borrow = i16::from(difference < 0);
            }
            assert_eq!(borrow, 0);
            let parsed = p256::ecdsa::Signature::from_slice(&signature).unwrap();
            assert_ne!(
                parsed.normalize_s(),
                parsed,
                "callback really returns high-S"
            );
            *self.returned_signature.lock().unwrap() = signature.clone();
            Ok(signature)
        }
        fn clear_secrets(&self) {}
    }

    let signer = P256Signer::generate().unwrap();
    let public_key = signer.public_key().to_vec();
    let returned_signature = Arc::new(Mutex::new(Vec::new()));
    let agent = MobileAgent::from_platform_signer(
        Box::new(HighSHardware {
            signer,
            returned_signature: returned_signature.clone(),
        }),
        r#"{"jacsName":"High-S platform test"}"#.into(),
    )
    .expect("platform identity self-signature is normalized too");
    let identity = agent.export_agent_json().unwrap();
    assert!(agent.verify_json(identity).unwrap().valid);

    let message = "hardware-origin ES256 signature";
    let emitted = STANDARD
        .decode(agent.sign_string(message.into()).unwrap())
        .unwrap();
    let high = returned_signature.lock().unwrap().clone();
    assert_ne!(emitted, high, "raw hardware high-S bytes must not escape");
    assert_eq!(
        p256::ecdsa::Signature::from_slice(&high)
            .unwrap()
            .normalize_s()
            .to_bytes()
            .as_slice(),
        emitted,
    );
    jacs_core::verify::verify_detached(
        SigningAlgorithm::Es256,
        &public_key,
        message.as_bytes(),
        &emitted,
    )
    .expect("normalized callback output verifies with the advertised key");
    assert!(
        jacs_core::verify::verify_detached(
            SigningAlgorithm::Es256,
            &public_key,
            message.as_bytes(),
            &high,
        )
        .is_err()
    );

    let document = agent
        .sign_message_json(r#"{"platform":"high-S"}"#.into())
        .unwrap();
    assert!(agent.verify_json(document).unwrap().valid);
}

#[test]
fn human_recovery_interoperates_with_core_and_rejects_wrong_pins() {
    let mobile = MobileAgent::create_human().unwrap();
    let identity: serde_json::Value =
        serde_json::from_str(&mobile.export_agent_json().unwrap()).unwrap();
    let id = identity["jacsId"].as_str().unwrap().to_string();
    assert_eq!(identity["jacsAgentType"], "human");
    assert_eq!(mobile.algorithm().unwrap(), MobileAlgorithm::Pq2025);
    assert!(mobile.verify_json(identity.to_string()).unwrap().valid);
    let backup = mobile.export_recovery().unwrap();
    let wire = material_to_json(backup.material.clone()).unwrap();
    let core = jacs_core::recovery::import_recovery(
        serde_json::from_str(&wire).unwrap(),
        &backup.code,
        &id,
        &mobile.public_key().unwrap(),
        SigningAlgorithm::Pq2025,
    )
    .unwrap();
    assert_eq!(core.export_agent(), identity);
    let core_backup = jacs_core::recovery::export_recovery(&core).unwrap();
    let restored = MobileAgent::import_recovery(
        core_backup.material.into(),
        core_backup.code.to_lowercase(),
        id.clone(),
        mobile.public_key().unwrap(),
        MobileAlgorithm::Pq2025,
    )
    .unwrap();
    let signed = restored
        .sign_message_json(r#"{"human":"restored"}"#.into())
        .unwrap();
    assert!(
        core.verify(&serde_json::from_str(&signed).unwrap())
            .unwrap()
            .valid
    );
    assert!(
        MobileAgent::import_recovery(
            backup.material.clone(),
            generate_recovery_code().unwrap(),
            id.clone(),
            mobile.public_key().unwrap(),
            MobileAlgorithm::Pq2025
        )
        .is_err()
    );
    assert!(
        MobileAgent::import_recovery(
            backup.material.clone(),
            backup.code.clone(),
            "wrong-id".into(),
            mobile.public_key().unwrap(),
            MobileAlgorithm::Pq2025
        )
        .is_err()
    );
    let mut malformed = backup.material;
    malformed.encrypted_private_key.truncate(2);
    assert!(
        MobileAgent::import_recovery(
            malformed,
            backup.code,
            id,
            mobile.public_key().unwrap(),
            MobileAlgorithm::Pq2025
        )
        .is_err()
    );
    assert!(
        mobile
            .verify_json(mobile.sign_message_json("{}".into()).unwrap())
            .unwrap()
            .valid
    );
    mobile.clear_secrets().unwrap();
    assert!(mobile.export_recovery().is_err());
}

#[test]
fn recovery_readback_and_complete_document_use_public_only_results() {
    let agent = MobileAgent::create_human().unwrap();
    let identity: serde_json::Value =
        serde_json::from_str(&agent.export_agent_json().unwrap()).unwrap();
    let backup = agent.export_recovery().unwrap();
    assert_eq!(
        normalize_recovery_code(backup.code.to_lowercase()).unwrap(),
        backup.code
    );
    let verified = verify_recovery(
        backup.material,
        backup.code,
        identity["jacsId"].as_str().unwrap().into(),
        agent.public_key().unwrap(),
        MobileAlgorithm::Pq2025,
    )
    .unwrap();
    assert_eq!(verified, agent.export_agent_json().unwrap());
    let signed = agent
        .sign_document_json(r#"{"exact":"terms"}"#.into())
        .unwrap();
    let document: serde_json::Value = serde_json::from_str(&signed).unwrap();
    assert_eq!(document["content"], serde_json::json!({"exact":"terms"}));
    assert_eq!(
        document["jacsSha256"],
        jacs_core::document_hash_v1(&document).unwrap()
    );
    assert!(agent.verify_json(signed).unwrap().valid);
    agent.clear_secrets().unwrap();
    assert!(agent.sign_document_json("{}".into()).is_err());
}

#[test]
fn prepared_document_roundtrip_refuses_changed_context_wrong_key_duplicates_and_locked_handle() {
    let agent = MobileAgent::create_human().unwrap();
    let identity: serde_json::Value =
        serde_json::from_str(&agent.export_agent_json().unwrap()).unwrap();
    let scope = jacs_core::SigningKeyScope::from_public_key(
        identity["jacsId"].as_str().unwrap(),
        identity["jacsVersion"].as_str().unwrap(),
        SigningAlgorithm::Pq2025,
        &agent.public_key().unwrap(),
        [
            jacs_core::SigningPurpose::Document,
            jacs_core::SigningPurpose::LegacyRaw,
        ],
        jacs_core::PurposeIsolationAssurance::SharedRawCapable,
    )
    .unwrap();
    let prepared = jacs_core::prepare_message_v2(
        &scope,
        &serde_json::json!({"full": "frozen mobile document"}),
        jacs_core::SignatureMetadataV2::now(),
    )
    .unwrap();
    let serialized = serde_json::to_string(&prepared).unwrap();
    let signed = agent
        .sign_prepared_document_json(serialized.clone())
        .unwrap();
    assert!(agent.verify_json(signed.clone()).unwrap().valid);
    let mut unsigned: serde_json::Value = serde_json::from_str(&signed).unwrap();
    assert_eq!(
        unsigned["jacsSha256"],
        jacs_core::document_hash_v1(&unsigned).unwrap()
    );
    unsigned.as_object_mut().unwrap().remove("jacsSha256");
    unsigned["jacsSignature"]["signature"] = serde_json::json!("");
    assert_eq!(&unsigned, prepared.unsigned_envelope());
    let mut changed = serde_json::to_value(&prepared).unwrap();
    changed["signingRequestContext"]["identity"] = serde_json::json!("another-owner");
    assert!(
        agent
            .sign_prepared_document_json(changed.to_string())
            .is_err()
    );
    let other = MobileAgent::create_human().unwrap();
    assert!(
        other
            .sign_prepared_document_json(serialized.clone())
            .is_err()
    );
    let duplicate = format!("{{\"profile\":\"duplicate\",{}", &serialized[1..]);
    assert!(agent.sign_prepared_document_json(duplicate).is_err());
    agent.clear_secrets().unwrap();
    assert!(matches!(agent.sign_prepared_document_json(serialized),
        Err(MobileError::Core { code, .. }) if code == "Locked"));
}

#[test]
fn staged_rotation_reopens_ciphertext_and_checks_public_acceptance() {
    let agent = MobileAgent::create_human().unwrap();
    let password = "mobile rotation local wrapping secret".to_string();
    let old = agent.export_agent_json().unwrap();
    let old_material = agent.export_encrypted_agent(password.clone()).unwrap();
    let stage = agent.prepare_key_rotation(password.clone()).unwrap();
    agent.clear_secrets().unwrap();
    assert!(
        agent
            .sign_rotation_document_json(stage.clone(), password.clone(), "{}".into())
            .is_err()
    );
    let agent = MobileAgent::import_encrypted_agent(old_material, password.clone()).unwrap();
    assert_eq!(
        agent
            .validate_key_rotation(stage.clone(), password.clone())
            .unwrap(),
        stage.agent_json
    );
    let proof = agent
        .sign_rotation_document_json(stage.clone(), password.clone(), "{\"challenge\":1}".into())
        .unwrap();
    assert!(
        jacs_mobile::verify_with_key(proof, stage.public_key.clone(), MobileAlgorithm::Pq2025)
            .unwrap()
            .valid
    );
    let recovery = agent
        .export_rotation_recovery(stage.clone(), password.clone())
        .unwrap();
    let identity: serde_json::Value = serde_json::from_str(&stage.agent_json).unwrap();
    assert_eq!(
        jacs_mobile::verify_recovery(
            recovery.material,
            recovery.code,
            identity["jacsId"].as_str().unwrap().into(),
            stage.public_key.clone(),
            MobileAlgorithm::Pq2025
        )
        .unwrap(),
        stage.agent_json
    );
    assert_eq!(agent.export_agent_json().unwrap(), old);
    agent
        .commit_key_rotation(
            stage.clone(),
            password,
            stage.agent_json.clone(),
            stage.public_key.clone(),
        )
        .unwrap();
    let metadata = agent.describe().unwrap();
    assert_eq!(metadata.agent_json, stage.agent_json);
    assert_eq!(
        metadata.public_key_hash,
        jacs_core::verify::sha256_hex(&stage.public_key)
    );
    assert!(
        metadata
            .public_key_pem
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );
}
