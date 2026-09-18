use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use jacs_core::{
    CoreAgent, CoreError, DetachedSigner, Ed25519DalekSigner, P256Signer, SigningAlgorithm,
    UnlockSecret, verify_key_rotation,
};
use serde_json::{Value, json};

const PASSWORD: &str = "rotation test encrypted candidate storage";

#[test]
fn pq_rotation_is_staged_preserves_identity_and_roundtrips_encrypted_material() {
    let mut active = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).unwrap();
    let old_identity = active.export_agent();
    let old_public_key = active.public_key().to_vec();
    let pending = active.prepare_key_rotation(None).unwrap();
    assert_eq!(active.export_agent(), old_identity);
    assert_eq!(active.public_key(), old_public_key);
    assert_eq!(pending.algorithm(), SigningAlgorithm::Pq2025);
    assert_ne!(pending.public_key(), old_public_key);
    assert_eq!(pending.agent()["jacsId"], old_identity["jacsId"]);
    assert_eq!(
        pending.agent()["jacsPreviousVersion"],
        old_identity["jacsVersion"]
    );
    assert_eq!(
        pending.agent()["jacsOriginalVersion"],
        old_identity["jacsOriginalVersion"]
    );
    assert_eq!(
        pending.agent()["jacsOriginalDate"],
        old_identity["jacsOriginalDate"]
    );
    assert_ne!(pending.agent()["jacsVersion"], old_identity["jacsVersion"]);
    assert_eq!(pending.proof()["version"], "jacs-key-rotation-v2");
    let material = pending.export_encrypted_material(PASSWORD).unwrap();
    let candidate_document = pending.agent();
    let committed = active.commit_key_rotation(pending).unwrap();
    assert_eq!(committed, candidate_document);
    assert_eq!(active.public_key(), material.public_key);
    let mut restored =
        CoreAgent::from_encrypted_material(material, UnlockSecret::Password(PASSWORD)).unwrap();
    let signed = restored
        .sign_message(&json!({"after": "rotation"}))
        .unwrap();
    assert!(active.verify(&signed).unwrap().valid);
    assert!(
        !CoreAgent::verify_with_key(&signed, &old_public_key, SigningAlgorithm::Pq2025)
            .unwrap()
            .valid
    );
    verify_key_rotation(
        &old_identity,
        &old_public_key,
        SigningAlgorithm::Pq2025,
        &committed,
        active.public_key(),
        active.algorithm(),
    )
    .unwrap();
}

#[test]
fn default_upgrades_to_pq_and_explicit_downgrades_are_rejected() {
    for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::Es256] {
        let agent = CoreAgent::ephemeral(algorithm).unwrap();
        assert_eq!(
            agent.prepare_key_rotation(None).unwrap().algorithm(),
            SigningAlgorithm::Pq2025
        );
        assert_eq!(
            agent
                .prepare_key_rotation(Some(algorithm))
                .unwrap()
                .algorithm(),
            algorithm
        );
    }
    let pq = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).unwrap();
    for weaker in [SigningAlgorithm::Ed25519, SigningAlgorithm::Es256] {
        assert!(matches!(
            pq.prepare_key_rotation(Some(weaker)),
            Err(CoreError::UnsupportedAlgorithm(_))
        ));
    }
}

#[test]
fn stale_foreign_competing_and_locked_stages_leave_active_state_unchanged() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let stale = agent
        .prepare_key_rotation(Some(SigningAlgorithm::Ed25519))
        .unwrap();
    agent
        .update_agent(&json!({"name": "changed after preparation"}))
        .unwrap();
    let updated = agent.export_agent();
    let key = agent.public_key().to_vec();
    assert!(agent.commit_key_rotation(stale).is_err());
    assert_eq!(agent.export_agent(), updated);
    assert_eq!(agent.public_key(), key);
    assert!(agent.is_unlocked());

    let foreign = CoreAgent::ephemeral(SigningAlgorithm::Ed25519)
        .unwrap()
        .prepare_key_rotation(Some(SigningAlgorithm::Ed25519))
        .unwrap();
    assert!(agent.commit_key_rotation(foreign).is_err());
    let first = agent
        .prepare_key_rotation(Some(SigningAlgorithm::Ed25519))
        .unwrap();
    let second = agent
        .prepare_key_rotation(Some(SigningAlgorithm::Ed25519))
        .unwrap();
    let committed = agent.commit_key_rotation(first).unwrap();
    assert!(agent.commit_key_rotation(second).is_err());
    assert_eq!(agent.export_agent(), committed);

    let pending = agent
        .prepare_key_rotation(Some(SigningAlgorithm::Ed25519))
        .unwrap();
    agent.clear_secrets();
    assert!(matches!(
        agent.commit_key_rotation(pending),
        Err(CoreError::Locked)
    ));
    assert!(matches!(
        agent.prepare_key_rotation(None),
        Err(CoreError::Locked)
    ));
    assert_eq!(agent.export_agent(), committed);
}

#[test]
fn proof_requires_independently_pinned_old_identity_and_exact_candidate() {
    let mut active = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let pending = active
        .prepare_key_rotation(Some(SigningAlgorithm::Ed25519))
        .unwrap();
    let material = pending.export_encrypted_material(PASSWORD).unwrap();
    let mut new_agent =
        CoreAgent::from_encrypted_material(material, UnlockSecret::Password(PASSWORD)).unwrap();
    let genuine = pending.agent();
    for (pointer, value) in [
        (
            "/jacsKeyRotationProof/oldAgentVersion",
            json!("other-old-version"),
        ),
        (
            "/jacsKeyRotationProof/newAgentVersion",
            json!("other-new-version"),
        ),
        ("/jacsKeyRotationProof/agentID", json!("other-agent")),
        (
            "/jacsKeyRotationProof/oldPublicKeyHash",
            json!("0".repeat(64)),
        ),
        (
            "/jacsKeyRotationProof/newPublicKeyHash",
            json!("0".repeat(64)),
        ),
        ("/jacsKeyRotationProof/version", json!("legacy")),
        ("/name", json!("unauthorized metadata replacement")),
    ] {
        let mut forged = genuine.clone();
        *forged.pointer_mut(pointer).unwrap() = value;
        // Give the attacker control of the new key: even a valid re-signature
        // cannot replace the independently required old-key authorization.
        resign(&mut new_agent, &mut forged);
        CoreAgent::validate_identity(&forged, new_agent.public_key(), new_agent.algorithm())
            .unwrap();
        assert!(
            active
                .verify_key_rotation(&forged, new_agent.public_key(), new_agent.algorithm())
                .is_err(),
            "accepted {pointer}"
        );
    }
    let unrelated = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    assert!(
        unrelated
            .verify_key_rotation(&genuine, pending.public_key(), pending.algorithm())
            .is_err()
    );
    let mut old_context = active.export_agent();
    old_context["name"] = json!("a different old context");
    resign(&mut active, &mut old_context);
    assert!(
        verify_key_rotation(
            &old_context,
            active.public_key(),
            active.algorithm(),
            &genuine,
            pending.public_key(),
            pending.algorithm()
        )
        .is_err()
    );
    let mut legacy = genuine.clone();
    legacy["jacsKeyRotationProof"] = json!({"transitionMessage":"JACS_KEY_ROTATION:legacy", "signature":"AA==", "signingAlgorithm":"ring-Ed25519"});
    resign(&mut new_agent, &mut legacy);
    assert!(
        active
            .verify_key_rotation(&legacy, pending.public_key(), pending.algorithm())
            .is_err()
    );
}

fn resign(agent: &mut CoreAgent, value: &mut Value) {
    value.as_object_mut().unwrap().remove("jacsSignature");
    value.as_object_mut().unwrap().remove("jacsSha256");
    agent.sign_document_inplace(value, "jacsSignature").unwrap();
    value["jacsSha256"] = json!(jacs_core::document_hash_v1(value).unwrap());
}

struct Provider {
    signer: Box<dyn DetachedSigner>,
    mode: Arc<AtomicUsize>,
    clear_calls: Arc<AtomicUsize>,
    drop_calls: Arc<AtomicUsize>,
    export_calls: Arc<AtomicUsize>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.drop_calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl DetachedSigner for Provider {
    fn algorithm(&self) -> SigningAlgorithm {
        self.signer.algorithm()
    }
    fn public_key(&self) -> &[u8] {
        self.signer.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        match self.mode.load(Ordering::SeqCst) {
            1 => Err(CoreError::SignerUnavailable(
                "test provider denied access".into(),
            )),
            2 => Ok(vec![0; 64]),
            _ => self.signer.sign(message),
        }
    }
    fn clear_secrets(&mut self) {
        self.clear_calls.fetch_add(1, Ordering::SeqCst);
        self.signer.clear_secrets();
    }
    fn export_private_key_bytes(&self) -> Result<Vec<u8>, CoreError> {
        self.export_calls.fetch_add(1, Ordering::SeqCst);
        Err(CoreError::NotExportable)
    }
}

#[derive(Default)]
struct Calls {
    mode: Arc<AtomicUsize>,
    clear: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    exported: Arc<AtomicUsize>,
}

fn provider(calls: &Calls, algorithm: SigningAlgorithm) -> Box<dyn DetachedSigner> {
    let signer: Box<dyn DetachedSigner> = match algorithm {
        SigningAlgorithm::Es256 => Box::new(P256Signer::generate().unwrap()),
        _ => Box::new(Ed25519DalekSigner::generate().unwrap()),
    };
    Box::new(Provider {
        signer,
        mode: calls.mode.clone(),
        clear_calls: calls.clear.clone(),
        drop_calls: calls.dropped.clone(),
        export_calls: calls.exported.clone(),
    })
}

#[test]
fn hardware_rotation_never_exports_keys_and_clears_the_old_provider_on_commit() {
    let old = Calls::default();
    let new = Calls::default();
    let mut agent = CoreAgent::from_signer(
        provider(&old, SigningAlgorithm::Es256),
        json!({"name":"hardware identity"}),
    )
    .unwrap();
    let pending = agent
        .prepare_key_rotation_with_signer(provider(&new, SigningAlgorithm::Es256))
        .unwrap();
    assert_eq!(old.exported.load(Ordering::SeqCst), 0);
    assert_eq!(new.exported.load(Ordering::SeqCst), 0);
    assert_eq!(old.clear.load(Ordering::SeqCst), 0);
    assert!(matches!(
        pending.export_encrypted_material(PASSWORD),
        Err(CoreError::NotExportable)
    ));
    let candidate = pending.agent();
    agent.commit_key_rotation(pending).unwrap();
    assert_eq!(agent.export_agent(), candidate);
    assert_eq!(old.clear.load(Ordering::SeqCst), 1);
    assert_eq!(old.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(new.clear.load(Ordering::SeqCst), 0);
    let signed = agent.sign_message(&json!({"hardware":"rotated"})).unwrap();
    assert!(agent.verify(&signed).unwrap().valid);
    agent.clear_secrets();
    assert_eq!(new.clear.load(Ordering::SeqCst), 1);
    assert_eq!(new.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn denied_or_corrupted_providers_never_replace_the_active_key() {
    let old = Calls::default();
    let mut agent =
        CoreAgent::from_signer(provider(&old, SigningAlgorithm::Ed25519), json!({})).unwrap();
    let old_identity = agent.export_agent();
    for mode in [1, 2] {
        old.mode.store(mode, Ordering::SeqCst);
        let new = Calls::default();
        assert!(
            agent
                .prepare_key_rotation_with_signer(provider(&new, SigningAlgorithm::Ed25519))
                .is_err()
        );
        assert_eq!(new.clear.load(Ordering::SeqCst), 1);
        assert_eq!(new.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(agent.export_agent(), old_identity);
        assert_eq!(old.clear.load(Ordering::SeqCst), 0);
    }
    old.mode.store(0, Ordering::SeqCst);
    let new = Calls::default();
    let pending = agent
        .prepare_key_rotation_with_signer(provider(&new, SigningAlgorithm::Ed25519))
        .unwrap();
    new.mode.store(2, Ordering::SeqCst);
    assert!(agent.commit_key_rotation(pending).is_err());
    assert_eq!(agent.export_agent(), old_identity);
    assert_eq!(old.clear.load(Ordering::SeqCst), 0);
    assert_eq!(new.clear.load(Ordering::SeqCst), 1);
    assert_eq!(new.dropped.load(Ordering::SeqCst), 1);
    assert!(agent.is_unlocked());
}

#[test]
fn abandoning_a_stage_clears_only_the_candidate_and_locked_old_key_can_verify() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let new = Calls::default();
    let pending = agent
        .prepare_key_rotation_with_signer(provider(&new, SigningAlgorithm::Ed25519))
        .unwrap();
    let candidate = pending.agent();
    let key = pending.public_key().to_vec();
    drop(pending);
    assert_eq!(new.clear.load(Ordering::SeqCst), 1);
    assert!(agent.is_unlocked());
    agent.clear_secrets();
    agent
        .verify_key_rotation(&candidate, &key, SigningAlgorithm::Ed25519)
        .unwrap();
}
