//! Security boundaries shared by browser and device identity bindings.
use jacs_core::{
    AgentMaterial, CoreAgent, CoreError, DetachedSigner, Ed25519DalekSigner, P256Signer,
    SigningAlgorithm, UnlockSecret,
};
use secrecy::SecretBox;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn raw_secret(private: &[u8]) -> UnlockSecret<'static> {
    UnlockSecret::RawPrivateKey(SecretBox::new(Box::new(private.to_vec())))
}

fn signed_material() -> (AgentMaterial, Vec<u8>) {
    let signer = Ed25519DalekSigner::generate().unwrap();
    let private = signer.export_private_key_bytes().unwrap();
    let agent = CoreAgent::from_signer(Box::new(signer), json!({"name": "phone"})).unwrap();
    (
        AgentMaterial {
            config: json!({}),
            agent: agent.export_agent(),
            public_key: agent.public_key().to_vec(),
            encrypted_private_key: vec![],
            algorithm: agent.algorithm(),
        },
        private,
    )
}

#[test]
fn all_algorithms_create_self_signed_identities_and_update_with_same_key() {
    for algorithm in [
        SigningAlgorithm::Ed25519,
        SigningAlgorithm::Pq2025,
        SigningAlgorithm::Es256,
    ] {
        let mut agent = CoreAgent::ephemeral(algorithm).unwrap();
        let previous = agent.export_agent();
        let public_key = agent.public_key().to_vec();
        assert!(agent.verify(&previous).unwrap().valid);
        let updated = agent
            .update_agent(&json!({"name":"device", "description":"local identity"}))
            .unwrap();
        assert_eq!(updated["jacsId"], previous["jacsId"]);
        assert_eq!(updated["jacsPreviousVersion"], previous["jacsVersion"]);
        assert_ne!(updated["jacsVersion"], previous["jacsVersion"]);
        assert_eq!(
            updated["jacsSignature"]["agentVersion"],
            updated["jacsVersion"]
        );
        assert_eq!(agent.public_key(), public_key);
        assert_eq!(updated["description"], "local identity");
        assert!(agent.verify(&updated).unwrap().valid);
        assert_eq!(
            updated["jacsSha256"],
            jacs_core::document_hash_v1(&updated).unwrap()
        );
    }
}

#[test]
fn encrypted_es256_roundtrip_reencrypt_and_clear_secrets() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Es256).unwrap();
    let exported = agent
        .export_encrypted_material("generated transfer phrase")
        .unwrap();
    let mut restored = CoreAgent::from_encrypted_material(
        exported,
        UnlockSecret::Password("generated transfer phrase"),
    )
    .unwrap();
    let stored = restored
        .export_encrypted_material("browser-local password")
        .unwrap();
    assert_eq!(agent.export_agent(), stored.agent);
    assert_eq!(agent.public_key(), stored.public_key);
    assert!(matches!(
        CoreAgent::from_encrypted_material(
            stored.clone(),
            UnlockSecret::Password("generated transfer phrase")
        ),
        Err(CoreError::InvalidPassword)
    ));
    let signed = restored.sign_message(&json!({"hello":"browser"})).unwrap();
    restored.clear_secrets();
    assert!(restored.verify(&signed).unwrap().valid);
    assert!(matches!(
        restored.sign_message(&json!({})),
        Err(CoreError::Locked)
    ));
    assert!(matches!(
        restored.update_agent(&json!({"name":"no"})),
        Err(CoreError::Locked)
    ));
    assert!(matches!(
        restored.export_encrypted_material("password"),
        Err(CoreError::Locked)
    ));
    let mut browser = CoreAgent::from_encrypted_material(
        stored,
        UnlockSecret::Password("browser-local password"),
    )
    .unwrap();
    let signed = browser.sign_message(&json!({})).unwrap();
    assert!(browser.verify(&signed).unwrap().valid);
}

#[test]
fn strict_import_rejects_tampering_stripping_key_swap_and_algorithm_mismatch() {
    let (material, private) = signed_material();
    CoreAgent::from_encrypted_material(material.clone(), raw_secret(&private)).unwrap();
    for mutate in [
        |v: &mut Value| {
            v["name"] = json!("tampered");
        },
        |v: &mut Value| {
            v["jacsId"] = json!("another-identity");
        },
        |v: &mut Value| {
            v["jacsVersion"] = json!("another-version");
        },
        |v: &mut Value| {
            v["algorithm"] = json!("es256");
        },
        |v: &mut Value| {
            v["publicKey"] = json!("AAAA");
        },
        |v: &mut Value| {
            v["jacsSha256"] = json!("bad checksum");
        },
        |v: &mut Value| {
            v["jacsSignature"]["publicKeyHash"] = json!("wrong key");
        },
        |v: &mut Value| {
            v.as_object_mut().unwrap().remove("jacsSignature");
        },
    ] {
        let mut bad = material.clone();
        mutate(&mut bad.agent);
        assert!(CoreAgent::from_encrypted_material(bad, raw_secret(&private)).is_err());
    }
    let other = Ed25519DalekSigner::generate().unwrap();
    let other_private = other.export_private_key_bytes().unwrap();
    let mut bad = material.clone();
    bad.public_key = other.public_key().to_vec();
    assert!(matches!(
        CoreAgent::from_encrypted_material(bad.clone(), raw_secret(&private)),
        Err(CoreError::MalformedKey(_))
    ));
    // Even swapping BOTH key blobs cannot authenticate the original identity.
    assert!(CoreAgent::from_encrypted_material(bad, raw_secret(&other_private)).is_err());
    assert!(CoreAgent::from_signer(Box::new(other), material.agent).is_err());
}

#[test]
fn legacy_unsigned_import_requires_explicit_opt_in_and_becomes_signed() {
    let (mut material, private) = signed_material();
    material
        .agent
        .as_object_mut()
        .unwrap()
        .remove("jacsSignature");
    material.agent.as_object_mut().unwrap().remove("jacsSha256");
    assert!(CoreAgent::from_encrypted_material(material.clone(), raw_secret(&private)).is_err());
    let migrated =
        CoreAgent::from_legacy_encrypted_material(material, raw_secret(&private)).unwrap();
    assert!(migrated.verify(&migrated.export_agent()).unwrap().valid);
    let (mut signed, private) = signed_material();
    signed.agent["name"] = json!("tampered");
    // The migration escape hatch never ignores an invalid existing signature.
    assert!(CoreAgent::from_legacy_encrypted_material(signed, raw_secret(&private)).is_err());
}

struct PlatformSigner {
    inner: P256Signer,
    deny: Arc<AtomicBool>,
    corrupt: Arc<AtomicBool>,
}
impl DetachedSigner for PlatformSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> &[u8] {
        self.inner.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.deny.load(Ordering::SeqCst) {
            return Err(CoreError::Locked);
        }
        let mut signature = self.inner.sign(message)?;
        if self.corrupt.load(Ordering::SeqCst) {
            signature[0] ^= 1;
        }
        Ok(signature)
    }
    fn clear_secrets(&mut self) {
        self.inner.clear_secrets();
    }
    // No private key export implementation: hardware defaults to NotExportable.
}

#[test]
fn platform_signer_is_nonexportable_and_updates_are_atomic_on_provider_failure() {
    let deny = Arc::new(AtomicBool::new(false));
    let corrupt = Arc::new(AtomicBool::new(false));
    let signer = PlatformSigner {
        inner: P256Signer::generate().unwrap(),
        deny: deny.clone(),
        corrupt: corrupt.clone(),
    };
    let mut agent =
        CoreAgent::from_signer(Box::new(signer), json!({"name":"hardware identity"})).unwrap();
    assert!(matches!(
        agent.export_encrypted_material("password"),
        Err(CoreError::NotExportable)
    ));
    let before = agent.export_agent();
    deny.store(true, Ordering::SeqCst);
    assert!(matches!(
        agent.update_agent(&json!({"name":"denied"})),
        Err(CoreError::Locked)
    ));
    assert_eq!(agent.export_agent(), before);
    deny.store(false, Ordering::SeqCst);
    corrupt.store(true, Ordering::SeqCst);
    assert!(matches!(
        agent.update_agent(&json!({"name":"corrupt"})),
        Err(CoreError::SignatureInvalid(_))
    ));
    assert_eq!(agent.export_agent(), before);
    corrupt.store(false, Ordering::SeqCst);
    let updated = agent.update_agent(&json!({"name":"approved"})).unwrap();
    assert!(agent.verify(&updated).unwrap().valid);
    agent.clear_secrets();
    assert!(matches!(
        agent.sign_raw_bytes(b"no"),
        Err(CoreError::Locked)
    ));
    assert!(matches!(
        agent.export_encrypted_material("password"),
        Err(CoreError::Locked)
    ));
}

#[test]
fn updates_reject_protected_identity_fields_and_verification_downgrade() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let before = agent.export_agent();
    for field in [
        "jacsId",
        "jacsVersion",
        "algorithm",
        "publicKey",
        "jacsSignature",
        "jacsOriginalVersion",
        "jacsRegistration",
    ] {
        let mut update = json!({});
        update[field] = json!("replace");
        assert!(agent.update_agent(&update).is_err());
        assert_eq!(agent.export_agent(), before);
    }
    agent
        .update_agent(&json!({"jacsVerificationClaim":"verified"}))
        .unwrap();
    let verified = agent.export_agent();
    assert!(
        agent
            .update_agent(&json!({"jacsVerificationClaim":"unverified"}))
            .is_err()
    );
    assert_eq!(agent.export_agent(), verified);
    // Full exported documents are accepted with unchanged protected fields.
    let mut full = verified;
    full["name"] = json!("new name");
    agent.update_agent(&full).unwrap();
}

#[test]
fn es256_wire_encoding_is_canonical_and_matches_independent_verifier() {
    use p256::ecdsa::signature::Verifier;
    let mut signer = P256Signer::generate().unwrap();
    let public = signer.public_key().to_vec();
    let secret = signer.export_private_key_bytes().unwrap();
    let signature = signer.sign(b"hardware-compatible").unwrap();
    assert_eq!(public.len(), 65);
    assert_eq!(public[0], 4);
    assert_eq!(secret.len(), 32);
    assert_eq!(signature.len(), 64);
    let parsed = p256::ecdsa::Signature::from_slice(&signature).unwrap();
    assert_eq!(parsed.normalize_s(), parsed);
    let verify_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public).unwrap();
    verify_key.verify(b"hardware-compatible", &parsed).unwrap();
    P256Signer::verify(&public, b"hardware-compatible", &signature).unwrap();
    assert!(P256Signer::verify(&public, b"tampered", &signature).is_err());
    assert!(
        P256Signer::verify(&public, b"hardware-compatible", parsed.to_der().as_bytes()).is_err()
    );
    assert!(
        P256Signer::verify(
            verify_key.to_sec1_point(true).as_bytes(),
            b"hardware-compatible",
            &signature
        )
        .is_err()
    );
    let restored = P256Signer::from_private_bytes(&secret).unwrap();
    assert_eq!(restored.public_key(), public);
    assert_eq!(restored.sign(b"hardware-compatible").unwrap(), signature);
    signer.clear_secrets();
    assert_eq!(signer.public_key(), public);
    assert!(matches!(signer.sign(b"message"), Err(CoreError::Locked)));
    assert!(matches!(
        signer.export_private_key_bytes(),
        Err(CoreError::Locked)
    ));
    assert_eq!(
        SigningAlgorithm::from_wire_str("ES256"),
        Some(SigningAlgorithm::Es256)
    );
    assert_eq!(
        serde_json::to_string(&SigningAlgorithm::Es256).unwrap(),
        "\"es256\""
    );
}

#[test]
fn public_key_pem_preserves_native_registration_formats() {
    use base64::Engine as _;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::pkcs8::DecodePublicKey;
    for algorithm in [
        SigningAlgorithm::Ed25519,
        SigningAlgorithm::Pq2025,
        SigningAlgorithm::Es256,
    ] {
        let agent = CoreAgent::ephemeral(algorithm).unwrap();
        let pem = agent.public_key_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
        let encoded: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        if algorithm == SigningAlgorithm::Es256 {
            let key = p256::PublicKey::from_public_key_der(&decoded).unwrap();
            assert_eq!(key.to_sec1_point(false).as_bytes(), agent.public_key());
        } else {
            assert_eq!(decoded, agent.public_key());
        }
    }
}

#[test]
fn native_legacy_public_key_hash_is_accepted_only_with_valid_exact_key_signature() {
    use base64::Engine as _;
    use jacs_core::verify::{build_signature_content_v2, sha256_hex};
    let (mut material, private) = signed_material();
    let signer = Ed25519DalekSigner::from_pkcs8(&private).unwrap();
    let (encoding, _) =
        encoding_rs::Encoding::for_bom(&material.public_key).unwrap_or((encoding_rs::UTF_8, 0));
    let decoded = encoding.decode(&material.public_key).0;
    let legacy = sha256_hex(decoded.trim().replace('\r', "").as_bytes());
    material.agent["jacsSignature"]["publicKeyHash"] = json!(legacy);
    let fields: Vec<String> = material.agent["jacsSignature"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let canonical = build_signature_content_v2(
        &material.agent,
        &fields,
        "jacsSignature",
        &material.agent["jacsSignature"],
    )
    .unwrap();
    material.agent["jacsSignature"]["signature"] = json!(
        base64::engine::general_purpose::STANDARD
            .encode(signer.sign(canonical.as_bytes()).unwrap())
    );
    material.agent["jacsSha256"] = json!(jacs_core::document_hash_v1(&material.agent).unwrap());
    CoreAgent::validate_identity(&material.agent, &material.public_key, material.algorithm)
        .unwrap();
    CoreAgent::from_encrypted_material(material.clone(), raw_secret(&private)).unwrap();
    material.agent["name"] = json!("tampered");
    material.agent["jacsSha256"] = json!(jacs_core::document_hash_v1(&material.agent).unwrap());
    assert!(matches!(
        CoreAgent::validate_identity(&material.agent, &material.public_key, material.algorithm),
        Err(CoreError::SignatureInvalid(_))
    ));
}

#[test]
fn native_previous_version_signatures_require_the_exact_authenticated_link() {
    use base64::Engine as _;
    use jacs_core::verify::{build_signature_content_v2, default_signed_fields};
    let (mut material, private) = signed_material();
    let signer = Ed25519DalekSigner::from_pkcs8(&private).unwrap();
    let previous = material.agent["jacsVersion"].clone();
    material.agent["jacsPreviousVersion"] = previous.clone();
    material.agent["jacsVersion"] = json!(uuid::Uuid::new_v4().to_string());
    material.agent["jacsSignature"]["agentVersion"] = previous;
    let fields = default_signed_fields(&material.agent, "jacsSignature");
    material.agent["jacsSignature"]["fields"] = json!(fields);
    let resign = |agent: &mut Value| {
        let canonical =
            build_signature_content_v2(agent, &fields, "jacsSignature", &agent["jacsSignature"])
                .unwrap();
        agent["jacsSignature"]["signature"] = json!(
            base64::engine::general_purpose::STANDARD
                .encode(signer.sign(canonical.as_bytes()).unwrap())
        );
        agent["jacsSha256"] = json!(jacs_core::document_hash_v1(agent).unwrap());
    };
    resign(&mut material.agent);
    CoreAgent::validate_identity(&material.agent, &material.public_key, material.algorithm)
        .unwrap();
    CoreAgent::from_encrypted_material(material.clone(), raw_secret(&private)).unwrap();
    material.agent["jacsSignature"]["agentVersion"] = json!("unrelated-old-version");
    resign(&mut material.agent);
    assert!(matches!(
        CoreAgent::validate_identity(&material.agent, &material.public_key, material.algorithm),
        Err(CoreError::MalformedDocument(_))
    ));
}

#[test]
fn metadata_update_authenticates_as_previous_identity_and_rolls_back_on_auth_denial() {
    let deny = Arc::new(AtomicBool::new(false));
    let signer = PlatformSigner {
        inner: P256Signer::generate().unwrap(),
        deny: deny.clone(),
        corrupt: Arc::new(AtomicBool::new(false)),
    };
    let mut agent = CoreAgent::from_signer(Box::new(signer), json!({"name":"hardware"})).unwrap();
    let before = agent.export_agent();
    let old_lookup = format!(
        "{}:{}",
        before["jacsId"].as_str().unwrap(),
        before["jacsVersion"].as_str().unwrap()
    );
    let url = "https://hai.example/api/v1/agents/register";
    let denied = agent.update_agent_with_prepare::<String, CoreError>(
        &json!({"name":"not committed"}),
        |old, candidate| {
            assert_eq!(old.export_agent(), before);
            assert_ne!(candidate["jacsVersion"], before["jacsVersion"]);
            deny.store(true, Ordering::SeqCst);
            old.build_request_auth_header(
                "POST",
                url,
                &serde_json::to_vec(candidate).unwrap(),
                "hai.ai",
            )
        },
    );
    assert!(matches!(denied, Err(CoreError::Locked)));
    assert_eq!(agent.export_agent(), before);
    deny.store(false, Ordering::SeqCst);
    let (updated, (body, header)) = agent
        .update_agent_with_prepare::<_, CoreError>(
            &json!({"name":"committed"}),
            |old, candidate| {
                let body = serde_json::to_vec(candidate).unwrap();
                let header = jacs_core::request_auth::build_request_auth_header_at(
                    old,
                    "POST",
                    url,
                    &body,
                    "hai.ai",
                    1_800_000_000,
                )?;
                Ok((body, header))
            },
        )
        .unwrap();
    let claims =
        jacs_core::request_auth::verify_request_auth_header_with_trusted_key_without_replay(
            &header,
            agent.public_key(),
            &old_lookup,
            "POST",
            url,
            &body,
            "hai.ai",
            60,
            1_800_000_000,
        )
        .unwrap();
    assert_eq!(claims.key_id, old_lookup);
    assert_eq!(agent.export_agent(), updated);
    assert_eq!(updated["jacsPreviousVersion"], before["jacsVersion"]);
}

#[test]
fn staged_updates_reject_stale_tampered_and_resigned_protected_metadata() {
    let (material, private) = signed_material();
    let mut agent = CoreAgent::from_encrypted_material(material, raw_secret(&private)).unwrap();
    agent
        .update_agent(&json!({"jacsVerificationClaim":"verified"}))
        .unwrap();
    let before = agent.export_agent();
    let first = agent
        .prepare_agent_update(&json!({"name":"first"}))
        .unwrap();
    let competing = agent
        .prepare_agent_update(&json!({"name":"second"}))
        .unwrap();
    assert_eq!(
        agent.export_agent(),
        before,
        "preparing leaves active identity unchanged"
    );
    let mut tampered = first.clone();
    tampered["name"] = json!("not signed");
    assert!(agent.commit_agent_update(&tampered).is_err());
    assert_eq!(agent.export_agent(), before);

    for (field, value) in [
        ("jacsId", json!("different-identity")),
        (
            "jacsOriginalVersion",
            json!(uuid::Uuid::new_v4().to_string()),
        ),
        ("$schema", json!("https://untrusted.example/schema")),
        ("jacsVerificationClaim", json!("unverified")),
        ("jacsPreviousVersion", json!("wrong-predecessor")),
    ] {
        let mut forged = first.clone();
        forged.as_object_mut().unwrap().remove("jacsSignature");
        forged.as_object_mut().unwrap().remove("jacsSha256");
        forged[field] = value;
        // Even a valid signature by the same key cannot bypass commit invariants.
        let signed = CoreAgent::from_signer(
            Box::new(Ed25519DalekSigner::from_pkcs8(&private).unwrap()),
            forged,
        )
        .unwrap()
        .export_agent();
        assert!(
            agent.commit_agent_update(&signed).is_err(),
            "protected field {field}"
        );
        assert_eq!(agent.export_agent(), before);
    }
    assert_eq!(agent.commit_agent_update(&first).unwrap(), first);
    assert!(
        agent.commit_agent_update(&competing).is_err(),
        "competing prepared update is stale"
    );
    assert!(
        agent.commit_agent_update(&first).is_err(),
        "repeated commit is stale"
    );
    assert_eq!(agent.export_agent(), first);
}

#[test]
fn malformed_hardware_request_auth_signature_does_not_commit_metadata_update() {
    let corrupt = Arc::new(AtomicBool::new(false));
    let signer = PlatformSigner {
        inner: P256Signer::generate().unwrap(),
        deny: Arc::new(AtomicBool::new(false)),
        corrupt: corrupt.clone(),
    };
    let mut agent = CoreAgent::from_signer(Box::new(signer), json!({})).unwrap();
    let before = agent.export_agent();
    let result = agent.update_agent_with_prepare::<String, CoreError>(
        &json!({"name":"must not commit"}),
        |old, candidate| {
            corrupt.store(true, Ordering::SeqCst);
            old.build_request_auth_header(
                "POST",
                "https://hai.example/api/v1/agents/register",
                &serde_json::to_vec(candidate).unwrap(),
                "hai.ai",
            )
        },
    );
    assert!(matches!(result, Err(CoreError::SignatureInvalid(_))));
    assert_eq!(agent.export_agent(), before);
}
