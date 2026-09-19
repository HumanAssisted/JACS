use jacs_core::{
    CoreAgent, CoreError, DetachedSigner, PreparedDocumentV2, PurposeIsolationAssurance,
    SignatureMetadataV2, SigningAlgorithm, SigningKeyScope, SigningPurpose, document_hash_v1,
    prepare_message_v2,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn prepare(agent: &CoreAgent) -> PreparedDocumentV2 {
    let identity = agent.export_agent();
    let scope = SigningKeyScope::from_public_key(
        identity["jacsId"].as_str().unwrap(),
        identity["jacsVersion"].as_str().unwrap(),
        agent.algorithm(),
        agent.public_key(),
        [SigningPurpose::Document, SigningPurpose::LegacyRaw],
        PurposeIsolationAssurance::SharedRawCapable,
    )
    .unwrap();
    prepare_message_v2(
        &scope,
        &json!({"exact": "frozen\n第二行", "nested": {"count": 3}}),
        SignatureMetadataV2 {
            date: "2026-01-01T00:00:00Z".into(),
            iat: 1767225600,
            jti: "prepared-before-client-dispatch".into(),
        },
    )
    .unwrap()
}

#[test]
fn prepared_document_preserves_every_frozen_field_and_verifies() {
    let mut agent = CoreAgent::create_human().unwrap();
    let prepared = prepare(&agent);
    let serialized = serde_json::to_string(&prepared).unwrap();
    let received: PreparedDocumentV2 = serde_json::from_str(&serialized).unwrap();
    let signed = agent.sign_prepared_document(&received).unwrap();
    assert_eq!(signed["jacsSha256"], document_hash_v1(&signed).unwrap());
    assert!(agent.verify(&signed).unwrap().valid);
    let mut unsigned = signed;
    unsigned.as_object_mut().unwrap().remove("jacsSha256");
    unsigned["jacsSignature"]["signature"] = json!("");
    assert_eq!(&unsigned, prepared.unsigned_envelope());
    assert_eq!(serde_json::to_string(&received).unwrap(), serialized);
    agent.clear_secrets();
    assert!(matches!(
        agent.sign_prepared_document(&received),
        Err(CoreError::Locked)
    ));
}

struct ObservedSigner {
    inner: jacs_core::Pq2025Signer,
    calls: Arc<AtomicUsize>,
}
impl DetachedSigner for ObservedSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> &[u8] {
        self.inner.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(message)
    }
    fn clear_secrets(&mut self) {
        self.inner.clear_secrets();
    }
}

#[test]
fn prepared_document_rejects_changed_envelope_context_and_key_before_private_dispatch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = CoreAgent::from_signer(
        Box::new(ObservedSigner {
            inner: jacs_core::Pq2025Signer::generate().unwrap(),
            calls: calls.clone(),
        }),
        json!({"jacsAgentType": "human"}),
    )
    .unwrap();
    calls.store(0, Ordering::SeqCst);
    let prepared = prepare(&agent);
    let serialized = serde_json::to_value(&prepared).unwrap();
    for (pointer, value) in [
        ("/envelope/content/exact", json!("substituted")),
        ("/envelope/jacsId", json!(uuid::Uuid::new_v4().to_string())),
        ("/envelope/jacsSignature/jti", json!("different-token")),
        ("/signatureInput", json!("e30=")),
        (
            "/signatureInputDigest",
            json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("/signingRequestContext/identity", json!("different-owner")),
        (
            "/signingRequestContextDigest",
            json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("/identity", json!("different-owner")),
        ("/purpose", json!("legacy_raw")),
    ] {
        let mut changed = serialized.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: PreparedDocumentV2 = serde_json::from_value(changed).unwrap();
        assert!(agent.sign_prepared_document(&changed).is_err(), "{pointer}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{pointer} reached key use");
    }
    let other = CoreAgent::create_human().unwrap();
    assert!(agent.sign_prepared_document(&prepare(&other)).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(agent.sign_prepared_document(&prepared).is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn complete_document_has_fresh_signed_headers_exact_content_and_checksum() {
    let mut agent = CoreAgent::create_human().unwrap();
    let content = json!({"approval_document":{"purpose":"test-only", "text":"exact\nterms", "n": 1.25}, "jacsId":"content-is-not-a-root-header"});
    let first = agent.sign_document(&content).unwrap();
    let second = agent.sign_document(&content).unwrap();
    assert_eq!(first["content"], content);
    for field in ["jacsId", "jacsVersion", "jacsOriginalVersion"] {
        uuid::Uuid::parse_str(first[field].as_str().unwrap()).unwrap();
        assert!(
            first["jacsSignature"]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == field)
        );
    }
    assert_ne!(first["jacsId"], second["jacsId"]);
    assert_ne!(first["jacsVersion"], second["jacsVersion"]);
    assert_eq!(first["jacsOriginalVersion"], first["jacsVersion"]);
    assert_eq!(first["jacsSha256"], document_hash_v1(&first).unwrap());
    assert!(
        CoreAgent::verify_with_key(&first, agent.public_key(), SigningAlgorithm::Pq2025)
            .unwrap()
            .valid
    );
    let schema =
        jacs_core::schema::EmbeddedSchemaResolver::resolve("schemas/header/v1/header.schema.json")
            .unwrap();
    let validator = jsonschema::options()
        .with_retriever(jacs_core::schema::EmbeddedSchemaResolver::new())
        .build(&schema)
        .unwrap();
    assert!(validator.is_valid(&first));
    for field in ["jacsId", "jacsVersion", "content"] {
        let mut altered = first.clone();
        altered[field] = json!("altered");
        assert!(!agent.verify(&altered).unwrap().valid);
    }
    let unchanged = agent.sign_message(&content).unwrap();
    assert!(unchanged.get("jacsId").is_none());
    assert!(unchanged.get("jacsSha256").is_none());
    agent.clear_secrets();
    assert!(matches!(
        agent.sign_document(&content),
        Err(CoreError::Locked)
    ));
}
