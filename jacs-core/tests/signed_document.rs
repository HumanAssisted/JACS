use jacs_core::{CoreAgent, CoreError, SigningAlgorithm, document_hash_v1};
use serde_json::json;

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
