//! Standalone archived-native verification harness. See README; deliberately
//! outside the active Cargo workspace's dependency graph.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jacs::{agent::Agent, verification::NonSigningVerifier};
use jacs_core::CoreAgent;
use serde_json::{Value, json};

fn check(identity: &Value, document: &Value, key: &[u8], content: &Value) {
    let verifier = NonSigningVerifier::new().unwrap();
    let native = Agent::ephemeral("pq2025").unwrap();
    for value in [identity, document] {
        let report = verifier.verify_with_key(&value.to_string(), key, "pq2025", None).unwrap();
        assert!(report.integrity_valid, "{:?}", report.errors);
        assert!(report.header_valid && report.document_hash_valid && report.signature_valid && report.public_key_hash_valid);
        assert!(native.verify_hash(value).unwrap());
    }
    assert_eq!(&document["content"], content);
    for field in ["jacsId", "jacsVersion", "jacsSha256", "content"] {
        let mut altered = document.clone();
        altered[field] = json!("tampered");
        assert!(!verifier.verify_with_key(&altered.to_string(), key, "pq2025", None).unwrap().integrity_valid);
    }
}
fn main() {
    let fixture: Value = serde_json::from_str(include_str!("../fixtures/native_compat/human_complete_document.json")).unwrap();
    let key = STANDARD.decode(fixture["publicKeyBase64"].as_str().unwrap()).unwrap();
    assert_eq!(fixture["document"]["jacsSha256"], fixture["expectedChecksum"]);
    check(&fixture["humanIdentity"], &fixture["document"], &key, &fixture["expectedContent"]);
    let human = CoreAgent::create_human().unwrap();
    let content = json!({"fixture":"fresh-core-to-archived-native", "exact":"terms\n第二行"});
    check(&human.export_agent(), &human.sign_document(&content).unwrap(), human.public_key(), &content);
    println!("PASS: archived NonSigningVerifier and Agent.verify_hash accept golden and fresh complete human documents; reject tampering");
}
