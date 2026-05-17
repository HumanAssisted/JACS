//! Tests for `jacs_core::agreements::{create, sign, verify}` (Task 014).

use jacs_core::agreements::{self, QuorumOutcome, SignerStatus};
use jacs_core::{CoreAgent, SigningAlgorithm};
use serde_json::{Value, json};

// -----------------------------------------------------------------------------
// agreements::create — skeleton shape
// -----------------------------------------------------------------------------

#[test]
fn agreements_create_initial_shape() {
    let doc = json!({
        "jacsType": "agreement",
        "subject": "merge proposal",
    });
    let agent_ids = vec!["alice".to_string(), "bob".to_string()];
    let out = agreements::create(&doc, &agent_ids, Some("Approve?"), Some("Repo merge"))
        .expect("create");

    let agreement = out.get("jacsAgreement").expect("jacsAgreement present");
    assert!(agreement.is_object());
    assert_eq!(agreement["question"], json!("Approve?"));
    assert_eq!(agreement["context"], json!("Repo merge"));
    assert_eq!(agreement["agentIDs"], json!(agent_ids));
    assert_eq!(agreement["signatures"], json!([]));
    // Untouched fields survive.
    assert_eq!(out["subject"], json!("merge proposal"));
}

// -----------------------------------------------------------------------------
// agreements::sign — appends signer entry
// -----------------------------------------------------------------------------

#[test]
fn agreements_sign_appends_signer_entry() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let agent_id = agent
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let mut doc = agreements::create(
        &json!({ "topic": "tea time" }),
        &[agent_id.clone()],
        None,
        None,
    )
    .expect("create");

    agreements::sign(&mut agent, &mut doc, "approver").expect("sign");

    let sigs = doc.pointer("/jacsAgreement/signatures").expect("sigs");
    let arr = sigs.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["agentID"], json!(agent_id));
    assert_eq!(arr[0]["role"], json!("approver"));
    assert!(arr[0]["signature"].as_str().is_some_and(|s| !s.is_empty()));
}

// -----------------------------------------------------------------------------
// Two-party sign + verify (happy path)
// -----------------------------------------------------------------------------

fn two_party_doc() -> (CoreAgent, CoreAgent, Value, String, Vec<u8>, String, Vec<u8>) {
    let mut a = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("a ephemeral");
    let mut b = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("b ephemeral");
    let id_a = a
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let id_b = b
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let pk_a = a.public_key().to_vec();
    let pk_b = b.public_key().to_vec();

    let mut doc = agreements::create(
        &json!({ "agreement": "merge" }),
        &[id_a.clone(), id_b.clone()],
        Some("Merge?"),
        None,
    )
    .expect("create");
    agreements::sign(&mut a, &mut doc, "signerA").expect("sign a");
    agreements::sign(&mut b, &mut doc, "signerB").expect("sign b");

    (a, b, doc, id_a, pk_a, id_b, pk_b)
}

#[test]
fn agreements_two_party_sign_and_verify_ok() {
    let (_a, _b, doc, id_a, pk_a, id_b, pk_b) = two_party_doc();
    let signers: Vec<(&str, &[u8], SigningAlgorithm)> = vec![
        (id_a.as_str(), pk_a.as_slice(), SigningAlgorithm::Ed25519),
        (id_b.as_str(), pk_b.as_slice(), SigningAlgorithm::Ed25519),
    ];
    let outcome: QuorumOutcome = agreements::verify(&doc, &signers).expect("verify");
    assert!(outcome.all_valid, "per_signer: {:?}", outcome.per_signer);
    assert_eq!(outcome.verified_signers, 2);
    assert_eq!(outcome.expected_signers, 2);
}

// -----------------------------------------------------------------------------
// Negative: missing key for one signer
// -----------------------------------------------------------------------------

#[test]
fn agreements_verify_missing_key_fails_that_signer() {
    let (_a, _b, doc, id_a, pk_a, _id_b, _pk_b) = two_party_doc();
    let signers: Vec<(&str, &[u8], SigningAlgorithm)> = vec![
        (id_a.as_str(), pk_a.as_slice(), SigningAlgorithm::Ed25519),
        // b omitted
    ];
    let outcome = agreements::verify(&doc, &signers).expect("verify");
    assert!(!outcome.all_valid);
    assert_eq!(outcome.verified_signers, 1);
    assert_eq!(outcome.expected_signers, 2);
    let missing = outcome
        .per_signer
        .iter()
        .find(|s| matches!(s.status, SignerStatus::SignerKeyMissing))
        .expect("one entry is SignerKeyMissing");
    assert!(!missing.agent_id.is_empty());
}

// -----------------------------------------------------------------------------
// Negative: tampered payload
// -----------------------------------------------------------------------------

#[test]
fn agreements_tampered_payload_fails_all_signatures() {
    let (_a, _b, mut doc, id_a, pk_a, id_b, pk_b) = two_party_doc();
    *doc.pointer_mut("/agreement").expect("agreement field") = json!("rejected");

    let signers: Vec<(&str, &[u8], SigningAlgorithm)> = vec![
        (id_a.as_str(), pk_a.as_slice(), SigningAlgorithm::Ed25519),
        (id_b.as_str(), pk_b.as_slice(), SigningAlgorithm::Ed25519),
    ];
    let outcome = agreements::verify(&doc, &signers).expect("verify");
    assert!(!outcome.all_valid);
    assert_eq!(outcome.verified_signers, 0);
    for entry in &outcome.per_signer {
        assert!(
            matches!(entry.status, SignerStatus::Invalid(_)),
            "expected Invalid, got {:?}",
            entry.status
        );
    }
}

// -----------------------------------------------------------------------------
// Negative: key/algorithm mismatch
// -----------------------------------------------------------------------------

#[test]
fn agreements_verify_algorithm_mismatch_flagged_per_signer() {
    let (_a, _b, doc, id_a, pk_a, id_b, pk_b) = two_party_doc();
    // Caller provides the right keys but with the wrong algorithm tag for
    // signer A. That entry must surface KeyAlgorithmMismatch (not crash).
    let signers: Vec<(&str, &[u8], SigningAlgorithm)> = vec![
        (id_a.as_str(), pk_a.as_slice(), SigningAlgorithm::Pq2025), // WRONG
        (id_b.as_str(), pk_b.as_slice(), SigningAlgorithm::Ed25519),
    ];
    let outcome = agreements::verify(&doc, &signers).expect("verify");
    assert!(!outcome.all_valid);
    let a_entry = outcome
        .per_signer
        .iter()
        .find(|e| e.agent_id == id_a)
        .expect("a entry");
    assert!(matches!(a_entry.status, SignerStatus::KeyAlgorithmMismatch));
    let b_entry = outcome
        .per_signer
        .iter()
        .find(|e| e.agent_id == id_b)
        .expect("b entry");
    assert!(matches!(b_entry.status, SignerStatus::Valid));
}

// -----------------------------------------------------------------------------
// Single-party sign + verify
// -----------------------------------------------------------------------------

#[test]
fn agreements_single_party_sign_and_verify_ok() {
    let mut a = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).expect("ephemeral");
    let id = a
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let pk = a.public_key().to_vec();
    let mut doc = agreements::create(&json!({"x": 1}), &[id.clone()], None, None).expect("create");
    agreements::sign(&mut a, &mut doc, "solo").expect("sign");

    let signers: Vec<(&str, &[u8], SigningAlgorithm)> =
        vec![(id.as_str(), pk.as_slice(), SigningAlgorithm::Pq2025)];
    let outcome = agreements::verify(&doc, &signers).expect("verify");
    assert!(outcome.all_valid);
}
