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
    let out =
        agreements::create(&doc, &agent_ids, Some("Approve?"), Some("Repo merge")).expect("create");

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
        std::slice::from_ref(&agent_id),
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

fn two_party_doc() -> (
    CoreAgent,
    CoreAgent,
    Value,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
) {
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
    let mut doc = agreements::create(&json!({"x": 1}), std::slice::from_ref(&id), None, None)
        .expect("create");
    agreements::sign(&mut a, &mut doc, "solo").expect("sign");

    let signers: Vec<(&str, &[u8], SigningAlgorithm)> =
        vec![(id.as_str(), pk.as_slice(), SigningAlgorithm::Pq2025)];
    let outcome = agreements::verify(&doc, &signers).expect("verify");
    assert!(outcome.all_valid);
}

#[test]
fn v2_transplanted_signature_from_other_agreement_is_rejected() {
    let mut a = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let id_a = a
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let pk_a = a.public_key().to_vec();

    let input = json!({
        "title": "Replay test",
        "description": "Identical consent fields across two agreements.",
        "terms": "Terms.",
        "termsFormat": "text/plain",
        "parties": [{"agentId": id_a, "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {"partyQuorum": "all"},
        "controllers": [id_a]
    });

    let agreement_a = agreements::v2::create(&mut a, &input).expect("create A");
    let agreement_b = agreements::v2::create(&mut a, &input).expect("create B");

    assert_ne!(agreement_a["jacsId"], agreement_b["jacsId"]);
    assert_eq!(
        agreement_a["jacsAgreementHash"],
        agreement_b["jacsAgreementHash"]
    );

    let signed_a = agreements::v2::sign(&mut a, &agreement_a, "signer").expect("sign A");
    let transplanted = signed_a["agreementSignatures"][0].clone();

    let mut tampered_b = agreement_b.clone();
    tampered_b["agreementSignatures"]
        .as_array_mut()
        .expect("agreementSignatures array")
        .push(transplanted);
    tampered_b["status"] = json!("final");

    let signers: Vec<(&str, &[u8], SigningAlgorithm)> =
        vec![(id_a.as_str(), pk_a.as_slice(), SigningAlgorithm::Ed25519)];
    let report = agreements::v2::verify(&tampered_b, &signers).expect("verify B");

    assert_eq!(report["valid"], json!(false));
    assert_eq!(report["signerCount"], json!(0));
    assert_eq!(report["signatures"][0]["valid"], json!(false));
}

fn core_v2_agent_id(agent: &CoreAgent) -> String {
    agent
        .export_agent()
        .get("jacsId")
        .and_then(Value::as_str)
        .expect("agent id")
        .to_string()
}

fn core_v2_input(agent_id: &str) -> Value {
    json!({
        "title": "Core agreement",
        "description": "Portable agreement schema validation.",
        "terms": "Terms.",
        "termsFormat": "text/plain",
        "status": "draft",
        "parties": [{"agentId": agent_id, "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {"partyQuorum": "all"},
        "controllers": [agent_id]
    })
}

fn core_v2_agreement() -> (CoreAgent, Value, String) {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let agent_id = core_v2_agent_id(&agent);
    let agreement =
        agreements::v2::create(&mut agent, &core_v2_input(&agent_id)).expect("create agreement");
    (agent, agreement, agent_id)
}

#[test]
fn core_rejects_schema_invalid_agreement() {
    let (mut agent, mut agreement, agent_id) = core_v2_agreement();
    agreement["title"] = json!("");
    let result = agreements::v2::apply(
        &mut agent,
        &agreement,
        &json!({"type": "setStatus", "status": "proposed"}),
    );
    assert!(
        result.is_err(),
        "portable apply must schema-validate output"
    );

    let invalid = json!({
        "$schema": jacs_core::schema::V2_SCHEMA_ID,
        "jacsId": agent_id,
        "jacsType": "agreement",
        "jacsVersion": "018f4dc2-85f9-7b2e-8c22-849b8463bcb3",
        "jacsVersionDate": "2030-01-01T00:00:00Z",
        "jacsOriginalVersion": "018f4dc2-85f9-7b2e-8c22-849b8463bcb3",
        "jacsOriginalDate": "2030-01-01T00:00:00Z",
        "jacsLevel": "artifact",
        "jacsAgreementHash": "hash",
        "title": "Missing parties",
        "description": "Invalid by schema.",
        "terms": "Terms.",
        "status": "draft",
        "signaturePolicy": {"partyQuorum": "all"},
        "agreementSignatures": []
    });
    assert!(
        jacs_core::schema::validate_agreement_v2_document(&invalid).is_err(),
        "direct validation must reject missing required parties"
    );
}

#[test]
fn core_rejects_unknown_top_level_field() {
    let (_agent, mut agreement, _agent_id) = core_v2_agreement();
    agreement["maliciousField"] = json!("x");
    let err = jacs_core::schema::validate_agreement_v2_document(&agreement)
        .expect_err("unknown top-level fields must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("maliciousField"),
        "error should name the offending field: {msg}"
    );
}

#[test]
fn core_rejects_downgraded_schema_identity() {
    let (_agent, mut agreement, _agent_id) = core_v2_agreement();
    agreement["$schema"] =
        json!("https://hai.ai/schemas/components/agreement/v1/agreement.schema.json");
    assert!(
        jacs_core::schema::validate_agreement_v2_document(&agreement).is_err(),
        "agreement v2 validator must reject downgraded schema identity"
    );

    let (_agent, mut agreement, _agent_id) = core_v2_agreement();
    agreement["jacsType"] = json!("document");
    assert!(
        jacs_core::schema::validate_agreement_v2_document(&agreement).is_err(),
        "agreement v2 validator must reject a flipped jacsType"
    );
}

#[test]
fn core_rejects_malformed_id() {
    let (_agent, mut agreement, _agent_id) = core_v2_agreement();
    agreement["controllers"][0] = json!("not-a-uuid");
    let err = jacs_core::schema::validate_agreement_v2_document(&agreement)
        .expect_err("malformed controller IDs must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("controllers[0]"),
        "error should name the malformed ID field: {msg}"
    );
}

#[test]
fn core_accepts_valid_agreement() {
    let (mut agent, agreement, _agent_id) = core_v2_agreement();
    let signed = agreements::v2::sign(&mut agent, &agreement, "signer").expect("sign agreement");
    jacs_core::schema::validate_agreement_v2_document(&signed)
        .expect("freshly signed agreement validates");
}

#[test]
fn v2_cannot_sign_after_expires_at() {
    let mut a = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let id_a = a
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let input = json!({
        "title": "Expiry test",
        "description": "Signing must fail past expiresAt.",
        "terms": "Terms.",
        "termsFormat": "text/plain",
        "expiresAt": "2000-01-01T00:00:00Z",
        "parties": [{"agentId": id_a, "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {"partyQuorum": "all"},
        "controllers": [id_a]
    });
    let agreement = agreements::v2::create(&mut a, &input).expect("create");
    assert!(
        agreements::v2::sign(&mut a, &agreement, "signer").is_err(),
        "signing past expiresAt must fail in jacs-core"
    );
}

#[test]
fn v2_cannot_sign_before_effective_from() {
    let mut a = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let id_a = a
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let input = json!({
        "title": "Effective test",
        "description": "Signing must fail before effectiveFrom.",
        "terms": "Terms.",
        "termsFormat": "text/plain",
        "effectiveFrom": "2999-01-01T00:00:00Z",
        "parties": [{"agentId": id_a, "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {"partyQuorum": "all"},
        "controllers": [id_a]
    });
    let agreement = agreements::v2::create(&mut a, &input).expect("create");
    assert!(
        agreements::v2::sign(&mut a, &agreement, "signer").is_err(),
        "signing before effectiveFrom must fail in jacs-core"
    );
}

#[test]
fn v2_final_agreement_remains_final_after_expires_at() {
    let mut a = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let id_a = a
        .export_agent()
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let pk_a = a.public_key().to_vec();
    // Future expiry so we can sign to final.
    let input = json!({
        "title": "Final-after-expiry",
        "description": "Final stays final even past expiresAt.",
        "terms": "Terms.",
        "termsFormat": "text/plain",
        "expiresAt": "2999-01-01T00:00:00Z",
        "parties": [{"agentId": id_a, "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {"partyQuorum": "all"},
        "controllers": [id_a]
    });
    let agreement = agreements::v2::create(&mut a, &input).expect("create");
    let signed = agreements::v2::sign(&mut a, &agreement, "signer").expect("sign to final");
    assert_eq!(signed["status"], json!("final"));

    // Rewrite expiresAt into the past and re-derive the expected status via
    // verify's expectedStatus (which calls recompute_status). The header
    // signature will now be invalid (we mutated a signed field), but
    // expectedStatus is computed independently and must remain "final".
    let mut past = signed.clone();
    past["expiresAt"] = json!("2000-01-01T00:00:00Z");
    let signers: Vec<(&str, &[u8], SigningAlgorithm)> =
        vec![(id_a.as_str(), pk_a.as_slice(), SigningAlgorithm::Ed25519)];
    let report = agreements::v2::verify(&past, &signers).expect("verify");
    assert_eq!(report["expectedStatus"], json!("final"));
}

#[test]
fn v2_portable_rejects_consent_mutation_on_final() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let agent_id = core_v2_agent_id(&agent);
    let agreement = agreements::v2::create(&mut agent, &core_v2_input(&agent_id)).expect("create");
    let signed = agreements::v2::sign(&mut agent, &agreement, "signer").expect("sign to final");
    assert_eq!(
        signed["status"],
        json!("final"),
        "single signer + quorum all => final"
    );

    let result = agreements::v2::apply(
        &mut agent,
        &signed,
        &json!({"type": "updateTerms", "terms": "Rewritten terms after final."}),
    );
    assert!(
        result.is_err(),
        "consent-scope mutation on a final agreement must be rejected"
    );
}

#[test]
fn v2_portable_rejects_quorum_downgrade_after_proposal() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let agent_id = core_v2_agent_id(&agent);
    let mut input = core_v2_input(&agent_id);
    // Two signer parties so partyQuorum "all" => quorum 2.
    input["parties"] = json!([
        {"agentId": agent_id, "agentType": "ai", "role": "signer"},
        {"agentId": "00000000-0000-4000-8000-000000000002", "agentType": "ai", "role": "signer"}
    ]);
    let agreement = agreements::v2::create(&mut agent, &input).expect("create");

    // Move to proposed => past point of reliance.
    let proposed = agreements::v2::apply(
        &mut agent,
        &agreement,
        &json!({"type": "setStatus", "status": "proposed"}),
    )
    .expect("set proposed");

    // Downgrade quorum from "all" (=2) to 1 => weaker => rejected.
    let result = agreements::v2::apply(
        &mut agent,
        &proposed,
        &json!({"type": "setSignaturePolicy", "signaturePolicy": {"partyQuorum": 1}}),
    );
    assert!(
        result.is_err(),
        "loosening partyQuorum after proposal must be rejected"
    );
}

#[test]
fn v2_portable_merge_binds_content_hash() {
    use jacs_core::canonical::canonicalize_json_try;
    use jacs_core::verify::sha256_hex;

    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let agent_id = core_v2_agent_id(&agent);
    let base = agreements::v2::create(&mut agent, &core_v2_input(&agent_id)).expect("create base");

    // Two transcript-only branches off the same parent.
    let left = agreements::v2::apply(
        &mut agent,
        &base,
        &json!({"type": "appendTranscript", "entry": {
            "jacsId": "00000000-0000-4000-8000-000000000011",
            "jacsVersion": "10000000-0000-4000-8000-000000000011",
            "jacsSha256": "left-branch-transcript-ref"
        }}),
    )
    .expect("left branch");
    let right = agreements::v2::apply(
        &mut agent,
        &base,
        &json!({"type": "appendTranscript", "entry": {
            "jacsId": "00000000-0000-4000-8000-000000000012",
            "jacsVersion": "10000000-0000-4000-8000-000000000012",
            "jacsSha256": "right-branch-transcript-ref"
        }}),
    )
    .expect("right branch");

    let merged =
        agreements::v2::merge_transcript_branches(&mut agent, &base, &left, &right).expect("merge");

    // Recompute the content hash of the merged-in (right) branch the same way the
    // engine does: strip jacsSha256, canonicalize, sha256 hex.
    let mut right_for_hash = right.clone();
    right_for_hash.as_object_mut().unwrap().remove("jacsSha256");
    let expected_hash = sha256_hex(
        canonicalize_json_try(&right_for_hash)
            .expect("canonicalize")
            .as_bytes(),
    );

    let right_id = right["jacsId"].as_str().unwrap();
    let right_version = right["jacsVersion"].as_str().unwrap();
    let links = merged["links"].as_array().expect("links array");
    let bound = links.iter().find(|link| {
        link["jacsId"].as_str() == Some(right_id)
            && link["jacsVersion"].as_str() == Some(right_version)
    });
    let bound = bound.expect("merge link to right branch present");
    assert_eq!(
        bound["jacsSha256"].as_str(),
        Some(expected_hash.as_str()),
        "merge link must bind the merged branch content hash"
    );
}

#[test]
fn v2_portable_valid_apply_and_merge_still_succeed() {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
    let agent_id = core_v2_agent_id(&agent);
    let agreement = agreements::v2::create(&mut agent, &core_v2_input(&agent_id)).expect("create");

    // Valid policy set on a fresh draft (not past point of reliance) succeeds.
    let updated = agreements::v2::apply(
        &mut agent,
        &agreement,
        &json!({"type": "setSignaturePolicy", "signaturePolicy": {"partyQuorum": "all", "witnessRequired": 0}}),
    )
    .expect("valid setSignaturePolicy on draft must still succeed");
    assert_eq!(updated["jacsType"], json!("agreement"));

    // Valid transcript merge on non-final branches still succeeds.
    let left = agreements::v2::apply(
        &mut agent,
        &agreement,
        &json!({"type": "appendTranscript", "entry": {
            "jacsId": "00000000-0000-4000-8000-000000000021",
            "jacsVersion": "10000000-0000-4000-8000-000000000021",
            "jacsSha256": "left-ref"
        }}),
    )
    .expect("left");
    let right = agreements::v2::apply(
        &mut agent,
        &agreement,
        &json!({"type": "appendTranscript", "entry": {
            "jacsId": "00000000-0000-4000-8000-000000000022",
            "jacsVersion": "10000000-0000-4000-8000-000000000022",
            "jacsSha256": "right-ref"
        }}),
    )
    .expect("right");
    let merged = agreements::v2::merge_transcript_branches(&mut agent, &agreement, &left, &right)
        .expect("valid transcript merge must still succeed");
    assert_eq!(merged["jacsType"], json!("agreement"));
}
