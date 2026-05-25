#![cfg(feature = "agreements")]

use jacs_binding_core::SimpleAgentWrapper;
use serde_json::{Value, json};

const AGREEMENT_V2_SCENARIO: &str = include_str!("fixtures/agreement_v2_scenarios.json");

fn fixture() -> Value {
    serde_json::from_str(AGREEMENT_V2_SCENARIO).expect("agreement v2 scenario fixture")
}

fn ephemeral_agent() -> (SimpleAgentWrapper, String) {
    let (wrapper, info_json) =
        SimpleAgentWrapper::ephemeral(Some("ed25519")).expect("ephemeral agent");
    let info: Value = serde_json::from_str(&info_json).expect("agent info json");
    let agent_id = info["agent_id"].as_str().expect("agent_id").to_string();
    (wrapper, agent_id)
}

fn base_input(agent_id: &str) -> Value {
    let scenario = fixture();
    let mut input = scenario["base_input"].clone();
    input["parties"] = json!([
        {"agentId": agent_id, "agentType": "ai", "role": "signer"}
    ]);
    input["controllers"] = json!([agent_id]);
    input
}

fn create_agreement(wrapper: &SimpleAgentWrapper, agent_id: &str) -> String {
    wrapper
        .create_agreement_v2_json(&base_input(agent_id).to_string())
        .expect("create agreement v2")
}

fn transcript_ref(name: &str) -> Value {
    fixture()["transcript_refs"][name].clone()
}

fn conflict_terms(name: &str) -> String {
    fixture()["terms_conflict"][name]
        .as_str()
        .expect("terms conflict value")
        .to_string()
}

fn apply_mutation(wrapper: &SimpleAgentWrapper, document: &str, mutation: Value) -> String {
    wrapper
        .apply_agreement_v2_json(document, &mutation.to_string())
        .expect("apply agreement v2 mutation")
}

#[test]
fn simple_wrapper_round_trips_create_sign_verify() {
    let (wrapper, agent_id) = ephemeral_agent();

    let created = create_agreement(&wrapper, &agent_id);
    let signed = wrapper
        .sign_agreement_v2_json(&created, "signer")
        .expect("sign agreement v2");
    let report_json = wrapper
        .verify_agreement_v2_json(&signed)
        .expect("verify agreement v2");
    let report: Value = serde_json::from_str(&report_json).expect("report json");

    assert_eq!(report["valid"], json!(true));
    assert_eq!(report["expectedStatus"], json!("final"));
    assert_eq!(report["signerCount"], json!(1));
}

#[test]
fn simple_wrapper_supports_notary_signature_role() {
    let (signer, signer_id) = ephemeral_agent();
    let (notary, notary_id) = ephemeral_agent();
    let mut input = base_input(&signer_id);
    input["parties"] = json!([
        {"agentId": signer_id, "agentType": "ai", "role": "signer"},
        {"agentId": notary_id, "agentType": "ai", "role": "notary"}
    ]);
    input["signaturePolicy"]["notaryRequired"] = json!(1);

    let created = signer
        .create_agreement_v2_json(&input.to_string())
        .expect("create agreement v2");
    let notarized = notary
        .sign_agreement_v2_json(&created, "notary")
        .expect("sign agreement v2 as notary");
    let document: Value = serde_json::from_str(&notarized).expect("notarized agreement json");

    assert_eq!(document["agreementSignatures"][0]["role"], json!("notary"));
}

#[test]
fn simple_wrapper_detects_and_merges_transcript_only_branches() {
    let (wrapper, agent_id) = ephemeral_agent();
    let base = create_agreement(&wrapper, &agent_id);
    let left_ref = transcript_ref("left");
    let right_ref = transcript_ref("right");

    let left = apply_mutation(
        &wrapper,
        &base,
        json!({"type": "appendTranscript", "entry": left_ref}),
    );
    let right = apply_mutation(
        &wrapper,
        &base,
        json!({"type": "appendTranscript", "entry": right_ref}),
    );

    let analysis_json = wrapper
        .detect_agreement_v2_branch_conflict_json(&base, &left, &right)
        .expect("analyze branch conflict");
    let analysis: Value = serde_json::from_str(&analysis_json).expect("analysis json");
    assert_eq!(analysis["sameDocument"], json!(true));
    assert_eq!(analysis["sameParent"], json!(true));
    assert_eq!(analysis["autoMergeable"], json!(true));

    let merged = wrapper
        .merge_agreement_v2_transcript_branches_json(&base, &left, &right)
        .expect("merge transcript branches");
    let merged_doc: Value = serde_json::from_str(&merged).expect("merged agreement json");

    assert_eq!(
        merged_doc["transcript"]
            .as_array()
            .expect("transcript")
            .len(),
        2
    );
    assert_eq!(
        merged_doc["links"][0]["jacsId"],
        json!(right_doc_id(&right))
    );
}

#[test]
fn simple_wrapper_resolves_terms_branch_conflict_explicitly() {
    let (wrapper, agent_id) = ephemeral_agent();
    let base = create_agreement(&wrapper, &agent_id);

    let left = apply_mutation(
        &wrapper,
        &base,
        json!({"type": "updateTerms", "terms": conflict_terms("left")}),
    );
    let right = apply_mutation(
        &wrapper,
        &base,
        json!({"type": "updateTerms", "terms": conflict_terms("right")}),
    );

    let analysis_json = wrapper
        .detect_agreement_v2_branch_conflict_json(&base, &left, &right)
        .expect("analyze branch conflict");
    let analysis: Value = serde_json::from_str(&analysis_json).expect("analysis json");
    assert_eq!(analysis["autoMergeable"], json!(false));
    assert!(
        analysis["conflictFields"]
            .as_array()
            .expect("conflict fields")
            .iter()
            .any(|field| field == "terms")
    );

    let resolved = wrapper
        .resolve_agreement_v2_branch_conflict_json(
            &base,
            &left,
            &right,
            &json!({"type": "updateTerms", "terms": conflict_terms("resolved")}).to_string(),
        )
        .expect("resolve branch conflict");
    let resolved_doc: Value = serde_json::from_str(&resolved).expect("resolved agreement json");

    assert_eq!(resolved_doc["terms"], json!(conflict_terms("resolved")));
    assert_eq!(
        resolved_doc["jacsPreviousVersion"],
        json!(doc_version(&left))
    );
    assert_eq!(
        resolved_doc["links"][0]["jacsId"],
        json!(right_doc_id(&right))
    );
    assert_eq!(
        resolved_doc["links"][0]["jacsVersion"],
        json!(doc_version(&right))
    );
}

fn right_doc_id(document_json: &str) -> String {
    let document: Value = serde_json::from_str(document_json).expect("agreement json");
    document["jacsId"].as_str().expect("jacsId").to_string()
}

fn doc_version(document_json: &str) -> String {
    let document: Value = serde_json::from_str(document_json).expect("agreement json");
    document["jacsVersion"]
        .as_str()
        .expect("jacsVersion")
        .to_string()
}
