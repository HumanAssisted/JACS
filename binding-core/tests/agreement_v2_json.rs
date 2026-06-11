#![cfg(feature = "agreements")]

use jacs_binding_core::{AgentWrapper, SimpleAgentWrapper};
use serde_json::{Value, json};

const AGREEMENT_V2_SCENARIO: &str = include_str!("fixtures/agreement_v2_scenarios.json");
const AGREEMENT_V2_SRC: &str = include_str!("../src/agreement_v2.rs");
const SIMPLE_WRAPPER_SRC: &str = include_str!("../src/simple_wrapper.rs");

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

fn ephemeral_agent_wrapper() -> AgentWrapper {
    let wrapper = AgentWrapper::new();
    wrapper
        .ephemeral(Some("ed25519"))
        .expect("ephemeral agent wrapper");
    wrapper
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

fn deeply_nested_value(depth: usize) -> Value {
    let mut value = json!("leaf");
    for _ in 0..depth {
        value = json!({ "a": value });
    }
    value
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
fn rejects_deeply_nested_agreement_at_binding_boundary() {
    let (wrapper, agent_id) = ephemeral_agent();
    let created = create_agreement(&wrapper, &agent_id);

    let result = wrapper.apply_agreement_v2_json(
        &created,
        &json!({
            "type": "appendTranscript",
            "entry": deeply_nested_value(70)
        })
        .to_string(),
    );

    let Err(err) = result else {
        panic!("expected deeply nested agreement input to be rejected");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("nesting depth"),
        "expected nesting depth error, got: {msg}"
    );
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
fn role_parser_is_single_canonical_impl() {
    let (wrapper, agent_id) = ephemeral_agent();
    let created = create_agreement(&wrapper, &agent_id);
    let err = wrapper
        .sign_agreement_v2_json(&created, "bogus-role")
        .expect_err("invalid role must be rejected");
    let msg = err.to_string();

    let agent_wrapper = ephemeral_agent_wrapper();
    let agent_err = agent_wrapper
        .sign_agreement_v2_json(&created, "bogus-role")
        .expect_err("invalid role must be rejected through AgentWrapper");

    assert_eq!(
        msg,
        agent_err.to_string(),
        "AgentWrapper and SimpleAgentWrapper must share the canonical role parser"
    );
    assert!(
        msg.contains("Invalid agreement v2 signature role 'bogus-role'"),
        "canonical role-parser message expected, got: {msg}"
    );
    assert_eq!(
        AGREEMENT_V2_SRC
            .matches("fn parse_agreement_v2_role")
            .count(),
        1,
        "agreement_v2.rs must own the canonical role parser"
    );
    assert_eq!(
        SIMPLE_WRAPPER_SRC
            .matches("fn parse_agreement_v2_role")
            .count(),
        0,
        "simple_wrapper.rs must not define a duplicate role parser"
    );
}

#[test]
fn v2_error_message_is_not_double_prefixed() {
    let (wrapper, _agent_id) = ephemeral_agent();
    let err = wrapper
        .create_agreement_v2_json("{not valid json")
        .expect_err("invalid create input must error");
    let msg = err.to_string();
    let count = msg.matches("Invalid agreement v2 create input").count();
    assert_eq!(
        count, 1,
        "context prefix must appear exactly once, got: {msg}"
    );
    assert!(
        AGREEMENT_V2_SRC.contains("pub(crate) const CTX_INVALID_CREATE_INPUT"),
        "agreement_v2.rs must own the invalid-create context constant"
    );
    assert!(
        SIMPLE_WRAPPER_SRC.contains("crate::agreement_v2::CTX_INVALID_CREATE_INPUT"),
        "simple_wrapper.rs must reference the canonical invalid-create context"
    );
    assert_eq!(
        SIMPLE_WRAPPER_SRC
            .matches("\"Invalid agreement v2 create input\"")
            .count(),
        0,
        "simple_wrapper.rs must not duplicate the invalid-create context literal"
    );
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
