#![cfg(feature = "agreements")]

use jacs_binding_core::AgentWrapper;
use serde_json::{Value, json};

#[test]
fn agreement_v2_json_adapter_round_trips_create_sign_verify() {
    let wrapper = AgentWrapper::new();
    let info_json = wrapper.ephemeral(Some("ed25519")).expect("ephemeral agent");
    let info: Value = serde_json::from_str(&info_json).expect("agent info json");
    let agent_id = info["agent_id"].as_str().expect("agent_id");

    let input = json!({
        "title": "Binding agreement",
        "description": "Smoke test for the binding-core JSON adapter.",
        "terms": "The binding adapter delegates agreement v2 rules to jacs core.",
        "termsFormat": "text/plain",
        "status": "proposed",
        "parties": [
            {"agentId": agent_id, "agentType": "ai", "role": "signer"}
        ],
        "signaturePolicy": {
            "partyQuorum": "all",
            "witnessRequired": 0,
            "notaryRequired": 0,
            "requiredAlgorithms": ["ring-Ed25519"],
            "minimumStrength": "classical"
        },
        "controllers": [agent_id]
    });

    let created = wrapper
        .create_agreement_v2_json(&input.to_string())
        .expect("create agreement v2");
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
