#![cfg(feature = "agreements")]

use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::{DocumentTraits, JACSDocument};
use jacs::agent::loaders::FileLoader;
use jacs::agent::{Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, JACS_PREVIOUS_VERSION_FIELDNAME};
use jacs::agreements::v2::{
    AgreementV2Mutation, AgreementV2Role, CreateAgreementV2, apply_with_agent,
    compute_agreement_hash, compute_transcript_hash, create_with_agent, sign_with_agent,
    verify_with_agent,
};
use jacs::crypt::hash::hash_public_key;
use jacs::validation::normalize_agent_id;
use serde_json::{Value, json};
use serial_test::serial;

mod utils;

use utils::{load_test_agent_one_ed25519, load_test_agent_two_ed25519};

#[test]
#[serial(jacs_env)]
fn golden_three_party_agreement_with_notary_counter_sign() {
    let mut agent_a = load_test_agent_one_ed25519();
    let mut agent_b = load_test_agent_two_ed25519();
    let mut hai = generated_ed25519_agent("HAI notary");
    let mut outsider = generated_ed25519_agent("Agent X");
    cache_all_public_keys(&mut [&mut agent_a, &mut agent_b, &mut hai, &mut outsider]);

    let a_id = normalized_id(&agent_a);
    let b_id = normalized_id(&agent_b);
    let hai_id = normalized_id(&hai);

    let created = create_with_agent(
        &mut agent_a,
        CreateAgreementV2 {
            title: "Golden agreement".to_string(),
            description: "A and B agree with HAI notary attestation.".to_string(),
            terms: "Initial terms.".to_string(),
            terms_format: "text/markdown".to_string(),
            status: "draft".to_string(),
            effective_from: None,
            expires_at: None,
            parties: vec![
                party(&a_id, "signer"),
                party(&b_id, "signer"),
                party(&hai_id, "notary"),
            ],
            signature_policy: json!({
                "partyQuorum": "all",
                "witnessRequired": 0,
                "notaryRequired": 1,
                "requiredAlgorithms": ["ring-Ed25519"],
                "minimumStrength": "classical"
            }),
            agreement_signatures: vec![],
            transcript: vec![],
            all_previous_versions: vec![],
            links: vec![],
            controllers: vec![a_id.clone(), b_id.clone(), hai_id.clone()],
        },
    )
    .expect("create agreement v2");
    let mut current = created.value;
    let initial_agreement_hash = required_str(&current, "jacsAgreementHash").to_string();

    let a_statement = signed_message_ref(&mut agent_a, "A opens negotiation.");
    current = apply_with_agent(
        &mut agent_a,
        &current.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: a_statement },
    )
    .expect("A append transcript")
    .value;
    assert_eq!(
        required_str(&current, "jacsAgreementHash"),
        initial_agreement_hash
    );
    let agent_a_id_for_header = agent_a.get_id().expect("agent A id");
    assert_eq!(
        current[DOCUMENT_AGENT_SIGNATURE_FIELDNAME]
            .get("agentID")
            .and_then(Value::as_str),
        Some(agent_a_id_for_header.as_str())
    );

    let b_statement = signed_message_ref(&mut agent_b, "B counters.");
    current = apply_with_agent(
        &mut agent_b,
        &current.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: b_statement },
    )
    .expect("B append transcript")
    .value;
    assert_eq!(
        required_str(&current, "jacsAgreementHash"),
        initial_agreement_hash
    );

    current = apply_with_agent(
        &mut agent_a,
        &current.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Final terms accepted by A and B.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("A updates terms")
    .value;
    assert_ne!(
        required_str(&current, "jacsAgreementHash"),
        initial_agreement_hash
    );
    assert_eq!(current["agreementSignatures"].as_array().unwrap().len(), 0);

    let final_hash = required_str(&current, "jacsAgreementHash").to_string();
    current = apply_with_agent(
        &mut agent_b,
        &current.to_string(),
        AgreementV2Mutation::SetStatus {
            status: "proposed".to_string(),
        },
    )
    .expect("B proposes final terms")
    .value;
    assert_eq!(required_str(&current, "jacsAgreementHash"), final_hash);

    current = sign_with_agent(&mut agent_a, &current.to_string(), AgreementV2Role::Signer)
        .expect("A signs")
        .value;
    assert_eq!(current["status"], json!("partially_signed"));

    current = sign_with_agent(&mut agent_b, &current.to_string(), AgreementV2Role::Signer)
        .expect("B signs")
        .value;
    assert_eq!(current["status"], json!("partially_signed"));

    current = sign_with_agent(&mut hai, &current.to_string(), AgreementV2Role::Notary)
        .expect("HAI notarizes")
        .value;
    assert_eq!(current["status"], json!("final"));

    let report = verify_with_agent(&mut agent_a, &current.to_string()).expect("verify final");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.signer_count, 2);
    assert_eq!(report.notary_count, 1);
    assert_eq!(report.expected_status, "final");
    assert_eq!(report.recomputed_agreement_hash, final_hash);
    assert_eq!(
        report.recomputed_transcript_hash,
        compute_transcript_hash(&current).expect("transcript hash")
    );

    let all_previous = current["allPreviousVersions"].as_array().unwrap();
    assert!(!all_previous.is_empty());
    assert_eq!(
        all_previous.last().and_then(Value::as_str),
        current[JACS_PREVIOUS_VERSION_FIELDNAME].as_str()
    );

    let outsider_terms_attempt = apply_with_agent(
        &mut outsider,
        &current.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Bad terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    );
    assert!(
        outsider_terms_attempt.is_err(),
        "outsider must not modify agreement"
    );

    let outsider_signature_attempt =
        sign_with_agent(&mut outsider, &current.to_string(), AgreementV2Role::Signer);
    assert!(
        outsider_signature_attempt.is_err(),
        "outsider must not sign agreement"
    );

    let mut tampered = current.clone();
    tampered["transcript"]
        .as_array_mut()
        .expect("transcript array")
        .remove(0);
    let tampered_key = format!(
        "{}:{}",
        current["jacsId"].as_str().unwrap(),
        current["jacsVersion"].as_str().unwrap()
    );
    let tampered = hai
        .update_document(&tampered_key, &tampered.to_string(), None, None)
        .expect("emit structurally valid tampered successor")
        .value;
    let tampered_report =
        verify_with_agent(&mut agent_a, &tampered.to_string()).expect("verify tampered");
    assert!(!tampered_report.valid);
    assert!(
        tampered_report
            .errors
            .iter()
            .any(|error| error.contains("Hash mismatch") || error.contains("hash")),
        "expected transcript tamper hash failure, got {:?}",
        tampered_report.errors
    );

    assert_eq!(
        compute_agreement_hash(&current).expect("agreement hash"),
        required_str(&current, "jacsAgreementHash")
    );
}

fn generated_ed25519_agent(name: &str) -> Agent {
    let mut agent = Agent::ephemeral("ring-Ed25519").expect("create ephemeral Ed25519 agent");
    let agent_json =
        jacs::create_minimal_blank_agent("ai".to_string(), Some(name.to_string()), None, None)
            .expect("create agent JSON");
    agent
        .create_agent_and_load(&agent_json, true, Some("ring-Ed25519"))
        .expect("load generated agent");
    agent
}

fn cache_all_public_keys(agents: &mut [&mut Agent]) {
    let keys: Vec<(String, Vec<u8>)> = agents
        .iter_mut()
        .map(|agent| {
            let public_key = agent.get_public_key().expect("public key");
            (hash_public_key(&public_key), public_key)
        })
        .collect();

    for receiver in agents.iter_mut() {
        for (hash, public_key) in &keys {
            receiver
                .fs_save_remote_public_key(hash, public_key, b"ring-Ed25519")
                .expect("cache remote public key");
        }
    }
}

fn normalized_id(agent: &Agent) -> String {
    normalize_agent_id(&agent.get_id().expect("agent id")).to_string()
}

fn party(agent_id: &str, role: &str) -> Value {
    json!({
        "agentId": agent_id,
        "agentType": "ai",
        "role": role
    })
}

fn signed_message_ref(agent: &mut Agent, content: &str) -> Value {
    let message = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": content
    });
    let doc = agent
        .create_document_and_load(&message.to_string(), None, None)
        .expect("create transcript message");
    doc_ref(&doc)
}

fn doc_ref(document: &JACSDocument) -> Value {
    json!({
        "jacsId": document.id,
        "jacsVersion": document.version,
        "jacsSha256": document.value["jacsSha256"].as_str().unwrap()
    })
}

fn required_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {}", field))
}
