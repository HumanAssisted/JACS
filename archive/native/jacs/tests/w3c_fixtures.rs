mod utils;

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const ORIGIN: &str = "https://agent.example.com";
const METHOD: &str = "POST";
const URL: &str = "https://api.example.com/tasks?priority=high";
const BODY: &str = "{\"task\":\"review proposal\",\"ok\":true}";
const CREATED: &str = "2026-01-01T00:00:00Z";
const NONCE: &str = "w3c-fixture-nonce-0001";
const MAX_AGE_SECONDS: u64 = 4_000_000_000;

fn fixture_dir() -> PathBuf {
    utils::fixture_path("w3c")
}

fn write_fixture(name: &str, value: &Value) {
    let path = fixture_dir().join(name);
    fs::create_dir_all(fixture_dir()).expect("create w3c fixture dir");
    let body = format!(
        "{}\n",
        serde_json::to_string_pretty(value).expect("pretty json")
    );
    fs::write(path, body).expect("write fixture");
}

fn read_fixture(name: &str) -> Value {
    let path = fixture_dir().join(name);
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("parse fixture {}: {}", path.display(), e))
}

fn well_known_as_object(documents: Vec<(String, Value)>) -> Value {
    let mut by_path = BTreeMap::new();
    for (path, value) in documents {
        by_path.insert(path, value);
    }
    serde_json::to_value(by_path).expect("well-known object")
}

fn generated_fixture_values() -> BTreeMap<&'static str, Value> {
    let mut agent = utils::load_test_agent_one_ed25519();
    let did_document = jacs::w3c::export_did_document(
        &agent,
        jacs::w3c::W3cDidOptions {
            origin: Some(ORIGIN.to_string()),
        },
    )
    .expect("did document");
    let agent_description = jacs::w3c::export_agent_description(
        &agent,
        jacs::w3c::W3cDidOptions {
            origin: Some(ORIGIN.to_string()),
        },
    )
    .expect("agent description");
    let well_known = well_known_as_object(
        jacs::w3c::generate_w3c_well_known_documents(
            &agent,
            jacs::w3c::W3cDidOptions {
                origin: Some(ORIGIN.to_string()),
            },
        )
        .expect("well-known documents"),
    );
    let proof = jacs::w3c::build_request_proof(
        &mut agent,
        jacs::w3c::W3cRequestProofParams {
            method: METHOD.to_string(),
            url: URL.to_string(),
            body: Some(BODY.to_string()),
            nonce: Some(NONCE.to_string()),
            created: Some(CREATED.to_string()),
            origin: Some(ORIGIN.to_string()),
        },
    )
    .expect("request proof");
    let verification = jacs::w3c::verify_request_proof_value_for_request(
        &agent,
        &proof,
        &did_document,
        Some(BODY),
        MAX_AGE_SECONDS,
        Some(METHOD),
        Some(URL),
    )
    .expect("request proof verification");

    BTreeMap::from([
        ("did-document.json", did_document),
        ("agent-description.json", agent_description),
        ("well-known.json", well_known),
        ("request-proof.json", proof),
        ("verification-result.json", verification),
    ])
}

#[test]
fn w3c_golden_fixtures_match_real_fixture_agent() {
    let generated = generated_fixture_values();

    if std::env::var_os("JACS_UPDATE_W3C_FIXTURES").is_some() {
        for (name, value) in &generated {
            write_fixture(name, value);
        }
        return;
    }

    for (name, value) in generated {
        assert_eq!(
            read_fixture(name),
            value,
            "W3C fixture {} is stale; rerun with JACS_UPDATE_W3C_FIXTURES=1",
            name
        );
    }
}

#[test]
fn w3c_golden_request_fails_for_wrong_actual_request() {
    if std::env::var_os("JACS_UPDATE_W3C_FIXTURES").is_some() {
        return;
    }

    let agent = utils::load_test_agent_one_ed25519();
    let did_document = read_fixture("did-document.json");
    let proof = read_fixture("request-proof.json");

    let result = jacs::w3c::verify_request_proof_value_for_request(
        &agent,
        &proof,
        &did_document,
        Some(BODY),
        MAX_AGE_SECONDS,
        Some(METHOD),
        Some("https://api.example.com/other"),
    );

    assert!(result.is_err(), "wrong target URI must be rejected");
}

#[test]
fn w3c_golden_fixture_documents_keep_jacs_id_canonical() {
    if std::env::var_os("JACS_UPDATE_W3C_FIXTURES").is_some() {
        return;
    }

    let did_document = read_fixture("did-document.json");
    let agent_description = read_fixture("agent-description.json");

    assert_eq!(
        did_document["jacs"]["jacsId"],
        agent_description["jacs"]["jacsId"]
    );
    assert!(
        did_document["id"]
            .as_str()
            .expect("did id")
            .starts_with("did:wba:agent.example.com:agent:")
    );
    assert_eq!(
        agent_description["did"].as_str(),
        did_document["id"].as_str()
    );
    assert_eq!(
        json!("AgentDescription"),
        did_document["service"][0]["type"]
    );
}
