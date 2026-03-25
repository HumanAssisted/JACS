//! Integration tests for SimpleAgent conversion convenience methods.

mod utils;

use jacs::simple::SimpleAgent;

fn make_ephemeral_agent() -> SimpleAgent {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("should create ephemeral agent");
    agent
}

#[test]
fn simple_agent_to_yaml_produces_valid_yaml() {
    let agent = make_ephemeral_agent();
    let signed = agent
        .sign_message(&serde_json::json!({"hello": "world"}))
        .expect("sign should succeed");
    let yaml = agent.to_yaml(&signed.raw).expect("to_yaml should succeed");
    // Verify it parses as YAML
    let _: serde_json::Value =
        serde_yaml_ng::from_str(&yaml).expect("YAML output should be valid YAML");
}

#[test]
fn simple_agent_from_yaml_produces_valid_json() {
    let agent = make_ephemeral_agent();
    let yaml = "hello: world\ncount: 42\n";
    let json = agent.from_yaml(yaml).expect("from_yaml should succeed");
    let _: serde_json::Value =
        serde_json::from_str(&json).expect("from_yaml output should be valid JSON");
}

#[test]
fn simple_agent_verify_yaml_round_trip() {
    let agent = make_ephemeral_agent();
    let signed = agent
        .sign_message(&serde_json::json!({"data": "test value", "number": 42}))
        .expect("sign should succeed");

    let yaml = agent.to_yaml(&signed.raw).expect("to_yaml should succeed");
    let result = agent
        .verify_yaml(&yaml)
        .expect("verify_yaml should succeed");
    assert!(
        result.valid,
        "Verification should pass after YAML round-trip: {:?}",
        result.errors
    );
}

#[test]
fn simple_agent_to_html_produces_valid_html() {
    let agent = make_ephemeral_agent();
    let signed = agent
        .sign_message(&serde_json::json!({"content": "test"}))
        .expect("sign should succeed");
    let html = agent.to_html(&signed.raw).expect("to_html should succeed");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains(r#"<script type="application/json" id="jacs-data">"#));
}

#[test]
fn simple_agent_from_html_round_trip() {
    let agent = make_ephemeral_agent();
    let signed = agent
        .sign_message(&serde_json::json!({"content": "hello"}))
        .expect("sign should succeed");

    let html = agent.to_html(&signed.raw).expect("to_html should succeed");
    let json_back = agent.from_html(&html).expect("from_html should succeed");

    let result = agent.verify(&json_back).expect("verify should succeed");
    assert!(
        result.valid,
        "Verification should pass after HTML round-trip: {:?}",
        result.errors
    );
}

#[test]
fn simple_agent_verify_yaml_invalid_yaml_returns_error() {
    let agent = make_ephemeral_agent();
    let result = agent.verify_yaml("{{{{ not yaml");
    assert!(result.is_err(), "Invalid YAML should return error");
}

#[test]
fn simple_agent_to_yaml_with_file_attachment() {
    let agent = make_ephemeral_agent();
    // Create a doc that includes file-like metadata
    let doc = serde_json::json!({
        "content": "document with attachment",
        "jacsFiles": [
            {"name": "report.pdf", "hash": "abc123", "mediaType": "application/pdf"}
        ]
    });
    let signed = agent.sign_message(&doc).expect("sign should succeed");
    let yaml = agent.to_yaml(&signed.raw).expect("to_yaml should succeed");
    assert!(
        yaml.contains("report.pdf"),
        "YAML should contain file metadata"
    );
}
