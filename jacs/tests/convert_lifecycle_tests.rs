//! Integration tests: full sign -> convert -> reconvert -> verify lifecycle.
//!
//! Tests the complete chain for both YAML and HTML with different key algorithms
//! and tamper detection.

mod utils;

use jacs::convert::{html_to_jacs, jacs_to_html, jacs_to_yaml, yaml_to_jacs};
use jacs::simple::SimpleAgent;

fn make_agent(algorithm: &str) -> SimpleAgent {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some(algorithm)).expect("should create ephemeral agent");
    agent
}

// =========================================================================
// Ed25519 lifecycle tests
// =========================================================================

#[test]
fn sign_yaml_verify_ed25519() {
    let agent = make_agent("ed25519");
    let signed = agent
        .sign_message(&serde_json::json!({"data": "lifecycle test", "count": 99}))
        .expect("sign should succeed");

    let yaml = jacs_to_yaml(&signed.raw).expect("jacs_to_yaml");
    let json_back = yaml_to_jacs(&yaml).expect("yaml_to_jacs");
    let result = agent.verify(&json_back).expect("verify should succeed");
    assert!(
        result.valid,
        "Ed25519 sign -> YAML -> JSON -> verify should pass: {:?}",
        result.errors
    );
}

#[test]
fn sign_html_verify_ed25519() {
    let agent = make_agent("ed25519");
    let signed = agent
        .sign_message(&serde_json::json!({"data": "html lifecycle", "flag": true}))
        .expect("sign should succeed");

    let html = jacs_to_html(&signed.raw).expect("jacs_to_html");
    let json_back = html_to_jacs(&html).expect("html_to_jacs");
    let result = agent.verify(&json_back).expect("verify should succeed");
    assert!(
        result.valid,
        "Ed25519 sign -> HTML -> JSON -> verify should pass: {:?}",
        result.errors
    );
}

// =========================================================================
// Complex payload tests
// =========================================================================

#[test]
fn sign_complex_payload_yaml_round_trip() {
    let agent = make_agent("ed25519");
    let complex = serde_json::json!({
        "name": "Complex Test",
        "nested": {
            "level1": {
                "level2": {
                    "items": [1, 2, 3, "four", null, true],
                    "metadata": {"@context": "http://example.com", "$ref": "#/def"}
                }
            }
        },
        "tags": ["rust", "jacs", "yaml"],
        "description": "A document with\nnewlines and\ttabs",
        "unicode": "\u{00e9}\u{00e8}\u{00ea}"
    });
    let signed = agent.sign_message(&complex).expect("sign");
    let yaml = jacs_to_yaml(&signed.raw).expect("to yaml");
    let json_back = yaml_to_jacs(&yaml).expect("from yaml");
    let result = agent.verify(&json_back).expect("verify");
    assert!(
        result.valid,
        "Complex payload YAML round-trip: {:?}",
        result.errors
    );
}

#[test]
fn sign_complex_payload_html_round_trip() {
    let agent = make_agent("ed25519");
    let complex = serde_json::json!({
        "name": "HTML Complex Test",
        "values": [1.5, -0.0, 9007199254740993_u64, 0],
        "html_chars": "a < b & c > d",
        "nested": {"deep": {"deeper": "bottom"}}
    });
    let signed = agent.sign_message(&complex).expect("sign");
    let html = jacs_to_html(&signed.raw).expect("to html");
    let json_back = html_to_jacs(&html).expect("from html");
    let result = agent.verify(&json_back).expect("verify");
    assert!(
        result.valid,
        "Complex payload HTML round-trip: {:?}",
        result.errors
    );
}

// =========================================================================
// Chained conversions
// =========================================================================

#[test]
fn yaml_to_html_to_yaml_chain() {
    let agent = make_agent("ed25519");
    let signed = agent
        .sign_message(&serde_json::json!({"chain": "test"}))
        .expect("sign");

    // JSON -> YAML -> JSON -> HTML -> JSON -> verify
    let yaml = jacs_to_yaml(&signed.raw).expect("to yaml");
    let json1 = yaml_to_jacs(&yaml).expect("from yaml");
    let html = jacs_to_html(&json1).expect("to html");
    let json2 = html_to_jacs(&html).expect("from html");

    let result = agent.verify(&json2).expect("verify");
    assert!(
        result.valid,
        "Chained YAML->HTML round-trip: {:?}",
        result.errors
    );
}

// =========================================================================
// Tamper detection tests
// =========================================================================

#[test]
fn tampered_yaml_fails_verification() {
    let agent = make_agent("ed25519");
    let signed = agent
        .sign_message(&serde_json::json!({"secret": "original value"}))
        .expect("sign");

    let yaml = jacs_to_yaml(&signed.raw).expect("to yaml");

    // Tamper with the YAML -- change the value
    let tampered_yaml = yaml.replace("original value", "TAMPERED value");
    assert_ne!(yaml, tampered_yaml, "YAML should have been modified");

    let json_back = yaml_to_jacs(&tampered_yaml).expect("from yaml");
    let result = agent.verify(&json_back);

    // Verification should either fail or return valid: false
    if let Ok(vr) = result {
        assert!(!vr.valid, "Tampered document should not verify");
    }
    // Err is also acceptable for tampered docs
}

// =========================================================================
// pq2025 lifecycle tests (feature-gated)
// =========================================================================

#[cfg(feature = "pq-tests")]
#[test]
fn sign_yaml_verify_pq2025() {
    let agent = make_agent("pq2025");
    let signed = agent
        .sign_message(&serde_json::json!({"pq_yaml": "test", "algorithm": "pq2025"}))
        .expect("sign should succeed");

    let yaml = jacs_to_yaml(&signed.raw).expect("jacs_to_yaml");
    let json_back = yaml_to_jacs(&yaml).expect("yaml_to_jacs");
    let result = agent.verify(&json_back).expect("verify should succeed");
    assert!(
        result.valid,
        "pq2025 sign -> YAML -> JSON -> verify should pass: {:?}",
        result.errors
    );
}

#[cfg(feature = "pq-tests")]
#[test]
fn sign_html_verify_pq2025() {
    let agent = make_agent("pq2025");
    let signed = agent
        .sign_message(&serde_json::json!({"pq_html": "test", "algorithm": "pq2025"}))
        .expect("sign should succeed");

    let html = jacs_to_html(&signed.raw).expect("jacs_to_html");
    let json_back = html_to_jacs(&html).expect("html_to_jacs");
    let result = agent.verify(&json_back).expect("verify should succeed");
    assert!(
        result.valid,
        "pq2025 sign -> HTML -> JSON -> verify should pass: {:?}",
        result.errors
    );
}

// =========================================================================
// Tamper detection tests
// =========================================================================

#[test]
fn tampered_html_embedded_json_fails_verification() {
    let agent = make_agent("ed25519");
    let signed = agent
        .sign_message(&serde_json::json!({"important": "do not change"}))
        .expect("sign");

    let html = jacs_to_html(&signed.raw).expect("to html");

    // Tamper with the embedded JSON in the script tag
    let tampered_html = html.replace("do not change", "CHANGED!");
    assert_ne!(html, tampered_html, "HTML should have been modified");

    let json_back = html_to_jacs(&tampered_html).expect("from html");
    let result = agent.verify(&json_back);

    if let Ok(vr) = result {
        assert!(!vr.valid, "Tampered HTML document should not verify");
    }
    // Err is also acceptable
}
