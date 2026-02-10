//! Tests for document signing and verification via binding-core.
//!
//! These validate the underlying APIs that jacs-mcp's jacs_sign_document
//! and jacs_verify_document tools delegate to.

use jacs_binding_core::AgentWrapper;
use serde_json::{Value, json};

fn create_ephemeral_wrapper() -> AgentWrapper {
    let wrapper = AgentWrapper::new();
    wrapper
        .ephemeral(Some("ed25519"))
        .expect("Failed to create ephemeral agent");
    wrapper
}

#[test]
fn test_sign_document_and_verify_valid() {
    let wrapper = create_ephemeral_wrapper();

    let content = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": {"hello": "world"}
    });

    // Sign (create_document with no_save=true)
    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    assert!(!signed.is_empty(), "signed document should not be empty");

    // Parse to confirm it's valid JSON with JACS fields
    let parsed: Value = serde_json::from_str(&signed).expect("signed doc should be valid JSON");
    assert!(parsed.get("id").is_some() || parsed.get("jacsId").is_some(),
        "signed doc should have an id field");

    // Verify using verify_signature (self-signed ephemeral agent)
    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature should succeed");
    assert!(valid, "document should verify as valid");
}

#[test]
fn test_verify_document_invalid_garbage() {
    let wrapper = create_ephemeral_wrapper();

    // Garbage string should fail verification
    let result = wrapper.verify_document("not-a-valid-jacs-document");
    assert!(result.is_err(), "garbage input should return an error");
}

#[test]
fn test_verify_document_tampered() {
    let wrapper = create_ephemeral_wrapper();

    let content = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": {"data": "original"}
    });

    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    // Tamper with the signed document by modifying content
    let mut parsed: Value = serde_json::from_str(&signed).unwrap();
    if let Some(doc) = parsed.get_mut("jacsDocument") {
        if let Some(content_obj) = doc.get_mut("content") {
            *content_obj = json!({"data": "tampered"});
        }
    }
    let tampered = serde_json::to_string(&parsed).unwrap();

    // Tampered document should fail hash verification
    let result = wrapper.verify_document(&tampered);
    assert!(result.is_err(), "tampered document should fail verification");
}

#[test]
fn test_sign_batch_returns_signatures_for_each_message() {
    let wrapper = create_ephemeral_wrapper();

    let messages = vec![
        "message one".to_string(),
        "message two".to_string(),
        "message three".to_string(),
    ];
    let signatures = wrapper
        .sign_batch(messages.clone())
        .expect("sign_batch should succeed");

    assert_eq!(
        signatures.len(),
        messages.len(),
        "should return one signature per message"
    );
    for (i, sig) in signatures.iter().enumerate() {
        assert!(!sig.is_empty(), "signature {} should not be empty", i);
    }

    // Each signature should be unique (different messages -> different sigs)
    let unique: std::collections::HashSet<&String> = signatures.iter().collect();
    assert_eq!(
        unique.len(),
        signatures.len(),
        "all signatures should be distinct"
    );
}

#[test]
fn test_sign_batch_empty_input() {
    let wrapper = create_ephemeral_wrapper();
    let signatures = wrapper
        .sign_batch(vec![])
        .expect("sign_batch with empty input should succeed");
    assert!(signatures.is_empty(), "empty input should return empty output");
}

#[test]
fn test_sign_document_roundtrip() {
    let wrapper = create_ephemeral_wrapper();

    let content = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": {"task": "test roundtrip", "value": 42}
    });

    // Sign
    let signed = wrapper
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("create_document should succeed");

    // Verify via verify_signature (self-signed)
    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature should succeed");
    assert!(valid, "roundtrip: signed document should verify");
}
