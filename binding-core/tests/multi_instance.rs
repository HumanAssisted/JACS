//! Multi-instance tests for binding-core's AgentWrapper.
//!
//! Proves that multiple AgentWrapper instances can coexist and operate
//! concurrently through the binding layer.

use jacs_binding_core::AgentWrapper;
use serde_json::{Value, json};
use std::sync::Arc;
use std::thread;

fn create_ephemeral_wrapper(algo: &str) -> (AgentWrapper, String) {
    let wrapper = AgentWrapper::new();
    let info_json = wrapper
        .ephemeral(Some(algo))
        .expect("Failed to create ephemeral agent");
    let info: Value = serde_json::from_str(&info_json).expect("Bad agent info JSON");
    let agent_id = info["agent_id"].as_str().unwrap().to_string();
    (wrapper, agent_id)
}

#[test]
fn test_two_wrappers_different_ids() {
    let (_, id_a) = create_ephemeral_wrapper("ed25519");
    let (_, id_b) = create_ephemeral_wrapper("rsa-pss");

    assert_ne!(id_a, id_b, "Two AgentWrappers must have different IDs");
}

#[test]
fn test_wrapper_sign_and_self_verify() {
    let (wrapper, _) = create_ephemeral_wrapper("ed25519");

    let doc_content = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": {"hello": "world"}
    });

    let signed = wrapper
        .create_document(&doc_content.to_string(), None, None, true, None, None)
        .expect("create_document failed");

    // Use verify_signature (uses agent's own key) rather than verify_document
    // (which tries external key resolution unsuitable for ephemeral agents).
    let valid = wrapper
        .verify_signature(&signed, None)
        .expect("verify_signature failed");
    assert!(valid, "Wrapper should verify its own signed document");
}

#[test]
fn test_concurrent_wrappers() {
    let (wrapper_a, _) = create_ephemeral_wrapper("ed25519");
    let (wrapper_b, _) = create_ephemeral_wrapper("ed25519");

    // AgentWrapper is Clone (Arc<Mutex<Agent>> inside)
    let wa = Arc::new(wrapper_a);
    let wb = Arc::new(wrapper_b);

    const N: usize = 5;

    let a = Arc::clone(&wa);
    let handle_a = thread::spawn(move || {
        let mut docs = Vec::new();
        for i in 0..N {
            let content = json!({
                "jacsType": "message",
                "jacsLevel": "raw",
                "content": {"from": "A", "i": i}
            });
            let signed = a
                .create_document(&content.to_string(), None, None, true, None, None)
                .expect("Wrapper A create_document failed");
            docs.push(signed);
        }
        docs
    });

    let b = Arc::clone(&wb);
    let handle_b = thread::spawn(move || {
        let mut docs = Vec::new();
        for i in 0..N {
            let content = json!({
                "jacsType": "message",
                "jacsLevel": "raw",
                "content": {"from": "B", "i": i}
            });
            let signed = b
                .create_document(&content.to_string(), None, None, true, None, None)
                .expect("Wrapper B create_document failed");
            docs.push(signed);
        }
        docs
    });

    let docs_a = handle_a.join().expect("Thread A panicked");
    let docs_b = handle_b.join().expect("Thread B panicked");

    assert_eq!(docs_a.len(), N);
    assert_eq!(docs_b.len(), N);

    // Verify each wrapper's documents with itself (using verify_signature)
    for doc in &docs_a {
        assert!(wa.verify_signature(doc, None).expect("verify failed"));
    }
    for doc in &docs_b {
        assert!(wb.verify_signature(doc, None).expect("verify failed"));
    }
}

#[test]
fn test_cross_verification_fails() {
    let (wrapper_a, _) = create_ephemeral_wrapper("ed25519");
    let (wrapper_b, _) = create_ephemeral_wrapper("ed25519");

    let content = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": {"signed_by": "A"}
    });

    let signed = wrapper_a
        .create_document(&content.to_string(), None, None, true, None, None)
        .expect("Wrapper A signing failed");

    // Wrapper B verifying A's document with B's key should fail
    let result = wrapper_b.verify_signature(&signed, None);
    assert!(
        result.is_err(),
        "Wrapper B should fail to verify Wrapper A's document (different keys)"
    );
}
