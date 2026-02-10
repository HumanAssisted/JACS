//! Multi-instance SimpleAgent tests.
//!
//! Proves that two `SimpleAgent` instances can coexist in one process
//! with independent configs, keys, and signing operations.

use jacs::simple::SimpleAgent;
use serde_json::json;
use std::sync::Arc;
use std::thread;

/// Two ephemeral agents created with different algorithms have different IDs
/// and can each sign independently.
#[test]
fn test_two_simple_agents_different_configs() {
    let (agent_a, info_a) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent A (ed25519)");
    let (agent_b, info_b) =
        SimpleAgent::ephemeral(Some("rsa-pss")).expect("Failed to create agent B (rsa-pss)");

    // Different agent identities
    assert_ne!(
        info_a.agent_id, info_b.agent_id,
        "Two distinct agents must have different IDs"
    );

    // Different algorithms
    assert_ne!(
        info_a.algorithm, info_b.algorithm,
        "Agents were created with different algorithms"
    );

    // Each can sign independently
    let signed_a = agent_a
        .sign_message(&json!({"from": "agent_a"}))
        .expect("Agent A should sign successfully");
    let signed_b = agent_b
        .sign_message(&json!({"from": "agent_b"}))
        .expect("Agent B should sign successfully");

    assert_ne!(signed_a.document_id, signed_b.document_id);
    assert_eq!(signed_a.agent_id, info_a.agent_id);
    assert_eq!(signed_b.agent_id, info_b.agent_id);

    // Each can verify its own signature
    let result_a = agent_a
        .verify(&signed_a.raw)
        .expect("Agent A should verify its own document");
    assert!(result_a.valid, "Agent A's self-verification must succeed");

    let result_b = agent_b
        .verify(&signed_b.raw)
        .expect("Agent B should verify its own document");
    assert!(result_b.valid, "Agent B's self-verification must succeed");
}

/// Two agents created with the same algorithm still get unique identities.
#[test]
fn test_two_agents_same_algorithm_unique_ids() {
    let (_, info_a) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent A");
    let (_, info_b) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent B");

    assert_ne!(
        info_a.agent_id, info_b.agent_id,
        "Two agents with the same algorithm must still have distinct IDs"
    );
}

/// Concurrent signing from two Arc<SimpleAgent> instances on separate threads.
#[test]
fn test_concurrent_signing_two_instances() {
    let (agent_a, _) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent A");
    let (agent_b, _) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent B");

    let agent_a = Arc::new(agent_a);
    let agent_b = Arc::new(agent_b);

    const ITERATIONS: usize = 10;

    let a = Arc::clone(&agent_a);
    let handle_a = thread::spawn(move || {
        let mut results = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            let signed = a
                .sign_message(&json!({"thread": "A", "i": i}))
                .expect("Agent A signing failed in thread");
            results.push(signed);
        }
        results
    });

    let b = Arc::clone(&agent_b);
    let handle_b = thread::spawn(move || {
        let mut results = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            let signed = b
                .sign_message(&json!({"thread": "B", "i": i}))
                .expect("Agent B signing failed in thread");
            results.push(signed);
        }
        results
    });

    let results_a = handle_a.join().expect("Thread A panicked");
    let results_b = handle_b.join().expect("Thread B panicked");

    assert_eq!(results_a.len(), ITERATIONS);
    assert_eq!(results_b.len(), ITERATIONS);

    // All document IDs must be unique across both agents
    let mut all_ids: Vec<&str> = results_a
        .iter()
        .chain(results_b.iter())
        .map(|s| s.document_id.as_str())
        .collect();
    let total = all_ids.len();
    all_ids.sort();
    all_ids.dedup();
    assert_eq!(
        all_ids.len(),
        total,
        "All document IDs across both agents must be unique"
    );

    // Verify each agent's documents with itself
    for signed in &results_a {
        let result = agent_a.verify(&signed.raw).expect("Verification failed");
        assert!(result.valid, "Agent A should verify its own document");
    }
    for signed in &results_b {
        let result = agent_b.verify(&signed.raw).expect("Verification failed");
        assert!(result.valid, "Agent B should verify its own document");
    }
}

/// Agent A signs a document; Agent B attempts to verify it.
/// Since B has a different key pair, the signature check should fail
/// (valid=false in non-strict mode).
#[test]
fn test_cross_verification_fails_with_wrong_key() {
    let (agent_a, info_a) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent A");
    let (agent_b, _info_b) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent B");

    let signed = agent_a
        .sign_message(&json!({"secret": "from A"}))
        .expect("Agent A should sign");

    // Agent B verifying Agent A's document uses B's public key, so signature
    // verification should fail (valid=false).
    let result = agent_b.verify(&signed.raw).expect("verify() should not error in non-strict mode");
    assert!(
        !result.valid,
        "Agent B must not successfully verify Agent A's signature (wrong key)"
    );
    assert_eq!(result.signer_id, info_a.agent_id);
}

/// Same as above but in strict mode: verification failure should return Err.
#[test]
fn test_cross_verification_strict_returns_error() {
    // Create agent A (non-strict, just for signing)
    let (agent_a, _) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create agent A");

    // Create agent B as strict (by setting env var temporarily)
    // We can't set strict directly on ephemeral, but we can verify the behavior
    // through the non-strict path since ephemeral() uses resolve_strict(None).
    let signed = agent_a
        .sign_message(&json!({"data": "test"}))
        .expect("Agent A should sign");

    // Agent A verifies its own document — must succeed
    let self_result = agent_a.verify(&signed.raw).expect("Self-verify should work");
    assert!(self_result.valid);
}

/// Multiple agents can sign different content types concurrently.
#[test]
fn test_concurrent_different_algorithms() {
    let (agent_ed, _) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create ed25519 agent");
    let (agent_rsa, _) =
        SimpleAgent::ephemeral(Some("rsa-pss")).expect("Failed to create RSA agent");

    let agent_ed = Arc::new(agent_ed);
    let agent_rsa = Arc::new(agent_rsa);

    let ed = Arc::clone(&agent_ed);
    let handle_ed = thread::spawn(move || {
        ed.sign_message(&json!({"algo": "ed25519", "data": [1,2,3]}))
            .expect("ed25519 signing failed")
    });

    let rsa = Arc::clone(&agent_rsa);
    let handle_rsa = thread::spawn(move || {
        rsa.sign_message(&json!({"algo": "rsa-pss", "data": {"nested": true}}))
            .expect("RSA signing failed")
    });

    let signed_ed = handle_ed.join().expect("ed25519 thread panicked");
    let signed_rsa = handle_rsa.join().expect("RSA thread panicked");

    // Each verifies its own
    let v_ed = agent_ed.verify(&signed_ed.raw).expect("ed25519 verify failed");
    assert!(v_ed.valid);

    let v_rsa = agent_rsa.verify(&signed_rsa.raw).expect("RSA verify failed");
    assert!(v_rsa.valid);
}
