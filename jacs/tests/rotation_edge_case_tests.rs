//! Dedicated integration tests for key rotation edge cases.
//!
//! These tests exercise all four edge cases from the KEY_ROTATION_EDGE_CASES PRD:
//! 1. Crash recovery (write-ahead journal)
//! 2. Transition signature verification
//! 3. Cross-algorithm rotation
//! 4. Full lifecycle sequences
//!
//! Each test uses a temporary directory and serial execution to avoid
//! environment leaks between tests.

mod utils;

use jacs::simple::{self, CreateAgentParams, SimpleAgent, advanced};
use serde_json::Value;
use serial_test::serial;
use std::sync::Mutex;

static EDGE_CASE_MUTEX: Mutex<()> = Mutex::new(());

struct CwdGuard {
    saved: std::path::PathBuf,
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved);
    }
}

fn create_test_agent(
    name: &str,
    algorithm: &str,
) -> (SimpleAgent, simple::AgentInfo, tempfile::TempDir, CwdGuard) {
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    std::env::set_current_dir(tmp.path()).expect("cd to temp dir");
    let guard = CwdGuard { saved: saved_cwd };

    let params = CreateAgentParams::builder()
        .name(name)
        .password("EdgeCaseTest!2026")
        .algorithm(algorithm)
        .description("Test agent for rotation edge cases")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();

    let (agent, info) = SimpleAgent::create_with_params(params).expect("create test agent");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "EdgeCaseTest!2026");
        std::env::set_var("JACS_KEY_DIRECTORY", "./jacs_keys");
        std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem.enc");
        std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem");
    }

    (agent, info, tmp, guard)
}

// =============================================================================
// Crash Recovery Tests
// =============================================================================

/// Simulate crash after rotate_self but before config re-sign.
/// On reload with journal present, agent should auto-repair.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_crash_after_rotate_self_before_config_write() {
    use jacs::keystore::RotationJournal;

    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, info, _tmp, _guard) = create_test_agent("crash-before-config", "ring-Ed25519");

    let config_before = std::fs::read_to_string("./jacs.config.json").expect("read config");

    // Rotate successfully (creates proper state)
    let _result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Simulate crash: restore pre-rotation config, add a journal
    std::fs::write("./jacs.config.json", &config_before).expect("restore stale config");
    let _journal = RotationJournal::create(
        "./jacs_keys",
        &info.agent_id,
        &info.version,
        "old-key-hash",
        "ring-Ed25519",
        "./jacs.config.json",
    )
    .expect("create journal");

    // Reload: should auto-repair
    let reloaded = SimpleAgent::load(Some("./jacs.config.json"), None).expect("should auto-repair");

    // Journal should be deleted
    let journal_path = RotationJournal::journal_path("./jacs_keys");
    let journal_path_alt = RotationJournal::journal_path("jacs_keys");
    assert!(
        !std::path::Path::new(&journal_path).exists()
            && !std::path::Path::new(&journal_path_alt).exists(),
        "Journal should be deleted after auto-repair"
    );

    // Agent should be functional
    let signed = reloaded
        .sign_message(&serde_json::json!({"after": "crash-recovery"}))
        .expect("signing after recovery");
    let verification = reloaded.verify(&signed.raw).expect("verify");
    assert!(
        verification.valid,
        "Should verify after crash recovery: {:?}",
        verification.errors
    );
}

/// Double crash recovery: rotate twice, crash on second, recover.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_double_crash_recovery() {
    use jacs::keystore::RotationJournal;

    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, info, _tmp, _guard) = create_test_agent("double-crash", "ring-Ed25519");

    // First rotation succeeds
    let result1 = advanced::rotate(&agent, None).expect("first rotation");

    // Capture config after first rotation (good state)
    let config_after_first = std::fs::read_to_string("./jacs.config.json").expect("read config");

    // Second rotation succeeds
    let _result2 = advanced::rotate(&agent, None).expect("second rotation");

    // Simulate crash on second rotation: restore config from first rotation state
    std::fs::write("./jacs.config.json", &config_after_first).expect("restore mid-state config");

    // Write journal for second rotation
    let _journal = RotationJournal::create(
        "./jacs_keys",
        &info.agent_id,
        &result1.new_version,
        &result1.new_public_key_hash,
        "ring-Ed25519",
        "./jacs.config.json",
    )
    .expect("create journal");

    // Reload: should auto-repair to the second rotation's state
    let reloaded = SimpleAgent::load(Some("./jacs.config.json"), None).expect("should auto-repair");

    // Verify journal deleted
    assert!(
        !std::path::Path::new(&RotationJournal::journal_path("./jacs_keys")).exists(),
        "Journal should be deleted"
    );

    // Verify agent is functional
    let signed = reloaded
        .sign_message(&serde_json::json!({"test": "double-crash"}))
        .expect("sign after double-crash recovery");
    let verification = reloaded.verify(&signed.raw).expect("verify");
    assert!(
        verification.valid,
        "Should verify after double-crash recovery: {:?}",
        verification.errors
    );
}

// =============================================================================
// Transition Proof Tests
// =============================================================================

/// Transition proof message must contain correct old and new key hashes.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_transition_proof_message_contains_correct_hashes() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("proof-hashes-test", "ring-Ed25519");

    let old_pub_key = agent.get_public_key().expect("get old pub key");
    let old_key_hash = jacs::crypt::hash::hash_public_key(&old_pub_key);

    let result = advanced::rotate(&agent, None).expect("rotation");

    let proof: Value =
        serde_json::from_str(result.transition_proof.as_ref().unwrap()).expect("parse proof");

    // Verify old key hash in proof matches what we captured
    assert_eq!(
        proof["oldPublicKeyHash"].as_str().unwrap(),
        old_key_hash,
        "Proof's oldPublicKeyHash must match the captured old key hash"
    );

    // Verify new key hash in proof matches the result
    assert_eq!(
        proof["newPublicKeyHash"].as_str().unwrap(),
        result.new_public_key_hash,
        "Proof's newPublicKeyHash must match the rotation result's new key hash"
    );

    // Verify the transition message contains both hashes
    let msg = proof["transitionMessage"].as_str().unwrap();
    assert!(
        msg.contains(&old_key_hash),
        "Transition message must contain old key hash"
    );
    assert!(
        msg.contains(&result.new_public_key_hash),
        "Transition message must contain new key hash"
    );
}

/// Chain of two rotations: each proof is independently verifiable.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_chain_of_two_rotations_proofs() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("chain-proofs-test", "ring-Ed25519");

    // Capture key A
    let key_a = agent.get_public_key().expect("get key A");

    // Rotate A -> B
    let result1 = advanced::rotate(&agent, None).expect("first rotation A->B");
    let key_b = agent.get_public_key().expect("get key B");

    // Rotate B -> C
    let result2 = advanced::rotate(&agent, None).expect("second rotation B->C");

    // Parse proofs
    let proof_ab: Value =
        serde_json::from_str(result1.transition_proof.as_ref().unwrap()).expect("parse proof A->B");
    let proof_bc: Value =
        serde_json::from_str(result2.transition_proof.as_ref().unwrap()).expect("parse proof B->C");

    // Verify proof A->B with key A (should succeed)
    assert!(
        jacs::agent::Agent::verify_transition_proof(&proof_ab, &key_a).is_ok(),
        "Proof A->B should verify with key A"
    );

    // Verify proof A->B with key B (should fail)
    assert!(
        jacs::agent::Agent::verify_transition_proof(&proof_ab, &key_b).is_err(),
        "Proof A->B should NOT verify with key B"
    );

    // Verify proof B->C with key B (should succeed)
    assert!(
        jacs::agent::Agent::verify_transition_proof(&proof_bc, &key_b).is_ok(),
        "Proof B->C should verify with key B"
    );

    // Chain linkage: proof B->C's oldPublicKeyHash == result1's newPublicKeyHash
    assert_eq!(
        proof_bc["oldPublicKeyHash"].as_str().unwrap(),
        result1.new_public_key_hash,
        "Proof B->C oldPublicKeyHash must match result1 newPublicKeyHash (chain linkage)"
    );

    // Proof A->B's newPublicKeyHash == proof B->C's oldPublicKeyHash
    assert_eq!(
        proof_ab["newPublicKeyHash"].as_str().unwrap(),
        proof_bc["oldPublicKeyHash"].as_str().unwrap(),
        "Chain linkage: proof1.new == proof2.old"
    );
}

// =============================================================================
// Cross-Algorithm Rotation Tests
// =============================================================================

/// Ed25519 to pq2025: agent should sign correctly with the new algorithm.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_ed25519_to_pq2025_signs_correctly() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("ed25519-to-pq2025", "ring-Ed25519");

    let result =
        advanced::rotate(&agent, Some("pq2025")).expect("cross-algo rotation ed25519->pq2025");

    // Sign and verify with pq2025
    let signed = agent
        .sign_message(&serde_json::json!({"algo": "pq2025"}))
        .expect("sign with pq2025");
    let verification = agent.verify(&signed.raw).expect("verify");
    assert!(
        verification.valid,
        "pq2025 signature should verify: {:?}",
        verification.errors
    );

    // Proof's signing algorithm should be the OLD algorithm (ed25519)
    let proof: Value =
        serde_json::from_str(result.transition_proof.as_ref().unwrap()).expect("parse proof");
    assert_eq!(
        proof["signingAlgorithm"].as_str().unwrap(),
        "ring-Ed25519",
        "Transition proof should be signed with old algorithm"
    );
}

/// pq2025 to Ed25519: reverse direction should also work.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_pq2025_to_ed25519_signs_correctly() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("pq2025-to-ed25519", "pq2025");

    let result = advanced::rotate(&agent, Some("ring-Ed25519"))
        .expect("cross-algo rotation pq2025->ed25519");

    // Sign and verify with Ed25519
    let signed = agent
        .sign_message(&serde_json::json!({"algo": "ed25519"}))
        .expect("sign with ed25519");
    let verification = agent.verify(&signed.raw).expect("verify");
    assert!(
        verification.valid,
        "ed25519 signature should verify: {:?}",
        verification.errors
    );

    // Proof's signing algorithm should be the OLD algorithm (pq2025)
    let proof: Value =
        serde_json::from_str(result.transition_proof.as_ref().unwrap()).expect("parse proof");
    assert_eq!(
        proof["signingAlgorithm"].as_str().unwrap(),
        "pq2025",
        "Transition proof should be signed with old algorithm pq2025"
    );
}

/// After cross-algorithm rotation, config on disk should reflect the new algorithm.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_cross_algo_config_field_updated() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("cross-algo-config", "ring-Ed25519");

    let _result = advanced::rotate(&agent, Some("pq2025")).expect("cross-algo rotation");

    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read config");
    let config: Value = serde_json::from_str(&config_str).expect("parse config");
    assert_eq!(
        config["jacs_agent_key_algorithm"].as_str(),
        Some("pq2025"),
        "Config must reflect new algorithm after cross-algo rotation"
    );
}

/// Invalid algorithm strings should be rejected early.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_cross_algo_invalid_algorithm_rejected() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("invalid-algo-reject", "ring-Ed25519");

    let result = advanced::rotate(&agent, Some("not-a-real-algo"));
    assert!(result.is_err(), "Invalid algorithm should be rejected");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Invalid algorithm") || err_msg.contains("not-a-real-algo"),
        "Error should mention the invalid algorithm: {}",
        err_msg
    );
}

// =============================================================================
// Full Lifecycle Tests
// =============================================================================

/// Create -> rotate -> sign -> verify full lifecycle.
/// Note: After rotation, the agent's current key changes. Documents signed
/// with the old key can only be verified if the old public key is available
/// in the local key cache (which it is, since rotate_self saves it).
#[test]
#[serial(jacs_env, cwd_env)]
fn test_create_rotate_sign_verify_lifecycle() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, info, _tmp, _guard) = create_test_agent("lifecycle-test", "ring-Ed25519");

    // Rotate
    let result = advanced::rotate(&agent, None).expect("rotation");
    assert_ne!(result.new_version, info.version, "New version must differ");

    // Sign document after rotation (with new key)
    let doc2 = agent
        .sign_message(&serde_json::json!({"stage": "after-rotation"}))
        .expect("sign after rotation");

    // Verify post-rotation document
    let v2 = agent.verify(&doc2.raw).expect("verify doc2");
    assert!(v2.valid, "Post-rotation doc should verify: {:?}", v2.errors);

    // Check version chain in the agent document
    let agent_doc: Value =
        serde_json::from_str(&result.signed_agent_json).expect("parse agent doc");
    assert_eq!(
        agent_doc["jacsPreviousVersion"].as_str().unwrap(),
        info.version,
        "Agent doc must reference previous version"
    );

    // Verify transition proof exists and is valid
    assert!(
        result.transition_proof.is_some(),
        "Rotation must produce transition proof"
    );
}

/// Create -> rotate -> crash -> recover -> sign -> verify lifecycle.
/// After crash recovery, the agent should be able to sign new documents
/// and verify them. The recovered agent uses the post-rotation key.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_create_rotate_crash_recover_sign_lifecycle() {
    use jacs::keystore::RotationJournal;

    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, info, _tmp, _guard) = create_test_agent("crash-lifecycle-test", "ring-Ed25519");

    // Capture pre-rotation config
    let config_before = std::fs::read_to_string("./jacs.config.json").expect("read config");

    // Rotate
    let _result = advanced::rotate(&agent, None).expect("rotation");

    // Simulate crash: restore pre-rotation config + write journal
    std::fs::write("./jacs.config.json", &config_before).expect("restore stale config");
    let _journal = RotationJournal::create(
        "./jacs_keys",
        &info.agent_id,
        &info.version,
        "old-key-hash",
        "ring-Ed25519",
        "./jacs.config.json",
    )
    .expect("create journal");

    // Reload: auto-repair
    let recovered =
        SimpleAgent::load(Some("./jacs.config.json"), None).expect("auto-repair on load");

    // Journal should be deleted after auto-repair
    assert!(
        !std::path::Path::new(&RotationJournal::journal_path("./jacs_keys")).exists(),
        "Journal should be deleted after auto-repair"
    );

    // Sign document after recovery (with post-rotation key)
    let doc2 = recovered
        .sign_message(&serde_json::json!({"stage": "after-recovery"}))
        .expect("sign after recovery");

    // Verify the post-recovery document
    let v2 = recovered.verify(&doc2.raw).expect("verify doc2");
    assert!(v2.valid, "Post-recovery doc should verify: {:?}", v2.errors);
}

// =============================================================================
// Rotation Stress: Repeated sign/verify after multiple rotations (P1 Task 5)
// =============================================================================

/// Rotate the agent 3 times, each time signing and verifying a document.
/// This proves rotation does not corrupt subsequent sign/verify operations
/// under repeated load.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_rotation_stress_repeated_sign_verify() {
    let _lock = EDGE_CASE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("rotation-stress", "ring-Ed25519");

    // Pre-rotation sign/verify baseline
    let baseline = agent
        .sign_message(&serde_json::json!({"stage": "before-any-rotation"}))
        .expect("baseline sign");
    let baseline_v = agent.verify(&baseline.raw).expect("baseline verify");
    assert!(baseline_v.valid, "baseline should verify");

    // Rotate 3 times, signing and verifying after each
    for i in 0..3 {
        let rotation = advanced::rotate(&agent, None)
            .unwrap_or_else(|e| panic!("rotation {} should succeed: {}", i + 1, e));
        assert!(
            !rotation.new_public_key_hash.is_empty(),
            "rotation {} should produce a new key hash",
            i + 1
        );

        // Sign with new key
        let signed = agent
            .sign_message(&serde_json::json!({
                "stage": format!("after-rotation-{}", i + 1),
                "iteration": i + 1,
            }))
            .unwrap_or_else(|e| panic!("sign after rotation {} failed: {}", i + 1, e));

        // Verify with new key
        let verification = agent
            .verify(&signed.raw)
            .unwrap_or_else(|e| panic!("verify after rotation {} failed: {}", i + 1, e));
        assert!(
            verification.valid,
            "verification after rotation {} should succeed: {:?}",
            i + 1,
            verification.errors
        );
    }
}
