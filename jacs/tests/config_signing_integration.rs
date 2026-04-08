//! Integration tests verifying that config write sites produce signed configs on disk.
//!
//! These cover PRD Phase 3.6, 3.8, 3.10, 3.12 requirements:
//! - SimpleAgent::create writes a signed config
//! - Key rotation re-signs the config
//! - Agent migration re-signs the config

mod utils;

use jacs::simple::{self, CreateAgentParams, SimpleAgent, advanced};
use serde_json::Value;
use serial_test::serial;
use std::sync::Mutex;

static CONFIG_SIGN_MUTEX: Mutex<()> = Mutex::new(());

struct CwdGuard {
    saved: std::path::PathBuf,
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved);
    }
}

fn create_test_agent(name: &str) -> (SimpleAgent, simple::AgentInfo, tempfile::TempDir, CwdGuard) {
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    std::env::set_current_dir(tmp.path()).expect("cd to temp dir");
    let guard = CwdGuard { saved: saved_cwd };

    let params = CreateAgentParams::builder()
        .name(name)
        .password("ConfigSignTest!2026")
        .algorithm("ring-Ed25519")
        .description("Test agent for config signing")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();

    let (agent, info) = SimpleAgent::create_with_params(params).expect("create test agent");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "ConfigSignTest!2026");
        std::env::set_var("JACS_KEY_DIRECTORY", "./jacs_keys");
        std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem.enc");
        std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem");
    }

    (agent, info, tmp, guard)
}

/// PRD Phase 3.6: SimpleAgent::create writes a signed config to disk.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_create_agent_produces_signed_config_on_disk() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (_agent, _info, _tmp, _guard) = create_test_agent("create-signed-config-test");

    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read config");
    let config: Value = serde_json::from_str(&config_str).expect("parse config");

    assert!(
        config.get("jacsSignature").is_some(),
        "Config written by SimpleAgent::create must have jacsSignature"
    );
    assert_eq!(
        config.get("jacsType").and_then(|v| v.as_str()),
        Some("config"),
        "Config must have jacsType == config"
    );
    assert_eq!(
        config.get("jacsLevel").and_then(|v| v.as_str()),
        Some("config"),
        "Config must have jacsLevel == config"
    );
    assert!(
        config.get("jacsId").is_some(),
        "Signed config must have jacsId"
    );
    assert!(
        config.get("jacsVersion").is_some(),
        "Signed config must have jacsVersion"
    );
    assert!(
        config.get("jacsSha256").is_some(),
        "Signed config must have jacsSha256"
    );
}

/// PRD Phase 3.8: Key rotation re-signs the config with a new version.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_rotation_re_signs_config() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("rotate-signed-config-test");

    // Read config before rotation to capture original version
    let config_before_str =
        std::fs::read_to_string("./jacs.config.json").expect("read config before");
    let config_before: Value =
        serde_json::from_str(&config_before_str).expect("parse config before");
    let version_before = config_before
        .get("jacsVersion")
        .and_then(|v| v.as_str())
        .expect("must have jacsVersion before rotation")
        .to_string();

    // Rotate keys
    let _result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Read config after rotation
    let config_after_str =
        std::fs::read_to_string("./jacs.config.json").expect("read config after");
    let config_after: Value = serde_json::from_str(&config_after_str).expect("parse config after");

    assert!(
        config_after.get("jacsSignature").is_some(),
        "Config after rotation must still have jacsSignature"
    );
    let version_after = config_after
        .get("jacsVersion")
        .and_then(|v| v.as_str())
        .expect("must have jacsVersion after rotation");
    assert_ne!(
        version_after, version_before,
        "Config jacsVersion must change after rotation"
    );
    assert_eq!(
        config_after
            .get("jacsPreviousVersion")
            .and_then(|v| v.as_str()),
        Some(version_before.as_str()),
        "Config jacsPreviousVersion must be the old version"
    );
}

/// PRD Phase 3.10: Agent migration re-signs the config with a new version.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_migration_re_signs_config() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (_agent, _info, _tmp, _guard) = create_test_agent("migrate-signed-config-test");

    // Read config before migration to capture original version
    let config_before_str =
        std::fs::read_to_string("./jacs.config.json").expect("read config before migration");
    let config_before: Value =
        serde_json::from_str(&config_before_str).expect("parse config before migration");
    let version_before = config_before
        .get("jacsVersion")
        .and_then(|v| v.as_str())
        .expect("must have jacsVersion before migration")
        .to_string();

    // Run migration
    let result =
        advanced::migrate_agent(Some("./jacs.config.json")).expect("migration should succeed");
    assert!(
        !result.new_version.is_empty(),
        "Migration must produce a new version"
    );

    // Read config after migration
    let config_after_str =
        std::fs::read_to_string("./jacs.config.json").expect("read config after migration");
    let config_after: Value =
        serde_json::from_str(&config_after_str).expect("parse config after migration");

    assert!(
        config_after.get("jacsSignature").is_some(),
        "Config after migration must still have jacsSignature"
    );
    let version_after = config_after
        .get("jacsVersion")
        .and_then(|v| v.as_str())
        .expect("must have jacsVersion after migration");
    assert_ne!(
        version_after, version_before,
        "Config jacsVersion must change after migration"
    );
    assert_eq!(
        config_after
            .get("jacsPreviousVersion")
            .and_then(|v| v.as_str()),
        Some(version_before.as_str()),
        "Config jacsPreviousVersion must be the old version after migration"
    );
}

/// PRD Phase 3.5: Unsigned configs still load without error (backward compat).
#[test]
fn test_unsigned_config_loads_without_error() {
    let config_json = r#"{
        "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
        "jacs_use_filesystem": "true",
        "jacs_use_security": "true",
        "jacs_data_directory": ".",
        "jacs_key_directory": "keys",
        "jacs_agent_private_key_filename": "agent.private.pem.enc",
        "jacs_agent_public_key_filename": "agent.public.pem",
        "jacs_agent_key_algorithm": "ring-Ed25519",
        "jacs_agent_schema_version": "v1",
        "jacs_header_schema_version": "v1",
        "jacs_signature_schema_version": "v1",
        "jacs_default_storage": "fs"
    }"#;

    let tmp = tempfile::tempdir().expect("create temp dir");
    let config_path = tmp.path().join("jacs.config.json");
    std::fs::write(&config_path, config_json).expect("write unsigned config");

    let config = jacs::config::Config::from_file(&config_path.display().to_string())
        .expect("unsigned config should load without error");

    assert!(
        !config.is_signed,
        "unsigned config should report is_signed == false"
    );
}

// =============================================================================
// Key Rotation Edge Case Tests (PRD: KEY_ROTATION_EDGE_CASES)
// =============================================================================

/// After a successful rotation, no journal file should remain on disk.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_rotate_creates_and_deletes_journal() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (_agent, _info, _tmp, _guard) = create_test_agent("journal-cleanup-test");

    let _result = advanced::rotate(&_agent, None).expect("rotation should succeed");

    // Journal should not exist after successful rotation
    let journal_path = "./jacs_keys/.jacs_rotation_journal.json";
    assert!(
        !std::path::Path::new(journal_path).exists(),
        "Journal file should be deleted after successful rotation"
    );
}

/// Transition proof should be present in the rotation result.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_rotation_produces_transition_proof() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("transition-proof-test");

    let result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Transition proof should be present
    assert!(
        result.transition_proof.is_some(),
        "Rotation result must include transition_proof"
    );

    let proof_json: Value = serde_json::from_str(result.transition_proof.as_ref().unwrap())
        .expect("transition_proof should be valid JSON");

    // Verify proof structure
    assert!(
        proof_json.get("transitionMessage").is_some(),
        "Proof must have transitionMessage"
    );
    assert!(
        proof_json.get("signature").is_some(),
        "Proof must have signature"
    );
    assert!(
        proof_json.get("signingAlgorithm").is_some(),
        "Proof must have signingAlgorithm"
    );
    assert!(
        proof_json.get("oldPublicKeyHash").is_some(),
        "Proof must have oldPublicKeyHash"
    );
    assert!(
        proof_json.get("newPublicKeyHash").is_some(),
        "Proof must have newPublicKeyHash"
    );
    assert!(
        proof_json.get("timestamp").is_some(),
        "Proof must have timestamp"
    );

    // Verify message format
    let msg = proof_json["transitionMessage"].as_str().unwrap();
    assert!(
        msg.starts_with("JACS_KEY_ROTATION:"),
        "Transition message must start with JACS_KEY_ROTATION prefix, got: {}",
        msg
    );
}

/// Transition proof should be embedded in the agent document.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_rotation_proof_in_agent_document() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("proof-in-doc-test");

    let result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Parse the signed agent JSON
    let agent_doc: Value =
        serde_json::from_str(&result.signed_agent_json).expect("parse signed agent");

    assert!(
        agent_doc.get("jacsKeyRotationProof").is_some(),
        "Agent document must contain jacsKeyRotationProof after rotation"
    );

    let proof = &agent_doc["jacsKeyRotationProof"];
    assert_eq!(
        proof["signingAlgorithm"].as_str().unwrap(),
        "ring-Ed25519",
        "Proof signing algorithm should be the OLD algorithm"
    );
}

/// Cross-algorithm rotation: Ed25519 to pq2025.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_cross_algorithm_rotation_ed25519_to_pq2025() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("cross-algo-test");

    // Rotate from Ed25519 (default in create_test_agent) to pq2025
    let result =
        advanced::rotate(&agent, Some("pq2025")).expect("cross-algo rotation should succeed");

    // Verify the config on disk has the new algorithm
    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read config");
    let config: Value = serde_json::from_str(&config_str).expect("parse config");
    assert_eq!(
        config["jacs_agent_key_algorithm"].as_str(),
        Some("pq2025"),
        "Config should reflect new algorithm after cross-algo rotation"
    );

    // Verify the agent can sign and verify with the new algorithm
    let signed = agent
        .sign_message(&serde_json::json!({"after": "cross-algo rotation"}))
        .expect("signing after cross-algo rotation should succeed");
    let verification = agent.verify(&signed.raw).expect("verify should succeed");
    assert!(
        verification.valid,
        "Message signed after cross-algo rotation should verify: {:?}",
        verification.errors
    );

    // Verify the transition proof references the old algorithm
    let proof: Value = serde_json::from_str(result.transition_proof.as_ref().unwrap())
        .expect("parse transition proof");
    assert_eq!(
        proof["signingAlgorithm"].as_str().unwrap(),
        "ring-Ed25519",
        "Transition proof should be signed with old algorithm"
    );
}

/// Same-algorithm rotation preserves the config field.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_same_algorithm_rotation_preserves_config_field() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("same-algo-test");

    let _result = advanced::rotate(&agent, None).expect("rotation should succeed");

    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read config");
    let config: Value = serde_json::from_str(&config_str).expect("parse config");
    assert_eq!(
        config["jacs_agent_key_algorithm"].as_str(),
        Some("ring-Ed25519"),
        "Config algorithm should remain Ed25519 after same-algo rotation"
    );
}

/// Crash recovery: simulate crash after rotation, verify auto-repair on reload.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_crash_recovery_full_flow() {
    use jacs::keystore::RotationJournal;

    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, info, _tmp, _guard) = create_test_agent("crash-recovery-test");

    // Capture pre-rotation config
    let config_before = std::fs::read_to_string("./jacs.config.json").expect("read config before");

    // Perform rotation (this produces a properly signed config)
    let result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Simulate crash: overwrite the config with the pre-rotation version (stale)
    std::fs::write("./jacs.config.json", &config_before)
        .expect("overwrite config with stale version");

    // Write a journal file to indicate incomplete rotation
    let _journal = RotationJournal::create(
        "./jacs_keys",
        &info.agent_id,
        &info.version,
        "old-key-hash",
        "ring-Ed25519",
        "./jacs.config.json",
    )
    .expect("create journal");

    // Reload the agent -- should auto-repair
    let reloaded = SimpleAgent::load(Some("./jacs.config.json"), None)
        .expect("agent should load and auto-repair");

    // Verify the journal was deleted
    let journal_path = RotationJournal::journal_path("./jacs_keys");
    let journal_path_no_dot = RotationJournal::journal_path("jacs_keys");
    assert!(
        !std::path::Path::new(&journal_path).exists()
            && !std::path::Path::new(&journal_path_no_dot).exists(),
        "Journal should be deleted after auto-repair. Paths checked: '{}', '{}'",
        journal_path,
        journal_path_no_dot
    );

    // Verify the agent is functional after recovery
    let signed = reloaded
        .sign_message(&serde_json::json!({"after": "crash-recovery"}))
        .expect("signing after crash recovery should succeed");
    let verification = reloaded.verify(&signed.raw).expect("verify should succeed");
    assert!(
        verification.valid,
        "Message signed after crash recovery should verify: {:?}",
        verification.errors
    );
}

/// Without a journal, a stale config pointing to the old agent version fails to load.
/// The journal is what enables crash recovery -- without it, there's no way to know
/// that the inconsistency is from a crash rather than tampering.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_no_crash_recovery_without_journal() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("no-journal-test");

    // Capture pre-rotation config
    let config_before = std::fs::read_to_string("./jacs.config.json").expect("read config before");

    // Rotate
    let _result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Tamper: overwrite config with pre-rotation version, but do NOT write a journal
    std::fs::write("./jacs.config.json", &config_before)
        .expect("overwrite config with stale version");

    // Reload -- should FAIL because the old agent version was signed with old keys
    // but the keys on disk are new (old keys were archived during rotation).
    // Without a journal, the system cannot auto-recover.
    let load_result = SimpleAgent::load(Some("./jacs.config.json"), None);
    assert!(
        load_result.is_err(),
        "Loading with stale config and no journal should fail"
    );

    // Config on disk should be unchanged (no auto-repair without journal)
    let config_after = std::fs::read_to_string("./jacs.config.json").expect("read config after");
    assert_eq!(
        config_before, config_after,
        "Without journal, config should NOT be modified"
    );
}

/// Double rotation: both rotations should produce transition proofs
/// and the version chain should be correct.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_double_rotation_preserves_chain() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, info, _tmp, _guard) = create_test_agent("double-rotation-test");

    let v0 = info.version.clone();

    // First rotation
    let result1 = advanced::rotate(&agent, None).expect("first rotation should succeed");
    let v1 = result1.new_version.clone();
    assert_ne!(v1, v0, "v1 must differ from v0");
    assert!(
        result1.transition_proof.is_some(),
        "First rotation must produce transition proof"
    );

    // Second rotation
    let result2 = advanced::rotate(&agent, None).expect("second rotation should succeed");
    let v2 = result2.new_version.clone();
    assert_ne!(v2, v1, "v2 must differ from v1");
    assert_eq!(
        result2.old_version, v1,
        "Second rotation's old_version must be v1"
    );
    assert!(
        result2.transition_proof.is_some(),
        "Second rotation must produce transition proof"
    );

    // The signed agent doc should have the latest proof (v1->v2)
    let doc: Value = serde_json::from_str(&result2.signed_agent_json).expect("parse signed agent");
    let proof = &doc["jacsKeyRotationProof"];
    let msg = proof["transitionMessage"].as_str().unwrap();
    assert!(
        msg.starts_with("JACS_KEY_ROTATION:"),
        "Transition message must start with JACS_KEY_ROTATION:, got: {}",
        msg
    );
    // The proof should reference the second rotation's new key hash
    assert!(
        msg.contains(&result2.new_public_key_hash),
        "Transition message must contain the new key hash {}, got: {}",
        result2.new_public_key_hash,
        msg
    );

    // Verify the agent is still functional
    let signed = agent
        .sign_message(&serde_json::json!({"after": "double-rotation"}))
        .expect("signing after double rotation");
    let verification = agent.verify(&signed.raw).expect("verify");
    assert!(
        verification.valid,
        "Should verify after double rotation: {:?}",
        verification.errors
    );
}

/// Verify that the transition proof can be cryptographically verified with the old key.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_transition_proof_verifiable_with_old_key() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("proof-verify-test");

    // Capture old public key before rotation
    let old_pub_key = agent.get_public_key().expect("get old public key");

    // Rotate
    let result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Extract the transition proof from the signed agent document
    let doc: Value = serde_json::from_str(&result.signed_agent_json).expect("parse signed agent");
    let proof = &doc["jacsKeyRotationProof"];
    assert!(
        proof.is_object(),
        "Agent doc should have jacsKeyRotationProof"
    );

    // Verify the proof with the OLD public key — should succeed
    let verify_result = jacs::agent::Agent::verify_transition_proof(proof, &old_pub_key);
    assert!(
        verify_result.is_ok(),
        "Transition proof should verify with old key: {:?}",
        verify_result.err()
    );

    // Verify the proof with the NEW public key — should fail
    let new_pub_key = agent.get_public_key().expect("get new public key");
    let bad_result = jacs::agent::Agent::verify_transition_proof(proof, &new_pub_key);
    assert!(
        bad_result.is_err(),
        "Transition proof should NOT verify with new key"
    );
}
