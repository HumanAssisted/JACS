//! Integration tests verifying that config write sites produce signed configs on disk.
//!
//! These cover PRD Phase 3.6, 3.8, 3.10, 3.12 requirements:
//! - SimpleAgent::create writes a signed config
//! - Key rotation re-signs the config
//! - Agent migration re-signs the config

mod utils;

use jacs::agent::boilerplate::BoilerPlate;
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
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    std::env::set_current_dir(&tmp_root).expect("cd to temp dir");
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

    // Build a historical Ed25519 agent via the legacy/test-only escape
    // hatch. These tests exercise pre-P2 agents (old-algorithm proofs, migration on
    // rotation), so they need a genuine Ed25519 root.
    let (agent, info) =
        SimpleAgent::create_legacy_ed25519_agent_for_fixtures(params).expect("create test agent");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "ConfigSignTest!2026");
        std::env::set_var("JACS_KEY_DIRECTORY", "./jacs_keys");
        std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem.enc");
        std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem");
    }

    (agent, info, tmp, guard)
}

/// Create a pq2025 test agent via the PUBLIC creation path. Used by the
/// crash-recovery tests, which exercise same-algorithm rotation crashes
/// (rotation from a grandfathered Ed25519 agent is a cross-algorithm
/// migration; crash recovery across a migration is a separate concern).
fn create_pq_test_agent(
    name: &str,
) -> (SimpleAgent, simple::AgentInfo, tempfile::TempDir, CwdGuard) {
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    std::env::set_current_dir(&tmp_root).expect("cd to temp dir");
    let guard = CwdGuard { saved: saved_cwd };

    let params = CreateAgentParams::builder()
        .name(name)
        .password("ConfigSignTest!2026")
        .description("PQ test agent for crash recovery")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();

    let (agent, info) = SimpleAgent::create_with_params(params).expect("create pq test agent");

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
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    let config_path = tmp_root.join("jacs.config.json");
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

/// Routine no-argument rotation preserves a grandfathered Ed25519 identity's
/// algorithm. Moving to pq2025 remains an explicit, separately tested upgrade.
#[test]
#[serial(jacs_env, cwd_env)]
fn grandfathered_agent_rotation_preserves_ed25519_by_default() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("grandfather-migrate-test");

    let result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Config on disk remains aligned with the replacement Ed25519 key.
    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read config");
    let config: Value = serde_json::from_str(&config_str).expect("parse config");
    assert_eq!(
        config["jacs_agent_key_algorithm"].as_str(),
        Some("ring-Ed25519"),
        "No-argument rotation must preserve the current algorithm"
    );

    // The transition proof is signed with the OLD (Ed25519) key — the
    // grandfathered root authorizes its own migration.
    let proof: Value =
        serde_json::from_str(result.transition_proof.as_ref().expect("proof present"))
            .expect("parse proof");
    assert_eq!(
        proof["signingAlgorithm"].as_str(),
        Some("ring-Ed25519"),
        "Transition proof must be signed by the old Ed25519 key"
    );

    // And the replacement key signs + verifies with Ed25519.
    let signed = agent
        .sign_message(&serde_json::json!({"migrated": true}))
        .expect("sign after migration");
    let signed_value: Value = serde_json::from_str(&signed.raw).expect("signed JSON");
    assert_eq!(
        signed_value["jacsSignature"]["signingAlgorithm"].as_str(),
        Some("ring-Ed25519"),
        "post-rotation signatures must preserve Ed25519"
    );
    let verification = agent.verify(&signed.raw).expect("verify");
    assert!(verification.valid, "{:?}", verification.errors);
}

/// Existing Ed25519 agents keep signing and remain reloadable. Rotation still
/// defaults to the pq2025 migration target.
#[test]
#[serial(jacs_env, cwd_env)]
fn existing_ed25519_agent_still_signs_grandfathered() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("grandfather-sign-test");

    let signed = agent
        .sign_message(&serde_json::json!({"grandfathered": true}))
        .expect("grandfathered Ed25519 sign must succeed");
    let signed_value: Value = serde_json::from_str(&signed.raw).expect("signed JSON");
    assert_eq!(
        signed_value["jacsSignature"]["signingAlgorithm"].as_str(),
        Some("ring-Ed25519"),
        "grandfathered agent signs with its existing Ed25519 root"
    );
    let verification = agent.verify(&signed.raw).expect("verify");
    assert!(verification.valid, "{:?}", verification.errors);

    // Reload from disk and sign again — grandfathering survives load.
    let reloaded =
        SimpleAgent::load(Some("./jacs.config.json"), None).expect("grandfathered agent loads");
    let signed2 = reloaded
        .sign_message(&serde_json::json!({"grandfathered": "after reload"}))
        .expect("grandfathered sign after reload");
    let signed2_value: Value = serde_json::from_str(&signed2.raw).expect("signed JSON");
    assert_eq!(
        signed2_value["jacsSignature"]["signingAlgorithm"].as_str(),
        Some("ring-Ed25519")
    );
}

/// A config requesting ring-Ed25519 for a new agent is honored without
/// rewriting either the returned metadata or persisted configuration.
#[test]
#[serial(jacs_env, cwd_env)]
fn config_ed25519_creates_matching_ed25519_signing_agent() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    std::env::set_current_dir(tmp.path().canonicalize().expect("canonical")).expect("cd");
    let _guard = CwdGuard { saved: saved_cwd };

    let params = CreateAgentParams::builder()
        .name("new-agent-ed25519-request")
        .password("ConfigSignTest!2026")
        .algorithm("ring-Ed25519")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();
    let (agent, info) = SimpleAgent::create_with_params(params).expect("Ed25519 creation");
    assert_eq!(info.algorithm, "ring-Ed25519");
    assert_eq!(agent.get_public_key().expect("public key").len(), 32);

    let signed = agent
        .sign_message(&serde_json::json!({"algorithm": "ed25519"}))
        .expect("Ed25519 signing");
    let signed: Value = serde_json::from_str(&signed.raw).expect("signed JSON");
    assert_eq!(
        signed["jacsSignature"]["signingAlgorithm"].as_str(),
        Some("ring-Ed25519")
    );

    let config: Value =
        serde_json::from_str(&std::fs::read_to_string("./jacs.config.json").expect("read"))
            .expect("parse");
    assert_eq!(
        config["jacs_agent_key_algorithm"].as_str(),
        Some("ring-Ed25519"),
        "config must record the algorithm actually minted"
    );
}

/// P2 Task 001 / NG1: ES256 is never a native signing option — a creation
/// request for it is a typed error, not a late keygen failure.
#[test]
#[serial(jacs_env, cwd_env)]
fn config_es256_does_not_create_new_native_signing_agent() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    std::env::set_current_dir(tmp.path().canonicalize().expect("canonical")).expect("cd");
    let _guard = CwdGuard { saved: saved_cwd };

    for bad in ["es256", "ES256", "ring-ES256"] {
        let params = CreateAgentParams::builder()
            .name("new-agent-es256-request")
            .password("ConfigSignTest!2026")
            .algorithm(bad)
            .data_directory("./jacs_data")
            .key_directory("./jacs_keys")
            .config_path("./jacs.config.json")
            .build();
        let err = SimpleAgent::create_with_params(params)
            .err()
            .unwrap_or_else(|| panic!("'{bad}' must be rejected for new agents"));
        assert!(
            err.to_string().contains("pq2025"),
            "error should steer to pq2025, got: {err}"
        );
    }
}

/// Crash recovery: simulate crash after rotation, verify auto-repair on reload.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_crash_recovery_full_flow() {
    use jacs::crypt::hash::hash_public_key;
    use jacs::keystore::RotationJournal;

    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, info, _tmp, _guard) = create_pq_test_agent("crash-recovery-test");
    let old_public_key = agent.get_public_key().expect("get old public key");
    let old_key_hash = hash_public_key(&old_public_key);

    // Capture pre-rotation config
    let config_before = std::fs::read_to_string("./jacs.config.json").expect("read config before");

    // Perform rotation (this produces a properly signed config)
    let _result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Simulate crash: overwrite the config with the pre-rotation version (stale)
    std::fs::write("./jacs.config.json", &config_before)
        .expect("overwrite config with stale version");

    // Write a journal file to indicate incomplete rotation
    let mut journal = RotationJournal::create(
        "./jacs_keys",
        &info.agent_id,
        &info.version,
        &old_key_hash,
        "pq2025",
        "./jacs.config.json",
    )
    .expect("create journal");
    journal
        .advance("agent_saved")
        .expect("record crash after rotated agent save");

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

    // Chain linkage: second rotation's proof must reference first rotation's new key as oldPublicKeyHash
    let proof2: Value =
        serde_json::from_str(result2.transition_proof.as_ref().unwrap()).expect("parse proof2");
    assert_eq!(
        proof2["oldPublicKeyHash"].as_str().unwrap(),
        result1.new_public_key_hash,
        "Second rotation's proof must reference first rotation's new key as oldPublicKeyHash"
    );

    // Also verify first rotation's proof references first rotation's new key as newPublicKeyHash
    let proof1: Value =
        serde_json::from_str(result1.transition_proof.as_ref().unwrap()).expect("parse proof1");
    assert_eq!(
        proof1["newPublicKeyHash"].as_str().unwrap(),
        result1.new_public_key_hash,
        "First rotation's proof newPublicKeyHash must match result1.new_public_key_hash"
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

/// Transition proof verification must reject proofs whose structured fields do
/// not match the signed transition message.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_transition_proof_rejects_field_message_mismatch() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("proof-mismatch-test");
    let old_pub_key = agent.get_public_key().expect("get old public key");

    let result = advanced::rotate(&agent, None).expect("rotation should succeed");
    let mut proof: Value =
        serde_json::from_str(result.transition_proof.as_ref().unwrap()).expect("parse proof");
    proof["newPublicKeyHash"] = serde_json::json!("tampered-new-key-hash");

    let verify_result = jacs::agent::Agent::verify_transition_proof(&proof, &old_pub_key);
    assert!(
        verify_result.is_err(),
        "Transition proof verification must fail when proof fields and signed message diverge"
    );
}

/// Issue 008 test #1: Ephemeral agent rotation should NOT create a journal file.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_rotate_journal_not_created_for_ephemeral() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    std::env::set_current_dir(tmp.path()).expect("cd to temp dir");
    let _guard = CwdGuard { saved: saved_cwd };

    // Create ephemeral agent (no disk state)
    let (agent, _info) = SimpleAgent::ephemeral_legacy_ed25519_for_fixtures()
        .expect("create grandfathered Ed25519 fixture");

    // Rotate the ephemeral agent
    let result = advanced::rotate(&agent, None).expect("ephemeral rotation should succeed");
    assert!(
        !result.new_version.is_empty(),
        "Ephemeral rotation should produce a new version"
    );

    // No journal file should exist anywhere in the temp dir
    let journal_path = tmp.path().join("jacs_keys/.jacs_rotation_journal.json");
    assert!(
        !journal_path.exists(),
        "Ephemeral agent rotation must not create a journal file"
    );

    // Also check current directory
    assert!(
        !std::path::Path::new(".jacs_rotation_journal.json").exists(),
        "No journal file should exist in CWD for ephemeral agent"
    );
}

/// Issue 008 test #8: Invalid algorithm string should return a clear error.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_rotate_self_invalid_algorithm_returns_error() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, _info, _tmp, _guard) = create_test_agent("invalid-algo-test");

    // Attempt to rotate with an invalid algorithm
    let result = advanced::rotate(&agent, Some("bogus-algo"));
    assert!(
        result.is_err(),
        "Rotation with invalid algorithm should fail"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Invalid algorithm") || err_msg.contains("bogus-algo"),
        "Error should mention the invalid algorithm, got: {}",
        err_msg
    );
}

/// Issue 008 test #5: After crash recovery, config's jacs_agent_id_and_version
/// should match the current agent's ID and version.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_crash_recovery_updates_id_and_version() {
    use jacs::crypt::hash::hash_public_key;
    use jacs::keystore::RotationJournal;

    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, info, _tmp, _guard) = create_pq_test_agent("recovery-id-version-test");
    let old_public_key = agent.get_public_key().expect("get old public key");
    let old_key_hash = hash_public_key(&old_public_key);

    // Capture pre-rotation config
    let config_before = std::fs::read_to_string("./jacs.config.json").expect("read config before");

    // Perform rotation
    let _result = advanced::rotate(&agent, None).expect("rotation should succeed");

    // Simulate crash: overwrite config with the pre-rotation version
    std::fs::write("./jacs.config.json", &config_before)
        .expect("overwrite config with stale version");

    // Write a journal file
    let mut journal = RotationJournal::create(
        "./jacs_keys",
        &info.agent_id,
        &info.version,
        &old_key_hash,
        "pq2025",
        "./jacs.config.json",
    )
    .expect("create journal");
    journal
        .advance("agent_saved")
        .expect("record crash after rotated agent save");

    // Reload agent -- triggers auto-repair
    let _reloaded = SimpleAgent::load(Some("./jacs.config.json"), None)
        .expect("agent should load and auto-repair");

    // Read repaired config and verify jacs_agent_id_and_version
    let config_after_str =
        std::fs::read_to_string("./jacs.config.json").expect("read config after repair");
    let config_after: Value =
        serde_json::from_str(&config_after_str).expect("parse config after repair");

    let id_and_version = config_after["jacs_agent_id_and_version"]
        .as_str()
        .expect("config must have jacs_agent_id_and_version after repair");

    // The ID should match the agent's stable ID
    assert!(
        id_and_version.starts_with(&info.agent_id),
        "Repaired config's jacs_agent_id_and_version should start with the agent ID '{}', got: '{}'",
        info.agent_id,
        id_and_version
    );

    // The version should be the NEW version (from the rotation), not the old one
    // After repair, the config should reference the latest agent version on disk
    assert_ne!(
        id_and_version,
        format!("{}:{}", info.agent_id, info.version),
        "Repaired config should NOT reference the pre-rotation version"
    );
}

/// A rotation journal must not cause arbitrary config tampering to be
/// re-signed as if it were a legitimate crash-recovery case.
#[test]
#[serial(jacs_env, cwd_env)]
fn test_crash_recovery_refuses_tampered_config_even_with_valid_journal() {
    use jacs::crypt::hash::hash_public_key;
    use jacs::keystore::RotationJournal;

    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (agent, info, _tmp, _guard) = create_test_agent("recovery-tamper-test");
    let old_public_key = agent.get_public_key().expect("get old public key");
    let old_key_hash = hash_public_key(&old_public_key);

    let config_before_str =
        std::fs::read_to_string("./jacs.config.json").expect("read config before rotation");
    let mut tampered_config: Value =
        serde_json::from_str(&config_before_str).expect("parse config before rotation");

    let _result = advanced::rotate(&agent, None).expect("rotation should succeed");

    tampered_config["agent_email"] = serde_json::json!("attacker@example.com");
    let mut hash_input = tampered_config.clone();
    hash_input
        .as_object_mut()
        .expect("config object")
        .remove("jacsSha256");
    let canonical = jacs_core::canonical::canonicalize_json_try(&hash_input)
        .expect("canonicalize tampered config");
    tampered_config["jacsSha256"] = serde_json::json!(jacs::crypt::hash::hash_string(&canonical));
    std::fs::write(
        "./jacs.config.json",
        serde_json::to_string_pretty(&tampered_config).expect("serialize tampered config"),
    )
    .expect("write tampered stale config");

    let mut journal = RotationJournal::create(
        "./jacs_keys",
        &info.agent_id,
        &info.version,
        &old_key_hash,
        "ring-Ed25519",
        "./jacs.config.json",
    )
    .expect("create journal");
    journal
        .advance("agent_saved")
        .expect("record crash after rotated agent save");

    let load_result = SimpleAgent::load(Some("./jacs.config.json"), None);
    assert!(
        load_result.is_err(),
        "tampered signed config must fail closed even when a journal exists"
    );
    let load_error = load_result.err().expect("tampered load error").to_string();
    assert!(
        load_error.contains("Signed config failed verification")
            || load_error.contains("historical"),
        "error must identify config integrity failure, got: {load_error}"
    );

    let config_after_str =
        std::fs::read_to_string("./jacs.config.json").expect("read config after load");
    let config_after: Value =
        serde_json::from_str(&config_after_str).expect("parse config after load");
    let expected_stale_lookup = format!("{}:{}", info.agent_id, info.version);

    assert_eq!(
        config_after["jacs_agent_id_and_version"].as_str(),
        Some(expected_stale_lookup.as_str()),
        "Tampered config must not be auto-rewritten to the new rotation target"
    );
    assert_eq!(
        config_after["agent_email"].as_str(),
        Some("attacker@example.com"),
        "Tampered config body should not be silently re-signed during crash recovery"
    );
    assert!(
        std::path::Path::new(&RotationJournal::journal_path("./jacs_keys")).exists(),
        "Journal should remain present when crash recovery is refused"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn signed_config_signature_stripping_is_rejected_by_default() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (_agent, _info, _tmp, _guard) = create_test_agent("config-strip-test");

    unsafe {
        std::env::remove_var("JACS_ALLOW_UNSIGNED_AGENT_CONFIG");
    }

    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read signed config");
    let mut config: Value = serde_json::from_str(&config_str).expect("parse signed config");
    for field in [
        "jacsSignature",
        "jacsSha256",
        "jacsId",
        "jacsVersion",
        "jacsVersionDate",
        "jacsType",
        "jacsLevel",
    ] {
        config.as_object_mut().expect("config object").remove(field);
    }
    std::fs::write(
        "./jacs.config.json",
        serde_json::to_string_pretty(&config).expect("serialize stripped config"),
    )
    .expect("write stripped config");

    let result = SimpleAgent::load(Some("./jacs.config.json"), None);
    assert!(
        result.is_err(),
        "removing signed-config metadata must not downgrade an existing identity to unsigned"
    );
    assert!(
        result
            .err()
            .expect("unsigned downgrade error")
            .to_string()
            .contains("unsigned agent config"),
        "error should explain the explicit unsigned migration policy"
    );

    unsafe {
        std::env::set_var("JACS_ALLOW_UNSIGNED_AGENT_CONFIG", "true");
    }
    let migrated = SimpleAgent::load(Some("./jacs.config.json"), None);
    unsafe {
        std::env::remove_var("JACS_ALLOW_UNSIGNED_AGENT_CONFIG");
    }
    assert!(
        migrated.is_ok(),
        "the explicit legacy-migration switch should allow a known unsigned identity: {:?}",
        migrated.err()
    );

    config
        .as_object_mut()
        .expect("config object")
        .remove("jacs_agent_id_and_version");
    std::fs::write(
        "./jacs.config.json",
        serde_json::to_string_pretty(&config).expect("serialize identity-stripped config"),
    )
    .expect("write identity-stripped config");
    let identity_stripped = SimpleAgent::load(Some("./jacs.config.json"), None);
    assert!(
        identity_stripped.is_err(),
        "stripping both signature metadata and the identity must not turn load into a successful empty agent"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn signed_config_is_verified_before_storage_selection() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (_agent, _info, _tmp, _guard) = create_test_agent("config-storage-tamper-test");

    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read signed config");
    let mut config: Value = serde_json::from_str(&config_str).expect("parse signed config");
    config["jacs_default_storage"] = serde_json::json!("memory");
    std::fs::write(
        "./jacs.config.json",
        serde_json::to_string_pretty(&config).expect("serialize tampered config"),
    )
    .expect("write tampered config");

    let error = SimpleAgent::load(Some("./jacs.config.json"), None)
        .err()
        .expect("tampered config must fail")
        .to_string();
    assert!(
        error.contains("Signed config failed verification"),
        "signature failure must precede backend initialization, got: {error}"
    );
    assert!(
        !error.contains("Unknown storage type"),
        "untrusted storage selection must not run before verification"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn from_config_verifies_signature_before_applying_storage_selection() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (_agent, _info, _tmp, _guard) = create_test_agent("from-config-tamper-test");

    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read signed config");
    let mut config_value: Value = serde_json::from_str(&config_str).expect("parse signed config");
    config_value["jacs_default_storage"] = serde_json::json!("memory");
    std::fs::write(
        "./jacs.config.json",
        serde_json::to_string_pretty(&config_value).expect("serialize tampered config"),
    )
    .expect("write tampered config");

    let config = jacs::config::Config::from_file("./jacs.config.json")
        .expect("tampered config remains structurally valid");
    let error = jacs::agent::Agent::from_config(config, Some("ConfigSignTest!2026"))
        .expect_err("Agent::from_config must reject tampered signed config")
        .to_string();
    assert!(
        error.contains("Signed config failed verification"),
        "canonical from_config path must fail on signature verification first, got: {error}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn current_signed_config_does_not_require_historical_key_archive() {
    use jacs::crypt::hash::hash_public_key;

    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _info, _tmp, _guard) = create_test_agent("current-key-no-archive-test");
    let current_hash = hash_public_key(agent.get_public_key().expect("current public key"));
    std::fs::remove_file(format!("./jacs_data/public_keys/{current_hash}.pem"))
        .expect("remove redundant content-addressed key");

    SimpleAgent::load(Some("./jacs.config.json"), None)
        .expect("current configured public key is sufficient for config verification");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn signed_config_public_key_read_is_bounded_before_use() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (_agent, _info, _tmp, _guard) = create_test_agent("bounded-config-key-test");

    std::fs::write("./jacs_keys/oversized.public", vec![0x41; 64 * 1024 + 1])
        .expect("write oversized public key candidate");
    let config_str = std::fs::read_to_string("./jacs.config.json").expect("read signed config");
    let mut config: Value = serde_json::from_str(&config_str).expect("parse signed config");
    config["jacs_agent_public_key_filename"] = serde_json::json!("oversized.public");
    std::fs::write(
        "./jacs.config.json",
        serde_json::to_string_pretty(&config).expect("serialize tampered config"),
    )
    .expect("write tampered config");

    unsafe {
        std::env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
    }
    let error = SimpleAgent::load(Some("./jacs.config.json"), None)
        .err()
        .expect("oversized attacker-selected key must fail closed")
        .to_string();
    unsafe {
        std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem");
    }
    assert!(
        error.contains("65536-byte limit"),
        "bounded read should be visible in the failure, got: {error}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn failed_config_load_does_not_partially_reconfigure_existing_agent() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (_agent, info, tmp, _guard) = create_test_agent("transactional-config-load-test");

    let mut raw_agent = jacs::get_empty_agent();
    raw_agent
        .load_by_config("./jacs.config.json".to_string())
        .expect("initial agent load");
    let preserved_root = tmp.path().join("preserved-storage-root");
    raw_agent
        .set_storage_root(preserved_root.clone())
        .expect("set distinguishable storage root");
    let preserved_lookup = raw_agent.get_lookup_id().expect("loaded lookup");

    std::fs::write(
        "./jacs_keys/jacs.private.pem.enc",
        b"not-an-encrypted-private-key",
    )
    .expect("corrupt private key after config preflight material is established");
    let result = raw_agent.load_by_config("./jacs.config.json".to_string());
    assert!(result.is_err(), "staged identity load should fail");
    assert_eq!(
        raw_agent
            .get_lookup_id()
            .expect("original identity retained"),
        preserved_lookup
    );
    assert_eq!(
        preserved_lookup,
        format!("{}:{}", info.agent_id, info.version)
    );
    assert_eq!(
        raw_agent.storage_ref().root(),
        Some(preserved_root.as_path()),
        "failed load must not commit its staged storage configuration"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn reencrypt_uses_authenticated_config_relative_key_path_outside_config_directory() {
    let _lock = CONFIG_SIGN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().expect("temp project");
    let tmp_root = tmp.path().canonicalize().expect("canonical temp project");
    let config_path = tmp_root.join("jacs.config.json");
    let params = CreateAgentParams::builder()
        .name("config-relative-reencrypt-test")
        .password("ConfigRelativeOld!2026")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path(config_path.to_str().expect("UTF-8 config path"))
        .build();
    let (agent, _info) =
        SimpleAgent::create_with_params(params).expect("create config-relative agent");
    let encrypted_key = tmp_root.join("jacs_keys/jacs.private.pem.enc");
    assert!(
        encrypted_key.is_file(),
        "creation must resolve the key directory from the config location"
    );

    advanced::reencrypt_key(&agent, "ConfigRelativeOld!2026", "ConfigRelativeNew!2026")
        .expect("re-encrypt through authenticated resolved key path");
    advanced::reencrypt_key(&agent, "ConfigRelativeNew!2026", "ConfigRelativeOld!2026")
        .expect("restored password proves the same config-relative key was selected");
}
