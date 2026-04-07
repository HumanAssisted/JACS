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
    let _result = advanced::rotate(&agent).expect("rotation should succeed");

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
