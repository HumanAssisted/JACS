use jacs::agent::boilerplate::BoilerPlate;
use serial_test::serial;
use std::fs;
use std::path::Path;

mod utils;
use utils::{
    create_agent_v1, create_ring_test_agent, fixtures_dir_string, fixtures_keys_dir_string,
    read_new_agent_fixture, set_min_test_env_vars,
};

// Note: The password in this config is deprecated and should be ignored.
// Actual password comes from JACS_PRIVATE_KEY_PASSWORD env var.
// Uses centralized fixture paths from utils.
fn get_config_content() -> String {
    format!(
        r#"{{
    "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
    "jacs_use_filesystem": "true",
    "jacs_use_security": "true",
    "jacs_data_directory": "{}",
    "jacs_key_directory": "{}",
    "jacs_agent_private_key_filename": "agent-one.private.pem.enc",
    "jacs_agent_public_key_filename": "agent-one.public.pem",
    "jacs_agent_key_algorithm": "RSA-PSS",
    "jacs_agent_schema_version": "v1",
    "jacs_header_schema_version": "v1",
    "jacs_signature_schema_version": "v1",
    "jacs_private_key_password": "",
    "jacs_default_storage": "fs",
    "jacs_agent_id_and_version": "ddf35096-d212-4ca9-a299-feda597d5525:b57d480f-b8d4-46e7-9d7c-942f2b132717"
}}"#,
        fixtures_dir_string(),
        fixtures_keys_dir_string()
    )
}

fn setup() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Create config file if it doesn't exist
    if !Path::new("jacs.config.json").exists() {
        fs::write("jacs.config.json", get_config_content()).expect("Failed to write config file");
    }
}

/// Verify that the committed RSA-PSS agent fixture still loads and
/// exposes `RSA-PSS` as its key algorithm.
///
/// This covers the "legacy RSA artifacts remain readable" side of the
/// RUSTSEC-2023-0071 hardening. The `update_self` + re-sign leg of the
/// original test moved to `test_update_ed25519_agent_and_verify_versions`
/// because RSA private-key signing is now disabled.
///
/// `#[serial]` because `test_update_ed25519_agent_and_verify_versions`
/// mutates `JACS_DATA_DIRECTORY` et al. via `create_ring_test_agent()`;
/// running in parallel would cause this test to look for the RSA
/// fixture under the Ed25519 scratch directory.
#[test]
#[serial]
fn test_rsa_fixture_load_exposes_algorithm() {
    setup();
    set_min_test_env_vars();
    log::debug!("Starting test_rsa_fixture_load_exposes_algorithm");

    // cargo test --test agent_tests -- --nocapture test_rsa_fixture_load_exposes_algorithm

    let config: serde_json::Value =
        serde_json::from_str(&get_config_content()).expect("Failed to parse config");
    let agent_id = config["jacs_agent_id_and_version"]
        .as_str()
        .expect("Failed to get agent ID from config")
        .to_string();

    let mut agent = create_agent_v1().expect("Agent schema should have instantiated");
    agent.load_by_id(agent_id).expect("Agent loading failed");

    println!(
        "AGENT LOADED {} {} ",
        agent.get_id().unwrap(),
        agent.get_version().unwrap()
    );
    assert_eq!(
        agent.get_key_algorithm().map(|s| s.as_str()),
        Some("RSA-PSS"),
        "Fixture-backed load_by_id must use RSA-PSS for agent-one keys"
    );
}

/// Exercise the `update_self` + `verify_self_signature` flow: after an
/// update, the agent gains a new `jacsVersion` and the new signature
/// verifies. Uses an Ed25519 agent because RSA-PSS private-key signing
/// is blocked by RUSTSEC-2023-0071.
///
/// `#[serial]` because `create_ring_test_agent()` mutates process-wide
/// env vars (`JACS_DATA_DIRECTORY`, etc.) that would otherwise race
/// with `test_rsa_fixture_load_exposes_algorithm`.
#[test]
#[serial]
fn test_update_ed25519_agent_and_verify_versions() {
    let mut agent = create_ring_test_agent().expect("Failed to create ring test agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
    // create_keys=true so the scratch key files are generated; the existing
    // `test-ring-Ed25519-*.pem` fixtures are not copied into the per-test
    // scratch directory.
    agent
        .create_agent_and_load(&json_data, true, None)
        .expect("Failed to create and load Ed25519 agent");

    let original_version = agent
        .get_version()
        .expect("newly-created agent should have a version");

    // Build a modified copy of the current agent JSON by tweaking a
    // non-identity field. `update_self` requires matching id/version
    // between the stored and proposed documents.
    let mut modified_value = agent
        .get_value()
        .cloned()
        .expect("agent value should be loaded after create_agent_and_load");
    modified_value["description"] =
        serde_json::json!("Updated by test_update_ed25519_agent_and_verify_versions");
    let modified_agent_string =
        serde_json::to_string(&modified_value).expect("serialize modified agent");

    agent
        .update_self(&modified_agent_string)
        .expect("update_self should succeed with Ed25519 signing");

    let new_version = agent
        .get_version()
        .expect("updated agent should still report a version");
    assert_ne!(
        original_version, new_version,
        "update_self must produce a new jacsVersion"
    );

    agent
        .verify_self_signature()
        .expect("updated agent signature must verify");
}

#[test]
fn test_validate_agent_json_raw() {
    setup();
    set_min_test_env_vars();
    let json_data = r#"{
      "id": "agent123",
      "name": "Agent Smith",
      "role": "Field Agent"
    }"#
    .to_string();

    let mut agent = create_agent_v1().expect("Agent schema should have instantiated");
    let result = agent.load(&json_data);
    assert!(
        result.is_err(),
        "Correctly failed to validate myagent.json: {}",
        result.unwrap_err()
    );
}
