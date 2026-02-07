use jacs::agent::boilerplate::BoilerPlate;
use std::fs;
use std::path::Path;

mod utils;
use utils::{
    create_agent_v1, fixtures_dir_string, fixtures_keys_dir_string, load_local_document,
    raw_fixture, set_min_test_env_vars,
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

#[test]
fn test_update_agent_and_verify_versions() {
    setup();
    set_min_test_env_vars();
    log::debug!("Starting test_update_agent_and_verify_versions");

    // cargo test   --test agent_tests -- --nocapture

    // Parse config to get agent ID
    let config: serde_json::Value =
        serde_json::from_str(&get_config_content()).expect("Failed to parse config");
    let agent_id = config["jacs_agent_id_and_version"]
        .as_str()
        .expect("Failed to get agent ID from config")
        .to_string();

    let mut agent = create_agent_v1().expect("Agent schema should have instantiated");
    let result = agent.load_by_id(agent_id);

    match result {
        Ok(_) => {
            println!(
                "AGENT LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }

    let modified_agent_string = load_local_document(
        &raw_fixture("modified-agent-for-updating.json")
            .to_string_lossy()
            .to_string(),
    )
    .unwrap();

    match agent.update_self(&modified_agent_string) {
        Ok(_) => assert!(true),
        Err(error) => {
            println!("{}", error);
            assert!(false);
            println!("NEW AGENT VERSION prevented");
        }
    };

    agent.verify_self_signature().unwrap();
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
