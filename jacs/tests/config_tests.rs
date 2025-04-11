// Add to JACS/jacs/tests/config_tests.rs
mod utils;
use jacs::config::check_env_vars;
use serial_test::serial;
use utils::{clear_test_env_vars, set_test_env_vars};
// use std::fs;

//RUST_BACKTRACE=1 cargo test   --test config_tests -- --nocapture

#[test]
#[serial]
fn test_config_with_no_file_but_env_vars() {
    // Setup
    clear_test_env_vars();

    // // Create a minimal valid config JSON string
    // let config_json = r#"{
    //     "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
    //     "jacs_data_directory": "/tmp/jacs_data",
    //     "jacs_key_directory": "/tmp/jacs_keys",
    //     "jacs_agent_private_key_filename": "private.key",
    //     "jacs_agent_public_key_filename": "public.key",
    //     "jacs_agent_key_algorithm": "RSA-PSS",
    //     "jacs_default_storage": "fs"
    // }"#;

    // // Debug print the config we're trying to validate
    // println!("Attempting to validate config JSON: {}", config_json);

    // // Try validate_config directly first
    // match validate_config(config_json) {
    //     Ok(value) => println!("Validation succeeded, parsed value: {:?}", value),
    //     Err(e) => println!("Validation failed: {:?}", e),
    // }

    // // Test set_env_vars with explicit config
    // let result = set_env_vars(false, Some(config_json), false);
    // match &result {
    //     Ok(msg) => println!("set_env_vars succeeded with message: {}", msg),
    //     Err(e) => println!("set_env_vars failed with error: {:?}", e),
    // }
    // assert!(result.is_ok(), "set_env_vars failed: {:?}", result.err());

    // Set required env vars
    set_test_env_vars();

    // // Print current env var state
    // println!("\nEnvironment variables after setting:");
    // let vars = [
    //     "JACS_USE_SECURITY",
    //     "JACS_USE_FILESYSTEM",
    //     "JACS_DATA_DIRECTORY",
    //     "JACS_KEY_DIRECTORY",
    //     "JACS_AGENT_PRIVATE_KEY_FILENAME",
    //     "JACS_AGENT_PUBLIC_KEY_FILENAME",
    //     "JACS_AGENT_KEY_ALGORITHM",
    //     "JACS_SCHEMA_AGENT_VERSION",
    //     "JACS_SCHEMA_HEADER_VERSION",
    //     "JACS_SCHEMA_SIGNATURE_VERSION",
    //     "JACS_PRIVATE_KEY_PASSWORD",
    //     "JACS_AGENT_ID_AND_VERSION",
    // ];

    // for var in vars.iter() {
    //     match std::env::var(var) {
    //         Ok(val) => println!("{}: {}", var, val),
    //         Err(_) => println!("{}: NOT SET", var),
    //     }
    // }

    // Test check_env_vars
    let check_result = check_env_vars(false);
    assert!(
        check_result.is_ok(),
        "check_env_vars failed: {:?}",
        check_result.err()
    );

    let message = check_result.unwrap();
    println!("Check env vars message: {}", message);
    assert!(!message.contains("Missing required environment variables"));

    // Cleanup
    clear_test_env_vars();
}

#[test]
#[serial]
fn test_config_with_missing_env_vars() {
    // Setup - clear env vars but don't set them
    clear_test_env_vars();

    // Debug: Print all env vars to verify they're cleared
    println!("\nEnvironment variables after clearing:");
    let vars = [
        "JACS_USE_SECURITY",
        "JACS_USE_FILESYSTEM",
        "JACS_DATA_DIRECTORY",
        "JACS_KEY_DIRECTORY",
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        "JACS_AGENT_KEY_ALGORITHM",
        "JACS_SCHEMA_AGENT_VERSION",
        "JACS_SCHEMA_HEADER_VERSION",
        "JACS_SCHEMA_SIGNATURE_VERSION",
        "JACS_PRIVATE_KEY_PASSWORD",
        "JACS_AGENT_ID_AND_VERSION",
    ];

    for var in vars.iter() {
        match std::env::var(var) {
            Ok(val) => println!("{}: {}", var, val),
            Err(_) => println!("{}: NOT SET", var),
        }
    }

    // Test check_env_vars with missing variables
    let check_result = check_env_vars(false);
    assert!(
        check_result.is_ok(),
        "check_env_vars unexpected error: {:?}",
        check_result.err()
    );

    // Verify the message contains missing vars
    let message = check_result.unwrap();
    println!("Check env vars message: {}", message);
    assert!(
        message.contains("Missing required environment variables"),
        "Should have found missing environment variables"
    );

    // Cleanup
    clear_test_env_vars();
}
