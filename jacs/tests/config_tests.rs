// Add to JACS/jacs/tests/config_tests.rs
mod utils;
use jacs::config::{check_env_vars, load_config_12factor, load_config_12factor_optional};
use jacs::storage::jenv::set_env_var;
use serial_test::serial;
use utils::{clear_test_env_vars, set_test_env_vars, PASSWORD_ENV_VAR};

//RUST_BACKTRACE=1 cargo test   --test config_tests -- --nocapture

#[test]
#[serial]
fn test_config_with_no_file_but_env_vars() {
    // Setup
    clear_test_env_vars();

    // Set required env vars
    set_test_env_vars();

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
        PASSWORD_ENV_VAR,
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

/// Test 12-Factor config loading: env vars override config file values
#[test]
#[serial]
fn test_12factor_env_vars_override_config_file() {
    clear_test_env_vars();

    // Set env vars that should override any config file values
    set_env_var("JACS_DATA_DIRECTORY", "/override/from/env").unwrap();
    set_env_var("JACS_AGENT_KEY_ALGORITHM", "pq2025").unwrap();

    // Load with a config file path that doesn't exist - should use defaults + env
    let config = load_config_12factor_optional(Some("nonexistent.config.json"))
        .expect("Should succeed even with missing config");

    // Verify env vars took effect
    assert_eq!(
        config.jacs_data_directory().as_deref(),
        Some("/override/from/env"),
        "Env var should override default data directory"
    );
    assert_eq!(
        config.jacs_agent_key_algorithm().as_deref(),
        Some("pq2025"),
        "Env var should override default algorithm"
    );

    // Verify defaults are used for non-overridden values
    assert_eq!(
        config.jacs_default_storage().as_deref(),
        Some("fs"),
        "Default storage should be 'fs'"
    );

    clear_test_env_vars();
}

/// Test 12-Factor config loading with no config file, just env vars
#[test]
#[serial]
fn test_12factor_env_vars_only() {
    clear_test_env_vars();

    // Set all required env vars
    set_test_env_vars();

    // Load without any config file
    let config = load_config_12factor(None).expect("Should load with just env vars");

    // Verify env vars are reflected in config
    assert_eq!(
        config.jacs_key_directory().as_deref(),
        Some("tests/fixtures/keys"),
        "Key directory should come from env var"
    );
    assert_eq!(
        config.jacs_agent_key_algorithm().as_deref(),
        Some("RSA-PSS"),
        "Algorithm should come from env var"
    );

    clear_test_env_vars();
}

/// Test that 12-Factor config falls back to defaults when nothing is set
#[test]
#[serial]
fn test_12factor_defaults() {
    clear_test_env_vars();

    // Load without config file and without env vars - should use defaults
    let config = load_config_12factor(None).expect("Should load with defaults");

    // Verify sensible defaults
    assert_eq!(
        config.jacs_use_security().as_deref(),
        Some("false"),
        "Default security should be false"
    );
    assert_eq!(
        config.jacs_default_storage().as_deref(),
        Some("fs"),
        "Default storage should be 'fs'"
    );
    assert_eq!(
        config.jacs_agent_key_algorithm().as_deref(),
        Some("RSA-PSS"),
        "Default algorithm should be RSA-PSS"
    );

    clear_test_env_vars();
}
