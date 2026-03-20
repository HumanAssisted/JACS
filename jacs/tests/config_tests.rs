mod utils;
use jacs::agent::Agent;
#[allow(deprecated)]
use jacs::config::{Config, check_env_vars, load_config_12factor, load_config_12factor_optional};
use jacs::storage::jenv::set_env_var;
use serial_test::serial;
use std::path::Path;
use utils::{PASSWORD_ENV_VAR, clear_test_env_vars, set_test_env_vars};

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
    let expected_key_dir = utils::fixtures_keys_dir_string();
    assert_eq!(
        config.jacs_key_directory().as_deref(),
        Some(expected_key_dir.as_str()),
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
        Some("pq2025"),
        "Default algorithm should be pq2025"
    );

    clear_test_env_vars();
}

// ============================================================================
// Config.config_dir tests (Task 001: config_dir field)
// ============================================================================

/// Test that Config::from_file sets config_dir to parent directory
#[test]
fn test_config_from_file_sets_config_dir() {
    let config_path = utils::raw_fixture("ring.jacs.config.json");
    let config = Config::from_file(&config_path.to_string_lossy()).unwrap();
    let expected_parent = config_path.parent().unwrap();
    assert_eq!(
        config.config_dir(),
        Some(expected_parent.as_ref()),
        "config_dir should be set to the parent directory of the config file"
    );
}

/// Test that Config::with_defaults has config_dir = None
#[test]
fn test_config_with_defaults_has_no_config_dir() {
    let config = Config::with_defaults();
    assert_eq!(
        config.config_dir(),
        None,
        "Config::with_defaults() should have config_dir = None"
    );
}

/// Test that Config::from_file with absolute path sets absolute config_dir
#[test]
fn test_config_from_file_absolute_path_sets_absolute_config_dir() {
    let config_path = utils::raw_fixture("ring.jacs.config.json");
    // The fixture path is already absolute (from CARGO_MANIFEST_DIR)
    assert!(
        config_path.is_absolute(),
        "Fixture path should be absolute for this test"
    );
    let config = Config::from_file(&config_path.to_string_lossy()).unwrap();
    let dir = config.config_dir().expect("config_dir should be set");
    assert!(
        dir.is_absolute(),
        "config_dir should be absolute when loaded from absolute path"
    );
}

/// Test that config_dir survives merge (other.config_dir takes precedence if Some)
#[test]
fn test_config_dir_survives_merge() {
    let mut base = Config::with_defaults();
    base.set_config_dir(Some(std::path::PathBuf::from("/original/dir")));

    let mut other = Config::with_defaults();
    other.set_config_dir(Some(std::path::PathBuf::from("/override/dir")));

    base.merge(other);
    assert_eq!(
        base.config_dir(),
        Some(Path::new("/override/dir")),
        "config_dir from other should override base"
    );
}

/// Test that config_dir merge does not override when other.config_dir is None
#[test]
fn test_config_dir_merge_preserves_when_none() {
    let mut base = Config::with_defaults();
    base.set_config_dir(Some(std::path::PathBuf::from("/original/dir")));

    let other = Config::with_defaults(); // config_dir = None

    base.merge(other);
    assert_eq!(
        base.config_dir(),
        Some(Path::new("/original/dir")),
        "config_dir should be preserved when other.config_dir is None"
    );
}

/// Test that set_config_dir works
#[test]
fn test_set_config_dir() {
    let mut config = Config::with_defaults();
    assert_eq!(config.config_dir(), None);
    config.set_config_dir(Some(std::path::PathBuf::from("/my/config/dir")));
    assert_eq!(config.config_dir(), Some(Path::new("/my/config/dir")));
    config.set_config_dir(None);
    assert_eq!(config.config_dir(), None);
}

// ============================================================================
// Agent::from_config tests (Task 002: Agent::from_config constructor)
// ============================================================================

/// Test that Agent::from_config works with explicit password
#[test]
#[serial]
fn test_agent_from_config_with_explicit_password() {
    clear_test_env_vars();
    // Set up env for fixture keys
    utils::set_min_test_env_vars();

    let config_path = utils::raw_fixture("ring.jacs.config.json");
    let mut config = Config::from_file(&config_path.to_string_lossy()).unwrap();
    config.apply_env_overrides();

    // Agent::from_config should succeed with the fixture password
    let agent = Agent::from_config(config, Some(utils::TEST_PASSWORD_FIXTURES));
    assert!(
        agent.is_ok(),
        "Agent::from_config should succeed with explicit password: {:?}",
        agent.err()
    );

    clear_test_env_vars();
}

/// Test that Agent::from_config sets the password field
#[test]
#[serial]
fn test_agent_from_config_sets_password() {
    clear_test_env_vars();
    utils::set_min_test_env_vars();

    let config_path = utils::raw_fixture("ring.jacs.config.json");
    let mut config = Config::from_file(&config_path.to_string_lossy()).unwrap();
    config.apply_env_overrides();

    let agent = Agent::from_config(config, Some("my-test-password")).unwrap();
    // Verify the password was actually stored on the agent
    assert_eq!(
        agent.password(),
        Some("my-test-password"),
        "Agent password should be set to the value passed to from_config"
    );

    clear_test_env_vars();
}

/// Test that Agent::from_config without apply_env_overrides uses only file config
#[test]
#[serial]
fn test_agent_from_config_without_env_overrides() {
    clear_test_env_vars();

    // Build a programmatic config (no file with ".." paths) to test pure file-config path
    let mut config = Config::with_defaults();
    config.set_config_dir(Some(std::path::PathBuf::from(".")));
    // Deliberately skip apply_env_overrides -- config should still work
    // with_defaults sets jacs_data_directory = "./jacs_data", jacs_key_directory = "./jacs_keys"

    // This should succeed: config has enough info to initialize storage
    let agent = Agent::from_config(config, Some(utils::TEST_PASSWORD_FIXTURES));
    assert!(
        agent.is_ok(),
        "Agent::from_config should work without env overrides: {:?}",
        agent.err()
    );

    clear_test_env_vars();
}

/// Test that Agent::from_config with None password falls back to env var
#[test]
#[serial]
fn test_agent_from_config_none_password_uses_env_fallback() {
    clear_test_env_vars();
    utils::set_min_test_env_vars();
    // set_min_test_env_vars sets JACS_PRIVATE_KEY_PASSWORD to TEST_PASSWORD_LEGACY

    let config_path = utils::raw_fixture("ring.jacs.config.json");
    let mut config = Config::from_file(&config_path.to_string_lossy()).unwrap();
    config.apply_env_overrides();

    // None password -- should fall back to env var
    let agent = Agent::from_config(config, None);
    assert!(
        agent.is_ok(),
        "Agent::from_config with None password should fall back to env: {:?}",
        agent.err()
    );

    clear_test_env_vars();
}

/// Test that config_dir is dropped by serde round-trip (justifying the explicit
/// preservation step in calculate_storage_root_and_normalize).
#[test]
fn test_config_dir_dropped_by_serde_roundtrip() {
    let mut config = Config::with_defaults();
    config.set_config_dir(Some(std::path::PathBuf::from("/my/config/dir")));
    assert_eq!(
        config.config_dir(),
        Some(std::path::Path::new("/my/config/dir")),
        "config_dir should be set before round-trip"
    );

    // Serialize and deserialize (simulates the normalization round-trip)
    let json = serde_json::to_value(&config).unwrap();
    let roundtripped: Config = serde_json::from_value(json).unwrap();

    // config_dir should be None after round-trip because of #[serde(skip)]
    assert_eq!(
        roundtripped.config_dir(),
        None,
        "config_dir should be None after serde round-trip (serde(skip) drops it)"
    );
}

/// Test that two agents created with Agent::from_config using different passwords
/// do not interfere with each other (no env var leakage).
#[test]
#[serial]
fn test_concurrent_agents_with_different_passwords() {
    clear_test_env_vars();
    utils::set_min_test_env_vars();

    let config_path = utils::raw_fixture("ring.jacs.config.json");

    // Create first agent with password "alpha-password"
    // apply_env_overrides to use safe test directories (fixture has ".." paths)
    let mut config1 = Config::from_file(&config_path.to_string_lossy()).unwrap();
    config1.apply_env_overrides();
    let agent1 = Agent::from_config(config1, Some("alpha-password")).unwrap();

    // Create second agent with a different password
    let mut config2 = Config::from_file(&config_path.to_string_lossy()).unwrap();
    config2.apply_env_overrides();
    let agent2 = Agent::from_config(config2, Some("beta-password")).unwrap();

    // Verify each agent has its own password (no cross-contamination)
    assert_eq!(
        agent1.password(),
        Some("alpha-password"),
        "Agent 1 should retain its password"
    );
    assert_eq!(
        agent2.password(),
        Some("beta-password"),
        "Agent 2 should retain its password"
    );

    // Verify they are distinct agents with distinct passwords
    assert_ne!(
        agent1.password(),
        agent2.password(),
        "The two agents should have different passwords"
    );

    clear_test_env_vars();
}
