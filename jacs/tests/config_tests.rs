// Add to JACS/jacs/tests/config_tests.rs
mod utils;
use jacs::config::check_env_vars;
use serial_test::serial;
use utils::{clear_test_env_vars, set_test_env_vars};

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
