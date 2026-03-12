//! Integration tests for the `storage` option in `CreateAgentParams`.
//!
//! Tests that `create_with_params()` accepts custom storage backends
//! and that the default behavior (filesystem) is unchanged when `storage: None`.

use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs::storage::MultiStorage;
use serial_test::serial;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestP@ss123!#";

/// Helper: create params pointing at a fresh tempdir.
fn params_in_tempdir(tmp: &TempDir) -> CreateAgentParams {
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    CreateAgentParams::builder()
        .name("storage-test-agent")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .description("Test agent for storage option tests")
        .build()
}

// =============================================================================
// Default behavior (storage: None)
// =============================================================================

#[test]
#[serial]
fn create_with_params_defaults_to_filesystem_when_storage_is_none() {
    let tmp = TempDir::new().expect("create tempdir");
    let params = params_in_tempdir(&tmp);

    // storage field should default to None
    assert!(params.storage.is_none(), "default storage should be None");

    let (_agent, info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    assert!(!info.agent_id.is_empty(), "agent should have an ID");

    // The agent document should exist on the filesystem
    let agent_dir = tmp.path().join("jacs_data").join("agent");
    assert!(
        agent_dir.exists(),
        "agent directory should exist on filesystem"
    );
}

// =============================================================================
// Custom storage backend
// =============================================================================

#[test]
#[serial]
fn create_with_params_accepts_custom_memory_storage() {
    let tmp = TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let memory_storage =
        MultiStorage::new("memory".to_string()).expect("create memory storage");

    let params = CreateAgentParams::builder()
        .name("memory-storage-agent")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .description("Agent with custom memory storage")
        .storage(memory_storage)
        .build();

    assert!(
        params.storage.is_some(),
        "storage should be Some when explicitly set"
    );

    let (_agent, info) =
        SimpleAgent::create_with_params(params).expect("create_with_params with custom storage");

    assert!(!info.agent_id.is_empty(), "agent should have an ID");
}

#[test]
#[serial]
fn agent_with_custom_storage_can_sign_document() {
    let tmp = TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let memory_storage =
        MultiStorage::new("memory".to_string()).expect("create memory storage");

    let params = CreateAgentParams::builder()
        .name("sign-test-agent")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .description("Agent for signing with custom storage")
        .storage(memory_storage)
        .build();

    // Re-set env vars so the agent can find its keys
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
        std::env::set_var("JACS_DATA_DIRECTORY", data_dir.to_str().unwrap());
        std::env::set_var("JACS_KEY_DIRECTORY", key_dir.to_str().unwrap());
    }

    let (agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params with custom storage");

    // Sign a message using the agent
    let data = serde_json::json!({"test": "data", "number": 42});
    let signed = agent
        .sign_message(&data)
        .expect("sign_message should succeed with custom storage");

    assert!(
        !signed.raw.is_empty(),
        "signed document should have content"
    );
    assert!(
        !signed.document_id.is_empty(),
        "signed document should have a document ID"
    );
}

#[test]
#[serial]
fn create_still_defaults_to_filesystem() {
    // The `create()` method delegates to `create_with_params()` internally.
    // This validates that adding the storage option didn't break the default path.
    // We use `create_with_params` with `storage: None` to verify the same code path.
    let tmp = TempDir::new().expect("create tempdir");
    let params = params_in_tempdir(&tmp);

    // Confirm storage is None (default)
    assert!(params.storage.is_none());

    let (_agent, info) =
        SimpleAgent::create_with_params(params).expect("default fs path should work");

    assert!(!info.agent_id.is_empty(), "agent should have an ID");

    // Agent data directory should exist on filesystem
    let agent_dir = tmp.path().join("jacs_data").join("agent");
    assert!(
        agent_dir.exists(),
        "agent directory should exist on filesystem for default storage"
    );
}

#[test]
#[serial]
fn custom_fs_storage_with_explicit_path() {
    let tmp = TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    // Create a filesystem storage with a specific base directory
    let custom_data_dir = tmp.path().join("custom_data");
    std::fs::create_dir_all(&custom_data_dir).expect("create custom data dir");
    let fs_storage = MultiStorage::_new("fs".to_string(), custom_data_dir.clone())
        .expect("create custom fs storage");

    let params = CreateAgentParams::builder()
        .name("custom-fs-agent")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .description("Agent with custom filesystem storage path")
        .storage(fs_storage)
        .build();

    let (_agent, info) =
        SimpleAgent::create_with_params(params).expect("create_with_params with custom fs storage");

    assert!(!info.agent_id.is_empty(), "agent should have an ID");
}
