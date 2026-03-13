use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs_binding_core::{AgentWrapper, DocumentServiceWrapper};
use serde_json::Value;
use serial_test::serial;
use std::fs;

const TEST_PASSWORD: &str = "TestP@ss123!#";

fn agent_with_storage(storage: &str) -> (AgentWrapper, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("binding-doc-wrapper-backend-test")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .build();

    let (_agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    // Overwrite the default_storage to the requested backend
    let mut config_json: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("read generated config"))
            .expect("parse generated config");
    config_json["jacs_default_storage"] = Value::String(storage.to_string());
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config_json).expect("serialize config"),
    )
    .expect("write updated config");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }

    let wrapper = AgentWrapper::new();
    wrapper
        .load(config_path.to_string_lossy().into_owned())
        .expect("agent load should succeed");

    (wrapper, tmp)
}

fn sqlite_ready_agent() -> (AgentWrapper, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("binding-doc-wrapper-sqlite")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .build();

    let (_agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    let mut config_json: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("read generated config"))
            .expect("parse generated config");
    config_json["jacs_default_storage"] = Value::String("rusqlite".to_string());
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config_json).expect("serialize config"),
    )
    .expect("write updated config");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }

    let wrapper = AgentWrapper::new();
    wrapper
        .load(config_path.to_string_lossy().into_owned())
        .expect("agent load should succeed");

    (wrapper, tmp)
}

#[test]
#[serial]
fn from_agent_wrapper_uses_sqlite_search_backend() {
    let (agent, _tmp) = sqlite_ready_agent();
    let docs = DocumentServiceWrapper::from_agent_wrapper(&agent)
        .expect("document service wrapper should resolve sqlite backend");

    docs.create_json(r#"{"content":"bindingsqliteprobe alpha"}"#, None)
        .expect("create first doc");
    docs.create_json(r#"{"content":"bindingsqliteprobe beta"}"#, None)
        .expect("create second doc");

    let result_json = docs
        .search_json(r#"{"query":"bindingsqliteprobe","limit":10,"offset":0}"#)
        .expect("search_json should succeed");
    let result: Value = serde_json::from_str(&result_json).expect("search result should be JSON");

    assert_eq!(result["method"], "FullText");
    assert!(
        result["results"]
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false),
        "sqlite-backed search should return at least one hit: {}",
        result
    );
}

// =========================================================================
// Task 005: Backend selection integration tests
// =========================================================================

/// Default storage ("fs") resolves to filesystem backend with FieldMatch search.
///
/// The `service_from_agent` function reads `jacs_data_directory` from config,
/// which `load_by_config` may have rewritten to a relative path. We set the CWD
/// to the config's parent directory so that `MultiStorage` resolves the path
/// correctly.
#[test]
#[serial]
fn from_agent_wrapper_uses_filesystem_by_default() {
    let (agent, tmp) = agent_with_storage("fs");

    // service_from_agent reads the config's (possibly relative) data dir.
    // Ensure CWD matches the config parent so the relative path resolves.
    let saved_cwd = std::env::current_dir().expect("get cwd");
    std::env::set_current_dir(tmp.path()).expect("set cwd to temp dir");

    let docs = DocumentServiceWrapper::from_agent_wrapper(&agent)
        .expect("document service wrapper should resolve filesystem backend");

    // CRUD works
    let created_json = docs
        .create_json(r#"{"content":"fsprobe alpha"}"#, None)
        .expect("create doc on filesystem");
    let created: Value =
        serde_json::from_str(&created_json).expect("created doc should be valid JSON");
    assert!(
        created.get("jacsId").is_some(),
        "created doc should have jacsId"
    );

    // Search returns FieldMatch method (filesystem uses FieldMatch, not FullText)
    let result_json = docs
        .search_json(r#"{"query":"fsprobe","limit":10,"offset":0}"#)
        .expect("search_json should succeed on filesystem");
    let result: Value =
        serde_json::from_str(&result_json).expect("search result should be valid JSON");
    assert_eq!(
        result["method"], "FieldMatch",
        "filesystem search should use FieldMatch method, got: {}",
        result
    );

    // Restore CWD
    std::env::set_current_dir(saved_cwd).expect("restore cwd");
}

/// `service_from_agent` resolves a SQLite connection string
/// (`sqlite:///path/to/db.sqlite3`) into a `SqliteDocumentService` that writes
/// to the specified database file.
#[test]
#[serial]
#[cfg(all(not(target_arch = "wasm32"), feature = "attestation"))]
fn service_from_agent_with_sqlite_connection_string() {
    let tmp = tempfile::TempDir::new().expect("create tempdir");

    // Create the agent with default FS storage first, then patch to a
    // connection-string-style sqlite URL pointing at a specific db path.
    let db_path = tmp.path().join("custom.sqlite3");
    let conn_string = format!("sqlite://{}", db_path.display());

    let (agent, _agent_tmp) = agent_with_storage("fs");

    // Patch config to use the connection string
    let agent_arc = agent.inner_arc();
    {
        let mut agent_guard = agent_arc.lock().unwrap();
        if let Some(ref mut config) = agent_guard.config {
            let mut config_val = serde_json::to_value(&*config).unwrap();
            config_val["jacs_default_storage"] = Value::String(conn_string.clone());
            *config = serde_json::from_value(config_val).unwrap();
        }
    }

    let service = jacs::document::service_from_agent(agent_arc)
        .expect("service_from_agent should resolve sqlite connection string");

    // The service should be functional — create a document.
    // The agent-backed SqliteDocumentService signs and assigns ID/version,
    // so we pass raw content without jacsId or jacsVersion.
    let doc = service
        .create(
            r#"{"data":"connection string test"}"#,
            jacs::document::types::CreateOptions::default(),
        )
        .expect("create document via connection-string-resolved sqlite backend");
    assert!(!doc.id.is_empty(), "created doc should have an assigned jacsId");

    // The database file should exist at the path from the connection string
    assert!(
        db_path.exists(),
        "SQLite database should exist at the connection-string path: {}",
        db_path.display()
    );
}

/// `service_from_agent` returns a descriptive error when the config specifies
/// a storage type that has no DocumentService wiring (e.g. "memory").
///
/// We test at the `service_from_agent` level because `load_by_config` would
/// fail to load the agent file from a non-FS store. So we load the agent
/// normally (with FS), then patch the config's `jacs_default_storage` to
/// "memory" and call `service_from_agent` directly.
#[test]
#[serial]
fn service_from_agent_rejects_unsupported_backend() {
    let (agent, _tmp) = agent_with_storage("fs");

    // Patch the in-memory config to say "memory" (which service_from_agent doesn't handle)
    let agent_arc = agent.inner_arc();
    {
        let mut agent_guard = agent_arc.lock().unwrap();
        if let Some(ref mut config) = agent_guard.config {
            let mut config_val = serde_json::to_value(&*config).unwrap();
            config_val["jacs_default_storage"] = Value::String("memory".to_string());
            *config = serde_json::from_value(config_val).unwrap();
        }
    }

    let result = jacs::document::service_from_agent(agent_arc);
    let err_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("service_from_agent should fail for unsupported backend 'memory'"),
    };
    assert!(
        err_msg.contains("memory"),
        "error message should mention the unsupported backend name 'memory': {}",
        err_msg
    );
}
