use jacs::agent::boilerplate::BoilerPlate;
use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs_binding_core::{AgentWrapper, DocumentServiceWrapper};
use serde_json::Value;
use serial_test::serial;

const TEST_PASSWORD: &str = "TestP@ss123!#";

fn agent_with_storage(storage: &str) -> (AgentWrapper, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("create tempdir");
    // Canonicalize to resolve macOS /var -> /private/var symlink so that
    // paths written into the config match the paths the agent sees at runtime.
    let tmp_canonical = tmp
        .path()
        .canonicalize()
        .unwrap_or_else(|_| tmp.path().to_path_buf());
    let data_dir = tmp_canonical.join("jacs_data");
    let key_dir = tmp_canonical.join("jacs_keys");
    let config_path = tmp_canonical.join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("binding-doc-wrapper-backend-test")
        .password(TEST_PASSWORD)
        .algorithm("pq2025")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage(storage)
        .build();

    let (_agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
        // Restrict key resolution to local-only so verification never attempts remote fetch
        std::env::set_var("JACS_KEY_RESOLUTION", "local");
    }

    let wrapper = AgentWrapper::new();
    wrapper
        .load(config_path.to_string_lossy().into_owned())
        .expect("agent load should succeed");

    (wrapper, tmp)
}

fn override_storage(wrapper: &AgentWrapper, storage: &str) {
    let agent = wrapper.inner_arc();
    let mut agent = agent.lock().expect("agent lock");
    let config = agent.config.as_mut().expect("loaded config");
    config.merge(jacs::config::Config::new(
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(storage.to_string()),
    ));
}

fn sqlite_ready_agent() -> (AgentWrapper, tempfile::TempDir) {
    let (wrapper, tmp) = agent_with_storage("fs");
    override_storage(&wrapper, "rusqlite");
    (wrapper, tmp)
}

#[test]
#[serial]
fn from_agent_wrapper_uses_sqlite_search_backend() {
    let (agent, tmp) = sqlite_ready_agent();

    let docs = DocumentServiceWrapper::from_agent_wrapper(&agent)
        .expect("document service wrapper should resolve sqlite backend");
    let expected_db = tmp.path().join("jacs_data/jacs_documents.sqlite3");
    assert!(
        expected_db.exists(),
        "relative sqlite data directory must be rooted at the config directory: {}",
        expected_db.display()
    );

    let first = docs
        .create_json(r#"{"content":"bindingsqliteprobe alpha"}"#, None)
        .expect("create first doc");
    let second = docs
        .create_json(r#"{"content":"bindingsqliteprobe beta"}"#, None)
        .expect("create second doc");

    let first: Value = serde_json::from_str(&first).expect("first document JSON");
    let second: Value = serde_json::from_str(&second).expect("second document JSON");
    let agent_arc = agent.inner_arc();
    let agent_guard = agent_arc.lock().expect("agent lock");
    let current_agent_id = agent_guard.get_id().expect("loaded agent ID");
    let current_value_id = agent_guard
        .get_value()
        .and_then(|value| value["jacsId"].as_str())
        .expect("loaded agent document ID");
    let first_signer_id = first["jacsSignature"]["agentID"]
        .as_str()
        .expect("first signer ID");
    let second_signer_id = second["jacsSignature"]["agentID"]
        .as_str()
        .expect("second signer ID");
    assert_eq!(current_agent_id, current_value_id);
    assert!(first_signer_id.starts_with(&current_agent_id));
    assert_eq!(first_signer_id, second_signer_id);
    drop(agent_guard);

    let claimed_hash = first["jacsSignature"]["publicKeyHash"]
        .as_str()
        .expect("signed document publicKeyHash");
    assert_eq!(
        claimed_hash,
        second["jacsSignature"]["publicKeyHash"]
            .as_str()
            .expect("second signed document publicKeyHash"),
        "one loaded agent must emit a stable publicKeyHash across documents"
    );
    let cached_key = tmp
        .path()
        .join("jacs_data/public_keys")
        .join(format!("{claimed_hash}.pem"));
    assert!(
        cached_key.exists(),
        "signing key must be cached under the exact hash emitted in new documents: {}",
        cached_key.display()
    );

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
/// The service must use the authenticated config's origin for relative paths;
/// the caller's unrelated process CWD must not select a different data store.
#[test]
#[serial]
fn from_agent_wrapper_uses_filesystem_by_default() {
    let (agent, tmp) = agent_with_storage("fs");
    assert_ne!(
        std::env::current_dir().expect("process cwd"),
        tmp.path(),
        "regression requires a CWD unrelated to the config directory"
    );

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
}

/// `service_from_agent` resolves a SQLite connection string
/// (`sqlite:///path/to/db.sqlite3`) into a `SqliteDocumentService` that writes
/// to the specified database file.
#[test]
#[serial]
fn service_from_agent_with_sqlite_connection_string() {
    let tmp = tempfile::TempDir::new().expect("create tempdir");

    // Create the agent with default FS storage first, then patch to a
    // connection-string-style sqlite URL pointing at a specific db path.
    let db_path = tmp.path().join("custom.sqlite3");
    let conn_string = format!("sqlite://{}", db_path.display());

    let (agent, _agent_tmp) = agent_with_storage("fs");

    override_storage(&agent, &conn_string);

    let agent_arc = agent.inner_arc();

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
    assert!(
        !doc.id.is_empty(),
        "created doc should have an assigned jacsId"
    );

    // The database file should exist at the path from the connection string
    assert!(
        db_path.exists(),
        "SQLite database should exist at the connection-string path: {}",
        db_path.display()
    );
}

#[test]
#[serial]
fn relative_sqlite_connection_string_is_rooted_at_config_directory() {
    let (agent, tmp) = agent_with_storage("fs");
    override_storage(&agent, "sqlite://nested/custom.sqlite3");

    let service = jacs::document::service_from_agent(agent.inner_arc())
        .expect("relative sqlite connection path should resolve from config directory");
    service
        .create(
            r#"{"data":"relative connection string test"}"#,
            jacs::document::types::CreateOptions::default(),
        )
        .expect("create document through relative sqlite connection path");

    let expected = tmp.path().join("nested/custom.sqlite3");
    assert!(
        expected.exists(),
        "relative sqlite connection path must not depend on process CWD: {}",
        expected.display()
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

    override_storage(&agent, "memory");

    let result = jacs::document::service_from_agent(agent.inner_arc());
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
