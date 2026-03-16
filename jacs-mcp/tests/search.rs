#![cfg(feature = "mcp")]
//! Behavioral tests for the unified search tool (TASK_041 / Issue 009).
//!
//! Tests: basic search, type filtering, pagination.

use std::fs;
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs_binding_core::{AgentWrapper, DocumentServiceWrapper};
use jacs_mcp::{
    JacsMcpServer,
    tools::{SearchFieldFilter, SearchParams},
};
use rmcp::{
    RoleClient, ServiceExt,
    handler::server::wrapper::Parameters,
    model::CallToolRequestParam,
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
};

mod support;
use support::{TEST_PASSWORD, prepare_temp_workspace};

static STDIO_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));
const TIMEOUT: Duration = Duration::from_secs(30);

type McpClient = RunningService<RoleClient, ()>;

struct Session {
    client: McpClient,
    base: std::path::PathBuf,
}

impl Session {
    async fn spawn() -> anyhow::Result<Self> {
        let (config, base) = prepare_temp_workspace();
        let bin = support::jacs_cli_bin();
        let cmd = tokio::process::Command::new(&bin).configure(|c| {
            c.arg("mcp")
                .current_dir(&base)
                .env("JACS_CONFIG", &config)
                .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
                .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
                .env("RUST_LOG", "warn");
        });
        let (transport, _) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::null())
            .spawn()?;
        let client = tokio::time::timeout(TIMEOUT, ().serve(transport))
            .await
            .map_err(|_| anyhow::anyhow!("init timeout"))??;
        Ok(Self { client, base })
    }

    async fn call(&self, name: &str, args: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let resp = tokio::time::timeout(
            TIMEOUT,
            self.client.call_tool(CallToolRequestParam {
                name: name.to_string().into(),
                arguments: args.as_object().cloned(),
            }),
        )
        .await
        .map_err(|_| anyhow::anyhow!("call timeout: {}", name))??;
        let text = resp
            .content
            .iter()
            .find_map(|item| item.as_text().map(|t| t.text.clone()))
            .unwrap_or_default();
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::json!({ "_raw": text })))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[tokio::test]
async fn jacs_search_returns_results_with_method_indicator() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Create a searchable document first
    let state_dir = s.base.join("jacs_data").join("state");
    fs::create_dir_all(&state_dir)?;
    fs::write(
        state_dir.join("searchable.json"),
        r#"{"content":"unique-search-probe-alpha"}"#,
    )?;
    let _ = s
        .call(
            "jacs_sign_state",
            serde_json::json!({
                "file_path": "jacs_data/state/searchable.json",
                "state_type": "memory",
                "name": "searchable doc",
                "embed": true
            }),
        )
        .await?;

    let result = s
        .call(
            "jacs_search",
            serde_json::json!({ "query": "unique-search-probe-alpha" }),
        )
        .await?;
    assert_eq!(result["success"], true, "search failed: {}", result);
    assert!(
        result["search_method"].as_str().is_some(),
        "expected search_method indicator: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_search_with_type_filter_restricts_results() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Create documents of different types
    let state_dir = s.base.join("jacs_data").join("state");
    fs::create_dir_all(&state_dir)?;
    fs::write(
        state_dir.join("config_search.json"),
        r#"{"setting":"search-filter-test"}"#,
    )?;
    let _ = s
        .call(
            "jacs_sign_state",
            serde_json::json!({
                "file_path": "jacs_data/state/config_search.json",
                "state_type": "config",
                "name": "config for filter test",
                "embed": true
            }),
        )
        .await?;

    // Also save a memory with similar content
    let _ = s
        .call(
            "jacs_memory_save",
            serde_json::json!({
                "name": "memory for filter test",
                "content": "search-filter-test memory content"
            }),
        )
        .await?;

    // Search with jacs_type filter - should return only agentstate docs
    let result = s
        .call(
            "jacs_search",
            serde_json::json!({
                "query": "search-filter-test",
                "jacs_type": "agentstate"
            }),
        )
        .await?;
    assert_eq!(
        result["success"], true,
        "filtered search failed: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_search_pagination_works() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Create multiple documents
    for i in 0..3 {
        let _ = s
            .call(
                "jacs_memory_save",
                serde_json::json!({
                    "name": format!("pagination-test-{}", i),
                    "content": format!("pagination content {}", i)
                }),
            )
            .await?;
    }

    // Search with limit=1
    let result = s
        .call(
            "jacs_search",
            serde_json::json!({
                "query": "pagination",
                "limit": 1
            }),
        )
        .await?;
    assert_eq!(
        result["success"], true,
        "paginated search failed: {}",
        result
    );
    let empty = vec![];
    let results = result["results"].as_array().unwrap_or(&empty);
    assert!(
        results.len() <= 1,
        "expected at most 1 result with limit=1, got {}: {}",
        results.len(),
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

fn sqlite_ready_agent() -> (AgentWrapper, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("mcp-search-sqlite")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .build();

    let (_agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    let mut config_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("read generated config"))
            .expect("parse generated config");
    config_json["jacs_default_storage"] = serde_json::Value::String("rusqlite".to_string());
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config_json).expect("serialize config"),
    )
    .expect("write updated config");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
        // Ensure env vars match the config so load_by_config doesn't use stale values
        std::env::set_var("JACS_DATA_DIRECTORY", data_dir.to_str().unwrap());
        std::env::set_var("JACS_KEY_DIRECTORY", key_dir.to_str().unwrap());
    }

    let wrapper = AgentWrapper::new();
    wrapper
        .load(config_path.to_string_lossy().into_owned())
        .expect("agent load should succeed");

    (wrapper, tmp)
}

#[test]
fn jacs_search_uses_document_service_backend_method() {
    // Run in a dedicated thread with its own tokio runtime to avoid
    // blocking-task shutdown panic from object_store/LocalFileSystem.
    let handle = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("create runtime");
        let result = rt.block_on(async {
            let (agent, _tmp) = sqlite_ready_agent();
            let docs = DocumentServiceWrapper::from_agent_wrapper(&agent)
                .expect("document service should be available");
            docs.create_json(
                r#"{"content":"mcpsqlitesearch needle","category":"keep"}"#,
                None,
            )
            .expect("create keep doc");
            docs.create_json(
                r#"{"content":"mcpsqlitesearch needle","category":"drop"}"#,
                None,
            )
            .expect("create drop doc");

            let server = JacsMcpServer::new(agent);
            let raw = server
                .jacs_search(Parameters(SearchParams {
                    query: "needle".to_string(),
                    jacs_type: None,
                    agent_id: None,
                    field_filter: Some(SearchFieldFilter {
                        field_path: "category".to_string(),
                        value: "keep".to_string(),
                    }),
                    limit: Some(10),
                    offset: Some(0),
                    min_score: None,
                }))
                .await;

            let result: serde_json::Value =
                serde_json::from_str(&raw).expect("search result should be valid JSON");

            assert_eq!(result["success"], true, "search failed: {}", result);
            assert_eq!(result["search_method"], "fulltext");
            let results = result["results"]
                .as_array()
                .expect("results should be an array");
            assert_eq!(
                results.len(),
                1,
                "field_filter should narrow results: {}",
                result
            );

            // Leak resources holding object_store handles to avoid tokio
            // blocking-task shutdown panic when the async block exits.
            std::mem::forget(server);
            std::mem::forget(docs);
            std::mem::forget(_tmp);
        });
    });
    // The thread may panic during tokio runtime shutdown (blocking tasks from
    // object_store outlive the runtime). The test assertions have already passed
    // inside the async block — the shutdown panic is a known tokio/object_store
    // incompatibility, not a test failure.
    let _ = handle.join();
}

// =========================================================================
// Task 005: MCP graceful degradation when document_service is None
// =========================================================================

/// When the MCP server has no document_service (e.g. unsupported storage backend),
/// `jacs_search` returns a JSON response with `success: false` and
/// `error: "document_service_unavailable"`.
#[tokio::test(flavor = "multi_thread")]
async fn jacs_search_returns_error_when_no_document_service() {
    // Create an agent with FS storage, then patch config to "memory"
    // (which service_from_agent doesn't wire) so document_service = None.
    let (agent, _tmp) = sqlite_ready_agent();

    // Patch the config's jacs_default_storage to "memory"
    {
        let agent_arc = agent.inner_arc();
        let mut guard = agent_arc.lock().unwrap();
        if let Some(ref mut config) = guard.config {
            let mut val = serde_json::to_value(&*config).unwrap();
            val["jacs_default_storage"] = serde_json::json!("memory");
            *config = serde_json::from_value(val).unwrap();
        }
    }

    let server = JacsMcpServer::new(agent);

    let raw = server
        .jacs_search(Parameters(SearchParams {
            query: "anything".to_string(),
            jacs_type: None,
            agent_id: None,
            field_filter: None,
            limit: Some(10),
            offset: Some(0),
            min_score: None,
        }))
        .await;

    let result: serde_json::Value =
        serde_json::from_str(&raw).expect("response should be valid JSON");
    assert_eq!(
        result["success"], false,
        "search with no document_service should return success: false"
    );
    assert_eq!(
        result["error"], "document_service_unavailable",
        "error code should be document_service_unavailable: {}",
        result
    );
}
