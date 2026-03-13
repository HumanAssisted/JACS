#![cfg(feature = "mcp")]
//! Behavioral tests for memory tools (TASK_040 / Issue 009).
//!
//! Tests: save, recall, list, forget, update — and that memory tools
//! do NOT return non-memory agentstate documents.

use std::fs;
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

use rmcp::{
    RoleClient, ServiceExt,
    model::CallToolRequestParam,
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
};

mod support;
use support::{TEST_PASSWORD, prepare_temp_workspace};

static STDIO_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
const TIMEOUT: Duration = Duration::from_secs(30);

type McpClient = RunningService<RoleClient, ()>;

struct Session {
    client: McpClient,
    _base: std::path::PathBuf,
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
        Ok(Self { client, _base: base })
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
        let _ = fs::remove_dir_all(&self._base);
    }
}

#[tokio::test]
async fn jacs_memory_save_creates_private_memory() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    let result = s
        .call(
            "jacs_memory_save",
            serde_json::json!({
                "name": "test memory",
                "content": "remembered fact: the sky is blue",
                "tags": ["color", "sky"]
            }),
        )
        .await?;

    assert_eq!(result["success"], true, "save failed: {}", result);
    assert!(
        result["jacs_document_id"].as_str().is_some(),
        "expected doc id: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_memory_recall_searches_private_memories() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Save a memory first
    let saved = s
        .call(
            "jacs_memory_save",
            serde_json::json!({
                "name": "recall target",
                "content": "unique-recall-probe-content-xyz"
            }),
        )
        .await?;
    assert_eq!(saved["success"], true, "save failed: {}", saved);

    // Recall it
    let recalled = s
        .call(
            "jacs_memory_recall",
            serde_json::json!({ "query": "unique-recall-probe-content-xyz" }),
        )
        .await?;
    assert_eq!(recalled["success"], true, "recall failed: {}", recalled);
    assert!(
        recalled["total"].as_u64().unwrap_or(0) >= 1,
        "expected at least 1 match: {}",
        recalled
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_memory_list_returns_only_memory_documents() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Create a non-memory state document
    let state_dir = s._base.join("jacs_data").join("state");
    fs::create_dir_all(&state_dir)?;
    let state_file = state_dir.join("config.json");
    fs::write(&state_file, r#"{"setting":"value"}"#)?;
    let _ = s
        .call(
            "jacs_sign_state",
            serde_json::json!({
                "file_path": "jacs_data/state/config.json",
                "state_type": "config",
                "name": "test config",
                "embed": true
            }),
        )
        .await?;

    // Create a memory document
    let saved = s
        .call(
            "jacs_memory_save",
            serde_json::json!({
                "name": "list test memory",
                "content": "memory content for list test"
            }),
        )
        .await?;
    assert_eq!(saved["success"], true);

    // List memories - should NOT include the config state doc
    let listed = s
        .call("jacs_memory_list", serde_json::json!({}))
        .await?;
    assert_eq!(listed["success"], true, "list failed: {}", listed);

    let empty_list = vec![];
    let memories = listed["memories"].as_array().unwrap_or(&empty_list);
    // All returned items should be memories (none should be the config doc)
    for mem in memories {
        assert!(
            mem["name"].as_str().unwrap_or_default() != "test config",
            "memory list returned a non-memory document: {}",
            mem
        );
    }

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_memory_forget_marks_memory_as_removed() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Save then forget
    let saved = s
        .call(
            "jacs_memory_save",
            serde_json::json!({
                "name": "forgettable",
                "content": "this will be forgotten"
            }),
        )
        .await?;
    let doc_id = saved["jacs_document_id"]
        .as_str()
        .expect("doc id from save");

    let forgot = s
        .call(
            "jacs_memory_forget",
            serde_json::json!({ "jacs_id": doc_id }),
        )
        .await?;
    assert_eq!(forgot["success"], true, "forget failed: {}", forgot);

    // The forgotten memory should not appear in list results
    let listed = s
        .call("jacs_memory_list", serde_json::json!({}))
        .await?;
    let empty_forget = vec![];
    let memories = listed["memories"].as_array().unwrap_or(&empty_forget);
    let found = memories
        .iter()
        .any(|m| m["name"].as_str() == Some("forgettable"));
    assert!(
        !found,
        "forgotten memory still appears in list: {}",
        listed
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_memory_update_creates_new_version() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    let saved = s
        .call(
            "jacs_memory_save",
            serde_json::json!({
                "name": "updatable",
                "content": "version 1"
            }),
        )
        .await?;
    let doc_id = saved["jacs_document_id"]
        .as_str()
        .expect("doc id from save");

    let updated = s
        .call(
            "jacs_memory_update",
            serde_json::json!({
                "jacs_id": doc_id,
                "content": "version 2"
            }),
        )
        .await?;
    assert_eq!(updated["success"], true, "update failed: {}", updated);

    let new_id = updated["jacs_document_id"]
        .as_str()
        .unwrap_or_default();
    assert_ne!(new_id, doc_id, "update should create new version");

    s.client.cancellation_token().cancel();
    Ok(())
}
