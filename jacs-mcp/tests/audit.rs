#![cfg(feature = "mcp")]
//! Behavioral tests for audit trail tools (TASK_041 / Issue 009).
//!
//! Tests: audit_log creates signed entries, audit_query searches by time range,
//! audit_export produces a signed JACS document.

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
async fn jacs_audit_log_creates_signed_entry() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    let result = s
        .call(
            "jacs_audit_log",
            serde_json::json!({
                "action": "tool_use",
                "target": "test-resource-id",
                "details": "{\"tool\":\"jacs_audit_log\",\"test\":true}"
            }),
        )
        .await?;

    assert_eq!(result["success"], true, "audit_log failed: {}", result);
    assert!(
        result["jacs_document_id"].as_str().is_some(),
        "expected jacs_document_id: {}",
        result
    );
    assert_eq!(
        result["action"].as_str(),
        Some("tool_use"),
        "action should be echoed back: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_audit_query_searches_by_time_range() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Log an audit entry first
    let _ = s
        .call(
            "jacs_audit_log",
            serde_json::json!({
                "action": "data_access",
                "target": "query-test-target"
            }),
        )
        .await?;

    // Query with a broad time range
    let result = s
        .call(
            "jacs_audit_query",
            serde_json::json!({
                "start_time": "2020-01-01T00:00:00Z",
                "end_time": "2030-01-01T00:00:00Z"
            }),
        )
        .await?;

    assert_eq!(result["success"], true, "audit_query failed: {}", result);
    let empty = vec![];
    let entries = result["entries"].as_array().unwrap_or(&empty);
    assert!(
        !entries.is_empty(),
        "expected at least 1 audit entry: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_audit_export_produces_signed_bundle() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Log an entry to export
    let _ = s
        .call(
            "jacs_audit_log",
            serde_json::json!({
                "action": "sign",
                "target": "export-test"
            }),
        )
        .await?;

    let result = s
        .call(
            "jacs_audit_export",
            serde_json::json!({
                "start_time": "2020-01-01T00:00:00Z",
                "end_time": "2030-01-01T00:00:00Z"
            }),
        )
        .await?;

    assert_eq!(result["success"], true, "audit_export failed: {}", result);
    assert!(
        result["signed_bundle"].as_str().is_some(),
        "expected signed_bundle: {}",
        result
    );
    assert!(
        result["entry_count"].as_u64().unwrap_or(0) >= 1,
        "expected at least 1 entry in export: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}
