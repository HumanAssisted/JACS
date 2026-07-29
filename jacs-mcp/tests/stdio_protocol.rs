use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

mod support;

use support::{
    LEGACY_SIGNATURE_CONTENT_ENV_VAR, TEST_PASSWORD, cleanup_workspace,
    prepare_temp_workspace_ed25519,
};

const MCP_IO_TIMEOUT: Duration = Duration::from_secs(90);
const MCP_STDERR_CAPTURE_LIMIT: usize = 64 * 1024;
const EXPECTED_TOOLS_TTL_MS: u64 = 300_000;

static STDIO_PROTOCOL_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

struct RawStdioSession {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    stderr_capture: Arc<Mutex<Vec<u8>>>,
    base: PathBuf,
}

impl RawStdioSession {
    async fn spawn() -> anyhow::Result<Self> {
        let (config, base) = prepare_temp_workspace_ed25519();
        let mut command = tokio::process::Command::new(support::jacs_cli_bin());
        command
            .arg("mcp")
            .arg("--profile")
            .arg("core")
            .current_dir(&base)
            .env("JACS_CONFIG", &config)
            .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
            .env(LEGACY_SIGNATURE_CONTENT_ENV_VAR, "true")
            .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
            .env("RUST_LOG", "warn")
            .env_remove("JACS_KEY_DIRECTORY")
            .env_remove("JACS_DATA_DIRECTORY")
            .env_remove("JACS_AGENT_ID_AND_VERSION")
            .env_remove("JACS_AGENT_KEY_ALGORITHM")
            .env_remove("JACS_AGENT_PRIVATE_KEY_FILENAME")
            .env_remove("JACS_AGENT_PUBLIC_KEY_FILENAME")
            .env_remove("JACS_DEFAULT_STORAGE")
            .env_remove("JACS_MCP_PROFILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("jacs mcp child has no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("jacs mcp child has no stdout"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("jacs mcp child has no stderr"))?;

        let stderr_capture = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&stderr_capture);
        tokio::spawn(async move {
            let mut chunk = [0_u8; 4096];
            loop {
                let read = match stderr.read(&mut chunk).await {
                    Ok(read) => read,
                    Err(_) => return,
                };
                if read == 0 {
                    return;
                }
                let mut captured = capture.lock().unwrap_or_else(|error| error.into_inner());
                let remaining = MCP_STDERR_CAPTURE_LIMIT.saturating_sub(captured.len());
                captured.extend_from_slice(&chunk[..read.min(remaining)]);
            }
        });

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
            stderr_capture,
            base,
        })
    }

    async fn send(&mut self, message: Value) -> anyhow::Result<()> {
        let mut encoded = serde_json::to_vec(&message)?;
        encoded.push(b'\n');
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MCP session stdin is closed"))?;
        tokio::time::timeout(MCP_IO_TIMEOUT, stdin.write_all(&encoded))
            .await
            .map_err(|_| anyhow::anyhow!("timed out writing MCP request"))??;
        tokio::time::timeout(MCP_IO_TIMEOUT, stdin.flush())
            .await
            .map_err(|_| anyhow::anyhow!("timed out flushing MCP request"))??;
        Ok(())
    }

    async fn request(&mut self, message: Value) -> anyhow::Result<Value> {
        let expected_id = message
            .get("id")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("MCP request must have an id"))?;
        self.send(message).await?;

        loop {
            let line = tokio::time::timeout(MCP_IO_TIMEOUT, self.stdout.next_line())
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "timed out waiting for MCP response; stderr:\n{}",
                        self.stderr()
                    )
                })??
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "MCP server closed stdout before response; stderr:\n{}",
                        self.stderr()
                    )
                })?;
            let response: Value = serde_json::from_str(&line)
                .map_err(|error| anyhow::anyhow!("invalid MCP response {line:?}: {error}"))?;
            if response.get("id") == Some(&expected_id) {
                if let Some(error) = response.get("error") {
                    return Err(anyhow::anyhow!(
                        "MCP request {expected_id} failed: {error}; stderr:\n{}",
                        self.stderr()
                    ));
                }
                return Ok(response);
            }
        }
    }

    fn stderr(&self) -> String {
        let captured = self
            .stderr_capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        String::from_utf8_lossy(&captured).into_owned()
    }

    async fn shutdown(mut self) {
        self.stdin.take();
        if tokio::time::timeout(Duration::from_secs(2), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
        cleanup_workspace(&self.base);
    }
}

impl Drop for RawStdioSession {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        cleanup_workspace(&self.base);
    }
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "jacs-rmcp-3-spike",
            "version": "1.0.0"
        },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn tool_names(response: &Value) -> Vec<&str> {
    response["result"]["tools"]
        .as_array()
        .expect("tools/list result must contain tools")
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .expect("each MCP tool must have a name")
        })
        .collect()
}

#[tokio::test]
async fn legacy_initialize_and_tools_list_remain_compatible() -> anyhow::Result<()> {
    let _guard = STDIO_PROTOCOL_LOCK.lock().await;
    let mut session = RawStdioSession::spawn().await?;

    let initialize = session
        .request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "jacs-legacy-protocol-test",
                    "version": "1.0.0"
                }
            }
        }))
        .await?;
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(initialize["result"]["serverInfo"]["name"], "jacs-mcp");

    session
        .send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .await?;

    let listed = session
        .request(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .await?;
    assert!(
        listed["result"].get("resultType").is_none(),
        "legacy peers must retain the pre-2026 result shape"
    );

    let names = tool_names(&listed);
    let expected_tools = jacs_mcp::Profile::Core.tools();
    let expected_names: Vec<&str> = expected_tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect();
    assert_eq!(names, expected_names);
    assert!(names.contains(&"jacs_sign_document"));
    assert!(!names.contains(&"jacs_create_agreement"));

    session.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn modern_discover_lists_cached_tools_and_calls_a_tool() -> anyhow::Result<()> {
    let _guard = STDIO_PROTOCOL_LOCK.lock().await;
    let mut session = RawStdioSession::spawn().await?;
    let meta = modern_meta();

    let discovered = session
        .request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": meta.clone() }
        }))
        .await?;
    assert_eq!(discovered["result"]["resultType"], "complete");
    assert!(
        discovered["result"]["supportedVersions"]
            .as_array()
            .expect("server/discover must report supportedVersions")
            .iter()
            .any(|version| version == "2026-07-28")
    );
    assert!(discovered["result"]["capabilities"]["tools"].is_object());
    assert_eq!(
        discovered["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "jacs-mcp"
    );
    assert_eq!(discovered["result"]["ttlMs"], 0);
    assert_eq!(discovered["result"]["cacheScope"], "private");

    let listed = session
        .request(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": { "_meta": meta.clone() }
        }))
        .await?;
    assert_eq!(listed["result"]["resultType"], "complete");
    assert_eq!(listed["result"]["ttlMs"], EXPECTED_TOOLS_TTL_MS);
    assert_eq!(listed["result"]["cacheScope"], "public");
    let names = tool_names(&listed);
    let expected_tools = jacs_mcp::Profile::Core.tools();
    let expected_names: Vec<&str> = expected_tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect();
    assert_eq!(names, expected_names);
    assert!(names.contains(&"jacs_sign_document"));
    assert!(!names.contains(&"jacs_create_agreement"));

    let listed_again = session
        .request(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": { "_meta": meta.clone() }
        }))
        .await?;
    assert_eq!(listed["result"]["tools"], listed_again["result"]["tools"]);

    let called = session
        .request(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "jacs_sign_document",
                "arguments": {
                    "content": "{\"message\":\"rmcp-3-spike\"}"
                },
                "_meta": meta
            }
        }))
        .await?;
    assert_eq!(called["result"]["resultType"], "complete");
    assert_eq!(called["result"]["isError"], false);
    let tool_text = called["result"]["content"]
        .as_array()
        .and_then(|content| content.iter().find(|item| item["type"] == "text"))
        .and_then(|item| item["text"].as_str())
        .expect("jacs_sign_document must return text content");
    let signed: Value = serde_json::from_str(tool_text)?;
    assert_eq!(signed["success"], true);
    assert!(
        signed["signed_document"]
            .as_str()
            .is_some_and(|document| !document.is_empty())
    );
    assert!(
        signed["content_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty())
    );
    assert!(
        signed["jacs_document_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );

    session.shutdown().await;
    Ok(())
}
