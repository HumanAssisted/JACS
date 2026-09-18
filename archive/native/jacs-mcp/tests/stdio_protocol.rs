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

enum SessionMode {
    VerifyOnly,
    DefaultVerifyOnly,
    LocalSign { files: bool },
}

struct RawStdioSession {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    stderr_capture: Arc<Mutex<Vec<u8>>>,
    base: PathBuf,
    verify_arguments: Value,
    signer_id: String,
}

impl RawStdioSession {
    async fn spawn() -> anyhow::Result<Self> {
        Self::spawn_with_mode(SessionMode::VerifyOnly).await
    }

    async fn spawn_with_mode(mode: SessionMode) -> anyhow::Result<Self> {
        let (config, base) = prepare_temp_workspace_ed25519();
        let fixture_agent = jacs::simple::SimpleAgent::from_config(
            jacs::config::Config::from_file(config.to_str().expect("UTF-8 config"))?,
            Some(TEST_PASSWORD),
            Some(false),
        )?;
        let fixture = fixture_agent.sign_message(&json!({"message":"rmcp-3-spike"}))?;
        let verify_arguments = json!({
            "document": fixture.raw,
            "public_key": fixture_agent.get_public_key()?,
            "algorithm": "ed25519",
        });
        let signer_id = fixture_agent.get_agent_id()?;
        drop(fixture_agent);
        let mut command = tokio::process::Command::new(support::jacs_cli_bin());
        // The operator's ambient network grants, identity/path overrides and
        // compatibility switches must not silently change this child process.
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("JACS_") {
                command.env_remove(name);
            }
        }
        command
            .arg("mcp")
            .current_dir(&base)
            .env(LEGACY_SIGNATURE_CONTENT_ENV_VAR, "true")
            .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
            .env("JACS_TRUST_STORE_DIR", base.join("trusted"))
            .env("RUST_LOG", "warn")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match mode {
            SessionMode::VerifyOnly | SessionMode::DefaultVerifyOnly => {
                if matches!(mode, SessionMode::VerifyOnly) {
                    command.args(["--profile", "verify-only"]);
                }
                // A real encrypted identity is present but cannot be unlocked
                // with this password. Verification must ignore it entirely.
                command.env("JACS_CONFIG", &config).env(
                    "JACS_PRIVATE_KEY_PASSWORD",
                    "intentionally-incorrect-raw-stdio-test-password",
                );
            }
            SessionMode::LocalSign { files } => {
                command
                    .args(["--profile", "local-sign", "--config"])
                    .arg(&config)
                    .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
                if files {
                    let content_root = base.join("content");
                    std::fs::create_dir(&content_root)?;
                    command.env("JACS_MCP_BASE_DIR", content_root);
                }
            }
        }

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
            verify_arguments,
            signer_id,
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
        let response = self.request_envelope(message).await?;
        if let Some(error) = response.get("error") {
            return Err(anyhow::anyhow!(
                "MCP request {} failed: {error}; stderr:\n{}",
                response["id"],
                self.stderr()
            ));
        }
        Ok(response)
    }

    /// Keep JSON-RPC errors intact so rejection tests can distinguish them
    /// from an MCP result containing a JACS application error.
    async fn request_envelope(&mut self, message: Value) -> anyhow::Result<Value> {
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
                assert_eq!(response["jsonrpc"], "2.0", "{response}");
                assert_ne!(
                    response.get("result").is_some(),
                    response.get("error").is_some(),
                    "JSON-RPC response must have exactly one of result or error: {response}"
                );
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

    async fn stderr_containing(&self, event: &str) -> anyhow::Result<String> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let stderr = self.stderr();
                if stderr.contains(event) {
                    return stderr;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("missing stderr event {event}; stderr:\n{}", self.stderr()))
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

fn modern_request(id: u64, method: &str, mut params: Value) -> Value {
    params["_meta"] = modern_meta();
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn modern_tool_call(id: u64, name: &str, arguments: Value) -> Value {
    modern_request(
        id,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

fn tool_result(response: &Value) -> anyhow::Result<Value> {
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["resultType"], "complete", "{response}");
    // Existing JACS tools return their typed success/valid/error envelope as
    // text. Application rejection is not a JSON-RPC dispatch failure.
    assert_eq!(response["result"]["isError"], false, "{response}");
    let text = response["result"]["content"]
        .as_array()
        .and_then(|content| content.iter().find(|item| item["type"] == "text"))
        .and_then(|item| item["text"].as_str())
        .ok_or_else(|| anyhow::anyhow!("MCP tool result has no text content: {response}"))?;
    Ok(serde_json::from_str(text)?)
}

fn assert_invalid_params(response: &Value) {
    assert!(response.get("result").is_none(), "{response}");
    assert_eq!(response["error"]["code"], -32602, "{response}");
    assert!(response["error"]["message"].is_string(), "{response}");
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
    let expected_tools = jacs_mcp::Profile::VerifyOnly.tools();
    let expected_names: Vec<&str> = expected_tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect();
    assert_eq!(names, expected_names);
    assert!(!names.contains(&"jacs_sign_document"));
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
    let expected_tools = jacs_mcp::Profile::VerifyOnly.tools();
    let expected_names: Vec<&str> = expected_tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect();
    assert_eq!(names, expected_names);
    assert!(!names.contains(&"jacs_sign_document"));
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
                "name": "jacs_verify_document",
                "arguments": session.verify_arguments.clone(),
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
        .expect("jacs_verify_document must return text content");
    let verified: Value = serde_json::from_str(tool_text)?;
    assert_eq!(verified["success"], true, "{verified}");
    assert_eq!(verified["valid"], true, "{verified}");
    assert_eq!(verified["signer_id"], session.signer_id);

    session.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn modern_protocol_and_metadata_rejections_allow_discovery_recovery() -> anyhow::Result<()> {
    let _guard = STDIO_PROTOCOL_LOCK.lock().await;
    let mut session = RawStdioSession::spawn().await?;

    // A complete inline opener with an unsupported version is rejected without
    // poisoning later discovery. A malformed first opener has different SDK
    // startup semantics, so malformed metadata is tested after discovery below.
    let mut unsupported = modern_request(1, "server/discover", json!({}));
    unsupported["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    let rejected = session.request_envelope(unsupported).await?;
    assert!(rejected.get("result").is_none(), "{rejected}");
    assert_eq!(rejected["error"]["code"], -32022, "{rejected}");
    assert_eq!(rejected["error"]["data"]["requested"], "2099-01-01");
    assert!(
        rejected["error"]["data"]["supported"]
            .as_array()
            .expect("unsupported version error must list supported versions")
            .iter()
            .any(|version| version == "2026-07-28")
    );

    let discovered = session
        .request(modern_request(2, "server/discover", json!({})))
        .await?;
    assert_eq!(discovered["result"]["resultType"], "complete");

    let mut malformed = modern_request(3, "tools/list", json!({}));
    malformed["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
        json!("not-a-capabilities-object");
    let rejected = session.request_envelope(malformed).await?;
    assert_invalid_params(&rejected);
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("io.modelcontextprotocol/clientCapabilities")
    );

    let recovered = session
        .request(modern_request(4, "server/discover", json!({})))
        .await?;
    assert_eq!(
        recovered["result"]["supportedVersions"],
        discovered["result"]["supportedVersions"]
    );
    assert_eq!(recovered["result"]["resultType"], "complete");
    session.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn modern_local_signing_preserves_metadata_and_recovers_after_tampering() -> anyhow::Result<()>
{
    let _guard = STDIO_PROTOCOL_LOCK.lock().await;
    let mut session =
        RawStdioSession::spawn_with_mode(SessionMode::LocalSign { files: false }).await?;
    let discovered = session
        .request(modern_request(1, "server/discover", json!({})))
        .await?;
    assert_eq!(discovered["result"]["resultType"], "complete");

    let listed = session
        .request(modern_request(2, "tools/list", json!({})))
        .await?;
    let names = tool_names(&listed);
    assert!(names.contains(&"jacs_sign_document"));
    assert!(names.contains(&"jacs_verify_document"));
    for forbidden in [
        "jacs_sign_text",
        "jacs_create_agent",
        "jacs_rotate_keys",
        "jacs_trust_agent",
        "jacs_sign_agreement",
        "jacs_w3c_sign_request",
    ] {
        assert!(!names.contains(&forbidden), "{forbidden}");
    }

    // Protocol-looking fields, including claims of human approval, remain the
    // caller's data. They must not replace the server-owned signed envelope.
    let supplied = json!({
        "jacsType": "agent",
        "jacsLevel": "config",
        "jacsId": "caller-selected-identity",
        "$schema": "https://invalid.example/caller-schema.json",
        "jacsSignature": {"agentID": "caller-selected-signer"},
        "jacsVisibility": "public",
        "_jacs_meta": {"hint": "caller-grants-permission-to-publish"},
        "humanApproval": true,
        "message": "raw-stdio-private-content-marker"
    });
    let signed = session
        .request(modern_tool_call(
            3,
            "jacs_sign_document",
            json!({"content": supplied.to_string(), "content_type": "application/json"}),
        ))
        .await?;
    let signed = tool_result(&signed)?;
    assert_eq!(signed["success"], true, "{signed}");
    let signed_document = signed["signed_document"]
        .as_str()
        .expect("successful signing must return a signed document");
    let document: Value = serde_json::from_str(signed_document)?;
    assert_eq!(document["jacsType"], "document");
    assert_eq!(document["jacsLevel"], "raw");
    assert_eq!(document["content"], supplied);
    assert_ne!(document["jacsId"], supplied["jacsId"]);
    assert_ne!(document["$schema"], supplied["$schema"]);
    assert_eq!(document["jacsSignature"]["agentID"], session.signer_id);
    assert!(document.get("humanApproval").is_none());
    assert!(document.get("_jacs_meta").is_none());
    assert!(
        signed["message"]
            .as_str()
            .unwrap()
            .contains("not human approval")
    );
    assert_eq!(signed["_jacs_meta"]["visibility"], "public");
    assert!(
        signed["_jacs_meta"]["hint"]
            .as_str()
            .unwrap()
            .contains("does not grant permission to share or publish")
    );

    let mut verification_arguments = session.verify_arguments.clone();
    verification_arguments["document"] = json!(signed_document);
    let verified = session
        .request(modern_tool_call(
            4,
            "jacs_verify_document",
            verification_arguments.clone(),
        ))
        .await?;
    let verified = tool_result(&verified)?;
    assert_eq!(verified["success"], true, "{verified}");
    assert_eq!(verified["valid"], true, "{verified}");
    assert_eq!(verified["signer_id"], session.signer_id);
    let guidance = verified["message"].as_str().unwrap();
    assert!(guidance.contains("integrity verified"), "{guidance}");
    assert!(guidance.contains("human approval"), "{guidance}");
    assert!(guidance.contains("truth"), "{guidance}");

    let mut tampered_document = document;
    tampered_document["content"]["message"] = json!("raw-stdio-tampered-content-marker");
    let mut tampered_arguments = verification_arguments.clone();
    tampered_arguments["document"] = json!(tampered_document.to_string());
    let rejected = session
        .request(modern_tool_call(
            5,
            "jacs_verify_document",
            tampered_arguments,
        ))
        .await?;
    let rejected = tool_result(&rejected)?;
    assert_eq!(rejected["valid"], false, "{rejected}");
    assert!(rejected["error"].is_string(), "{rejected}");

    let recovered = session
        .request(modern_tool_call(
            6,
            "jacs_verify_document",
            verification_arguments,
        ))
        .await?;
    assert_eq!(tool_result(&recovered)?["valid"], true);
    let stderr = session.stderr_containing("mcp_verification_failed").await?;
    assert!(stderr.contains("WARN"), "{stderr}");
    for marker in [
        "raw-stdio-private-content-marker",
        "raw-stdio-tampered-content-marker",
        "caller-selected-signer",
    ] {
        assert!(
            !stderr.contains(marker),
            "verification logs leaked {marker}"
        );
    }

    session.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn modern_dispatch_and_argument_errors_are_recoverable() -> anyhow::Result<()> {
    let _guard = STDIO_PROTOCOL_LOCK.lock().await;
    let mut session =
        RawStdioSession::spawn_with_mode(SessionMode::LocalSign { files: false }).await?;
    session
        .request(modern_request(1, "server/discover", json!({})))
        .await?;

    for (id, name, arguments) in [
        (2, "jacs_rotate_keys", json!({})),
        (
            3,
            "unknown-tool-private-marker",
            json!({"content": "raw-stdio-rejected-argument-marker"}),
        ),
    ] {
        let rejected = session
            .request_envelope(modern_tool_call(id, name, arguments))
            .await?;
        assert_invalid_params(&rejected);
    }

    // The SDK's tool macro returns argument-deserialization errors as MCP
    // tool results with isError=true, not as JSON-RPC dispatch errors.
    for (id, arguments) in [
        (4, json!({"content": 42})),
        (
            5,
            json!({"content": "{}", "raw-stdio-rejected-argument-marker": true}),
        ),
    ] {
        let rejected = session
            .request(modern_tool_call(id, "jacs_sign_document", arguments))
            .await?;
        assert!(rejected.get("error").is_none(), "{rejected}");
        assert_eq!(rejected["result"]["resultType"], "complete");
        assert_eq!(rejected["result"]["isError"], true, "{rejected}");
        assert!(
            rejected["result"]["content"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["type"] == "text"
                    && item["text"]
                        .as_str()
                        .is_some_and(|text| text.contains("failed to deserialize parameters"))),
            "{rejected}"
        );
    }

    // Invalid embedded JSON is an application error after dispatch, retaining
    // the existing JACS envelope instead of becoming a JSON-RPC error.
    let malformed_content = session
        .request(modern_tool_call(
            6,
            "jacs_sign_document",
            json!({"content": "{not-json"}),
        ))
        .await?;
    let malformed_content = tool_result(&malformed_content)?;
    assert_eq!(malformed_content["success"], false);
    assert!(malformed_content.get("signed_document").is_none());

    let recovered = session
        .request(modern_tool_call(
            7,
            "jacs_sign_document",
            json!({"content": "{\"message\":\"after-rejection\"}"}),
        ))
        .await?;
    let recovered = tool_result(&recovered)?;
    assert_eq!(recovered["success"], true, "{recovered}");
    let mut verify_arguments = session.verify_arguments.clone();
    verify_arguments["document"] = recovered["signed_document"].clone();
    let verified = session
        .request(modern_tool_call(
            8,
            "jacs_verify_document",
            verify_arguments,
        ))
        .await?;
    assert_eq!(tool_result(&verified)?["valid"], true);

    let stderr = session.stderr_containing("mcp_tool_scope_denied").await?;
    assert!(stderr.contains("WARN"), "{stderr}");
    assert!(stderr.contains("jacs_rotate_keys"), "{stderr}");
    assert!(stderr.contains("unknown"), "{stderr}");
    assert!(!stderr.contains("unknown-tool-private-marker"));
    assert!(!stderr.contains("raw-stdio-rejected-argument-marker"));
    session.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn default_profile_rejects_signing_without_unlocking_configured_key() -> anyhow::Result<()> {
    let _guard = STDIO_PROTOCOL_LOCK.lock().await;
    let mut session = RawStdioSession::spawn_with_mode(SessionMode::DefaultVerifyOnly).await?;
    let config_before = std::fs::read(session.base.join("jacs.config.json"))?;
    // Native document storage is rooted beside the fixture config. Its
    // jacs_data_directory contains agent identities, not signed documents.
    let document_dir = session.base.join("documents");
    // The fixture signer already persisted the verification sample. The child
    // must neither add a signed document nor alter that existing artifact.
    let fixture_path = {
        let fixture: Value =
            serde_json::from_str(session.verify_arguments["document"].as_str().unwrap())?;
        document_dir.join(format!(
            "{}:{}.json",
            fixture["jacsId"].as_str().unwrap(),
            fixture["jacsVersion"].as_str().unwrap()
        ))
    };
    let fixture_before = std::fs::read(&fixture_path)?;
    let document_count_before = std::fs::read_dir(&document_dir)?.count();
    session
        .request(modern_request(1, "server/discover", json!({})))
        .await?;
    let listed = session
        .request(modern_request(2, "tools/list", json!({})))
        .await?;
    assert_eq!(tool_names(&listed), vec!["jacs_verify_document"]);

    let rejected = session
        .request_envelope(modern_tool_call(
            3,
            "jacs_sign_document",
            json!({"content": "{\"message\":\"default-profile-must-not-sign\"}"}),
        ))
        .await?;
    assert_invalid_params(&rejected);
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("verify-only")
    );
    let verified = session
        .request(modern_tool_call(
            4,
            "jacs_verify_document",
            session.verify_arguments.clone(),
        ))
        .await?;
    assert_eq!(tool_result(&verified)?["valid"], true);
    assert_eq!(
        std::fs::read(session.base.join("jacs.config.json"))?,
        config_before
    );
    assert_eq!(std::fs::read(&fixture_path)?, fixture_before);
    assert_eq!(
        std::fs::read_dir(&document_dir)?.count(),
        document_count_before
    );
    let stderr = session.stderr_containing("mcp_tool_scope_denied").await?;
    assert!(!stderr.contains("Unlock configured local signer"));
    assert!(!stderr.contains("default-profile-must-not-sign"));
    assert!(!stderr.contains("intentionally-incorrect-raw-stdio-test-password"));
    session.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn modern_file_scope_rejects_escape_then_signs_and_verifies_allowed_text()
-> anyhow::Result<()> {
    let _guard = STDIO_PROTOCOL_LOCK.lock().await;
    let mut session =
        RawStdioSession::spawn_with_mode(SessionMode::LocalSign { files: true }).await?;
    let content_root = session.base.join("content");
    let original = b"# Authorized content\nAn agent signature records provenance.\n";
    std::fs::write(content_root.join("note.md"), original)?;
    std::fs::write(
        session.base.join("outside.md"),
        b"outside the selected root",
    )?;
    let config_path = session.base.join("jacs.config.json");
    let config_before = std::fs::read(&config_path)?;
    session
        .request(modern_request(1, "server/discover", json!({})))
        .await?;
    let listed = session
        .request(modern_request(2, "tools/list", json!({})))
        .await?;
    assert!(tool_names(&listed).contains(&"jacs_sign_text"));

    for (id, path) in [
        (3, "../outside.md".to_string()),
        (4, "../jacs.config.json".to_string()),
        (5, config_path.to_string_lossy().into_owned()),
    ] {
        let rejected = session
            .request(modern_tool_call(
                id,
                "jacs_sign_text",
                json!({"file_path": path}),
            ))
            .await?;
        let rejected = tool_result(&rejected)?;
        assert_eq!(rejected["success"], false, "{rejected}");
        assert_eq!(rejected["signers_added"], 0, "{rejected}");
        assert!(
            rejected["error"]
                .as_str()
                .unwrap()
                .contains("PATH_POLICY_BLOCKED"),
            "{rejected}"
        );
    }
    assert_eq!(std::fs::read(&config_path)?, config_before);
    assert_eq!(
        std::fs::read(session.base.join("outside.md"))?,
        b"outside the selected root"
    );
    assert!(!session.base.join("outside.md.bak").exists());

    let signed = session
        .request(modern_tool_call(
            6,
            "jacs_sign_text",
            json!({"file_path": "note.md"}),
        ))
        .await?;
    let signed = tool_result(&signed)?;
    assert_eq!(signed["success"], true, "{signed}");
    assert_eq!(signed["signers_added"], 1);
    assert_eq!(std::fs::read(content_root.join("note.md.bak"))?, original);
    assert!(std::fs::read(content_root.join("note.md"))?.starts_with(original));
    let verified = session
        .request(modern_tool_call(
            7,
            "jacs_verify_text",
            json!({"file_path": "note.md", "strict": true}),
        ))
        .await?;
    let verified = tool_result(&verified)?;
    assert_eq!(verified["success"], true, "{verified}");
    assert_eq!(verified["signatures"][0]["status"], "valid");
    assert_eq!(verified["signatures"][0]["signer_id"], signed["signer_id"]);
    session.shutdown().await;
    Ok(())
}
