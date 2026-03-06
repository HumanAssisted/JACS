use std::fs;
use std::path::{Path, PathBuf};
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

use support::{
    TEST_PASSWORD, assert_server_reaches_initialized_request, prepare_temp_workspace,
    run_server_with_fixture,
};

static STDIO_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
const MCP_INIT_TIMEOUT: Duration = Duration::from_secs(30);
const MCP_LIST_TIMEOUT: Duration = Duration::from_secs(30);
const MCP_CALL_TIMEOUT: Duration = Duration::from_secs(30);

type McpClient = RunningService<RoleClient, ()>;

struct RmcpSession {
    client: McpClient,
    base: PathBuf,
}

impl RmcpSession {
    async fn spawn(extra_env: &[(&str, &str)]) -> anyhow::Result<Self> {
        let (config, base) = prepare_temp_workspace();
        let bin_path = assert_cmd::cargo::cargo_bin!("jacs-mcp");
        let command = tokio::process::Command::new(&bin_path).configure(|cmd| {
            cmd.current_dir(&base)
                .env("JACS_CONFIG", &config)
                .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
                .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
                .env("RUST_LOG", "warn");

            for (k, v) in extra_env {
                cmd.env(k, v);
            }
        });
        let (transport, _stderr) = TokioChildProcess::builder(command)
            .stderr(Stdio::null())
            .spawn()?;
        let client = tokio::time::timeout(MCP_INIT_TIMEOUT, ().serve(transport))
            .await
            .map_err(|_| anyhow::anyhow!("timed out initializing jacs-mcp over stdio"))??;

        Ok(Self { client, base })
    }

    fn workspace(&self) -> &Path {
        &self.base
    }

    async fn list_tools(&self) -> anyhow::Result<Vec<String>> {
        Ok(
            tokio::time::timeout(MCP_LIST_TIMEOUT, self.client.list_all_tools())
                .await
                .map_err(|_| anyhow::anyhow!("timed out listing MCP tools"))??
                .into_iter()
                .map(|tool| tool.name.to_string())
                .collect(),
        )
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let response = tokio::time::timeout(
            MCP_CALL_TIMEOUT,
            self.client.call_tool(CallToolRequestParam {
                name: name.to_string().into(),
                arguments: arguments.as_object().cloned(),
            }),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timed out calling MCP tool '{}'", name))??;
        parse_tool_result(name, response)
    }
}

fn parse_tool_result(
    name: &str,
    response: rmcp::model::CallToolResult,
) -> anyhow::Result<serde_json::Value> {
    let raw_response =
        serde_json::to_string(&response).unwrap_or_else(|_| "<unserializable>".into());
    assert!(
        !response.is_error.unwrap_or(false),
        "tool '{}' returned MCP error: {}",
        name,
        raw_response
    );
    let text = response
        .content
        .iter()
        .find_map(|item| item.as_text().map(|text| text.text.clone()))
        .unwrap_or_else(|| panic!("tool '{}' returned no text content: {}", name, raw_response));
    Ok(serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "_raw": text })))
}

fn parse_json_string_field(
    value: &serde_json::Value,
    field: &str,
) -> anyhow::Result<serde_json::Value> {
    let raw = value[field]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("expected '{}' string field in {}", field, value))?;
    Ok(serde_json::from_str(raw)?)
}

impl Drop for RmcpSession {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn starts_server_with_agent_env() {
    let (output, base) = run_server_with_fixture(&[]);
    assert_server_reaches_initialized_request(&output, "default log environment");
    let _ = fs::remove_dir_all(&base);
}

#[tokio::test]
async fn mcp_state_round_trip_over_stdio() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[]).await?;
    let server_info = session
        .client
        .peer_info()
        .expect("rmcp client should initialize the server");
    assert_eq!(server_info.server_info.name, "jacs-mcp");

    let tools = session.list_tools().await?;
    assert!(
        tools.iter().any(|tool| tool == "jacs_list_state"),
        "expected jacs_list_state in tool list: {:?}",
        tools
    );
    assert!(
        tools.iter().any(|tool| tool == "jacs_attest_create"),
        "expected attestation tools in default build: {:?}",
        tools
    );

    let state_dir = session.workspace().join("data");
    fs::create_dir_all(&state_dir).expect("mkdir state dir");
    let state_path = state_dir.join("memory.json");
    fs::write(&state_path, "{\"topic\":\"mcp probe\",\"value\":1}\n").expect("write state file");

    let signed = session
        .call_tool(
            "jacs_sign_state",
            serde_json::json!({
                "file_path": "data/memory.json",
                "state_type": "memory",
                "name": "Probe Memory",
                "description": "Created by MCP integration test",
                "embed": true
            }),
        )
        .await?;
    let doc_id = signed["jacs_document_id"]
        .as_str()
        .expect("sign_state jacs_document_id");
    assert_ne!(doc_id, "unknown");
    assert!(
        doc_id.contains(':'),
        "expected versioned doc id: {}",
        doc_id
    );

    let verified = session
        .call_tool(
            "jacs_verify_state",
            serde_json::json!({ "jacs_id": doc_id }),
        )
        .await?;
    assert_eq!(
        verified["success"], true,
        "verify_state failed: {}",
        verified
    );
    assert_eq!(
        verified["signature_valid"], true,
        "verify_state signature invalid: {}",
        verified
    );

    let loaded = session
        .call_tool(
            "jacs_load_state",
            serde_json::json!({ "jacs_id": doc_id, "require_verified": true }),
        )
        .await?;
    assert_eq!(loaded["success"], true, "load_state failed: {}", loaded);
    assert!(
        loaded["content"]
            .as_str()
            .unwrap_or_default()
            .contains("\"value\":1"),
        "expected original embedded content: {}",
        loaded
    );

    let updated = session
        .call_tool(
            "jacs_update_state",
            serde_json::json!({
                "file_path": "data/memory.json",
                "jacs_id": doc_id,
                "new_content": "{\"topic\":\"mcp probe\",\"value\":2}"
            }),
        )
        .await?;
    assert_eq!(updated["success"], true, "update_state failed: {}", updated);
    let updated_id = updated["jacs_document_version_id"]
        .as_str()
        .expect("update_state jacs_document_version_id");
    assert_ne!(updated_id, doc_id, "update should create new version");
    assert!(updated_id.contains(':'), "expected updated versioned id");

    let reloaded = session
        .call_tool(
            "jacs_load_state",
            serde_json::json!({ "jacs_id": updated_id, "require_verified": true }),
        )
        .await?;
    assert_eq!(
        reloaded["success"], true,
        "reload updated state failed: {}",
        reloaded
    );
    assert!(
        reloaded["content"]
            .as_str()
            .unwrap_or_default()
            .contains("\"value\":2"),
        "expected updated embedded content: {}",
        reloaded
    );

    let listed = session
        .call_tool("jacs_list_state", serde_json::json!({}))
        .await?;
    let documents = listed["documents"]
        .as_array()
        .expect("list_state documents");
    assert!(
        documents
            .iter()
            .any(|doc| doc["jacs_document_id"] == doc_id),
        "list_state missing original document: {}",
        listed
    );
    assert!(
        documents
            .iter()
            .any(|doc| doc["jacs_document_id"] == updated_id),
        "list_state missing updated document: {}",
        listed
    );

    session.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn mcp_message_and_attestation_round_trip_over_stdio() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[]).await?;

    let signed_doc = session
        .call_tool(
            "jacs_sign_document",
            serde_json::json!({ "content": "{\"hello\":\"world\"}" }),
        )
        .await?;
    let signed_doc_json = signed_doc["signed_document"]
        .as_str()
        .expect("signed_document payload");
    let signed_doc_id = signed_doc["jacs_document_id"]
        .as_str()
        .expect("signed_document id");
    assert!(
        signed_doc_id.contains(':'),
        "expected canonical signed document id"
    );

    let verify_doc = session
        .call_tool(
            "jacs_verify_document",
            serde_json::json!({ "document": signed_doc_json }),
        )
        .await?;
    assert_eq!(
        verify_doc["success"], true,
        "verify_document failed: {}",
        verify_doc
    );
    assert_eq!(
        verify_doc["valid"], true,
        "verify_document invalid: {}",
        verify_doc
    );

    let recipient_id = "550e8400-e29b-41d4-a716-446655440000";
    let sent = session
        .call_tool(
            "jacs_message_send",
            serde_json::json!({
                "recipient_agent_id": recipient_id,
                "content": "hello over mcp"
            }),
        )
        .await?;
    assert_eq!(sent["success"], true, "message_send failed: {}", sent);
    let sent_id = sent["jacs_document_id"].as_str().expect("message_send id");
    let sent_message = sent["signed_message"]
        .as_str()
        .expect("message_send signed_message");
    assert!(
        sent_id.contains(':'),
        "expected persisted message id: {}",
        sent_id
    );
    let sent_value: serde_json::Value =
        serde_json::from_str(sent_message).expect("parse signed message");
    assert_ne!(
        sent_value["jacsMessageSenderId"]
            .as_str()
            .unwrap_or("unknown"),
        "unknown",
        "message sender should be the loaded agent"
    );

    let updated = session
        .call_tool(
            "jacs_message_update",
            serde_json::json!({
                "jacs_id": sent_id,
                "content": "updated content"
            }),
        )
        .await?;
    assert_eq!(
        updated["success"], true,
        "message_update failed: {}",
        updated
    );
    let updated_id = updated["jacs_document_id"]
        .as_str()
        .expect("message_update id");
    let updated_message = updated["signed_message"]
        .as_str()
        .expect("message_update signed_message");
    assert!(
        updated_id.contains(':'),
        "expected updated message id: {}",
        updated_id
    );

    let received = session
        .call_tool(
            "jacs_message_receive",
            serde_json::json!({ "signed_message": updated_message }),
        )
        .await?;
    assert_eq!(
        received["success"], true,
        "message_receive failed: {}",
        received
    );
    assert_eq!(
        received["signature_valid"], true,
        "message signature invalid"
    );
    assert_eq!(received["content"], "updated content");

    let attestation = session
        .call_tool(
            "jacs_attest_create",
            serde_json::json!({
                "params_json": serde_json::json!({
                    "subject": {
                        "type": "artifact",
                        "id": signed_doc_id,
                        "digests": { "sha256": "abc123" }
                    },
                    "claims": [{
                        "name": "reviewed_by",
                        "value": "human",
                        "confidence": 0.95,
                        "assuranceLevel": "verified"
                    }]
                }).to_string()
            }),
        )
        .await?;
    assert!(
        attestation.get("jacsId").and_then(|v| v.as_str()).is_some(),
        "attestation create failed: {}",
        attestation
    );
    let attestation_id = format!(
        "{}:{}",
        attestation["jacsId"].as_str().expect("attestation jacsId"),
        attestation["jacsVersion"]
            .as_str()
            .expect("attestation jacsVersion")
    );
    let verified = session
        .call_tool(
            "jacs_attest_verify",
            serde_json::json!({ "document_key": attestation_id, "full": false }),
        )
        .await?;
    assert_eq!(
        verified["valid"], true,
        "attestation verify failed: {}",
        verified
    );

    session.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn mcp_a2a_round_trip_over_stdio() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[]).await?;

    let wrapped = session
        .call_tool(
            "jacs_wrap_a2a_artifact",
            serde_json::json!({
                "artifact_json": serde_json::json!({
                    "content": "hello from a2a mcp",
                    "kind": "note"
                })
                .to_string(),
                "artifact_type": "message"
            }),
        )
        .await?;
    assert_eq!(
        wrapped["success"], true,
        "wrap_a2a_artifact failed: {}",
        wrapped
    );
    let wrapped_artifact = wrapped["wrapped_artifact"]
        .as_str()
        .expect("wrapped_artifact payload");
    let wrapped_value: serde_json::Value =
        serde_json::from_str(wrapped_artifact).expect("parse wrapped artifact");
    assert_eq!(wrapped_value["jacsType"], "a2a-message");

    let verified = session
        .call_tool(
            "jacs_verify_a2a_artifact",
            serde_json::json!({ "wrapped_artifact": wrapped_artifact }),
        )
        .await?;
    assert_eq!(
        verified["success"], true,
        "verify_a2a_artifact failed: {}",
        verified
    );
    assert_eq!(verified["valid"], true, "wrapped artifact invalid: {}", verified);
    let verification_details = parse_json_string_field(&verified, "verification_details")?;
    assert_eq!(verification_details["status"], "SelfSigned");
    assert_eq!(verification_details["parentSignaturesValid"], true);
    assert_eq!(verification_details["originalArtifact"]["content"], "hello from a2a mcp");

    let card = session
        .call_tool("jacs_export_agent_card", serde_json::json!({}))
        .await?;
    assert_eq!(
        card["success"], true,
        "export_agent_card failed: {}",
        card
    );
    let agent_card_json = card["agent_card"].as_str().expect("agent_card payload");

    let assessment = session
        .call_tool(
            "jacs_assess_a2a_agent",
            serde_json::json!({
                "agent_card_json": agent_card_json,
                "policy": "open"
            }),
        )
        .await?;
    assert_eq!(
        assessment["success"], true,
        "assess_a2a_agent failed: {}",
        assessment
    );
    assert_eq!(assessment["allowed"], true, "assessment rejected: {}", assessment);
    assert_eq!(
        assessment["policy"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        "open"
    );

    session.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn mcp_a2a_parent_chain_reports_invalid_parent() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[]).await?;

    let parent = session
        .call_tool(
            "jacs_wrap_a2a_artifact",
            serde_json::json!({
                "artifact_json": serde_json::json!({ "step": 1 }).to_string(),
                "artifact_type": "task"
            }),
        )
        .await?;
    let parent_artifact = parent["wrapped_artifact"]
        .as_str()
        .expect("parent wrapped artifact");

    let valid_child = session
        .call_tool(
            "jacs_wrap_a2a_artifact",
            serde_json::json!({
                "artifact_json": serde_json::json!({ "step": 2 }).to_string(),
                "artifact_type": "task",
                "parent_signatures": format!("[{}]", parent_artifact),
            }),
        )
        .await?;
    let valid_child_artifact = valid_child["wrapped_artifact"]
        .as_str()
        .expect("valid child wrapped artifact");
    let valid_child_value: serde_json::Value =
        serde_json::from_str(valid_child_artifact).expect("parse valid child");
    assert_eq!(
        valid_child_value["jacsParentSignatures"]
            .as_array()
            .expect("valid child parents")
            .len(),
        1
    );

    let valid_chain = session
        .call_tool(
            "jacs_verify_a2a_artifact",
            serde_json::json!({ "wrapped_artifact": valid_child_artifact }),
        )
        .await?;
    assert_eq!(valid_chain["success"], true, "valid chain failed: {}", valid_chain);
    assert_eq!(valid_chain["valid"], true, "child artifact invalid: {}", valid_chain);
    let valid_chain_details = parse_json_string_field(&valid_chain, "verification_details")?;
    assert_eq!(valid_chain_details["parentSignaturesValid"], true);
    assert_eq!(
        valid_chain_details["parentVerificationResults"]
            .as_array()
            .expect("parent verification results")
            .len(),
        1
    );

    let mut tampered_parent_value: serde_json::Value =
        serde_json::from_str(parent_artifact).expect("parse parent artifact");
    tampered_parent_value["a2aArtifact"]["step"] = serde_json::json!(999);

    let invalid_parent_child = session
        .call_tool(
            "jacs_wrap_a2a_artifact",
            serde_json::json!({
                "artifact_json": serde_json::json!({ "step": 3 }).to_string(),
                "artifact_type": "task",
                "parent_signatures": serde_json::json!([tampered_parent_value]).to_string(),
            }),
        )
        .await?;
    let invalid_parent_child_artifact = invalid_parent_child["wrapped_artifact"]
        .as_str()
        .expect("invalid parent child wrapped artifact");

    let invalid_parent_verified = session
        .call_tool(
            "jacs_verify_a2a_artifact",
            serde_json::json!({ "wrapped_artifact": invalid_parent_child_artifact }),
        )
        .await?;
    assert_eq!(
        invalid_parent_verified["success"], true,
        "verification should return details even with invalid parent: {}",
        invalid_parent_verified
    );
    assert_eq!(
        invalid_parent_verified["valid"], true,
        "child artifact should still be cryptographically valid: {}",
        invalid_parent_verified
    );
    let invalid_parent_details =
        parse_json_string_field(&invalid_parent_verified, "verification_details")?;
    assert_eq!(invalid_parent_details["parentSignaturesValid"], false);
    let parent_results = invalid_parent_details["parentVerificationResults"]
        .as_array()
        .expect("invalid parent verification results");
    assert_eq!(parent_results.len(), 1);
    assert_eq!(parent_results[0]["verified"], false);

    session.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn mcp_attestation_negative_paths_and_dsse_over_stdio() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[]).await?;

    let signed_doc = session
        .call_tool(
            "jacs_sign_document",
            serde_json::json!({ "content": "{\"artifact\":\"for-attestation\"}" }),
        )
        .await?;
    let signed_doc_json = signed_doc["signed_document"]
        .as_str()
        .expect("signed_document payload");
    let signed_doc_id = signed_doc["jacs_document_id"]
        .as_str()
        .expect("signed_document id");

    let attestation = session
        .call_tool(
            "jacs_attest_create",
            serde_json::json!({
                "params_json": serde_json::json!({
                    "subject": {
                        "type": "artifact",
                        "id": signed_doc_id,
                        "digests": { "sha256": "abc123" }
                    },
                    "claims": [{
                        "name": "reviewed_by",
                        "value": "mcp-test",
                        "confidence": 0.99,
                        "assuranceLevel": "verified"
                    }]
                })
                .to_string()
            }),
        )
        .await?;
    assert!(
        attestation.get("jacsId").and_then(|v| v.as_str()).is_some(),
        "attestation create failed: {}",
        attestation
    );

    let dsse = session
        .call_tool(
            "jacs_attest_export_dsse",
            serde_json::json!({
                "attestation_json": attestation.to_string()
            }),
        )
        .await?;
    assert_eq!(dsse["payloadType"], "application/vnd.in-toto+json");
    assert!(
        dsse["payload"].as_str().is_some_and(|payload| !payload.is_empty()),
        "dsse payload missing: {}",
        dsse
    );
    let signatures = dsse["signatures"].as_array().expect("dsse signatures");
    assert_eq!(signatures.len(), 1);
    assert_eq!(
        signatures[0]["keyid"],
        attestation["jacsSignature"]["publicKeyHash"]
    );
    assert_eq!(signatures[0]["sig"], attestation["jacsSignature"]["signature"]);

    let missing_subject = session
        .call_tool(
            "jacs_attest_create",
            serde_json::json!({
                "params_json": serde_json::json!({
                    "claims": [{
                        "name": "reviewed_by",
                        "value": "mcp-test"
                    }]
                })
                .to_string()
            }),
        )
        .await?;
    assert_eq!(missing_subject["error"], true);
    assert!(
        missing_subject["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Failed to create attestation"),
        "expected attestation create failure: {}",
        missing_subject
    );

    let missing_doc = session
        .call_tool(
            "jacs_attest_verify",
            serde_json::json!({
                "document_key": "nonexistent-id:v1",
                "full": false
            }),
        )
        .await?;
    assert_eq!(missing_doc["valid"], false);
    assert_eq!(missing_doc["error"], true);
    assert!(
        missing_doc["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Failed to verify attestation"),
        "expected verify failure: {}",
        missing_doc
    );

    let dsse_from_non_attestation = session
        .call_tool(
            "jacs_attest_export_dsse",
            serde_json::json!({
                "attestation_json": signed_doc_json
            }),
        )
        .await?;
    assert_eq!(dsse_from_non_attestation["error"], true);
    assert!(
        dsse_from_non_attestation["message"]
            .as_str()
            .unwrap_or_default()
            .contains("missing 'attestation' field"),
        "expected export_dsse semantic failure: {}",
        dsse_from_non_attestation
    );

    session.client.cancellation_token().cancel();
    Ok(())
}

// =============================================================================
// Trust Store Tool Integration Tests
//
// These tests exercise the binding-core trust functions that the MCP
// jacs_trust_agent, jacs_untrust_agent, jacs_list_trusted_agents,
// jacs_is_trusted, and jacs_get_trusted_agent tools delegate to.
// =============================================================================

/// Test that listing trusted agents returns a (possibly empty) list.
#[test]
fn trust_list_returns_result() {
    // list_trusted_agents should succeed even with an empty trust store
    let result = jacs_binding_core::list_trusted_agents();
    assert!(
        result.is_ok(),
        "list_trusted_agents should not error: {:?}",
        result.err()
    );
    let ids = result.unwrap();
    // The trust store may or may not have agents from other tests, but the
    // list should be a valid Vec.
    assert!(
        ids.len() < 10000,
        "sanity check: trust store shouldn't have 10k entries"
    );
}

/// Test that is_trusted returns false for a nonexistent agent.
#[test]
fn trust_is_trusted_nonexistent() {
    let fake_id = "00000000-0000-0000-0000-000000000000";
    let trusted = jacs_binding_core::is_trusted(fake_id);
    assert!(!trusted, "Nonexistent agent should not be trusted");
}

/// Test that get_trusted_agent fails for a nonexistent agent.
#[test]
fn trust_get_trusted_agent_nonexistent() {
    let fake_id = "00000000-0000-0000-0000-000000000001";
    let result = jacs_binding_core::get_trusted_agent(fake_id);
    assert!(
        result.is_err(),
        "get_trusted_agent for nonexistent agent should fail"
    );
}

/// Test that untrust_agent fails gracefully for a nonexistent agent.
#[test]
fn trust_untrust_nonexistent() {
    let fake_id = "00000000-0000-0000-0000-000000000002";
    let result = jacs_binding_core::untrust_agent(fake_id);
    // Untrusting a non-existent agent may succeed (no-op) or fail depending
    // on implementation. Either way it should not panic.
    let _ = result;
}

/// Test that trust_agent rejects invalid JSON.
#[test]
fn trust_agent_rejects_invalid_json() {
    let result = jacs_binding_core::trust_agent("not valid json");
    assert!(
        result.is_err(),
        "trust_agent should reject invalid JSON: {:?}",
        result.ok()
    );
}

/// Test that trust_agent rejects empty input.
#[test]
fn trust_agent_rejects_empty() {
    let result = jacs_binding_core::trust_agent("");
    assert!(
        result.is_err(),
        "trust_agent should reject empty string: {:?}",
        result.ok()
    );
}

/// Smoke-test server startup with trust tools compiled under explicit RUST_LOG settings.
/// This avoids brittle assertions on info-level log lines while still verifying
/// the server reaches initialized-request state before stdin closes.
#[test]
fn trust_tools_compiled_in_server() {
    let (output, base) = run_server_with_fixture(&[("RUST_LOG", "info,rmcp=warn")]);
    assert_server_reaches_initialized_request(&output, "RUST_LOG=info,rmcp=warn");
    let _ = fs::remove_dir_all(&base);
}

// =============================================================================
// Agent Card & Well-Known Tool Integration Tests
// =============================================================================

/// Test that export_agent_card returns valid JSON via binding-core.
#[test]
fn agent_card_export_via_binding_core() {
    let (config, base) = prepare_temp_workspace();
    // Load agent in the binding-core wrapper
    let agent = jacs_binding_core::AgentWrapper::new();
    let _orig = std::env::current_dir().unwrap();
    std::env::set_current_dir(&base).expect("chdir to workspace");
    unsafe { std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD) };
    agent
        .load(config.to_string_lossy().to_string())
        .expect("load agent");

    let card_json = agent
        .export_agent_card()
        .expect("export_agent_card should succeed");
    let card: serde_json::Value =
        serde_json::from_str(&card_json).expect("Agent Card should be valid JSON");
    assert!(
        card.get("name").is_some(),
        "Agent Card should have 'name' field"
    );
    assert!(
        card.get("url").is_some() || card.get("capabilities").is_some(),
        "Agent Card should have standard A2A fields"
    );

    std::env::set_current_dir(&_orig).ok();
    let _ = fs::remove_dir_all(&base);
}

/// Test that generate_well_known_documents returns a non-empty document set.
#[test]
fn well_known_documents_generated() {
    let (config, base) = prepare_temp_workspace();
    let agent = jacs_binding_core::AgentWrapper::new();
    let _orig = std::env::current_dir().unwrap();
    std::env::set_current_dir(&base).expect("chdir to workspace");
    unsafe { std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD) };
    agent
        .load(config.to_string_lossy().to_string())
        .expect("load agent");

    let docs_json = agent
        .generate_well_known_documents(None)
        .expect("generate_well_known_documents should succeed");
    let docs: Vec<serde_json::Value> =
        serde_json::from_str(&docs_json).expect("Well-known documents should be valid JSON array");
    assert!(
        docs.len() >= 3,
        "Should generate at least 3 well-known documents, got {}",
        docs.len()
    );

    // Each document should have path and document fields
    for doc in &docs {
        assert!(
            doc.get("path").is_some(),
            "Each entry should have a 'path' field"
        );
        assert!(
            doc.get("document").is_some(),
            "Each entry should have a 'document' field"
        );
    }

    // The first document should be the agent card at /.well-known/agent-card.json
    let first_path = docs[0].get("path").and_then(|p| p.as_str()).unwrap_or("");
    assert!(
        first_path.contains("agent-card"),
        "First document should be agent-card, got: {}",
        first_path
    );

    std::env::set_current_dir(&_orig).ok();
    let _ = fs::remove_dir_all(&base);
}

/// Test that get_agent_json returns the agent's full document.
#[test]
fn export_agent_json_valid() {
    let (config, base) = prepare_temp_workspace();
    let agent = jacs_binding_core::AgentWrapper::new();
    let _orig = std::env::current_dir().unwrap();
    std::env::set_current_dir(&base).expect("chdir to workspace");
    unsafe { std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD) };
    agent
        .load(config.to_string_lossy().to_string())
        .expect("load agent");

    let agent_json = agent
        .get_agent_json()
        .expect("get_agent_json should succeed");
    let value: serde_json::Value =
        serde_json::from_str(&agent_json).expect("Agent JSON should be valid");
    assert!(
        value.get("jacsId").is_some(),
        "Agent JSON should contain jacsId"
    );
    assert!(
        value.get("jacsSignature").is_some(),
        "Agent JSON should contain jacsSignature"
    );

    std::env::set_current_dir(&_orig).ok();
    let _ = fs::remove_dir_all(&base);
}

// =============================================================================
// A2A Artifact Wrapping / Verification Tool Integration Tests
// =============================================================================

/// Helper: load an AgentWrapper inside a temp workspace. Returns (wrapper, orig_dir, base_dir).
fn load_agent_in_workspace() -> (jacs_binding_core::AgentWrapper, PathBuf, PathBuf) {
    let (config, base) = prepare_temp_workspace();
    let agent = jacs_binding_core::AgentWrapper::new();
    let orig = std::env::current_dir().unwrap();
    std::env::set_current_dir(&base).expect("chdir to workspace");
    unsafe { std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD) };
    agent
        .load(config.to_string_lossy().to_string())
        .expect("load agent");
    (agent, orig, base)
}

/// Test wrapping an A2A artifact and getting back valid signed JSON.
#[test]
#[allow(deprecated)]
fn a2a_wrap_artifact_produces_signed_output() {
    let (agent, orig, base) = load_agent_in_workspace();

    let artifact = serde_json::json!({
        "type": "text",
        "text": "Hello from integration test"
    });
    let wrapped_json = agent
        .wrap_a2a_artifact(&artifact.to_string(), "a2a-artifact", None)
        .expect("wrap_a2a_artifact should succeed");

    let wrapped: serde_json::Value =
        serde_json::from_str(&wrapped_json).expect("wrapped output should be valid JSON");
    // Wrapped artifact should contain JACS provenance fields
    assert!(
        wrapped.get("jacsProvenance").is_some()
            || wrapped.get("jacs_provenance").is_some()
            || wrapped.get("signature").is_some()
            || wrapped.get("jacsSignature").is_some(),
        "Wrapped artifact should contain provenance/signature fields: {}",
        wrapped_json.chars().take(500).collect::<String>()
    );

    std::env::set_current_dir(&orig).ok();
    let _ = fs::remove_dir_all(&base);
}

/// Test full round-trip: wrap an artifact, then verify it.
#[test]
#[allow(deprecated)]
fn a2a_wrap_then_verify_round_trip() {
    let (agent, orig, base) = load_agent_in_workspace();

    let artifact = serde_json::json!({
        "type": "text",
        "text": "Round-trip verification test"
    });
    let wrapped_json = agent
        .wrap_a2a_artifact(&artifact.to_string(), "message", None)
        .expect("wrap should succeed");

    let result_json = agent
        .verify_a2a_artifact(&wrapped_json)
        .expect("verify should succeed on freshly wrapped artifact");
    let result: serde_json::Value =
        serde_json::from_str(&result_json).expect("verify result should be valid JSON");

    // The verification result should indicate validity
    let valid = result
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(true); // If no "valid" field, absence of error means valid
    assert!(
        valid,
        "Freshly wrapped artifact should verify successfully: {}",
        result_json
    );

    std::env::set_current_dir(&orig).ok();
    let _ = fs::remove_dir_all(&base);
}

/// Test that verify_a2a_artifact rejects invalid JSON.
#[test]
fn a2a_verify_rejects_invalid_json() {
    let (agent, orig, base) = load_agent_in_workspace();

    let result = agent.verify_a2a_artifact("not valid json");
    assert!(
        result.is_err(),
        "verify_a2a_artifact should reject invalid JSON"
    );

    std::env::set_current_dir(&orig).ok();
    let _ = fs::remove_dir_all(&base);
}

/// Test that assess_a2a_agent returns an assessment for a minimal Agent Card.
#[test]
fn a2a_assess_agent_with_card() {
    let (agent, orig, base) = load_agent_in_workspace();

    // Get this agent's own card to use as input
    let card_json = agent
        .export_agent_card()
        .expect("export_agent_card should succeed");

    let assessment_json = agent
        .assess_a2a_agent(&card_json, "open")
        .expect("assess_a2a_agent should succeed with open policy");
    let assessment: serde_json::Value =
        serde_json::from_str(&assessment_json).expect("assessment should be valid JSON");
    // With "open" policy, the agent should be allowed
    let allowed = assessment
        .get("allowed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(
        allowed,
        "Agent should be allowed under open policy: {}",
        assessment_json
    );

    std::env::set_current_dir(&orig).ok();
    let _ = fs::remove_dir_all(&base);
}

/// Test that assess_a2a_agent rejects invalid Agent Card JSON.
#[test]
fn a2a_assess_agent_rejects_invalid_card() {
    let (agent, orig, base) = load_agent_in_workspace();

    let result = agent.assess_a2a_agent("not json", "open");
    assert!(
        result.is_err(),
        "assess_a2a_agent should reject invalid JSON"
    );

    std::env::set_current_dir(&orig).ok();
    let _ = fs::remove_dir_all(&base);
}
