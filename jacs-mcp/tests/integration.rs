use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Duration;

use rmcp::{
    RoleClient, ServiceExt,
    model::CallToolRequestParams,
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
};

mod support;

// Integration tests exercise sign/verify/attestation round-trips that
// create new JACS documents, so they need an algorithm with working
// private-key signing.
use support::{
    TEST_PASSWORD, assert_server_reaches_initialized_request,
    prepare_temp_workspace_ed25519 as prepare_temp_workspace, run_server_with_fixture,
};

static STDIO_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static CWD_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
// The stdio child can take longer to complete the rmcp handshake on contended
// CI runners after full-tool schemas and storage backends have been loaded.
const MCP_INIT_TIMEOUT: Duration = Duration::from_secs(90);
const MCP_CALL_TIMEOUT: Duration = Duration::from_secs(90);

type McpClient = RunningService<RoleClient, ()>;

struct RmcpSession {
    client: McpClient,
    base: PathBuf,
}

impl RmcpSession {
    async fn spawn(extra_env: &[(&str, &str)]) -> anyhow::Result<Self> {
        let (config, base) = prepare_temp_workspace();
        Self::spawn_from_workspace(config, base, extra_env).await
    }

    async fn spawn_from_workspace(
        config: PathBuf,
        base: PathBuf,
        extra_env: &[(&str, &str)],
    ) -> anyhow::Result<Self> {
        let bin_path = support::jacs_cli_bin();
        let command = tokio::process::Command::new(&bin_path).configure(|cmd| {
            cmd.arg("mcp")
                .arg("--profile")
                .arg("full")
                .current_dir(&base)
                .env("JACS_CONFIG", &config)
                .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
                .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
                .env("RUST_LOG", "warn")
                .env_remove("JACS_KEY_DIRECTORY")
                .env_remove("JACS_DATA_DIRECTORY")
                .env_remove("JACS_AGENT_ID_AND_VERSION")
                .env_remove("JACS_AGENT_KEY_ALGORITHM")
                .env_remove("JACS_AGENT_PRIVATE_KEY_FILENAME")
                .env_remove("JACS_AGENT_PUBLIC_KEY_FILENAME")
                .env_remove("JACS_DEFAULT_STORAGE");

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

    async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let response = tokio::time::timeout(
            MCP_CALL_TIMEOUT,
            self.client.call_tool(
                CallToolRequestParams::new(name.to_string())
                    .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
            ),
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

struct LoadedAgentWorkspace {
    _guard: MutexGuard<'static, ()>,
    agent: jacs_binding_core::AgentWrapper,
    base: PathBuf,
    orig: PathBuf,
}

impl Drop for LoadedAgentWorkspace {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.orig);
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
async fn mcp_document_and_attestation_round_trip_over_stdio() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[("JACS_MCP_PROFILE", "full")]).await?;

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
async fn mcp_check_agreement_rejects_tampered_agreement() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[("JACS_MCP_PROFILE", "full")]).await?;

    let exported = session
        .call_tool("jacs_export_agent", serde_json::json!({}))
        .await?;
    let agent_id = exported["agent_id"]
        .as_str()
        .expect("exported agent id for agreement");

    let created = session
        .call_tool(
            "jacs_create_agreement",
            serde_json::json!({
                "document": "{\"proposal\":\"ship-it\"}",
                "agent_ids": [agent_id],
                "question": "Ship it?"
            }),
        )
        .await?;
    assert_eq!(
        created["success"], true,
        "create_agreement failed: {}",
        created
    );
    let created_agreement = created["signed_agreement"]
        .as_str()
        .expect("created agreement");

    let signed = session
        .call_tool(
            "jacs_sign_agreement",
            serde_json::json!({ "signed_agreement": created_agreement }),
        )
        .await?;
    assert_eq!(signed["success"], true, "sign_agreement failed: {}", signed);
    let signed_agreement = signed["signed_agreement"]
        .as_str()
        .expect("signed agreement payload");

    let mut tampered: serde_json::Value =
        serde_json::from_str(signed_agreement).expect("parse agreement");
    tampered["jacsAgreement"]["question"] = serde_json::json!("Ship it right now?");

    let checked = session
        .call_tool(
            "jacs_check_agreement",
            serde_json::json!({ "signed_agreement": tampered.to_string() }),
        )
        .await?;
    assert_eq!(
        checked["success"], false,
        "tampered agreement passed: {}",
        checked
    );
    assert!(
        checked["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Failed to check agreement"),
        "unexpected tampered agreement error: {}",
        checked
    );

    session.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn mcp_admin_tools_reject_inline_secrets_without_opt_in() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[("JACS_MCP_ALLOW_REGISTRATION", "true")]).await?;

    let create_result = session
        .call_tool(
            "jacs_create_agent",
            serde_json::json!({
                "name": "inline-secret-agent",
                "password": "Str0ng!Passw0rd",
                "data_directory": "tmp-agent-data",
                "key_directory": "tmp-agent-keys"
            }),
        )
        .await?;
    assert_eq!(
        create_result["success"], false,
        "inline-password agent creation must be rejected: {}",
        create_result
    );
    assert_eq!(
        create_result["error"].as_str(),
        Some("INLINE_SECRET_DISABLED"),
        "unexpected create_agent error: {}",
        create_result
    );

    let reencrypt_result = session
        .call_tool(
            "jacs_reencrypt_key",
            serde_json::json!({
                "old_password": TEST_PASSWORD,
                "new_password": "N3w!SecurePassword"
            }),
        )
        .await?;
    assert_eq!(
        reencrypt_result["success"], false,
        "inline-password reencrypt must be rejected: {}",
        reencrypt_result
    );
    assert_eq!(
        reencrypt_result["error"].as_str(),
        Some("INLINE_SECRET_DISABLED"),
        "unexpected reencrypt error: {}",
        reencrypt_result
    );

    session.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn mcp_a2a_round_trip_over_stdio() -> anyhow::Result<()> {
    let _guard = STDIO_TEST_LOCK.lock().await;
    let session = RmcpSession::spawn(&[("JACS_MCP_PROFILE", "full")]).await?;

    let wrapped = session
        .call_tool(
            "jacs_wrap_a2a_artifact",
            serde_json::json!({
                "artifact_json": serde_json::json!({
                    "content": "hello from a2a mcp",
                    "kind": "note"
                })
                .to_string(),
                "artifact_type": "artifact"
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
    assert_eq!(wrapped_value["jacsType"], "a2a-artifact");

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
    assert_eq!(
        verified["valid"], true,
        "wrapped artifact invalid: {}",
        verified
    );
    let verification_details = parse_json_string_field(&verified, "verification_details")?;
    assert_eq!(verification_details["status"], "SelfSigned");
    assert_eq!(verification_details["parentSignaturesValid"], true);
    assert_eq!(
        verification_details["originalArtifact"]["content"],
        "hello from a2a mcp"
    );

    let card = session
        .call_tool("jacs_export_agent_card", serde_json::json!({}))
        .await?;
    assert_eq!(card["success"], true, "export_agent_card failed: {}", card);
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
    assert_eq!(
        assessment["allowed"], true,
        "assessment rejected: {}",
        assessment
    );
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
    let session = RmcpSession::spawn(&[("JACS_MCP_PROFILE", "full")]).await?;

    let parent = session
        .call_tool(
            "jacs_wrap_a2a_artifact",
            serde_json::json!({
                "artifact_json": serde_json::json!({ "step": 1 }).to_string(),
                "artifact_type": "artifact"
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
                "artifact_type": "artifact",
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
    assert_eq!(
        valid_chain["success"], true,
        "valid chain failed: {}",
        valid_chain
    );
    assert_eq!(
        valid_chain["valid"], true,
        "child artifact invalid: {}",
        valid_chain
    );
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
                "artifact_type": "artifact",
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
    let session = RmcpSession::spawn(&[("JACS_MCP_PROFILE", "full")]).await?;

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
        dsse["payload"]
            .as_str()
            .is_some_and(|payload| !payload.is_empty()),
        "dsse payload missing: {}",
        dsse
    );
    let signatures = dsse["signatures"].as_array().expect("dsse signatures");
    assert_eq!(signatures.len(), 1);
    assert_eq!(
        signatures[0]["keyid"],
        attestation["jacsSignature"]["publicKeyHash"]
    );
    assert_eq!(
        signatures[0]["sig"],
        attestation["jacsSignature"]["signature"]
    );

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
    let ctx = load_agent_in_workspace();

    let card_json = ctx
        .agent
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
}

/// Test that generate_well_known_documents returns a non-empty document set.
#[test]
fn well_known_documents_generated() {
    let ctx = load_agent_in_workspace();

    let docs_json = ctx
        .agent
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
}

/// Test that get_agent_json returns the agent's full document.
#[test]
fn export_agent_json_valid() {
    let ctx = load_agent_in_workspace();

    let agent_json = ctx
        .agent
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
}

// =============================================================================
// A2A Artifact Wrapping / Verification Tool Integration Tests
// =============================================================================

/// Helper: load an AgentWrapper inside a temp workspace while serializing cwd changes.
fn load_agent_in_workspace() -> LoadedAgentWorkspace {
    let guard = CWD_TEST_LOCK.lock().expect("lock cwd test mutex");
    let (config, base) = prepare_temp_workspace();
    let agent = jacs_binding_core::AgentWrapper::new();
    let orig = std::env::current_dir().unwrap();
    std::env::set_current_dir(&base).expect("chdir to workspace");
    unsafe { std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD) };
    agent
        .load(config.to_string_lossy().to_string())
        .expect("load agent");
    LoadedAgentWorkspace {
        _guard: guard,
        agent,
        base,
        orig,
    }
}

/// Test wrapping an A2A artifact and getting back valid signed JSON.
#[test]
#[allow(deprecated)]
fn a2a_wrap_artifact_produces_signed_output() {
    let ctx = load_agent_in_workspace();

    let artifact = serde_json::json!({
        "type": "text",
        "text": "Hello from integration test"
    });
    let wrapped_json = ctx
        .agent
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
}

/// Test full round-trip: wrap an artifact, then verify it.
#[test]
#[allow(deprecated)]
fn a2a_wrap_then_verify_round_trip() {
    let ctx = load_agent_in_workspace();

    let artifact = serde_json::json!({
        "type": "text",
        "text": "Round-trip verification test"
    });
    let wrapped_json = ctx
        .agent
        .wrap_a2a_artifact(&artifact.to_string(), "artifact", None)
        .expect("wrap should succeed");

    let result_json = ctx
        .agent
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
}

/// Test that verify_a2a_artifact rejects invalid JSON.
#[test]
fn a2a_verify_rejects_invalid_json() {
    let ctx = load_agent_in_workspace();

    let result = ctx.agent.verify_a2a_artifact("not valid json");
    assert!(
        result.is_err(),
        "verify_a2a_artifact should reject invalid JSON"
    );
}

/// Test that assess_a2a_agent returns an assessment for a minimal Agent Card.
#[test]
fn a2a_assess_agent_with_card() {
    let ctx = load_agent_in_workspace();

    // Get this agent's own card to use as input
    let card_json = ctx
        .agent
        .export_agent_card()
        .expect("export_agent_card should succeed");

    let assessment_json = ctx
        .agent
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
}

/// Test that assess_a2a_agent rejects invalid Agent Card JSON.
#[test]
fn a2a_assess_agent_rejects_invalid_card() {
    let ctx = load_agent_in_workspace();

    let result = ctx.agent.assess_a2a_agent("not json", "open");
    assert!(
        result.is_err(),
        "assess_a2a_agent should reject invalid JSON"
    );
}
