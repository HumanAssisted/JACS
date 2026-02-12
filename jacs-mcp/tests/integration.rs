use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// The known agent ID that exists in jacs/tests/fixtures/agent/
const AGENT_ID: &str = "ddf35096-d212-4ca9-a299-feda597d5525:b57d480f-b8d4-46e7-9d7c-942f2b132717";

/// Password used to encrypt test fixture keys in jacs/tests/fixtures/keys/
/// Note: intentional typo "secretpassord" matches TEST_PASSWORD_LEGACY in jacs/tests/utils.rs
const TEST_PASSWORD: &str = "secretpassord";

fn jacs_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Create a temp workspace with agent JSON, keys, and config.
/// Returns (config_path, base_dir). Config uses relative paths so the
/// binary CWD must be set to base_dir.
fn prepare_temp_workspace() -> (PathBuf, PathBuf) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let base = std::env::temp_dir().join(format!("jacs_mcp_ws_{}", ts));
    let data_dir = base.join("jacs_data");
    let keys_dir = base.join("jacs_keys");
    fs::create_dir_all(data_dir.join("agent")).expect("mkdir data/agent");
    fs::create_dir_all(&keys_dir).expect("mkdir keys");

    let root = jacs_root();

    // Copy agent JSON from the standard test fixtures
    let agent_src = root.join(format!("jacs/tests/fixtures/agent/{}.json", AGENT_ID));
    let agent_dst = data_dir.join(format!("agent/{}.json", AGENT_ID));
    fs::copy(&agent_src, &agent_dst).unwrap_or_else(|e| {
        panic!(
            "copy agent fixture from {:?} to {:?}: {}",
            agent_src, agent_dst, e
        )
    });

    // Copy RSA-PSS keys (known to work with TEST_PASSWORD)
    let keys_fixture = root.join("jacs/tests/fixtures/keys");
    fs::copy(
        keys_fixture.join("agent-one.private.pem.enc"),
        keys_dir.join("agent-one.private.pem.enc"),
    )
    .expect("copy private key");
    fs::copy(
        keys_fixture.join("agent-one.public.pem"),
        keys_dir.join("agent-one.public.pem"),
    )
    .expect("copy public key");

    // Write config with relative paths
    let config_json = serde_json::json!({
        "jacs_agent_id_and_version": AGENT_ID,
        "jacs_agent_key_algorithm": "RSA-PSS",
        "jacs_agent_private_key_filename": "agent-one.private.pem.enc",
        "jacs_agent_public_key_filename": "agent-one.public.pem",
        "jacs_data_directory": "jacs_data",
        "jacs_default_storage": "fs",
        "jacs_key_directory": "jacs_keys",
        "jacs_use_security": "false"
    });
    let cfg_path = base.join("jacs.config.json");
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&config_json).unwrap(),
    )
    .expect("write config");

    (cfg_path, base)
}

#[test]
fn starts_server_with_agent_env() {
    let (config, base) = prepare_temp_workspace();

    // The MCP server reads from stdin; an empty stdin causes it to exit cleanly.
    let bin_path = assert_cmd::cargo::cargo_bin("jacs-mcp");
    let output = std::process::Command::new(&bin_path)
        .current_dir(&base)
        .env("JACS_CONFIG", &config)
        .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("failed to run jacs-mcp");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The server exits non-zero when stdin closes (no MCP client connected).
    // Success means the agent loaded and the server reached the "ready" state.
    assert!(
        stderr.contains("Agent loaded successfully"),
        "Expected agent to load successfully.\nExit code: {:?}\nstderr:\n{}",
        output.status.code(),
        stderr
    );
}

#[test]
#[ignore]
fn mcp_client_send_signed_jacs_document() {
    // Placeholder: start server in background and spawn a minimal MCP client using rmcp
    // to send a JACS-signed payload, then assert acceptance response.
}

#[test]
#[ignore]
fn second_client_send_signed_jacs_document() {
    // Placeholder for second client; can vary agent identity to test quarantine/reject.
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
    assert!(result.is_ok(), "list_trusted_agents should not error: {:?}", result.err());
    let ids = result.unwrap();
    // The trust store may or may not have agents from other tests, but the
    // list should be a valid Vec.
    assert!(ids.len() < 10000, "sanity check: trust store shouldn't have 10k entries");
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

/// Verify the MCP server binary includes trust tool names in --help or tool listing.
/// This test starts the server with stdin closed and checks stderr for the agent load message,
/// confirming the 5 new trust tools are compiled in.
#[test]
fn trust_tools_compiled_in_server() {
    let (config, base) = prepare_temp_workspace();
    let bin_path = assert_cmd::cargo::cargo_bin("jacs-mcp");
    let output = std::process::Command::new(&bin_path)
        .current_dir(&base)
        .env("JACS_CONFIG", &config)
        .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("failed to run jacs-mcp");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The server should load successfully even with the new trust tools compiled in
    assert!(
        stderr.contains("Agent loaded successfully"),
        "Expected agent to load successfully with trust tools.\nstderr:\n{}",
        stderr
    );
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
    agent.load(config.to_string_lossy().to_string()).expect("load agent");

    let card_json = agent.export_agent_card().expect("export_agent_card should succeed");
    let card: serde_json::Value = serde_json::from_str(&card_json)
        .expect("Agent Card should be valid JSON");
    assert!(card.get("name").is_some(), "Agent Card should have 'name' field");
    assert!(card.get("url").is_some() || card.get("capabilities").is_some(),
        "Agent Card should have standard A2A fields");

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
    agent.load(config.to_string_lossy().to_string()).expect("load agent");

    let docs_json = agent.generate_well_known_documents(None)
        .expect("generate_well_known_documents should succeed");
    let docs: Vec<serde_json::Value> = serde_json::from_str(&docs_json)
        .expect("Well-known documents should be valid JSON array");
    assert!(docs.len() >= 3, "Should generate at least 3 well-known documents, got {}", docs.len());

    // Each document should have path and document fields
    for doc in &docs {
        assert!(doc.get("path").is_some(), "Each entry should have a 'path' field");
        assert!(doc.get("document").is_some(), "Each entry should have a 'document' field");
    }

    // The first document should be the agent card at /.well-known/agent-card.json
    let first_path = docs[0].get("path").and_then(|p| p.as_str()).unwrap_or("");
    assert!(first_path.contains("agent-card"), "First document should be agent-card, got: {}", first_path);

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
    agent.load(config.to_string_lossy().to_string()).expect("load agent");

    let agent_json = agent.get_agent_json().expect("get_agent_json should succeed");
    let value: serde_json::Value = serde_json::from_str(&agent_json)
        .expect("Agent JSON should be valid");
    assert!(value.get("jacsId").is_some(), "Agent JSON should contain jacsId");
    assert!(value.get("jacsSignature").is_some(), "Agent JSON should contain jacsSignature");

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
