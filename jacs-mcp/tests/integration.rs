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
