use assert_cmd::Command;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn agent_fixture() -> PathBuf {
    // Use an existing agent fixture from the main jacs tests
    // This one resides under tests/fixtures/dns/jacs/agent/<uuid>:<uuid>.json
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    root.join("jacs/tests/fixtures/dns/jacs/agent/85058eed-81b0-4eb3-878e-c58e7902c4fd:6b2c5ddf-a07b-4e0a-af1b-b081f1b8cb32.json")
}

fn data_dir() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    root.join("jacs/tests/scratch/jacs_data")
}

fn config_fixture() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    root.join("jacs/tests/fixtures/dns/jacs.config.json")
}

fn abs_fixture_dir(rel: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    root.join(rel).to_string_lossy().to_string()
}

fn write_temp_config_with_abs_paths() -> PathBuf {
    let orig = fs::read_to_string(config_fixture()).expect("read fixture config");
    // Replace relative paths with absolute
    let data_abs = abs_fixture_dir("jacs/tests/fixtures/dns/jacs");
    let keys_abs = abs_fixture_dir("jacs/tests/fixtures/dns/jacs_keys");
    let modified = orig
        .replace(
            "\"jacs_data_directory\": \"./jacs\"",
            &format!("\"jacs_data_directory\": \"{}\"", data_abs),
        )
        .replace(
            "\"jacs_key_directory\": \"./jacs_keys\"",
            &format!("\"jacs_key_directory\": \"{}\"", keys_abs),
        );
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let out_path = std::env::temp_dir().join(format!("jacs_mcp_test_config_{}.json", ts));
    fs::write(&out_path, modified).expect("write temp config");
    out_path
}

fn prepare_temp_workspace(agent_path: &PathBuf) -> (PathBuf, PathBuf, PathBuf) {
    // Create temp data and keys directories, copy fixture agent and keys, and return (config, data_dir, keys_dir)
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let base = std::env::temp_dir().join(format!("jacs_mcp_ws_{}", ts));
    let data_dir = base.join("jacs_data");
    let keys_dir = base.join("jacs_keys");
    fs::create_dir_all(data_dir.join("agent")).expect("mkdir data/agent");
    fs::create_dir_all(&keys_dir).expect("mkdir keys");

    // Copy agent JSON
    let agent_filename = agent_path.file_name().unwrap();
    fs::copy(agent_path, data_dir.join("agent").join(agent_filename)).expect("copy agent json");

    // Copy keys from fixtures
    let keys_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("jacs/tests/fixtures/dns/jacs_keys");
    let priv_key = keys_fixture.join("jacs.private.pem.enc");
    let pub_key = keys_fixture.join("jacs.public.pem");
    fs::copy(priv_key, keys_dir.join("jacs.private.pem.enc")).expect("copy private key");
    fs::copy(pub_key, keys_dir.join("jacs.public.pem")).expect("copy public key");

    // Write config
    let id_and_version = agent_filename
        .to_string_lossy()
        .trim_end_matches(".json")
        .to_string();
    let config_json = serde_json::json!({
        "jacs_agent_domain": "hai.io",
        "jacs_agent_id_and_version": id_and_version,
        "jacs_agent_key_algorithm": "pq-dilithium",
        "jacs_agent_private_key_filename": "jacs.private.pem.enc",
        "jacs_agent_public_key_filename": "jacs.public.pem",
        "jacs_data_directory": data_dir.to_string_lossy(),
        "jacs_default_storage": "fs",
        "jacs_key_directory": keys_dir.to_string_lossy(),
        "jacs_private_key_password": "hello",
        "jacs_use_security": "false"
    });
    let cfg_path = base.join("jacs.config.json");
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&config_json).unwrap(),
    )
    .expect("write cfg");
    (cfg_path, data_dir, keys_dir)
}

#[test]
fn starts_server_with_agent_env() {
    let agent = agent_fixture();
    let (config, data, _keys) = prepare_temp_workspace(&agent);
    let mut cmd = Command::cargo_bin("jacs-mcp").expect("binary built");
    cmd.env("JACS_AGENT_FILE", agent);
    cmd.env("JACS_DATA_DIRECTORY", data);
    cmd.env("JACS_CONFIG", config);
    cmd.assert().success();
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
