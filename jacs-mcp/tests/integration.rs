use assert_cmd::Command;
use std::path::PathBuf;

fn agent_fixture() -> PathBuf {
    // Use an existing agent fixture from the main jacs tests
    // This one resides under tests/fixtures/dns/jacs/agent/<uuid>:<uuid>.json
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    root.join("jacs/tests/fixtures/dns/jacs/agent/85058eed-81b0-4eb3-878e-c58e7902c4fd:6b2c5ddf-a07b-4e0a-af1b-b081f1b8cb32.json")
}

#[test]
fn starts_server_with_agent_env() {
    let agent = agent_fixture();
    // Just assert binary starts and exits cleanly (it currently initializes and exits)
    let mut cmd = Command::cargo_bin("jacs-mcp").expect("binary built");
    cmd.env("JACS_AGENT_FILE", agent);
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


