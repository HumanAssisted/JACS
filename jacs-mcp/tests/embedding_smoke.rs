#![cfg(feature = "mcp")]

mod support;

use rmcp::ServerHandler;
use support::{ENV_LOCK, ScopedEnvVar, TEST_PASSWORD, cleanup_workspace, prepare_temp_workspace};

#[test]
fn embedders_can_construct_server_in_process() -> anyhow::Result<()> {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let (config_path, workspace) = prepare_temp_workspace();
    let _password = ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);

    let agent = jacs_mcp::load_agent_from_config_path(&config_path)?;
    let server = jacs_mcp::JacsMcpServer::new(agent);
    let info = server.get_info();
    let tools = jacs_mcp::JacsMcpServer::tools();

    assert_eq!(info.server_info.name, "jacs-mcp");
    // Core tool should always be present with default features
    assert!(
        tools
            .iter()
            .any(|tool| tool.name.as_ref() == "jacs_list_state")
    );
    // Attestation tools require the attestation-tools feature
    #[cfg(feature = "attestation-tools")]
    assert!(
        tools
            .iter()
            .any(|tool| tool.name.as_ref() == "jacs_attest_create")
    );
    #[cfg(not(feature = "attestation-tools"))]
    assert!(
        !tools
            .iter()
            .any(|tool| tool.name.as_ref() == "jacs_attest_create"),
        "jacs_attest_create should not be registered without attestation-tools feature"
    );

    cleanup_workspace(&workspace);
    Ok(())
}
