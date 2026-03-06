#![cfg(feature = "mcp")]

mod support;

use rmcp::ServerHandler;
use support::{ENV_LOCK, ScopedEnvVar, TEST_PASSWORD, cleanup_workspace, prepare_temp_workspace};

#[test]
fn crate_root_exports_server_and_config_helpers() -> anyhow::Result<()> {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let (config_path, workspace) = prepare_temp_workspace();
    let _password = ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);

    let agent = jacs_mcp::load_agent_from_config_path(&config_path)?;
    let server = jacs_mcp::JacsMcpServer::new(agent.clone());
    let info = server.get_info();

    assert_eq!(info.server_info.name, "jacs-mcp");

    let agent_json = agent.get_agent_json()?;
    let parsed: serde_json::Value = serde_json::from_str(&agent_json)?;
    assert_eq!(
        parsed["jacsId"].as_str(),
        Some("ddf35096-d212-4ca9-a299-feda597d5525")
    );

    cleanup_workspace(&workspace);
    Ok(())
}

#[test]
fn load_agent_from_config_env_uses_jacs_config() -> anyhow::Result<()> {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let (config_path, workspace) = prepare_temp_workspace();
    let _password = ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    let _config = ScopedEnvVar::set("JACS_CONFIG", &config_path);

    let agent = jacs_mcp::load_agent_from_config_env()?;
    let agent_json = agent.get_agent_json()?;
    let parsed: serde_json::Value = serde_json::from_str(&agent_json)?;

    assert_eq!(
        parsed["jacsId"].as_str(),
        Some("ddf35096-d212-4ca9-a299-feda597d5525")
    );

    cleanup_workspace(&workspace);
    Ok(())
}
