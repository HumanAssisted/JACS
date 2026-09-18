#![cfg(feature = "mcp")]

mod support;

use rmcp::ServerHandler;
use support::{
    ENV_LOCK, LEGACY_SIGNATURE_CONTENT_ENV_VAR, ScopedEnvVar, TEST_PASSWORD, cleanup_workspace,
    prepare_temp_workspace,
};

#[test]
fn crate_root_exports_server_and_config_helpers() -> anyhow::Result<()> {
    let _env_guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (config_path, workspace) = prepare_temp_workspace();
    let _password = ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    let _legacy_fixture = ScopedEnvVar::set(LEGACY_SIGNATURE_CONTENT_ENV_VAR, "true");

    let agent = jacs_mcp::load_agent_from_config_path(&config_path)?;
    let server = jacs_mcp::JacsMcpServer::new(agent.clone());
    let info = server.get_info();

    assert_eq!(info.server_info.name, "jacs-mcp");

    let agent_json = agent.get_agent_json()?;
    let parsed: serde_json::Value = serde_json::from_str(&agent_json)?;
    assert_agent_matches_config(&parsed, &config_path)?;

    cleanup_workspace(&workspace);
    Ok(())
}

#[test]
fn load_agent_from_config_env_uses_jacs_config() -> anyhow::Result<()> {
    let _env_guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (config_path, workspace) = prepare_temp_workspace();
    let _password = ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    let _legacy_fixture = ScopedEnvVar::set(LEGACY_SIGNATURE_CONTENT_ENV_VAR, "true");
    let _config = ScopedEnvVar::set("JACS_CONFIG", &config_path);

    let agent = jacs_mcp::load_agent_from_config_env()?;
    let agent_json = agent.get_agent_json()?;
    let parsed: serde_json::Value = serde_json::from_str(&agent_json)?;

    assert_agent_matches_config(&parsed, &config_path)?;

    cleanup_workspace(&workspace);
    Ok(())
}

fn assert_agent_matches_config(
    agent: &serde_json::Value,
    config_path: &std::path::Path,
) -> anyhow::Result<()> {
    let config: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(config_path)?)?;
    let configured_id_and_version = config["jacs_agent_id_and_version"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("signed config omitted jacs_agent_id_and_version"))?;
    let configured_id = configured_id_and_version
        .split_once(':')
        .map_or(configured_id_and_version, |(id, _version)| id);

    assert!(
        !configured_id.is_empty(),
        "configured agent ID must not be empty"
    );
    assert_eq!(agent["jacsId"].as_str(), Some(configured_id));
    Ok(())
}
