mod support;

use std::path::PathBuf;

use jacs::storage::jenv::get_env_var;
use support::{ENV_LOCK, ScopedEnvVar, TEST_PASSWORD, cleanup_workspace, prepare_temp_workspace};

#[test]
fn config_path_loader_resolves_relative_directories_from_config_location() -> anyhow::Result<()> {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let (config_path, workspace) = prepare_temp_workspace();
    let _password = ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);

    let agent = jacs_mcp::load_agent_from_config_path(&config_path)?;
    let _ = agent.get_agent_json()?;

    assert_eq!(
        PathBuf::from(get_env_var("JACS_DATA_DIRECTORY", false)?.expect("data dir override")),
        workspace.join("jacs_data")
    );
    assert_eq!(
        PathBuf::from(get_env_var("JACS_KEY_DIRECTORY", false)?.expect("key dir override")),
        workspace.join("jacs_keys")
    );

    cleanup_workspace(&workspace);
    Ok(())
}

#[test]
fn env_loader_resolves_relative_directories_from_jacs_config() -> anyhow::Result<()> {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let (config_path, workspace) = prepare_temp_workspace();
    let _password = ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    let _config = ScopedEnvVar::set("JACS_CONFIG", &config_path);

    let agent = jacs_mcp::load_agent_from_config_env()?;
    let _ = agent.get_agent_json()?;

    assert_eq!(
        PathBuf::from(get_env_var("JACS_DATA_DIRECTORY", false)?.expect("data dir override")),
        workspace.join("jacs_data")
    );
    assert_eq!(
        PathBuf::from(get_env_var("JACS_KEY_DIRECTORY", false)?.expect("key dir override")),
        workspace.join("jacs_keys")
    );

    cleanup_workspace(&workspace);
    Ok(())
}
