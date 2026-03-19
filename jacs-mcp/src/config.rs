use anyhow::anyhow;
use jacs_binding_core::AgentWrapper;
use std::path::Path;

const MISSING_JACS_CONFIG_MESSAGE: &str = "JACS_CONFIG environment variable is not set. \n\
             \n\
             To use the JACS MCP server, you need to:\n\
             1. Create a jacs.config.json file with your agent configuration\n\
             2. Set JACS_CONFIG=/path/to/jacs.config.json\n\
             \n\
             See the README for a Quick Start guide on creating an agent.";

pub fn load_agent_from_config_env() -> anyhow::Result<AgentWrapper> {
    let (agent_wrapper, _info) = load_agent_from_config_env_with_info()?;
    Ok(agent_wrapper)
}

pub fn load_agent_from_config_env_with_info() -> anyhow::Result<(AgentWrapper, serde_json::Value)> {
    let cfg_path =
        std::env::var("JACS_CONFIG").map_err(|_| anyhow!(MISSING_JACS_CONFIG_MESSAGE))?;
    load_agent_from_config_path_with_info(cfg_path)
}

pub fn load_agent_from_config_path_with_info(
    path: impl AsRef<Path>,
) -> anyhow::Result<(AgentWrapper, serde_json::Value)> {
    let config_path = path.as_ref();
    let config_path = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(config_path)
    };

    if !config_path.exists() {
        return Err(anyhow!(
            "Config file not found at '{}'. \n\
             \n\
             Please create a jacs.config.json file or update JACS_CONFIG \
             to point to an existing configuration file.",
            config_path.display()
        ));
    }

    let agent_wrapper = AgentWrapper::new();
    tracing::info!(config_path = %config_path.display(), "Loading agent from config file");
    let info_json = agent_wrapper
        .load_with_info(config_path.to_string_lossy().into_owned())
        .map_err(|e| anyhow!("Failed to load agent: {}", e))?;
    let info: serde_json::Value = serde_json::from_str(&info_json)
        .map_err(|e| anyhow!("Failed to parse loaded agent info: {}", e))?;

    tracing::info!("Agent loaded successfully from config");
    Ok((agent_wrapper, info))
}

pub fn load_agent_from_config_path(path: impl AsRef<Path>) -> anyhow::Result<AgentWrapper> {
    let (agent_wrapper, _info) = load_agent_from_config_path_with_info(path)?;
    Ok(agent_wrapper)
}

#[cfg(test)]
mod tests {
    use super::load_agent_from_config_path_with_info;
    use std::sync::{Mutex, OnceLock};

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn load_with_info_returns_resolved_directories() {
        let _guard = test_lock().lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        // Canonicalize to resolve macOS /var -> /private/var symlink
        let tmp_canonical = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        let config_dir = tmp_canonical.join("nested");
        let data_dir = config_dir.join("jacs_data");
        let key_dir = config_dir.join("jacs_keys");
        let config_path = config_dir.join("jacs.config.json");

        let params = jacs::simple::CreateAgentParams::builder()
            .name("mcp-config-test")
            .password("TestP@ss123!#")
            .algorithm("ring-Ed25519")
            .data_directory(data_dir.to_str().unwrap())
            .key_directory(key_dir.to_str().unwrap())
            .config_path(config_path.to_str().unwrap())
            .build();

        let (_agent, created_info) =
            jacs::simple::SimpleAgent::create_with_params(params).expect("create should succeed");

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        unsafe {
            std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#");
        }

        let (_wrapper, info) = load_agent_from_config_path_with_info("./nested/jacs.config.json")
            .expect("load_with_info should succeed");

        assert_eq!(info["agent_id"], created_info.agent_id);
        assert_eq!(
            info["config_path"],
            config_path.to_string_lossy().to_string()
        );
        assert_eq!(
            info["data_directory"],
            data_dir.to_string_lossy().to_string()
        );
        assert_eq!(info["key_directory"], key_dir.to_string_lossy().to_string());

        std::env::set_current_dir(original_dir).unwrap();
        unsafe {
            std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
        }
    }
}
