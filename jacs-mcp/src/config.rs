use anyhow::{Context, anyhow};
use jacs_binding_core::AgentWrapper;
use std::path::{Path, PathBuf};

const MISSING_JACS_CONFIG_MESSAGE: &str = "JACS_CONFIG environment variable is not set. \n\
             \n\
             To use the JACS MCP server, you need to:\n\
             1. Create a jacs.config.json file with your agent configuration\n\
             2. Set JACS_CONFIG=/path/to/jacs.config.json\n\
             \n\
             See the README for a Quick Start guide on creating an agent.";

pub fn load_agent_from_config_env() -> anyhow::Result<AgentWrapper> {
    let cfg_path = std::env::var("JACS_CONFIG").map_err(|_| anyhow!(MISSING_JACS_CONFIG_MESSAGE))?;
    load_agent_from_config_path(cfg_path)
}

pub fn load_agent_from_config_path(path: impl AsRef<Path>) -> anyhow::Result<AgentWrapper> {
    let config_path = path.as_ref();
    let config_path = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("Failed to determine current working directory")?
            .join(config_path)
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

    let cfg_str = std::fs::read_to_string(&config_path).map_err(|e| {
        anyhow!(
            "Failed to read config file '{}': {}. Check file permissions.",
            config_path.display(),
            e
        )
    })?;

    let resolved_cfg_str = resolve_relative_config_paths(&cfg_str, &config_path)?;

    #[allow(deprecated)]
    let _ = jacs::config::set_env_vars(true, Some(&resolved_cfg_str), false).map_err(|e| {
        anyhow!(
            "Invalid config file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let agent_wrapper = AgentWrapper::new();
    tracing::info!(config_path = %config_path.display(), "Loading agent from config file");
    agent_wrapper
        .load(config_path.to_string_lossy().into_owned())
        .map_err(|e| anyhow!("Failed to load agent: {}", e))?;

    tracing::info!("Agent loaded successfully from config");
    Ok(agent_wrapper)
}

fn resolve_relative_config_paths(config_json: &str, config_path: &Path) -> anyhow::Result<String> {
    let mut value: serde_json::Value =
        serde_json::from_str(config_json).context("Config file is not valid JSON")?;
    let config_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    for field in ["jacs_data_directory", "jacs_key_directory"] {
        if let Some(path_value) = value.get_mut(field) {
            if let Some(path_str) = path_value.as_str() {
                let path = Path::new(path_str);
                if !path.is_absolute() {
                    *path_value = serde_json::Value::String(
                        config_dir.join(path).to_string_lossy().into_owned(),
                    );
                }
            }
        }
    }

    serde_json::to_string(&value).context("Failed to serialize resolved config")
}

#[cfg(test)]
mod tests {
    use super::resolve_relative_config_paths;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn resolves_relative_directories_against_config_location() {
        let config = json!({
            "jacs_data_directory": "jacs_data",
            "jacs_key_directory": "jacs_keys",
        });

        let resolved = resolve_relative_config_paths(
            &config.to_string(),
            Path::new("/tmp/example/jacs.config.json"),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&resolved).unwrap();

        assert_eq!(
            parsed["jacs_data_directory"].as_str(),
            Some("/tmp/example/jacs_data")
        );
        assert_eq!(
            parsed["jacs_key_directory"].as_str(),
            Some("/tmp/example/jacs_keys")
        );
    }
}
