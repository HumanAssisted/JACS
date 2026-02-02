//! OS-specific path handling for JACS directories.
//!
//! This module provides platform-appropriate paths for:
//! - Trust store (trusted agent files)
//! - Keys directory
//! - Default configuration file

use std::path::PathBuf;

/// Returns the path to the trust store directory.
///
/// The trust store contains JSON files for agents that have been
/// explicitly trusted via `trust_agent()`.
///
/// Platform-specific locations:
/// - **macOS**: `~/Library/Application Support/jacs/trusted_agents/`
/// - **Linux**: `$XDG_DATA_HOME/jacs/trusted_agents/` or `~/.local/share/jacs/trusted_agents/`
/// - **Windows**: `%APPDATA%\jacs\trusted_agents\`
///
/// Falls back to `~/.jacs/trusted_agents/` if platform detection fails.
pub fn trust_store_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return home.join("Library/Application Support/jacs/trusted_agents");
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Follow XDG Base Directory specification
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg_data).join("jacs/trusted_agents");
        }
        if let Some(home) = dirs::home_dir() {
            return home.join(".local/share/jacs/trusted_agents");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = dirs::data_dir() {
            return appdata.join("jacs\\trusted_agents");
        }
    }

    // Fallback for other platforms or if dirs:: fails
    if let Some(home) = dirs::home_dir() {
        return home.join(".jacs/trusted_agents");
    }

    // Last resort: use current directory
    PathBuf::from("./.jacs/trusted_agents")
}

/// Returns the path to the JACS data directory.
///
/// This is where agent files, documents, and other data are stored.
///
/// Platform-specific locations:
/// - **macOS**: `~/Library/Application Support/jacs/data/`
/// - **Linux**: `$XDG_DATA_HOME/jacs/data/` or `~/.local/share/jacs/data/`
/// - **Windows**: `%APPDATA%\jacs\data\`
pub fn data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return home.join("Library/Application Support/jacs/data");
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg_data).join("jacs/data");
        }
        if let Some(home) = dirs::home_dir() {
            return home.join(".local/share/jacs/data");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = dirs::data_dir() {
            return appdata.join("jacs\\data");
        }
    }

    // Fallback
    if let Some(home) = dirs::home_dir() {
        return home.join(".jacs/data");
    }

    PathBuf::from("./.jacs/data")
}

/// Returns the path to the JACS keys directory.
///
/// This is where private and public keys are stored.
/// Note: For project-local agents, keys are typically stored in `./jacs_keys/`.
///
/// Platform-specific locations for global keys:
/// - **macOS**: `~/Library/Application Support/jacs/keys/`
/// - **Linux**: `$XDG_DATA_HOME/jacs/keys/` or `~/.local/share/jacs/keys/`
/// - **Windows**: `%APPDATA%\jacs\keys\`
pub fn keys_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return home.join("Library/Application Support/jacs/keys");
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg_data).join("jacs/keys");
        }
        if let Some(home) = dirs::home_dir() {
            return home.join(".local/share/jacs/keys");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = dirs::data_dir() {
            return appdata.join("jacs\\keys");
        }
    }

    // Fallback
    if let Some(home) = dirs::home_dir() {
        return home.join(".jacs/keys");
    }

    PathBuf::from("./.jacs/keys")
}

/// Returns the default configuration file path.
///
/// This is always `./jacs.config.json` in the current working directory,
/// as configuration is project-local by design.
pub fn default_config_path() -> PathBuf {
    PathBuf::from("./jacs.config.json")
}

/// Returns the default agent file path.
///
/// This is always `./jacs.agent.json` in the current working directory.
pub fn default_agent_path() -> PathBuf {
    PathBuf::from("./jacs.agent.json")
}

/// Returns the project-local keys directory path.
///
/// This is `./jacs_keys/` in the current working directory.
/// Used when creating agents with local storage.
pub fn local_keys_dir() -> PathBuf {
    PathBuf::from("./jacs_keys")
}

/// Returns the project-local data directory path.
///
/// This is `./jacs_data/` in the current working directory.
/// Used for storing documents and other agent data.
pub fn local_data_dir() -> PathBuf {
    PathBuf::from("./jacs_data")
}

/// Ensures a directory exists, creating it if necessary.
///
/// Returns the path if successful, or an error if creation fails.
pub fn ensure_dir_exists(path: &PathBuf) -> Result<&PathBuf, Box<dyn std::error::Error>> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("Failed to create directory '{}': {}", path.display(), e))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_store_dir_is_valid() {
        let path = trust_store_dir();
        // Should end with trusted_agents
        assert!(
            path.to_string_lossy().contains("trusted_agents"),
            "Trust store path should contain 'trusted_agents': {:?}",
            path
        );
    }

    #[test]
    fn test_default_config_path() {
        let path = default_config_path();
        assert_eq!(path, PathBuf::from("./jacs.config.json"));
    }

    #[test]
    fn test_default_agent_path() {
        let path = default_agent_path();
        assert_eq!(path, PathBuf::from("./jacs.agent.json"));
    }

    #[test]
    fn test_local_keys_dir() {
        let path = local_keys_dir();
        assert_eq!(path, PathBuf::from("./jacs_keys"));
    }

    #[test]
    fn test_local_data_dir() {
        let path = local_data_dir();
        assert_eq!(path, PathBuf::from("./jacs_data"));
    }
}
