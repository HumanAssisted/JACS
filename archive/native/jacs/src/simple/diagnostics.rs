//! Standalone diagnostics function (no agent required).
//!
//! This module provides environment and installation diagnostics
//! without requiring a loaded JACS agent.

/// Returns diagnostic information about the JACS installation.
///
/// This is a standalone function that does not require a loaded agent.
/// For agent-aware diagnostics, use [`super::SimpleAgent::diagnostics()`].
pub fn diagnostics() -> serde_json::Value {
    use crate::storage::jenv;
    serde_json::json!({
        "jacs_version": env!("CARGO_PKG_VERSION"),
        "rust_version": option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("unknown"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "config_path": jenv::get_env_var("JACS_CONFIG", false).ok().flatten().unwrap_or_default(),
        "data_directory": jenv::get_env_var("JACS_DATA_DIRECTORY", false).ok().flatten().unwrap_or_default(),
        "key_directory": jenv::get_env_var("JACS_KEY_DIRECTORY", false).ok().flatten().unwrap_or_default(),
        "key_algorithm": jenv::get_env_var("JACS_AGENT_KEY_ALGORITHM", false).ok().flatten().unwrap_or_default(),
        "default_storage": jenv::get_env_var("JACS_DEFAULT_STORAGE", false).ok().flatten().unwrap_or_default(),
        "strict_mode": jenv::get_env_var("JACS_STRICT_MODE", false).ok().flatten().unwrap_or_default(),
        "agent_loaded": false,
        "agent_id": serde_json::Value::Null,
    })
}
