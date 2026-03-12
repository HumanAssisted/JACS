//! Standalone diagnostics function (no agent required).
//!
//! This module provides environment and installation diagnostics
//! without requiring a loaded JACS agent.

/// Returns diagnostic information about the JACS installation.
///
/// This is a standalone function that does not require a loaded agent.
/// For agent-aware diagnostics, use [`super::SimpleAgent::diagnostics()`].
pub fn diagnostics() -> serde_json::Value {
    serde_json::json!({
        "jacs_version": env!("CARGO_PKG_VERSION"),
        "rust_version": option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("unknown"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "config_path": std::env::var("JACS_CONFIG").unwrap_or_default(),
        "data_directory": std::env::var("JACS_DATA_DIRECTORY").unwrap_or_default(),
        "key_directory": std::env::var("JACS_KEY_DIRECTORY").unwrap_or_default(),
        "key_algorithm": std::env::var("JACS_AGENT_KEY_ALGORITHM").unwrap_or_default(),
        "default_storage": std::env::var("JACS_DEFAULT_STORAGE").unwrap_or_default(),
        "strict_mode": std::env::var("JACS_STRICT_MODE").unwrap_or_default(),
        "agent_loaded": false,
        "agent_id": serde_json::Value::Null,
    })
}
