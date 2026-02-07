// Allow deprecated functions within this module - they call each other during migration
#![allow(deprecated)]

use crate::error::JacsError;
use crate::schema::utils::{CONFIG_SCHEMA_STRING, EmbeddedSchemaResolver};
use crate::storage::jenv::{EnvError, get_env_var, get_required_env_var, set_env_var_override};
use getset::Getters;
use jsonschema::{Draft, Validator};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::str::FromStr;
use tracing::{error, info, warn};

use crate::validation::{are_valid_uuid_parts, split_agent_id};

/// Source for resolving public keys during signature verification.
///
/// This enum represents the different sources from which JACS can retrieve
/// public keys when verifying document signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyResolutionSource {
    /// Local filesystem (default). Keys are stored in the data directory
    /// under `public_keys/{hash}.pem`.
    Local,
    /// DNS TXT record verification. Requires the agent to have a domain
    /// configured and the public key hash published in DNS.
    Dns,
    /// HAI key service (https://keys.hai.ai). Fetches public keys from
    /// the centralized HAI key distribution service.
    Hai,
}

impl fmt::Display for KeyResolutionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyResolutionSource::Local => write!(f, "local"),
            KeyResolutionSource::Dns => write!(f, "dns"),
            KeyResolutionSource::Hai => write!(f, "hai"),
        }
    }
}

impl FromStr for KeyResolutionSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "local" => Ok(KeyResolutionSource::Local),
            "dns" => Ok(KeyResolutionSource::Dns),
            "hai" => Ok(KeyResolutionSource::Hai),
            other => Err(format!(
                "Unknown key resolution source '{}'. Valid options are: local, dns, hai",
                other
            )),
        }
    }
}

/// Returns the configured key resolution order from the `JACS_KEY_RESOLUTION` environment variable.
///
/// The order determines which sources are tried (and in what sequence) when resolving
/// public keys for signature verification.
///
/// # Environment Variable
///
/// `JACS_KEY_RESOLUTION` - Comma-separated list of sources to try in order.
///
/// # Valid Values
///
/// - `local` - Local filesystem (keys in `public_keys/` directory)
/// - `dns` - DNS TXT record verification
/// - `hai` - HAI key service (https://keys.hai.ai)
///
/// # Examples
///
/// ```bash
/// # Default: try local first, then HAI
/// JACS_KEY_RESOLUTION=local,hai
///
/// # Include DNS verification
/// JACS_KEY_RESOLUTION=local,dns,hai
///
/// # Air-gapped mode (local only)
/// JACS_KEY_RESOLUTION=local
///
/// # HAI only (for testing or cloud-native deployments)
/// JACS_KEY_RESOLUTION=hai
/// ```
///
/// # Default
///
/// If the environment variable is not set or empty, returns `[Local, Hai]`.
///
/// # Behavior
///
/// - Invalid source names are logged as warnings and skipped
/// - Duplicate sources are preserved (first occurrence is used)
/// - If parsing results in an empty list, falls back to the default
pub fn get_key_resolution_order() -> Vec<KeyResolutionSource> {
    let default_order = vec![KeyResolutionSource::Local, KeyResolutionSource::Hai];

    let order_str = match get_env_var("JACS_KEY_RESOLUTION", false) {
        Ok(Some(val)) if !val.is_empty() => val,
        _ => return default_order,
    };

    let mut sources = Vec::new();
    for part in order_str.split(',') {
        match KeyResolutionSource::from_str(part) {
            Ok(source) => sources.push(source),
            Err(e) => {
                warn!("JACS_KEY_RESOLUTION: {}", e);
            }
        }
    }

    if sources.is_empty() {
        warn!(
            "JACS_KEY_RESOLUTION resulted in empty list after parsing '{}', using default (local,hai)",
            order_str
        );
        return default_order;
    }

    info!("Key resolution order: {:?}", sources);
    sources
}

pub mod constants;

/*
Config is embedded in agents and may have private information.

Configuration Loading (12-Factor App Pattern)
=============================================

JACS follows the 12-Factor App methodology for configuration (https://12factor.net/config).
Configuration is loaded in the following order, with later sources overriding earlier ones:

1. DEFAULTS: Sensible defaults are built into the code
2. CONFIG FILE: Optional JSON file provides project-specific defaults
3. ENVIRONMENT VARIABLES: Always take highest precedence (12-Factor compliance)

This allows:
- Development: Use config file for convenience
- Production: Override with environment variables for security and flexibility
- CI/CD: Set environment variables in deployment scripts

Environment Variables Supported:
- JACS_USE_SECURITY
- JACS_DATA_DIRECTORY
- JACS_KEY_DIRECTORY
- JACS_AGENT_PRIVATE_KEY_FILENAME
- JACS_AGENT_PUBLIC_KEY_FILENAME
- JACS_AGENT_KEY_ALGORITHM
- JACS_PRIVATE_KEY_PASSWORD (NEVER put in config file!)
- JACS_AGENT_ID_AND_VERSION
- JACS_DEFAULT_STORAGE
- JACS_AGENT_DOMAIN
- JACS_DNS_VALIDATE
- JACS_DNS_STRICT
- JACS_DNS_REQUIRED
- JACS_KEY_RESOLUTION (comma-separated: local,dns,hai - controls key lookup order)

Usage:
```rust
// Recommended: 12-Factor compliant loading
let config = load_config_12factor(Some("jacs.config.json"))?;

// Or with just defaults and env vars (no config file)
let config = load_config_12factor(None)?;
```

*/

#[derive(Serialize, Deserialize, Debug, Getters)]
pub struct Config {
    #[serde(rename = "$schema")]
    #[serde(default = "default_schema")]
    #[getset(get)]
    schema: String,
    #[getset(get = "pub")]
    #[serde(default = "default_security")]
    jacs_use_security: Option<String>,
    #[getset(get = "pub")]
    #[serde(default = "default_data_directory")]
    jacs_data_directory: Option<String>,
    #[getset(get = "pub")]
    #[serde(default = "default_key_directory")]
    jacs_key_directory: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_private_key_filename: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_public_key_filename: Option<String>,
    #[getset(get = "pub")]
    #[serde(default = "default_algorithm")]
    jacs_agent_key_algorithm: Option<String>,
    /// DEPRECATED: Password should NEVER be stored in config files.
    /// Use the JACS_PRIVATE_KEY_PASSWORD environment variable instead.
    /// This field is kept for backwards compatibility to detect and warn about insecure configs.
    #[serde(default, skip_serializing)]
    jacs_private_key_password: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_id_and_version: Option<String>,
    #[getset(get = "pub")]
    #[serde(default = "default_storage")]
    jacs_default_storage: Option<String>,
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_agent_domain: Option<String>,
    // DNS policy
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_dns_validate: Option<bool>,
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_dns_strict: Option<bool>,
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_dns_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilityConfig>,
    // Database storage configuration
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_database_url: Option<String>,
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_database_max_connections: Option<u32>,
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_database_min_connections: Option<u32>,
    #[getset(get = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jacs_database_connect_timeout_secs: Option<u64>,
}

fn default_schema() -> String {
    "https://hai.ai/schemas/jacs.config.schema.json".to_string()
}

/// Macro to generate default functions that check an environment variable with a fallback value.
/// This reduces repetition across the simple default_* functions.
macro_rules! env_default {
    ($fn_name:ident, $env_var:literal, $default:expr) => {
        fn $fn_name() -> Option<String> {
            match get_env_var($env_var, false) {
                Ok(Some(val)) if !val.is_empty() => Some(val),
                _ => Some($default.to_string()),
            }
        }
    };
}

env_default!(default_storage, "JACS_DEFAULT_STORAGE", "fs");
env_default!(default_algorithm, "JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
/// Check `JACS_ENABLE_FILESYSTEM_QUARANTINE` (preferred) first,
/// fall back to legacy `JACS_USE_SECURITY` with a deprecation warning.
fn default_security() -> Option<String> {
    // Preferred new name
    if let Ok(Some(val)) = get_env_var("JACS_ENABLE_FILESYSTEM_QUARANTINE", false) {
        if !val.is_empty() {
            return Some(val);
        }
    }
    // Legacy name (backwards compatible)
    if let Ok(Some(val)) = get_env_var("JACS_USE_SECURITY", false) {
        if !val.is_empty() {
            eprintln!(
                "DEPRECATION WARNING: JACS_USE_SECURITY is deprecated. \
                Use JACS_ENABLE_FILESYSTEM_QUARANTINE instead. \
                This env var only controls filesystem quarantine of executable files, \
                not cryptographic verification."
            );
            return Some(val);
        }
    }
    Some("false".to_string())
}

/// Helper to compute a directory default with CWD resolution for filesystem storage.
/// Falls back to a relative path if CWD cannot be determined or storage is not "fs".
fn default_directory_with_cwd(env_var: &str, dir_name: &str) -> Option<String> {
    match get_env_var(env_var, false) {
        Ok(Some(val)) if !val.is_empty() => Some(val),
        _ => {
            let fallback = format!("./{}", dir_name);
            if default_storage() == Some("fs".to_string()) {
                match std::env::current_dir() {
                    Ok(cur_dir) => Some(cur_dir.join(dir_name).to_string_lossy().to_string()),
                    Err(_) => Some(fallback),
                }
            } else {
                Some(fallback)
            }
        }
    }
}

fn default_data_directory() -> Option<String> {
    default_directory_with_cwd("JACS_DATA_DIRECTORY", "jacs_data")
}

fn default_key_directory() -> Option<String> {
    default_directory_with_cwd("JACS_KEY_DIRECTORY", "jacs_keys")
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema: default_schema(),
            jacs_use_security: default_security(),
            jacs_data_directory: default_data_directory(),
            jacs_key_directory: default_key_directory(),
            jacs_agent_private_key_filename: None,
            jacs_agent_public_key_filename: None,
            jacs_agent_key_algorithm: default_algorithm(),
            jacs_private_key_password: None,
            jacs_agent_id_and_version: None,
            jacs_default_storage: default_storage(),
            jacs_agent_domain: None,
            jacs_dns_validate: None,
            jacs_dns_strict: None,
            jacs_dns_required: None,
            observability: None,
            jacs_database_url: None,
            jacs_database_max_connections: None,
            jacs_database_min_connections: None,
            jacs_database_connect_timeout_secs: None,
        }
    }
}

/// Builder for creating Config instances with a fluent API.
///
/// # Example
/// ```rust,ignore
/// let config = Config::builder()
///     .key_algorithm("Ed25519")
///     .key_directory("/custom/keys")
///     .data_directory("/custom/data")
///     .use_security(true)
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    agent_id_and_version: Option<String>,
    key_algorithm: Option<String>,
    private_key_filename: Option<String>,
    public_key_filename: Option<String>,
    key_directory: Option<String>,
    data_directory: Option<String>,
    default_storage: Option<String>,
    use_security: Option<bool>,
    agent_domain: Option<String>,
    dns_validate: Option<bool>,
    dns_strict: Option<bool>,
    dns_required: Option<bool>,
    observability: Option<ObservabilityConfig>,
}

impl ConfigBuilder {
    /// Create a new ConfigBuilder with no values set.
    /// All fields will use sensible defaults when `build()` is called.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the agent ID and version (format: "UUID:UUID").
    pub fn agent_id_and_version(mut self, id_version: &str) -> Self {
        self.agent_id_and_version = Some(id_version.to_string());
        self
    }

    /// Set the key algorithm (e.g., "RSA-PSS", "Ed25519", "pq2025").
    pub fn key_algorithm(mut self, algo: &str) -> Self {
        self.key_algorithm = Some(algo.to_string());
        self
    }

    /// Set the private key filename.
    pub fn private_key_filename(mut self, filename: &str) -> Self {
        self.private_key_filename = Some(filename.to_string());
        self
    }

    /// Set the public key filename.
    pub fn public_key_filename(mut self, filename: &str) -> Self {
        self.public_key_filename = Some(filename.to_string());
        self
    }

    /// Set the directory where keys are stored.
    pub fn key_directory(mut self, dir: &str) -> Self {
        self.key_directory = Some(dir.to_string());
        self
    }

    /// Set the directory where data is stored.
    pub fn data_directory(mut self, dir: &str) -> Self {
        self.data_directory = Some(dir.to_string());
        self
    }

    /// Set the default storage backend (e.g., "fs", "memory").
    pub fn default_storage(mut self, storage: &str) -> Self {
        self.default_storage = Some(storage.to_string());
        self
    }

    /// Enable or disable security features.
    pub fn use_security(mut self, enabled: bool) -> Self {
        self.use_security = Some(enabled);
        self
    }

    /// Set the agent domain for DNS validation.
    pub fn agent_domain(mut self, domain: &str) -> Self {
        self.agent_domain = Some(domain.to_string());
        self
    }

    /// Enable or disable DNS validation.
    pub fn dns_validate(mut self, enabled: bool) -> Self {
        self.dns_validate = Some(enabled);
        self
    }

    /// Enable or disable strict DNS mode.
    pub fn dns_strict(mut self, enabled: bool) -> Self {
        self.dns_strict = Some(enabled);
        self
    }

    /// Enable or disable DNS requirement.
    pub fn dns_required(mut self, required: bool) -> Self {
        self.dns_required = Some(required);
        self
    }

    /// Set the observability configuration.
    pub fn observability(mut self, config: ObservabilityConfig) -> Self {
        self.observability = Some(config);
        self
    }

    /// Build the Config instance.
    ///
    /// Fields not explicitly set will use sensible defaults:
    /// - `key_algorithm`: "RSA-PSS"
    /// - `key_directory`: "./jacs_keys"
    /// - `data_directory`: "./jacs_data"
    /// - `default_storage`: "fs"
    /// - `use_security`: false
    pub fn build(self) -> Config {
        Config {
            schema: default_schema(),
            jacs_use_security: Some(
                self.use_security
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "false".to_string()),
            ),
            jacs_data_directory: Some(
                self.data_directory
                    .unwrap_or_else(|| "./jacs_data".to_string()),
            ),
            jacs_key_directory: Some(
                self.key_directory
                    .unwrap_or_else(|| "./jacs_keys".to_string()),
            ),
            jacs_agent_private_key_filename: self.private_key_filename,
            jacs_agent_public_key_filename: self.public_key_filename,
            jacs_agent_key_algorithm: Some(
                self.key_algorithm.unwrap_or_else(|| "RSA-PSS".to_string()),
            ),
            jacs_private_key_password: None, // Never store password in config
            jacs_agent_id_and_version: self.agent_id_and_version,
            jacs_default_storage: Some(self.default_storage.unwrap_or_else(|| "fs".to_string())),
            jacs_agent_domain: self.agent_domain,
            jacs_dns_validate: self.dns_validate,
            jacs_dns_strict: self.dns_strict,
            jacs_dns_required: self.dns_required,
            observability: self.observability,
            jacs_database_url: None,
            jacs_database_max_connections: None,
            jacs_database_min_connections: None,
            jacs_database_connect_timeout_secs: None,
        }
    }
}

impl Config {
    /// Create a ConfigBuilder for fluent configuration.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = Config::builder()
    ///     .key_algorithm("Ed25519")
    ///     .key_directory("/custom/keys")
    ///     .use_security(true)
    ///     .build();
    /// ```
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Create a new Config.
    ///
    /// # Arguments
    /// * `jacs_private_key_password` - DEPRECATED: This parameter is ignored.
    ///   Passwords should be set via the JACS_PRIVATE_KEY_PASSWORD environment variable only.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        jacs_use_security: Option<String>,
        jacs_data_directory: Option<String>,
        jacs_key_directory: Option<String>,
        jacs_agent_private_key_filename: Option<String>,
        jacs_agent_public_key_filename: Option<String>,
        jacs_agent_key_algorithm: Option<String>,
        jacs_private_key_password: Option<String>,
        jacs_agent_id_and_version: Option<String>,
        jacs_default_storage: Option<String>,
    ) -> Config {
        // Warn if password is passed - it will be ignored
        if jacs_private_key_password.is_some() {
            warn!(
                "SECURITY WARNING: Password passed to Config::new() is deprecated and will be ignored. \
                Use the JACS_PRIVATE_KEY_PASSWORD environment variable instead."
            );
        }
        Config {
            schema: default_schema(),
            jacs_use_security,
            jacs_data_directory,
            jacs_key_directory,
            jacs_agent_private_key_filename,
            jacs_agent_public_key_filename,
            jacs_agent_key_algorithm,
            jacs_private_key_password: None, // Never store password in config
            jacs_agent_id_and_version,
            jacs_default_storage,
            jacs_agent_domain: None,
            jacs_dns_validate: None,
            jacs_dns_strict: None,
            jacs_dns_required: None,
            observability: None,
            jacs_database_url: None,
            jacs_database_max_connections: None,
            jacs_database_min_connections: None,
            jacs_database_connect_timeout_secs: None,
        }
    }

    pub fn get_key_algorithm(&self) -> Result<String, Box<dyn std::error::Error>> {
        // 1. Try getting from config
        if let Some(algo_str) = self.jacs_agent_key_algorithm().as_deref() {
            // Config exists and has the key algorithm string
            return Ok(algo_str.to_string());
        }
        get_required_env_var("JACS_AGENT_KEY_ALGORITHM", true)
            .map_err(|e| Box::new(e) as Box<dyn Error>) // Map EnvError to Box<dyn Error>
    }

    /// Merge another config into this one.
    /// Values from `other` will override values in `self` if they are Some.
    pub fn merge(&mut self, other: Config) {
        if other.jacs_use_security.is_some() {
            self.jacs_use_security = other.jacs_use_security;
        }
        if other.jacs_data_directory.is_some() {
            self.jacs_data_directory = other.jacs_data_directory;
        }
        if other.jacs_key_directory.is_some() {
            self.jacs_key_directory = other.jacs_key_directory;
        }
        if other.jacs_agent_private_key_filename.is_some() {
            self.jacs_agent_private_key_filename = other.jacs_agent_private_key_filename;
        }
        if other.jacs_agent_public_key_filename.is_some() {
            self.jacs_agent_public_key_filename = other.jacs_agent_public_key_filename;
        }
        if other.jacs_agent_key_algorithm.is_some() {
            self.jacs_agent_key_algorithm = other.jacs_agent_key_algorithm;
        }
        if other.jacs_agent_id_and_version.is_some() {
            self.jacs_agent_id_and_version = other.jacs_agent_id_and_version;
        }
        if other.jacs_default_storage.is_some() {
            self.jacs_default_storage = other.jacs_default_storage;
        }
        if other.jacs_agent_domain.is_some() {
            self.jacs_agent_domain = other.jacs_agent_domain;
        }
        if other.jacs_dns_validate.is_some() {
            self.jacs_dns_validate = other.jacs_dns_validate;
        }
        if other.jacs_dns_strict.is_some() {
            self.jacs_dns_strict = other.jacs_dns_strict;
        }
        if other.jacs_dns_required.is_some() {
            self.jacs_dns_required = other.jacs_dns_required;
        }
        if other.observability.is_some() {
            self.observability = other.observability;
        }
        if other.jacs_database_url.is_some() {
            self.jacs_database_url = other.jacs_database_url;
        }
        if other.jacs_database_max_connections.is_some() {
            self.jacs_database_max_connections = other.jacs_database_max_connections;
        }
        if other.jacs_database_min_connections.is_some() {
            self.jacs_database_min_connections = other.jacs_database_min_connections;
        }
        if other.jacs_database_connect_timeout_secs.is_some() {
            self.jacs_database_connect_timeout_secs = other.jacs_database_connect_timeout_secs;
        }
    }

    /// Apply environment variable overrides to this config.
    /// Environment variables always take precedence (12-Factor compliance).
    ///
    /// This method reads from the following environment variables:
    /// - JACS_USE_SECURITY
    /// - JACS_DATA_DIRECTORY
    /// - JACS_KEY_DIRECTORY
    /// - JACS_AGENT_PRIVATE_KEY_FILENAME
    /// - JACS_AGENT_PUBLIC_KEY_FILENAME
    /// - JACS_AGENT_KEY_ALGORITHM
    /// - JACS_AGENT_ID_AND_VERSION
    /// - JACS_DEFAULT_STORAGE
    /// - JACS_AGENT_DOMAIN
    /// - JACS_DNS_VALIDATE
    /// - JACS_DNS_STRICT
    /// - JACS_DNS_REQUIRED
    ///
    /// Note: JACS_PRIVATE_KEY_PASSWORD is intentionally NOT loaded into config.
    /// It should be read directly from environment when needed for security.
    pub fn apply_env_overrides(&mut self) {
        // Helper to get env var as Option<String>
        fn env_opt(key: &str) -> Option<String> {
            match get_env_var(key, false) {
                Ok(Some(val)) if !val.is_empty() => Some(val),
                _ => None,
            }
        }

        // Helper to get env var as Option<bool>
        fn env_opt_bool(key: &str) -> Option<bool> {
            match get_env_var(key, false) {
                Ok(Some(val)) if !val.is_empty() => {
                    Some(val.to_lowercase() == "true" || val == "1")
                }
                _ => None,
            }
        }

        // Apply string overrides
        if let Some(val) = env_opt("JACS_USE_SECURITY") {
            self.jacs_use_security = Some(val);
        }
        if let Some(val) = env_opt("JACS_DATA_DIRECTORY") {
            self.jacs_data_directory = Some(val);
        }
        if let Some(val) = env_opt("JACS_KEY_DIRECTORY") {
            self.jacs_key_directory = Some(val);
        }
        if let Some(val) = env_opt("JACS_AGENT_PRIVATE_KEY_FILENAME") {
            self.jacs_agent_private_key_filename = Some(val);
        }
        if let Some(val) = env_opt("JACS_AGENT_PUBLIC_KEY_FILENAME") {
            self.jacs_agent_public_key_filename = Some(val);
        }
        if let Some(val) = env_opt("JACS_AGENT_KEY_ALGORITHM") {
            self.jacs_agent_key_algorithm = Some(val);
        }
        if let Some(val) = env_opt("JACS_AGENT_ID_AND_VERSION") {
            self.jacs_agent_id_and_version = Some(val);
        }
        if let Some(val) = env_opt("JACS_DEFAULT_STORAGE") {
            self.jacs_default_storage = Some(val);
        }
        if let Some(val) = env_opt("JACS_AGENT_DOMAIN") {
            self.jacs_agent_domain = Some(val);
        }

        // Apply boolean overrides
        if let Some(val) = env_opt_bool("JACS_DNS_VALIDATE") {
            self.jacs_dns_validate = Some(val);
        }
        if let Some(val) = env_opt_bool("JACS_DNS_STRICT") {
            self.jacs_dns_strict = Some(val);
        }
        if let Some(val) = env_opt_bool("JACS_DNS_REQUIRED") {
            self.jacs_dns_required = Some(val);
        }

        // Database configuration
        if let Some(val) = env_opt("JACS_DATABASE_URL") {
            self.jacs_database_url = Some(val);
        }
        if let Some(val) = env_opt("JACS_DATABASE_MAX_CONNECTIONS") {
            if let Ok(n) = val.parse::<u32>() {
                self.jacs_database_max_connections = Some(n);
            }
        }
        if let Some(val) = env_opt("JACS_DATABASE_MIN_CONNECTIONS") {
            if let Ok(n) = val.parse::<u32>() {
                self.jacs_database_min_connections = Some(n);
            }
        }
        if let Some(val) = env_opt("JACS_DATABASE_CONNECT_TIMEOUT_SECS") {
            if let Ok(n) = val.parse::<u64>() {
                self.jacs_database_connect_timeout_secs = Some(n);
            }
        }

        // Note: Password is intentionally NOT loaded from env into config
        // It should be read directly from env when needed via get_env_var("JACS_PRIVATE_KEY_PASSWORD", true)
    }

    /// Create a Config with only hardcoded defaults (no env var lookups).
    /// This is useful for testing or when you want explicit control.
    pub fn with_defaults() -> Self {
        Config {
            schema: default_schema(),
            jacs_use_security: Some("false".to_string()),
            jacs_data_directory: Some("./jacs_data".to_string()),
            jacs_key_directory: Some("./jacs_keys".to_string()),
            jacs_agent_private_key_filename: None,
            jacs_agent_public_key_filename: None,
            jacs_agent_key_algorithm: Some("RSA-PSS".to_string()),
            jacs_private_key_password: None,
            jacs_agent_id_and_version: None,
            jacs_default_storage: Some("fs".to_string()),
            jacs_agent_domain: None,
            jacs_dns_validate: None,
            jacs_dns_strict: None,
            jacs_dns_required: None,
            observability: None,
            jacs_database_url: None,
            jacs_database_max_connections: None,
            jacs_database_min_connections: None,
            jacs_database_connect_timeout_secs: None,
        }
    }

    /// Load config from a JSON file without applying environment overrides.
    /// Use `load_config_12factor` for the recommended 12-Factor compliant loading.
    pub fn from_file(path: &str) -> Result<Config, Box<dyn Error>> {
        let json_str = fs::read_to_string(path).map_err(|e| {
            let help = match e.kind() {
                std::io::ErrorKind::NotFound => {
                    format!(
                        "Config file not found at '{}'. Create a jacs.config.json file or use \
                            environment variables (JACS_DATA_DIRECTORY, JACS_KEY_DIRECTORY, etc.) \
                            to configure JACS without a file.",
                        path
                    )
                }
                std::io::ErrorKind::PermissionDenied => {
                    format!(
                        "Permission denied reading config file '{}'. Check file permissions.",
                        path
                    )
                }
                _ => {
                    format!("Failed to read config file '{}': {}", path, e)
                }
            };
            JacsError::ConfigError(help)
        })?;
        let validated_value: Value = validate_config(&json_str)
            .map_err(|e| JacsError::ConfigError(format!("Invalid config at '{}': {}", path, e)))?;
        let config: Config = serde_json::from_value(validated_value.clone()).map_err(|e| {
            // This can happen if the JSON structure doesn't match our Config struct
            JacsError::ConfigError(format!(
                "Config structure error at '{}': {}. The JSON may have valid syntax but incorrect field types.",
                path, e
            ))
        })?;

        // Warn if password is in config file
        if config.jacs_private_key_password.is_some() {
            warn!(
                "SECURITY WARNING: Password found in config file '{}'. \
                This is insecure - passwords should only be set via JACS_PRIVATE_KEY_PASSWORD \
                environment variable. The password in the config file will be ignored.",
                path
            );
        }

        Ok(config)
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
        Loading JACS config variables of:
            JACS_USE_SECURITY:               {},
            JACS_DATA_DIRECTORY:             {},
            JACS_KEY_DIRECTORY:              {},
            JACS_AGENT_PRIVATE_KEY_FILENAME: {},
            JACS_AGENT_PUBLIC_KEY_FILENAME:  {},
            JACS_AGENT_KEY_ALGORITHM:        {},
            JACS_PRIVATE_KEY_PASSWORD:       REDACTED,
            JACS_AGENT_ID_AND_VERSION:       {},
            JACS_DEFAULT_STORAGE:            {},
            JACS_DATABASE_URL:               {},
        "#,
            self.jacs_use_security.as_deref().unwrap_or(""),
            self.jacs_data_directory.as_deref().unwrap_or(""),
            self.jacs_key_directory.as_deref().unwrap_or(""),
            self.jacs_agent_private_key_filename
                .as_deref()
                .unwrap_or(""),
            self.jacs_agent_public_key_filename.as_deref().unwrap_or(""),
            self.jacs_agent_key_algorithm.as_deref().unwrap_or(""),
            self.jacs_agent_id_and_version.as_deref().unwrap_or(""),
            self.jacs_default_storage.as_deref().unwrap_or(""),
            if self.jacs_database_url.is_some() {
                "REDACTED"
            } else {
                ""
            }
        )
    }
}

/// Load configuration following 12-Factor App principles.
///
/// Configuration is loaded in this order (later sources override earlier):
/// 1. Hardcoded defaults
/// 2. Config file (if provided and exists)
/// 3. Environment variables (always take highest precedence)
///
/// # Arguments
/// * `config_path` - Optional path to a JSON config file
///
/// # Example
/// ```rust,ignore
/// // Load with config file and env overrides
/// let config = load_config_12factor(Some("jacs.config.json"))?;
///
/// // Load with just defaults and env overrides
/// let config = load_config_12factor(None)?;
/// ```
pub fn load_config_12factor(config_path: Option<&str>) -> Result<Config, Box<dyn Error>> {
    // Step 1: Start with hardcoded defaults
    let mut config = Config::with_defaults();

    // Step 2: If config file provided, merge those values
    if let Some(path) = config_path {
        match Config::from_file(path) {
            Ok(file_config) => {
                info!("Loaded config file: {}", path);
                config.merge(file_config);
            }
            Err(e) => {
                // File was specified but couldn't be loaded - this is an error
                return Err(e);
            }
        }
    }

    // Step 3: Environment variables override everything (12-Factor compliance)
    config.apply_env_overrides();

    info!("Final config (12-Factor):{}", config);
    Ok(config)
}

/// Load configuration with 12-Factor compliance, with optional config file that may not exist.
///
/// Unlike `load_config_12factor`, this function does not fail if the config file doesn't exist.
/// It will log a warning and continue with defaults + env vars.
///
/// # Arguments
/// * `config_path` - Optional path to a JSON config file (won't fail if missing)
pub fn load_config_12factor_optional(config_path: Option<&str>) -> Result<Config, Box<dyn Error>> {
    // Step 1: Start with hardcoded defaults
    let mut config = Config::with_defaults();

    // Step 2: If config file provided and exists, merge those values
    if let Some(path) = config_path {
        if std::path::Path::new(path).exists() {
            match Config::from_file(path) {
                Ok(file_config) => {
                    info!("Loaded config file: {}", path);
                    config.merge(file_config);
                }
                Err(e) => {
                    warn!(
                        "Failed to parse config file '{}': {}. Using defaults.",
                        path, e
                    );
                }
            }
        } else {
            info!(
                "Config file '{}' not found. Using defaults and environment variables.",
                path
            );
        }
    }

    // Step 3: Environment variables override everything (12-Factor compliance)
    config.apply_env_overrides();

    info!("Final config (12-Factor):{}", config);
    Ok(config)
}

/// DEPRECATED: Use `load_config_12factor` instead for 12-Factor compliant loading.
///
/// This function loads config from file only, without applying environment overrides.
/// It exists for backwards compatibility but does not follow 12-Factor principles.
#[deprecated(
    since = "0.2.0",
    note = "Use load_config_12factor() for 12-Factor compliant config loading"
)]
pub fn load_config(config_path: &str) -> Result<Config, Box<dyn Error>> {
    Config::from_file(config_path)
}

/// Splits an ID string in "id:version" format into its components.
///
/// # Deprecated
///
/// Use [`crate::validation::split_agent_id`] instead for new code.
#[deprecated(
    since = "0.3.0",
    note = "Use crate::validation::split_agent_id instead"
)]
pub fn split_id(input: &str) -> Option<(&str, &str)> {
    split_agent_id(input)
}

/// Known config fields with their expected formats for helpful error messages
const CONFIG_FIELD_HELP: &[(&str, &str)] = &[
    (
        "jacs_agent_key_algorithm",
        "Expected one of: RSA-PSS, ring-Ed25519, pq-dilithium, pq2025",
    ),
    ("jacs_default_storage", "Expected one of: fs, aws, hai"),
    (
        "jacs_use_security",
        "Expected 'true' or 'false' as a string",
    ),
    ("jacs_data_directory", "Expected a valid directory path"),
    ("jacs_key_directory", "Expected a valid directory path"),
    (
        "jacs_agent_private_key_filename",
        "Expected a filename (e.g., 'rsa_pss_private.pem')",
    ),
    (
        "jacs_agent_public_key_filename",
        "Expected a filename (e.g., 'rsa_pss_public.pem')",
    ),
    (
        "jacs_agent_id_and_version",
        "Expected format: UUID:UUID (e.g., '550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001')",
    ),
    (
        "jacs_agent_domain",
        "Expected a domain name (e.g., 'example.com')",
    ),
    ("jacs_dns_validate", "Expected a boolean (true/false)"),
    ("jacs_dns_strict", "Expected a boolean (true/false)"),
    ("jacs_dns_required", "Expected a boolean (true/false)"),
];

/// Get help text for a config field
fn get_field_help(field_name: &str) -> Option<&'static str> {
    CONFIG_FIELD_HELP
        .iter()
        .find(|(name, _)| field_name.contains(name))
        .map(|(_, help)| *help)
}

/// Format a schema validation error with actionable context
fn format_validation_error(error: &jsonschema::ValidationError, instance: &Value) -> String {
    let path = error.instance_path.to_string();
    let field_name = if path.is_empty() || path == "/" {
        "root".to_string()
    } else {
        path.trim_start_matches('/').to_string()
    };

    // Extract the actual invalid value from the instance using the path
    let invalid_value: Option<String> = if !path.is_empty() && path != "/" {
        // Try to get the value at the path from the instance
        let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let mut current = instance;
        for part in &path_parts {
            if let Some(obj) = current.as_object() {
                if let Some(val) = obj.get(*part) {
                    current = val;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if current != instance {
            let s = current.to_string();
            if s.len() > 50 {
                Some(format!("{}...", &s[..47]))
            } else {
                Some(s)
            }
        } else {
            None
        }
    } else {
        None
    };

    // Build the error message
    let mut msg = format!("Config validation error at '{}': {}", field_name, error);

    // Add the invalid value if we have it
    if let Some(val) = invalid_value {
        msg.push_str(&format!(" (got: {})", val));
    }

    // Add helpful guidance for known fields
    if let Some(help) = get_field_help(&field_name) {
        msg.push_str(&format!(". {}", help));
    }

    // Special handling for missing required fields
    let error_str = error.to_string();
    if error_str.contains("required") {
        // List required fields for context
        msg.push_str(". Required fields: jacs_data_directory, jacs_key_directory, jacs_agent_private_key_filename, jacs_agent_public_key_filename, jacs_agent_key_algorithm, jacs_default_storage");
    }

    // Special handling for enum violations
    if error_str.contains("is not one of") {
        if field_name.contains("jacs_agent_key_algorithm") {
            msg.push_str(". Valid algorithms: RSA-PSS, ring-Ed25519, pq-dilithium, pq2025");
        } else if field_name.contains("jacs_default_storage") {
            msg.push_str(". Valid storage options: fs, aws, hai");
        }
    }

    msg
}

pub fn validate_config(config_json: &str) -> Result<Value, Box<dyn Error>> {
    let jacsconfigschema_result: Value = serde_json::from_str(CONFIG_SCHEMA_STRING)?;

    let jacsconfigschema = Validator::options()
        .with_draft(Draft::Draft7)
        .with_retriever(EmbeddedSchemaResolver::new())
        .build(&jacsconfigschema_result)?;

    let instance: Value = serde_json::from_str(config_json).map_err(|e| {
        // Provide detailed JSON parse error with line/column
        let category = match e.classify() {
            serde_json::error::Category::Io => "IO error",
            serde_json::error::Category::Syntax => "syntax error",
            serde_json::error::Category::Data => "data type error",
            serde_json::error::Category::Eof => "unexpected end of file",
        };
        let err_msg = format!(
            "Config JSON parse error at line {}, column {}: {} - {}. \
            Ensure the config file contains valid JSON syntax (check for missing commas, quotes, or brackets).",
            e.line(),
            e.column(),
            category,
            e
        );
        error!("{}", err_msg);
        Box::<dyn Error>::from(err_msg)
    })?;

    // Validate and provide detailed error messages
    if let Err(e) = jacsconfigschema.validate(&instance) {
        let err_msg = format_validation_error(&e, &instance);
        error!("{}", err_msg);
        return Err(Box::<dyn Error>::from(err_msg));
    }

    Ok(instance)
}

/// DEPRECATED: Use `load_config_12factor_optional` instead.
///
/// Attempts to find and load a config file from the given path.
/// Falls back to Config::default() if file not found.
#[deprecated(
    since = "0.2.0",
    note = "Use load_config_12factor_optional() for 12-Factor compliant config loading"
)]
pub fn find_config(path: String) -> Result<Config, Box<dyn Error>> {
    let config: Config = match fs::read_to_string(format!("{}jacs.config.json", path)) {
        Ok(content) => {
            let validated_value = validate_config(&content)?;
            serde_json::from_value(validated_value)?
        }
        Err(_) => Config::default(),
    };
    Ok(config)
}

/// DEPRECATED: Use `load_config_12factor` instead.
///
/// This function takes config file values and sets them as environment variables,
/// which is the OPPOSITE of 12-Factor principles. Environment variables should
/// be the source of truth, not the target.
///
/// This function is kept for backwards compatibility only. New code should use
/// `load_config_12factor()` which reads env vars INTO config (correct direction).
#[deprecated(
    since = "0.2.0",
    note = "Use load_config_12factor() - env vars should override config, not vice versa"
)]
pub fn set_env_vars(
    do_override: bool,
    config_json: Option<&str>,
    ignore_agent_id: bool,
) -> Result<String, Box<dyn Error>> {
    let config: Config = match config_json {
        Some(json_str) => {
            let validated_value = validate_config(json_str)?;
            serde_json::from_value(validated_value)?
        }
        None => find_config(".".to_string())?,
    };
    // debug!("configs from file {:?}", config);
    validate_config(&serde_json::to_string(&config).map_err(|e| Box::new(e) as Box<dyn Error>)?)?;

    // Security: Password should come from environment variable, not config file
    if config.jacs_private_key_password.is_some() {
        warn!(
            "SECURITY WARNING: Password found in config file. \
            This is insecure - passwords should only be set via JACS_PRIVATE_KEY_PASSWORD \
            environment variable. The password in the config file will be ignored."
        );
    }
    // Do NOT set password from config - it must come from env var only
    // The password will be read directly from env var when needed

    let jacs_use_security = config
        .jacs_use_security
        .as_ref()
        .unwrap_or(&"false".to_string())
        .clone();
    set_env_var_override("JACS_USE_SECURITY", &jacs_use_security, do_override)?;

    let jacs_data_directory = config
        .jacs_data_directory
        .as_ref()
        .unwrap_or(
            &std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "./jacs_data".to_string()),
        )
        .clone();
    set_env_var_override("JACS_DATA_DIRECTORY", &jacs_data_directory, do_override)?;

    let jacs_key_directory = config
        .jacs_key_directory
        .as_ref()
        .unwrap_or(&".".to_string())
        .clone();
    set_env_var_override("JACS_KEY_DIRECTORY", &jacs_key_directory, do_override)?;

    let jacs_agent_private_key_filename = config
        .jacs_agent_private_key_filename
        .as_ref()
        .unwrap_or(&"rsa_pss_private.pem".to_string())
        .clone();
    set_env_var_override(
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        &jacs_agent_private_key_filename,
        do_override,
    )?;

    let jacs_agent_public_key_filename = config
        .jacs_agent_public_key_filename
        .as_ref()
        .unwrap_or(&"rsa_pss_public.pem".to_string())
        .clone();
    set_env_var_override(
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        &jacs_agent_public_key_filename,
        do_override,
    )?;

    let jacs_agent_key_algorithm = config
        .jacs_agent_key_algorithm
        .as_ref()
        .unwrap_or(&"RSA-PSS".to_string())
        .clone();
    set_env_var_override(
        "JACS_AGENT_KEY_ALGORITHM",
        &jacs_agent_key_algorithm,
        do_override,
    )?;

    let jacs_default_storage = config
        .jacs_default_storage
        .as_ref()
        .unwrap_or(&"fs".to_string())
        .clone();
    set_env_var_override("JACS_DEFAULT_STORAGE", &jacs_default_storage, do_override)?;

    let jacs_agent_id_and_version = config
        .jacs_agent_id_and_version
        .as_ref()
        .unwrap_or(&"".to_string())
        .clone();

    if !jacs_agent_id_and_version.is_empty() {
        if let Some((id, version)) = split_agent_id(&jacs_agent_id_and_version) {
            if !are_valid_uuid_parts(id, version) {
                warn!("ID and Version must be in the form UUID:UUID");
            }
        } else {
            warn!("ID and Version must be in the form UUID:UUID");
        }
    }

    set_env_var_override(
        "JACS_AGENT_ID_AND_VERSION",
        &jacs_agent_id_and_version,
        do_override,
    )?;

    let message = format!("{}", config);
    info!("{}", message);
    check_env_vars(ignore_agent_id).map_err(|e| {
        error!("Error checking environment variables: {}", e);
        Box::new(e) as Box<dyn Error>
    })?;
    Ok(message)
}

pub fn check_env_vars(ignore_agent_id: bool) -> Result<String, EnvError> {
    let vars = [
        ("JACS_USE_SECURITY", true),
        ("JACS_DATA_DIRECTORY", true),
        ("JACS_KEY_DIRECTORY", true),
        ("JACS_AGENT_PRIVATE_KEY_FILENAME", true),
        ("JACS_AGENT_PUBLIC_KEY_FILENAME", true),
        ("JACS_AGENT_KEY_ALGORITHM", true),
        ("JACS_PRIVATE_KEY_PASSWORD", true),
        ("JACS_AGENT_ID_AND_VERSION", true),
    ];

    let mut message = String::from("\nChecking JACS environment variables:\n");
    let mut missing_vars = Vec::new();

    for (var_name, required) in vars.iter() {
        if var_name == &"JACS_AGENT_ID_AND_VERSION" && ignore_agent_id {
            message.push_str(&format!(
                "    {:<35} {}\n",
                var_name.to_string() + ":",
                "SKIPPED (ignore_agent_id=true)"
            ));
            continue;
        }

        let value = get_env_var(var_name, *required)?;
        let status = match value {
            Some(val) => val,
            None => {
                if *required {
                    missing_vars.push(var_name);
                }
                "MISSING".to_string()
            }
        };
        message.push_str(&format!(
            "    {:<35} {}\n",
            var_name.to_string() + ":",
            status
        ));
    }

    if !missing_vars.is_empty() {
        message.push_str("\nMissing required environment variables:\n");
        for var in missing_vars {
            message.push_str(&format!("    {}\n", var));
        }
    }

    Ok(message)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub logs: LogConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tracing: Option<TracingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_destination")]
    pub destination: LogDestination,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::Stderr,
            headers: None,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_destination() -> LogDestination {
    LogDestination::Stderr
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub destination: MetricsDestination,
    pub export_interval_seconds: Option<u64>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
            headers: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    #[serde(default)]
    pub sampling: SamplingConfig,
    #[serde(default)]
    pub resource: Option<ResourceConfig>,
    #[serde(default)]
    pub destination: Option<TracingDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    #[serde(default = "default_sampling_ratio")]
    pub ratio: f64,
    #[serde(default)]
    pub parent_based: bool,
    #[serde(default)]
    pub rate_limit: Option<u32>, // samples per second
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            ratio: 1.0, // Sample everything by default
            parent_based: true,
            rate_limit: None,
        }
    }
}

fn default_sampling_ratio() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub service_name: String,
    pub service_version: Option<String>,
    pub environment: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

// Update the destination enums to support headers
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogDestination {
    #[serde(rename = "stderr")]
    Stderr,
    #[serde(rename = "file")]
    File { path: String },
    #[serde(rename = "otlp")]
    Otlp {
        endpoint: String,
        #[serde(default)]
        headers: Option<HashMap<String, String>>,
    },
    #[serde(rename = "null")]
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum MetricsDestination {
    #[serde(rename = "otlp")]
    Otlp {
        endpoint: String,
        #[serde(default)]
        headers: Option<HashMap<String, String>>,
    },
    #[serde(rename = "prometheus")]
    Prometheus {
        endpoint: String,
        #[serde(default)]
        headers: Option<HashMap<String, String>>,
    },
    #[serde(rename = "file")]
    File { path: String },
    #[serde(rename = "stdout")]
    #[default]
    Stdout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TracingDestination {
    #[serde(rename = "otlp")]
    Otlp {
        endpoint: String,
        #[serde(default)]
        headers: Option<HashMap<String, String>>,
    },
    #[serde(rename = "jaeger")]
    Jaeger {
        endpoint: String,
        #[serde(default)]
        headers: Option<HashMap<String, String>>,
    },
}

impl Default for TracingDestination {
    fn default() -> Self {
        TracingDestination::Otlp {
            endpoint: "http://localhost:4318".to_string(),
            headers: None,
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::storage::jenv::{clear_env_var, set_env_var};
    use serial_test::serial;

    /// Helper to clear all JACS env vars for test isolation
    fn clear_jacs_env_vars() {
        let vars = [
            "JACS_USE_SECURITY",
            "JACS_DATA_DIRECTORY",
            "JACS_KEY_DIRECTORY",
            "JACS_AGENT_PRIVATE_KEY_FILENAME",
            "JACS_AGENT_PUBLIC_KEY_FILENAME",
            "JACS_AGENT_KEY_ALGORITHM",
            "JACS_PRIVATE_KEY_PASSWORD",
            "JACS_AGENT_ID_AND_VERSION",
            "JACS_DEFAULT_STORAGE",
            "JACS_AGENT_DOMAIN",
            "JACS_DNS_VALIDATE",
            "JACS_DNS_STRICT",
            "JACS_DNS_REQUIRED",
        ];
        for var in vars {
            let _ = clear_env_var(var);
        }
    }

    #[test]
    fn test_config_with_defaults() {
        // This test doesn't use env vars, so no serial needed
        let config = Config::with_defaults();
        assert_eq!(config.jacs_use_security, Some("false".to_string()));
        assert_eq!(config.jacs_data_directory, Some("./jacs_data".to_string()));
        assert_eq!(config.jacs_key_directory, Some("./jacs_keys".to_string()));
        assert_eq!(config.jacs_agent_key_algorithm, Some("RSA-PSS".to_string()));
        assert_eq!(config.jacs_default_storage, Some("fs".to_string()));
        // Password should never be in config
        assert!(config.jacs_private_key_password.is_none());
    }

    #[test]
    fn test_config_merge() {
        // This test doesn't use env vars, so no serial needed
        let mut base = Config::with_defaults();
        let override_config = Config {
            schema: default_schema(),
            jacs_use_security: Some("true".to_string()),
            jacs_data_directory: Some("/custom/data".to_string()),
            jacs_key_directory: None, // Should not override
            jacs_agent_private_key_filename: Some("custom.pem".to_string()),
            jacs_agent_public_key_filename: None,
            jacs_agent_key_algorithm: Some("pq2025".to_string()),
            jacs_private_key_password: None,
            jacs_agent_id_and_version: None,
            jacs_default_storage: None, // Should not override
            jacs_agent_domain: Some("example.com".to_string()),
            jacs_dns_validate: Some(true),
            jacs_dns_strict: None,
            jacs_dns_required: None,
            observability: None,
            jacs_database_url: None,
            jacs_database_max_connections: None,
            jacs_database_min_connections: None,
            jacs_database_connect_timeout_secs: None,
        };

        base.merge(override_config);

        // Values that were Some should be overridden
        assert_eq!(base.jacs_use_security, Some("true".to_string()));
        assert_eq!(base.jacs_data_directory, Some("/custom/data".to_string()));
        assert_eq!(
            base.jacs_agent_private_key_filename,
            Some("custom.pem".to_string())
        );
        assert_eq!(base.jacs_agent_key_algorithm, Some("pq2025".to_string()));
        assert_eq!(base.jacs_agent_domain, Some("example.com".to_string()));
        assert_eq!(base.jacs_dns_validate, Some(true));

        // Values that were None should retain original
        assert_eq!(base.jacs_key_directory, Some("./jacs_keys".to_string()));
        assert_eq!(base.jacs_default_storage, Some("fs".to_string()));
    }

    #[test]
    #[serial]
    fn test_apply_env_overrides() {
        clear_jacs_env_vars();

        // Set some env vars
        set_env_var("JACS_DATA_DIRECTORY", "/env/data").unwrap();
        set_env_var("JACS_AGENT_KEY_ALGORITHM", "Ed25519").unwrap();
        set_env_var("JACS_DNS_VALIDATE", "true").unwrap();
        set_env_var("JACS_DNS_STRICT", "1").unwrap();

        let mut config = Config::with_defaults();
        config.apply_env_overrides();

        // Env vars should override defaults
        assert_eq!(config.jacs_data_directory, Some("/env/data".to_string()));
        assert_eq!(config.jacs_agent_key_algorithm, Some("Ed25519".to_string()));
        assert_eq!(config.jacs_dns_validate, Some(true));
        assert_eq!(config.jacs_dns_strict, Some(true));

        // Values not in env should remain default
        assert_eq!(config.jacs_key_directory, Some("./jacs_keys".to_string()));
        assert_eq!(config.jacs_default_storage, Some("fs".to_string()));

        clear_jacs_env_vars();
    }

    #[test]
    #[serial]
    fn test_env_overrides_config_file() {
        clear_jacs_env_vars();

        // Simulate: defaults -> config file -> env vars
        // Config file would set algorithm to pq2025
        // Env var should override to Ed25519

        let mut config = Config::with_defaults();

        // Simulate config file merge
        let file_config = Config {
            schema: default_schema(),
            jacs_use_security: None,
            jacs_data_directory: Some("/config/data".to_string()),
            jacs_key_directory: Some("/config/keys".to_string()),
            jacs_agent_private_key_filename: None,
            jacs_agent_public_key_filename: None,
            jacs_agent_key_algorithm: Some("pq2025".to_string()),
            jacs_private_key_password: None,
            jacs_agent_id_and_version: None,
            jacs_default_storage: None,
            jacs_agent_domain: None,
            jacs_dns_validate: None,
            jacs_dns_strict: None,
            jacs_dns_required: None,
            observability: None,
            jacs_database_url: None,
            jacs_database_max_connections: None,
            jacs_database_min_connections: None,
            jacs_database_connect_timeout_secs: None,
        };
        config.merge(file_config);

        // At this point, config has file values
        assert_eq!(config.jacs_data_directory, Some("/config/data".to_string()));
        assert_eq!(config.jacs_agent_key_algorithm, Some("pq2025".to_string()));

        // Now env vars override (12-Factor: env vars win)
        set_env_var("JACS_AGENT_KEY_ALGORITHM", "ring-Ed25519").unwrap();
        set_env_var("JACS_DATA_DIRECTORY", "/env/override/data").unwrap();

        config.apply_env_overrides();

        // Env vars should win (12-Factor compliance)
        assert_eq!(
            config.jacs_agent_key_algorithm,
            Some("ring-Ed25519".to_string())
        );
        assert_eq!(
            config.jacs_data_directory,
            Some("/env/override/data".to_string())
        );

        // Config file value not overridden by env should remain
        assert_eq!(config.jacs_key_directory, Some("/config/keys".to_string()));

        clear_jacs_env_vars();
    }

    #[test]
    #[serial]
    fn test_load_config_12factor_no_file() {
        clear_jacs_env_vars();

        // Set env vars
        set_env_var("JACS_USE_SECURITY", "true").unwrap();
        set_env_var("JACS_DATA_DIRECTORY", "/production/data").unwrap();

        // Load without config file
        let config = load_config_12factor(None).expect("Should load successfully");

        // Should have defaults overridden by env vars
        assert_eq!(config.jacs_use_security, Some("true".to_string()));
        assert_eq!(
            config.jacs_data_directory,
            Some("/production/data".to_string())
        );
        // Non-overridden defaults
        assert_eq!(config.jacs_key_directory, Some("./jacs_keys".to_string()));

        clear_jacs_env_vars();
    }

    #[test]
    #[serial]
    fn test_load_config_12factor_optional_missing_file() {
        clear_jacs_env_vars();

        // Set env vars
        set_env_var("JACS_AGENT_KEY_ALGORITHM", "pq2025").unwrap();

        // Load with non-existent config file - should NOT fail
        let config = load_config_12factor_optional(Some("/nonexistent/config.json"))
            .expect("Should load successfully even with missing file");

        // Should have defaults overridden by env vars
        assert_eq!(config.jacs_agent_key_algorithm, Some("pq2025".to_string()));
        assert_eq!(config.jacs_use_security, Some("false".to_string())); // default

        clear_jacs_env_vars();
    }

    #[test]
    #[serial]
    fn test_boolean_env_var_parsing() {
        clear_jacs_env_vars();

        // Test various boolean representations
        let mut config = Config::with_defaults();

        set_env_var("JACS_DNS_VALIDATE", "true").unwrap();
        config.apply_env_overrides();
        assert_eq!(config.jacs_dns_validate, Some(true));

        set_env_var("JACS_DNS_VALIDATE", "TRUE").unwrap();
        config.apply_env_overrides();
        assert_eq!(config.jacs_dns_validate, Some(true));

        set_env_var("JACS_DNS_VALIDATE", "1").unwrap();
        config.apply_env_overrides();
        assert_eq!(config.jacs_dns_validate, Some(true));

        set_env_var("JACS_DNS_VALIDATE", "false").unwrap();
        config.apply_env_overrides();
        assert_eq!(config.jacs_dns_validate, Some(false));

        set_env_var("JACS_DNS_VALIDATE", "0").unwrap();
        config.apply_env_overrides();
        assert_eq!(config.jacs_dns_validate, Some(false));

        clear_jacs_env_vars();
    }

    #[test]
    fn test_config_builder_defaults() {
        // Builder with no options set should produce sensible defaults
        let config = Config::builder().build();

        assert_eq!(config.jacs_use_security, Some("false".to_string()));
        assert_eq!(config.jacs_data_directory, Some("./jacs_data".to_string()));
        assert_eq!(config.jacs_key_directory, Some("./jacs_keys".to_string()));
        assert_eq!(config.jacs_agent_key_algorithm, Some("RSA-PSS".to_string()));
        assert_eq!(config.jacs_default_storage, Some("fs".to_string()));
        // Password should never be in config
        assert!(config.jacs_private_key_password.is_none());
        // Optional fields should be None
        assert!(config.jacs_agent_private_key_filename.is_none());
        assert!(config.jacs_agent_public_key_filename.is_none());
        assert!(config.jacs_agent_id_and_version.is_none());
        assert!(config.jacs_agent_domain.is_none());
    }

    #[test]
    fn test_config_builder_custom_values() {
        let config = Config::builder()
            .key_algorithm("Ed25519")
            .key_directory("/custom/keys")
            .data_directory("/custom/data")
            .default_storage("memory")
            .use_security(true)
            .private_key_filename("my_private.pem")
            .public_key_filename("my_public.pem")
            .agent_id_and_version(
                "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001",
            )
            .agent_domain("example.com")
            .dns_validate(true)
            .dns_strict(false)
            .dns_required(true)
            .build();

        assert_eq!(config.jacs_agent_key_algorithm, Some("Ed25519".to_string()));
        assert_eq!(config.jacs_key_directory, Some("/custom/keys".to_string()));
        assert_eq!(config.jacs_data_directory, Some("/custom/data".to_string()));
        assert_eq!(config.jacs_default_storage, Some("memory".to_string()));
        assert_eq!(config.jacs_use_security, Some("true".to_string()));
        assert_eq!(
            config.jacs_agent_private_key_filename,
            Some("my_private.pem".to_string())
        );
        assert_eq!(
            config.jacs_agent_public_key_filename,
            Some("my_public.pem".to_string())
        );
        assert_eq!(
            config.jacs_agent_id_and_version,
            Some(
                "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001"
                    .to_string()
            )
        );
        assert_eq!(config.jacs_agent_domain, Some("example.com".to_string()));
        assert_eq!(config.jacs_dns_validate, Some(true));
        assert_eq!(config.jacs_dns_strict, Some(false));
        assert_eq!(config.jacs_dns_required, Some(true));
    }

    #[test]
    fn test_config_builder_partial() {
        // Test that partial configuration works - only set some values
        let config = Config::builder()
            .key_algorithm("pq2025")
            .use_security(true)
            .build();

        // Explicitly set values
        assert_eq!(config.jacs_agent_key_algorithm, Some("pq2025".to_string()));
        assert_eq!(config.jacs_use_security, Some("true".to_string()));

        // Default values for unset fields
        assert_eq!(config.jacs_data_directory, Some("./jacs_data".to_string()));
        assert_eq!(config.jacs_key_directory, Some("./jacs_keys".to_string()));
        assert_eq!(config.jacs_default_storage, Some("fs".to_string()));
    }

    #[test]
    fn test_config_builder_method_chaining() {
        // Ensure method chaining works correctly
        let builder = ConfigBuilder::new()
            .key_algorithm("Ed25519")
            .key_directory("/keys")
            .data_directory("/data");

        let config = builder.build();

        assert_eq!(config.jacs_agent_key_algorithm, Some("Ed25519".to_string()));
        assert_eq!(config.jacs_key_directory, Some("/keys".to_string()));
        assert_eq!(config.jacs_data_directory, Some("/data".to_string()));
    }

    #[test]
    fn test_config_builder_vs_with_defaults() {
        // Builder defaults should match with_defaults() for the core fields
        let builder_config = Config::builder().build();
        let defaults_config = Config::with_defaults();

        // Core fields should have same default values
        assert_eq!(
            builder_config.jacs_use_security,
            defaults_config.jacs_use_security
        );
        assert_eq!(
            builder_config.jacs_agent_key_algorithm,
            defaults_config.jacs_agent_key_algorithm
        );
        assert_eq!(
            builder_config.jacs_default_storage,
            defaults_config.jacs_default_storage
        );
        // Note: data_directory and key_directory may differ due to CWD resolution
        // in with_defaults(), but builder uses static defaults
    }

    #[test]
    fn test_validate_config_invalid_json_error_message() {
        // Test that JSON parse errors include line/column info
        let invalid_json = r#"{
  "jacs_data_directory": "/data",
  "jacs_key_directory": "/keys"
  "jacs_agent_key_algorithm": "RSA-PSS"
}"#;
        let result = validate_config(invalid_json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Should include line number, column, and helpful message
        assert!(
            err.contains("line"),
            "Error should include line number: {}",
            err
        );
        assert!(
            err.contains("column"),
            "Error should include column: {}",
            err
        );
        assert!(
            err.contains("syntax"),
            "Error should mention syntax issue: {}",
            err
        );
        assert!(err.contains("JSON"), "Error should mention JSON: {}", err);
    }

    #[test]
    fn test_validate_config_invalid_algorithm_error_message() {
        // Test that invalid enum values show valid options
        let invalid_algo = r#"{
  "jacs_data_directory": "/data",
  "jacs_key_directory": "/keys",
  "jacs_agent_private_key_filename": "private.pem",
  "jacs_agent_public_key_filename": "public.pem",
  "jacs_agent_key_algorithm": "INVALID_ALGO",
  "jacs_default_storage": "fs"
}"#;
        let result = validate_config(invalid_algo);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Should mention the field name and valid options
        assert!(
            err.contains("jacs_agent_key_algorithm"),
            "Error should mention field name: {}",
            err
        );
        assert!(
            err.contains("RSA-PSS") || err.contains("Valid algorithms"),
            "Error should mention valid algorithms: {}",
            err
        );
    }

    #[test]
    fn test_validate_config_missing_required_field_error_message() {
        // Test that missing required fields are clearly indicated
        let missing_field = r#"{
  "jacs_data_directory": "/data"
}"#;
        let result = validate_config(missing_field);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Should mention required fields
        assert!(
            err.contains("required") || err.contains("Required"),
            "Error should mention required fields: {}",
            err
        );
    }

    #[test]
    fn test_validate_config_invalid_storage_error_message() {
        // Test that invalid storage values show valid options
        let invalid_storage = r#"{
  "jacs_data_directory": "/data",
  "jacs_key_directory": "/keys",
  "jacs_agent_private_key_filename": "private.pem",
  "jacs_agent_public_key_filename": "public.pem",
  "jacs_agent_key_algorithm": "RSA-PSS",
  "jacs_default_storage": "invalid_storage"
}"#;
        let result = validate_config(invalid_storage);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Should mention the field name
        assert!(
            err.contains("jacs_default_storage"),
            "Error should mention field name: {}",
            err
        );
        assert!(
            err.contains("fs") || err.contains("Valid storage"),
            "Error should mention valid storage options: {}",
            err
        );
    }

    #[test]
    fn test_config_from_file_not_found_error_message() {
        // Test that file not found errors are actionable
        let result = Config::from_file("/nonexistent/path/jacs.config.json");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Should include path and guidance
        assert!(
            err.contains("nonexistent"),
            "Error should include path: {}",
            err
        );
        assert!(
            err.contains("environment") || err.contains("not found"),
            "Error should provide guidance: {}",
            err
        );
    }

    #[test]
    fn test_get_field_help() {
        // Test the field help function returns appropriate guidance
        assert!(
            get_field_help("jacs_agent_key_algorithm")
                .unwrap()
                .contains("RSA-PSS")
        );
        assert!(
            get_field_help("jacs_default_storage")
                .unwrap()
                .contains("fs")
        );
        assert!(
            get_field_help("jacs_data_directory")
                .unwrap()
                .contains("path")
        );
        assert!(
            get_field_help("jacs_agent_id_and_version")
                .unwrap()
                .contains("UUID")
        );
        assert!(get_field_help("unknown_field").is_none());
    }

    // =========================================================================
    // Key Resolution Order Tests
    // =========================================================================

    #[test]
    fn test_key_resolution_source_from_str() {
        assert_eq!(
            KeyResolutionSource::from_str("local").unwrap(),
            KeyResolutionSource::Local
        );
        assert_eq!(
            KeyResolutionSource::from_str("LOCAL").unwrap(),
            KeyResolutionSource::Local
        );
        assert_eq!(
            KeyResolutionSource::from_str("Local").unwrap(),
            KeyResolutionSource::Local
        );
        assert_eq!(
            KeyResolutionSource::from_str("dns").unwrap(),
            KeyResolutionSource::Dns
        );
        assert_eq!(
            KeyResolutionSource::from_str("DNS").unwrap(),
            KeyResolutionSource::Dns
        );
        assert_eq!(
            KeyResolutionSource::from_str("hai").unwrap(),
            KeyResolutionSource::Hai
        );
        assert_eq!(
            KeyResolutionSource::from_str("HAI").unwrap(),
            KeyResolutionSource::Hai
        );
        assert_eq!(
            KeyResolutionSource::from_str(" hai ").unwrap(),
            KeyResolutionSource::Hai
        );

        // Invalid sources
        assert!(KeyResolutionSource::from_str("invalid").is_err());
        assert!(KeyResolutionSource::from_str("").is_err());
    }

    #[test]
    fn test_key_resolution_source_display() {
        assert_eq!(format!("{}", KeyResolutionSource::Local), "local");
        assert_eq!(format!("{}", KeyResolutionSource::Dns), "dns");
        assert_eq!(format!("{}", KeyResolutionSource::Hai), "hai");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_default() {
        clear_jacs_env_vars();
        let _ = clear_env_var("JACS_KEY_RESOLUTION");

        let order = get_key_resolution_order();
        assert_eq!(
            order,
            vec![KeyResolutionSource::Local, KeyResolutionSource::Hai]
        );
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_local_only() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", "local").unwrap();

        let order = get_key_resolution_order();
        assert_eq!(order, vec![KeyResolutionSource::Local]);

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_hai_only() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", "hai").unwrap();

        let order = get_key_resolution_order();
        assert_eq!(order, vec![KeyResolutionSource::Hai]);

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_with_dns() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", "local,dns,hai").unwrap();

        let order = get_key_resolution_order();
        assert_eq!(
            order,
            vec![
                KeyResolutionSource::Local,
                KeyResolutionSource::Dns,
                KeyResolutionSource::Hai,
            ]
        );

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_case_insensitive() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", "LOCAL,DNS,HAI").unwrap();

        let order = get_key_resolution_order();
        assert_eq!(
            order,
            vec![
                KeyResolutionSource::Local,
                KeyResolutionSource::Dns,
                KeyResolutionSource::Hai,
            ]
        );

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_skips_invalid() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", "local,invalid,hai").unwrap();

        let order = get_key_resolution_order();
        // Should skip "invalid" but include valid sources
        assert_eq!(
            order,
            vec![KeyResolutionSource::Local, KeyResolutionSource::Hai]
        );

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_all_invalid_falls_back() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", "invalid,also_invalid").unwrap();

        let order = get_key_resolution_order();
        // Should fall back to default when all sources are invalid
        assert_eq!(
            order,
            vec![KeyResolutionSource::Local, KeyResolutionSource::Hai]
        );

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_empty_string_falls_back() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", "").unwrap();

        let order = get_key_resolution_order();
        // Should fall back to default for empty string
        assert_eq!(
            order,
            vec![KeyResolutionSource::Local, KeyResolutionSource::Hai]
        );

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }

    #[test]
    #[serial]
    fn test_get_key_resolution_order_whitespace_handling() {
        clear_jacs_env_vars();
        set_env_var("JACS_KEY_RESOLUTION", " local , hai ").unwrap();

        let order = get_key_resolution_order();
        assert_eq!(
            order,
            vec![KeyResolutionSource::Local, KeyResolutionSource::Hai]
        );

        let _ = clear_env_var("JACS_KEY_RESOLUTION");
    }
}
