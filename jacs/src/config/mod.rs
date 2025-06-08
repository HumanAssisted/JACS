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
use tracing::{error, info, warn};
use uuid::Uuid;

pub mod constants;

/*
Config is embedded in agents and may have private information.

It can be
1. loadded from json
2. values from environment variables (useful for secrets)

The difficult part is bootstrapping an agent.

The agent file itself is NOT private (the .value field in the agent struct)
Each config _may_ be loaded from a file, or from environment variables.
For example, create_agent_and_load() does not neeed a config file at all?

*/

#[derive(Serialize, Deserialize, Default, Debug, Getters)]
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
    #[getset(get)]
    jacs_private_key_password: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_id_and_version: Option<String>,
    #[getset(get = "pub")]
    #[serde(default = "default_storage")]
    jacs_default_storage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilityConfig>,
}

fn default_schema() -> String {
    "https://hai.ai/schemas/jacs.config.schema.json".to_string()
}

// TODO change these to macros
fn default_storage() -> Option<String> {
    match get_env_var("JACS_DEFAULT_STORAGE", false) {
        Ok(Some(val)) if !val.is_empty() => Some(val),
        _ => Some("fs".to_string()),
    }
}

fn default_algorithm() -> Option<String> {
    match get_env_var("JACS_AGENT_KEY_ALGORITHM", false) {
        Ok(Some(val)) if !val.is_empty() => Some(val),
        _ => Some("RSA-PSS".to_string()),
    }
}

fn default_security() -> Option<String> {
    match get_env_var("JACS_USE_SECURITY", false) {
        Ok(Some(val)) if !val.is_empty() => Some(val),
        _ => Some("false".to_string()),
    }
}

fn default_data_directory() -> Option<String> {
    match get_env_var("JACS_DATA_DIRECTORY", false) {
        Ok(Some(val)) if !val.is_empty() => Some(val),
        _ => {
            if default_storage() == Some("fs".to_string()) {
                let cur_dir = std::env::current_dir().unwrap();
                let data_dir = cur_dir.join("jacs_data");
                Some(data_dir.to_string_lossy().to_string())
            } else {
                Some("./jacs_data".to_string())
            }
        }
    }
}

fn default_key_directory() -> Option<String> {
    match get_env_var("JACS_KEY_DIRECTORY", false) {
        Ok(Some(val)) if !val.is_empty() => Some(val),
        _ => {
            if default_storage() == Some("fs".to_string()) {
                let cur_dir = std::env::current_dir().unwrap();
                let data_dir = cur_dir.join("jacs_keys");
                Some(data_dir.to_string_lossy().to_string())
            } else {
                Some("./jacs_keys".to_string())
            }
        }
    }
}

impl Config {
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
        Config {
            schema: default_schema(),
            jacs_use_security,
            jacs_data_directory,
            jacs_key_directory,
            jacs_agent_private_key_filename,
            jacs_agent_public_key_filename,
            jacs_agent_key_algorithm,
            jacs_private_key_password,
            jacs_agent_id_and_version,
            jacs_default_storage,
            observability: None,
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
            self.jacs_default_storage.as_deref().unwrap_or("")
        )
    }
}

// the simplest way to load a config is to pass in a path to a config file
// the config is stored in the agent, no need to use ENV vars
pub fn load_config(config_path: &str) -> Result<Config, Box<dyn Error>> {
    let json_str = fs::read_to_string(config_path)?;
    let validated_value: Value = validate_config(&json_str)?;
    let config: Config = serde_json::from_value(validated_value)?;
    Ok(config)
}

pub fn split_id(input: &str) -> Option<(&str, &str)> {
    if !input.is_empty() && input.contains(':') {
        let mut parts = input.splitn(2, ':');
        let first = parts.next();
        let second = parts.next();
        match (first, second) {
            (Some(first), Some(second)) => Some((first, second)),
            _ => None, // In case the split fails unexpectedly or there's only one part
        }
    } else {
        None // If input is empty or does not contain ':'
    }
}

pub fn validate_config(config_json: &str) -> Result<Value, Box<dyn Error>> {
    let jacsconfigschema_result: Value = serde_json::from_str(CONFIG_SCHEMA_STRING)?;

    let jacsconfigschema = Validator::options()
        .with_draft(Draft::Draft7)
        .with_retriever(EmbeddedSchemaResolver::new())
        .build(&jacsconfigschema_result)?;

    let instance: Value = serde_json::from_str(config_json).map_err(|e| {
        error!("Invalid JSON: {}", e);
        e
    })?;

    //debug!("validate json {:?}", instance);

    // Validate and map any error into an owned error (a boxed String error).
    jacsconfigschema.validate(&instance).map_err(|e| {
        let err_msg = format!("Error validating config file: {}", e);
        error!("{}", err_msg);
        Box::<dyn Error>::from(err_msg)
    })?;

    Ok(instance)
}

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

// TODO DEPRICATE - focuse on configs created from env vars as backup
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

    let jacs_private_key_password = config
        .jacs_private_key_password
        .as_ref()
        .unwrap_or(&"true".to_string())
        .clone();
    set_env_var_override(
        "JACS_PRIVATE_KEY_PASSWORD",
        &jacs_private_key_password,
        do_override,
    )?;

    let jacs_use_security = config
        .jacs_use_security
        .as_ref()
        .unwrap_or(&"false".to_string())
        .clone();
    set_env_var_override("JACS_USE_SECURITY", &jacs_use_security, do_override)?;

    let jacs_data_directory = config
        .jacs_data_directory
        .as_ref()
        .unwrap_or(&format!("{:?}", std::env::current_dir().unwrap()))
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
        let (id, version) = split_id(&jacs_agent_id_and_version).unwrap_or(("", ""));
        if !Uuid::parse_str(id).is_ok() || !Uuid::parse_str(version).is_ok() {
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
                "SKIPPED (ignore_agent_id=true)".to_string()
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    Stdout,
}

impl Default for MetricsDestination {
    fn default() -> Self {
        MetricsDestination::Stdout
    }
}
