use crate::schema::utils::{CONFIG_SCHEMA_STRING, EmbeddedSchemaResolver};
use crate::storage::jenv::{EnvError, get_env_var, set_env_var, set_env_var_override};
use getset::Getters;
use jsonschema::{Draft, Validator};
use log::{debug, error, info};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

pub mod constants;
/*
Config is embedded agents and may have private information
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
    #[getset(get)]
    jacs_use_security: Option<String>,
    #[getset(get = "pub")]
    jacs_data_directory: Option<String>,
    #[getset(get = "pub")]
    jacs_key_directory: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_private_key_filename: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_public_key_filename: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_key_algorithm: Option<String>,
    #[getset(get)]
    jacs_private_key_password: Option<String>,
    #[getset(get = "pub")]
    jacs_agent_id_and_version: Option<String>,
    #[getset(get = "pub")]
    jacs_default_storage: Option<String>,
}

fn default_schema() -> String {
    "https://hai.ai/schemas/jacs.config.schema.json".to_string()
}

pub struct ConfigKey {
    pub key: &'static str,
    pub env_var: &'static str,
    pub required: bool,
    pub default: Option<&'static str>,
}

pub static ALL_CONFIG_KEYS: &[ConfigKey] = &[
    ConfigKey {
        key: "jacs_use_security",
        env_var: "JACS_USE_SECURITY",
        required: true,
        default: Some("true"),
    },
    ConfigKey {
        key: "jacs_data_directory",
        env_var: "JACS_DATA_DIRECTORY",
        required: true,
        default: Some("./jacs_data"),
    },
    ConfigKey {
        key: "jacs_key_directory",
        env_var: "JACS_KEY_DIRECTORY",
        required: true,
        default: Some("./jacs_keys"),
    },
    ConfigKey {
        key: "jacs_agent_private_key_filename",
        env_var: "JACS_AGENT_PRIVATE_KEY_FILENAME",
        required: true,
        default: Some("rsa_pss_private.pem"),
    },
    ConfigKey {
        key: "jacs_agent_public_key_filename",
        env_var: "JACS_AGENT_PUBLIC_KEY_FILENAME",
        required: true,
        default: Some("rsa_pss_public.pem"),
    },
    ConfigKey {
        key: "jacs_agent_key_algorithm",
        env_var: "JACS_AGENT_KEY_ALGORITHM",
        required: true,
        default: Some("RSA-PSS"),
    },
    ConfigKey {
        key: "jacs_private_key_password",
        env_var: "JACS_PRIVATE_KEY_PASSWORD",
        required: true,
        default: None,
    },
    ConfigKey {
        key: "jacs_agent_id_and_version",
        env_var: "JACS_AGENT_ID_AND_VERSION",
        required: true,
        default: None,
    },
    ConfigKey {
        key: "jacs_default_storage",
        env_var: "JACS_DEFAULT_STORAGE",
        required: true,
        default: Some("fs"),
    },
];

/// Finds a ConfigKey definition by its JSON/struct key name.
pub fn get_config_key(key: &str) -> Option<&'static ConfigKey> {
    ALL_CONFIG_KEYS
        .iter()
        .find(|&config_key| config_key.key == key)
}

pub fn get_config_key_default(key: &str) -> Option<String> {
    get_config_key(key).and_then(|config_key| config_key.default.map(|s| s.to_string()))
}

pub fn get_config_key_env_var(key: &str) -> Option<&'static str> {
    get_config_key(key).map(|config_key| config_key.env_var)
}

pub fn get_config_key_required(key: &str) -> bool {
    get_config_key(key).map_or(false, |config_key| config_key.required)
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
        }
    }

    pub fn find_config_value(&self, key: &str) -> Result<String, Box<dyn Error>> {
        // 1. Find the config key metadata
        let config_key =
            get_config_key(key).ok_or_else(|| format!("Invalid configuration key: {}", key))?;

        // 2. Check the value in the provided Config struct
        let struct_value_opt: Option<String> = match config_key.key {
            "jacs_use_security" => self.jacs_use_security().as_ref().map(|s| s.clone()),
            "jacs_data_directory" => self.jacs_data_directory().as_ref().map(|s| s.clone()),
            "jacs_key_directory" => self.jacs_key_directory().as_ref().map(|s| s.clone()),
            "jacs_agent_private_key_filename" => self
                .jacs_agent_private_key_filename()
                .as_ref()
                .map(|s| s.clone()),
            "jacs_agent_public_key_filename" => self
                .jacs_agent_public_key_filename()
                .as_ref()
                .map(|s| s.clone()),
            "jacs_agent_key_algorithm" => {
                self.jacs_agent_key_algorithm().as_ref().map(|s| s.clone())
            }
            "jacs_private_key_password" => self.jacs_private_key_password.clone(), // No getter, direct access
            "jacs_agent_id_and_version" => {
                self.jacs_agent_id_and_version().as_ref().map(|s| s.clone())
            }
            "jacs_default_storage" => self.jacs_default_storage().as_ref().map(|s| s.clone()),
            _ => None, // Should not happen
        };

        if let Some(value) = struct_value_opt {
            return Ok(value);
        }

        // 3. If not in struct, get from environment variable or use default
        match get_env_var(config_key.env_var, config_key.required) {
            Ok(Some(env_val)) => Ok(env_val), // Found in env
            Ok(None) => {
                // Not found in env, and was not required
                // Return default value or empty string
                Ok(config_key.default.unwrap_or("").to_string())
            }
            Err(e) => {
                // Error occurred (e.g., required but not found)
                Err(Box::new(e) as Box<dyn Error>)
            }
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
        Loading JACS config variables of:
            JACS_USE_SECURITY:                {},
            JACS_DATA_DIRECTORY:             {},
            JACS_KEY_DIRECTORY:              {},
            JACS_AGENT_PRIVATE_KEY_FILENAME: {},
            JACS_AGENT_PUBLIC_KEY_FILENAME:  {},
            JACS_AGENT_KEY_ALGORITHM:        {},
            JACS_PRIVATE_KEY_PASSWORD:       {},
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
            self.jacs_private_key_password.as_deref().unwrap_or(""),
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

// pub fn create_config_from_env_vars() -> Result<Config, Box<dyn Error>> {
//     let config = Config::new(
//             default_schema(),
//         "https://hai.ai/schemas/jacs.config.schema.json".to_string(),
//         get_env_var("JACS_USE_SECURITY", false)?,
//         get_env_var("JACS_DATA_DIRECTORY", false)?,
//     );
// }

pub fn get_default_dir() -> PathBuf {
    match get_env_var("JACS_DATA_DIRECTORY", false) {
        Ok(Some(dir)) => PathBuf::from(dir),
        _ => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = set_env_var("JACS_DATA_DIRECTORY", ".");
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            }
            #[cfg(target_arch = "wasm32")]
            {
                PathBuf::from(".")
            }
        }
    }
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

    debug!("validate json {:?}", instance);

    // Validate and map any error into an owned error (a boxed String error).
    jacsconfigschema.validate(&instance).map_err(|e| {
        let err_msg = format!("Error validating config file: {}", e);
        error!("{}", err_msg);
        Box::<dyn Error>::from(err_msg)
    })?;

    Ok(instance)
}

// THis function should be exposed to higher level functions that can load configs from
// anywhere. Additionally, since this is called automatically in creating an agent
// it should not override any existing env vars.
pub fn set_env_vars(
    do_override: bool,
    config_json: Option<&str>,
    ignore_agent_id: bool,
) -> Result<String, Box<dyn Error>> {
    let config: Config = match config_json {
        Some(json_str) => serde_json::from_value(validate_config(json_str).unwrap_or_default())
            .unwrap_or_default(),
        None => match fs::read_to_string("jacs.config.json") {
            Ok(content) => serde_json::from_value(validate_config(&content).unwrap_or_default())
                .unwrap_or_default(),
            Err(_) => Config::default(),
        },
    };
    debug!("configs from file {:?}", config);
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
            println!("ID and Version must be in the form UUID:UUID");
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
