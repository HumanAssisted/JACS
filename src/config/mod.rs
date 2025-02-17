use crate::storage::jenv::{get_env_var, set_env_var, EnvError};
use log::debug;
use log::info;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Config {
    #[serde(rename = "$schema")]
    schema: String,
    jacs_use_filesystem: Option<String>,
    jacs_use_security: Option<String>,
    jacs_data_directory: Option<String>,
    jacs_key_directory: Option<String>,
    jacs_agent_private_key_filename: Option<String>,
    jacs_agent_public_key_filename: Option<String>,
    jacs_agent_key_algorithm: Option<String>,
    jacs_agent_schema_version: Option<String>,
    jacs_header_schema_version: Option<String>,
    jacs_signature_schema_version: Option<String>,
    jacs_private_key_password: Option<String>,
    jacs_agent_id_and_version: Option<String>,
    jacs_default_storage: Option<String>,
}

impl Config {
    pub fn new(
        schema: String,
        jacs_use_filesystem: Option<String>,
        jacs_use_security: Option<String>,
        jacs_data_directory: Option<String>,
        jacs_key_directory: Option<String>,
        jacs_agent_private_key_filename: Option<String>,
        jacs_agent_public_key_filename: Option<String>,
        jacs_agent_key_algorithm: Option<String>,
        jacs_agent_schema_version: Option<String>,
        jacs_header_schema_version: Option<String>,
        jacs_signature_schema_version: Option<String>,
        jacs_private_key_password: Option<String>,
        jacs_agent_id_and_version: Option<String>,
        jacs_default_storage: Option<String>,
    ) -> Config {
        Config {
            schema,
            jacs_use_filesystem,
            jacs_use_security,
            jacs_data_directory,
            jacs_key_directory,
            jacs_agent_private_key_filename,
            jacs_agent_public_key_filename,
            jacs_agent_key_algorithm,
            jacs_agent_schema_version,
            jacs_header_schema_version,
            jacs_signature_schema_version,
            jacs_private_key_password,
            jacs_agent_id_and_version,
            jacs_default_storage,
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
        Loading JACS and Sophon env variables of:
            JACS_USE_SECURITY                {},
            JACS_USE_FILESYSTEM:             {},
            JACS_DATA_DIRECTORY:             {},
            JACS_KEY_DIRECTORY:              {},
            JACS_AGENT_PRIVATE_KEY_FILENAME: {},
            JACS_AGENT_PUBLIC_KEY_FILENAME:  {},
            JACS_AGENT_KEY_ALGORITHM:        {},
            JACS_AGENT_SCHEMA_VERSION:       {},
            JACS_HEADER_SCHEMA_VERSION:      {},
            JACS_SIGNATURE_SCHEMA_VERSION:   {},
            JACS_PRIVATE_KEY_PASSWORD        {},
            JACS_AGENT_ID_AND_VERSION        {}
        "#,
            self.jacs_use_security.as_deref().unwrap_or(""),
            self.jacs_use_filesystem.as_deref().unwrap_or(""),
            self.jacs_data_directory.as_deref().unwrap_or(""),
            self.jacs_key_directory.as_deref().unwrap_or(""),
            self.jacs_agent_private_key_filename
                .as_deref()
                .unwrap_or(""),
            self.jacs_agent_public_key_filename.as_deref().unwrap_or(""),
            self.jacs_agent_key_algorithm.as_deref().unwrap_or(""),
            self.jacs_agent_schema_version.as_deref().unwrap_or(""),
            self.jacs_header_schema_version.as_deref().unwrap_or(""),
            self.jacs_signature_schema_version.as_deref().unwrap_or(""),
            self.jacs_private_key_password.as_deref().unwrap_or(""),
            self.jacs_agent_id_and_version.as_deref().unwrap_or(""),
        )
    }
}

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

pub fn set_env_vars() -> Result<String, EnvError> {
    let config: Config = match fs::read_to_string("jacs.config.json") {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Config {
            schema: "https://hai.ai/schemas/jacs.config.schema.json".to_string(),
            jacs_use_filesystem: None,
            jacs_use_security: None,
            jacs_data_directory: None,
            jacs_key_directory: None,
            jacs_agent_private_key_filename: None,
            jacs_agent_public_key_filename: None,
            jacs_agent_key_algorithm: None,
            jacs_agent_schema_version: None,
            jacs_header_schema_version: None,
            jacs_signature_schema_version: None,
            jacs_private_key_password: None,
            jacs_agent_id_and_version: None,
            jacs_default_storage: None,
        },
    };
    debug!("configs from file {:?}", config);

    let jacs_use_filesystem = config
        .jacs_use_filesystem
        .as_ref()
        .unwrap_or(&"true".to_string())
        .clone();
    set_env_var("JACS_USE_FILESYSTEM", &jacs_use_filesystem)?;

    let jacs_private_key_password = config
        .jacs_private_key_password
        .as_ref()
        .unwrap_or(&"true".to_string())
        .clone();
    set_env_var("JACS_PRIVATE_KEY_PASSWORD", &jacs_private_key_password)?;

    let jacs_use_security = config
        .jacs_use_security
        .as_ref()
        .unwrap_or(&"false".to_string())
        .clone();
    set_env_var("JACS_USE_SECURITY", &jacs_use_security)?;

    let jacs_data_directory = config
        .jacs_data_directory
        .as_ref()
        .unwrap_or(&format!("{:?}", std::env::current_dir().unwrap()))
        .clone();
    set_env_var("JACS_DATA_DIRECTORY", &jacs_data_directory)?;

    let jacs_key_directory = config
        .jacs_key_directory
        .as_ref()
        .unwrap_or(&".".to_string())
        .clone();
    set_env_var("JACS_KEY_DIRECTORY", &jacs_key_directory)?;

    let jacs_agent_private_key_filename = config
        .jacs_agent_private_key_filename
        .as_ref()
        .unwrap_or(&"rsa_pss_private.pem".to_string())
        .clone();
    set_env_var(
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        &jacs_agent_private_key_filename,
    )?;

    let jacs_agent_public_key_filename = config
        .jacs_agent_public_key_filename
        .as_ref()
        .unwrap_or(&"rsa_pss_public.pem".to_string())
        .clone();
    set_env_var(
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        &jacs_agent_public_key_filename,
    )?;

    let jacs_agent_key_algorithm = config
        .jacs_agent_key_algorithm
        .as_ref()
        .unwrap_or(&"RSA-PSS".to_string())
        .clone();
    set_env_var("JACS_AGENT_KEY_ALGORITHM", &jacs_agent_key_algorithm)?;

    let jacs_agent_schema_version = config
        .jacs_agent_schema_version
        .as_ref()
        .unwrap_or(&"v1".to_string())
        .clone();
    set_env_var("JACS_AGENT_SCHEMA_VERSION", &jacs_agent_schema_version)?;

    let jacs_header_schema_version = config
        .jacs_header_schema_version
        .as_ref()
        .unwrap_or(&"v1".to_string())
        .clone();
    set_env_var("JACS_HEADER_SCHEMA_VERSION", &jacs_header_schema_version)?;

    let jacs_signature_schema_version = config
        .jacs_signature_schema_version
        .as_ref()
        .unwrap_or(&"v1".to_string())
        .clone();
    set_env_var(
        "JACS_SIGNATURE_SCHEMA_VERSION",
        &jacs_signature_schema_version,
    )?;

    let jacs_default_storage = config
        .jacs_default_storage
        .as_ref()
        .unwrap_or(&"fs".to_string())
        .clone();
    set_env_var("JACS_DEFAULT_STORAGE", &jacs_default_storage)?;

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

    set_env_var("JACS_AGENT_ID_AND_VERSION", &jacs_agent_id_and_version)?;

    let message = format!("{}", config);
    info!("{}", message);
    Ok(message)
}
