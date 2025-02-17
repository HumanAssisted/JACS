use log::debug;
use log::info;
use serde::Deserialize;
use serde::Serialize;
use std::env;
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

pub fn get_default_dir() -> PathBuf {
    env::var("JACS_DATA_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            env::set_var("JACS_DATA_DIRECTORY", ".");
            env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        })
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

pub fn set_env_vars() -> String {
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
        .unwrap_or_else(|| "true".to_string());
    env::set_var("JACS_USE_FILESYSTEM", &jacs_use_filesystem);

    let jacs_private_key_password = config
        .jacs_private_key_password
        .unwrap_or_else(|| "true".to_string());
    env::set_var("JACS_PRIVATE_KEY_PASSWORD", &jacs_private_key_password);

    let jacs_use_security = config
        .jacs_use_security
        .unwrap_or_else(|| "false".to_string());
    env::set_var("JACS_USE_SECURITY", &jacs_use_security);

    let jacs_data_directory = config
        .jacs_data_directory
        .unwrap_or_else(|| format!("{:?}", env::current_dir().unwrap()));
    env::set_var("JACS_DATA_DIRECTORY", &jacs_data_directory);

    let jacs_key_directory = config.jacs_key_directory.unwrap_or_else(|| ".".to_string());
    env::set_var("JACS_KEY_DIRECTORY", &jacs_key_directory);

    let jacs_agent_private_key_filename = config
        .jacs_agent_private_key_filename
        .unwrap_or_else(|| "rsa_pss_private.pem".to_string());
    env::set_var(
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        &jacs_agent_private_key_filename,
    );

    let jacs_agent_public_key_filename = config
        .jacs_agent_public_key_filename
        .unwrap_or_else(|| "rsa_pss_public.pem".to_string());
    env::set_var(
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        &jacs_agent_public_key_filename,
    );

    let jacs_agent_key_algorithm = config
        .jacs_agent_key_algorithm
        .unwrap_or_else(|| "RSA-PSS".to_string());
    env::set_var("JACS_AGENT_KEY_ALGORITHM", &jacs_agent_key_algorithm);

    let jacs_agent_schema_version = config
        .jacs_agent_schema_version
        .unwrap_or_else(|| "v1".to_string());
    env::set_var("JACS_AGENT_SCHEMA_VERSION", &jacs_agent_schema_version);

    let jacs_header_schema_version = config
        .jacs_header_schema_version
        .unwrap_or_else(|| "v1".to_string());
    env::set_var("JACS_HEADER_SCHEMA_VERSION", &jacs_header_schema_version);

    let jacs_signature_schema_version = config
        .jacs_signature_schema_version
        .unwrap_or_else(|| "v1".to_string());
    env::set_var(
        "JACS_SIGNATURE_SCHEMA_VERSION",
        &jacs_signature_schema_version,
    );

    let jacs_default_storage = config
        .jacs_default_storage
        .unwrap_or_else(|| "fs".to_string());
    env::set_var("JACS_DEFAULT_STORAGE", &jacs_default_storage);

    let jacs_agent_id_and_version = config
        .jacs_agent_id_and_version
        .unwrap_or_else(|| "".to_string());

    if !jacs_agent_id_and_version.is_empty() {
        let (id, version) = split_id(&jacs_agent_id_and_version).unwrap_or(("", ""));
        if !Uuid::parse_str(id).is_ok() || !Uuid::parse_str(version).is_ok() {
            println!("ID and Version must be in the form UUID:UUID");
        }
    }

    env::set_var("JACS_AGENT_ID_AND_VERSION", &jacs_agent_id_and_version);

    let loading_message = format!(
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
        jacs_use_security,
        jacs_use_filesystem,
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
    );

    info!("{}", loading_message);
    loading_message
}
