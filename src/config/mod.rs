use log::debug;
use log::info;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize, Default, Debug)]
struct Config {
    jacs_use_filesystem: Option<String>,
    jacs_use_security: Option<String>,
    jacs_data_directory: Option<String>,
    jacs_key_directory: Option<String>,
    jacs_agent_private_key_filename: Option<String>,
    jacs_agent_public_key_filename: Option<String>,
    jacs_agent_key_algorithm: Option<String>,
    jacs_agent_version: Option<String>,
    jacs_header_version: Option<String>,
    jacs_signature_version: Option<String>,
}

pub fn get_default_dir() -> PathBuf {
    env::var("JACS_DATA_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            env::set_var("JACS_DATA_DIRECTORY", ".");
            env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        })
}

pub fn set_env_vars() {
    let config: Config = match fs::read_to_string("jacs.config.json") {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Config {
            jacs_use_filesystem: None,
            jacs_use_security: None,
            jacs_data_directory: None,
            jacs_key_directory: None,
            jacs_agent_private_key_filename: None,
            jacs_agent_public_key_filename: None,
            jacs_agent_key_algorithm: None,
            jacs_agent_version: None,
            jacs_header_version: None,
            jacs_signature_version: None,
        },
    };
    debug!("configs from file {:?}", config);

    let jacs_use_filesystem = config
        .jacs_use_filesystem
        .unwrap_or_else(|| "true".to_string());
    env::set_var("JACS_USE_FILESYSTEM", &jacs_use_filesystem);

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

    let jacs_agent_version = config
        .jacs_agent_version
        .unwrap_or_else(|| "v1".to_string());
    env::set_var("JACS_AGENT_VERSION", &jacs_agent_version);

    let jacs_header_version = config
        .jacs_header_version
        .unwrap_or_else(|| "v1".to_string());
    env::set_var("JACS_HEADER_VERSION", &jacs_header_version);

    let jacs_signature_version = config
        .jacs_signature_version
        .unwrap_or_else(|| "v1".to_string());
    env::set_var("JACS_SIGNATURE_VERSION", &jacs_signature_version);

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
            JACS_AGENT_VERSION:              {},
            JACS_HEADER_VERSION:             {},
            JACS_SIGNATURE_VERSION:          {}
        "#,
        jacs_use_security,
        jacs_use_filesystem,
        jacs_data_directory,
        jacs_key_directory,
        jacs_agent_private_key_filename,
        jacs_agent_public_key_filename,
        jacs_agent_key_algorithm,
        jacs_agent_version,
        jacs_header_version,
        jacs_signature_version
    );

    info!("{}", loading_message);
}
