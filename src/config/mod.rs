use log::info;
use std::env;

/// sets default env variables for JACS usage
pub fn set_env_vars() {
    // to get reliable test outputs, use consistent keys

    let jacs_default_directory = env::var("JACS_AGENT_DEFAULT_DIRECTORY").unwrap_or_else(|_| {
        let default_dir = ".";
        env::set_var("JACS_AGENT_DEFAULT_DIRECTORY", default_dir);
        default_dir.to_string()
    });

    let jacs_key_directory = env::var("JACS_KEY_DIRECTORY").unwrap_or_else(|_| {
        let default_dir = ".";
        env::set_var("JACS_KEY_DIRECTORY", default_dir);
        default_dir.to_string()
    });
    let jacs_agent_private_key_filename = env::var("JACS_AGENT_PRIVATE_KEY_FILENAME")
        .unwrap_or_else(|_| {
            let filename = "rsa_pss_private.pem";
            env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", filename);
            filename.to_string()
        });
    let jacs_agent_public_key_filename =
        env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap_or_else(|_| {
            let filename = "rsa_pss_public.pem";
            env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", filename);
            filename.to_string()
        });

    let jacs_agent_key_algorithm = env::var("JACS_AGENT_KEY_ALGORITHM").unwrap_or_else(|_| {
        let algo = "RSA-PSS";
        env::set_var("JACS_AGENT_KEY_ALGORITHM", algo);
        algo.to_string()
    });

    let jacs_agent_version = env::var("JACS_AGENT_VERSION").unwrap_or_else(|_| {
        let version = "v1";
        env::set_var("JACS_AGENT_VERSION", version);
        version.to_string()
    });
    let jacs_header_version = env::var("JACS_HEADER_VERSION").unwrap_or_else(|_| {
        let version = "v1";
        env::set_var("JACS_HEADER_VERSION", version);
        version.to_string()
    });

    let jacs_signature_version = env::var("JACS_SIGNATURE_VERSION").unwrap_or_else(|_| {
        let version = "v1";
        env::set_var("JACS_SIGNATURE_VERSION", version);
        version.to_string()
    });

    // todo key or key location should be hidden from logs
    let loading_message = format!(
        r#"

Loading JACS and Sophon env variables of:
    JACS_AGENT_DEFAULT_DIRECTORY: {},
    JACS_KEY_DIRECTORY: {},
    JACS_AGENT_PRIVATE_KEY_FILENAME: {},
    JACS_AGENT_PUBLIC_KEY_FILENAME: {},
    JACS_AGENT_KEY_ALGORITHM: {},
    JACS_AGENT_VERSION: {},
    JACS_HEADER_VERSION: {},
    JACS_SIGNATURE_VERSION: {},

        "#,
        jacs_default_directory,
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
