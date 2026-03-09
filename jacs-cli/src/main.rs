use clap::{Arg, ArgAction, Command, crate_name, value_parser};

use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::cli_utils::create::{handle_agent_create, handle_agent_create_auto, handle_config_create};
use jacs::cli_utils::default_set_file_list;
use jacs::cli_utils::document::{
    check_agreement, create_agreement, create_documents, extract_documents, sign_documents,
    update_documents, verify_documents,
};
use jacs::config::load_config_12factor_optional;
// use jacs::create_task; // unused
use jacs::dns::bootstrap as dns_bootstrap;
use jacs::shutdown::{ShutdownGuard, install_signal_handler};
use jacs::{load_agent, load_agent_with_dns_policy};

use rpassword::read_password;
use std::env;
use std::error::Error;
use std::path::Path;
use std::process;

const CLI_PASSWORD_FILE_ENV: &str = "JACS_PASSWORD_FILE";
const DEFAULT_LEGACY_PASSWORD_FILE: &str = "./jacs_keys/.jacs_password";

fn quickstart_password_bootstrap_help() -> &'static str {
    "Password bootstrap options (set exactly one explicit source):
  1) Direct env (recommended):
     export JACS_PRIVATE_KEY_PASSWORD='your-strong-password'
  2) Export from a secret file:
     export JACS_PRIVATE_KEY_PASSWORD=\"$(cat /path/to/password)\"
  3) CLI convenience (file path):
     export JACS_PASSWORD_FILE=/path/to/password
If both JACS_PRIVATE_KEY_PASSWORD and JACS_PASSWORD_FILE are set, CLI fails to avoid ambiguity.
If neither is set, CLI will try legacy ./jacs_keys/.jacs_password when present."
}

fn read_password_from_file(path: &Path, source_name: &str) -> Result<String, String> {
    // SECURITY: Check file permissions before reading (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).map_err(|e| {
            format!(
                "Failed to read {} '{}': {}",
                source_name,
                path.display(),
                e
            )
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} '{}' has insecure permissions (mode {:04o}). \
                File must not be group-readable or world-readable. \
                Fix with: chmod 600 '{}'\n\n{}",
                source_name,
                path.display(),
                mode,
                path.display(),
                quickstart_password_bootstrap_help()
            ));
        }
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {} '{}': {}", source_name, path.display(), e))?;
    // Preserve intentional leading/trailing spaces in passphrases; strip only line endings.
    let password = raw.trim_end_matches(|c| c == '\n' || c == '\r');
    if password.is_empty() {
        return Err(format!(
            "{} '{}' is empty. {}",
            source_name,
            path.display(),
            quickstart_password_bootstrap_help()
        ));
    }
    Ok(password.to_string())
}

fn get_non_empty_env_var(key: &str) -> Result<Option<String>, String> {
    match env::var(key) {
        Ok(value) => {
            if value.trim().is_empty() {
                Err(format!(
                    "{} is set but empty. {}",
                    key,
                    quickstart_password_bootstrap_help()
                ))
            } else {
                Ok(Some(value))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{} contains non-UTF-8 data. {}",
            key,
            quickstart_password_bootstrap_help()
        )),
    }
}

fn ensure_cli_private_key_password() -> Result<(), String> {
    let env_password = get_non_empty_env_var("JACS_PRIVATE_KEY_PASSWORD")?;
    let password_file = get_non_empty_env_var(CLI_PASSWORD_FILE_ENV)?;

    if env_password.is_some() && password_file.is_some() {
        return Err(format!(
            "Multiple password sources configured: JACS_PRIVATE_KEY_PASSWORD and {}. \
Configure exactly one source.\n\n{}",
            CLI_PASSWORD_FILE_ENV,
            quickstart_password_bootstrap_help()
        ));
    }

    if let Some(password) = env_password {
        // SAFETY: CLI process is single-threaded for command handling at this point.
        unsafe {
            env::set_var("JACS_PRIVATE_KEY_PASSWORD", password);
        }
        return Ok(());
    }

    if let Some(path) = password_file {
        let password = read_password_from_file(Path::new(path.trim()), CLI_PASSWORD_FILE_ENV)?;
        // SAFETY: CLI process is single-threaded for command handling at this point.
        unsafe {
            env::set_var("JACS_PRIVATE_KEY_PASSWORD", password);
        }
        return Ok(());
    }

    let legacy_path = Path::new(DEFAULT_LEGACY_PASSWORD_FILE);
    if legacy_path.exists() {
        let password = read_password_from_file(legacy_path, "legacy password file")?;
        // SAFETY: CLI process is single-threaded for command handling at this point.
        unsafe {
            env::set_var("JACS_PRIVATE_KEY_PASSWORD", password);
        }
        eprintln!(
            "Using legacy password source '{}'. Prefer JACS_PRIVATE_KEY_PASSWORD or {}.",
            legacy_path.display(),
            CLI_PASSWORD_FILE_ENV
        );
    }

    Ok(())
}

fn resolve_dns_policy_overrides(
    ignore_dns: bool,
    require_strict: bool,
    require_dns: bool,
    non_strict: bool,
) -> (Option<bool>, Option<bool>, Option<bool>) {
    if ignore_dns {
        (Some(false), Some(false), Some(false))
    } else if require_strict {
        (Some(true), Some(true), Some(true))
    } else if require_dns {
        (Some(true), Some(true), Some(false))
    } else if non_strict {
        (Some(true), Some(false), Some(false))
    } else {
        (None, None, None)
    }
}

fn load_agent_with_cli_dns_policy(
    agent_file: Option<String>,
    ignore_dns: bool,
    require_strict: bool,
    require_dns: bool,
    non_strict: bool,
) -> Result<Agent, Box<dyn Error>> {
    let (dns_validate, dns_required, dns_strict) =
        resolve_dns_policy_overrides(ignore_dns, require_strict, require_dns, non_strict);
    load_agent_with_dns_policy(agent_file, dns_validate, dns_required, dns_strict)
}

fn wrap_quickstart_error_with_password_help(
    context: &str,
    err: impl std::fmt::Display,
) -> Box<dyn Error> {
    Box::new(std::io::Error::other(format!(
        "{}: {}\n\n{}",
        context,
        err,
        quickstart_password_bootstrap_help()
    )))
}

// install/download functions removed — MCP is now built into the CLI

pub fn main() -> Result<(), Box<dyn Error>> {
    // Install signal handler for graceful shutdown (Ctrl+C, SIGTERM)
    install_signal_handler();

    // Create shutdown guard to ensure cleanup on exit (including early returns)
    let _shutdown_guard = ShutdownGuard::new();
    let matches = Command::new(crate_name!())
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            Command::new("version")
                .about("Prints version and build information")
        )
        .subcommand(
            Command::new("config")
                .about(" work with JACS configuration")
                .subcommand(
                    Command::new("create")
                        .about(" create a config file")
                )
                .subcommand(
                    Command::new("read")
                    .about("read configuration and display to screen. This includes both the config file and the env variables.")
                ),
        )
        .subcommand(
            Command::new("agent")
                .about(" work with a JACS agent")
                .subcommand(
                    Command::new("dns")
                        .about("emit DNS TXT commands for publishing agent fingerprint")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .long("agent-file")
                                .value_parser(value_parser!(String))
                                .help("Path to agent JSON (optional; defaults via config)"),
                        )
                        .arg(
                            Arg::new("no-dns")
                                .long("no-dns")
                                .help("Disable DNS validation; rely on embedded fingerprint")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("require-dns")
                                .long("require-dns")
                                .help("Require DNS validation; if domain missing, fail. Not strict (no DNSSEC required).")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("require-strict-dns")
                                .long("require-strict-dns")
                                .help("Require strict DNSSEC validation; if domain missing, fail.")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("ignore-dns")
                                .long("ignore-dns")
                                .help("Ignore DNS validation entirely.")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(Arg::new("domain").long("domain").value_parser(value_parser!(String)))
                        .arg(Arg::new("agent-id").long("agent-id").value_parser(value_parser!(String)))
                        .arg(Arg::new("ttl").long("ttl").value_parser(value_parser!(u32)).default_value("3600"))
                        .arg(Arg::new("encoding").long("encoding").value_parser(["base64","hex"]).default_value("base64"))
                        .arg(Arg::new("provider").long("provider").value_parser(["plain","aws","azure","cloudflare"]).default_value("plain"))
                )
                .subcommand(
                    Command::new("create")
                        .about(" create an agent")
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Name of the json file with agent schema and jacsAgentType")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("create-keys")
                                .long("create-keys")
                                .required(true)
                                .help("Create keys or not if they already exist. Configure key type in jacs.config.json")
                                .value_parser(value_parser!(bool)),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                    .about(" verify an agent")
                    .arg(
                        Arg::new("agent-file")
                            .short('a')
                            .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("no-dns")
                            .long("no-dns")
                            .help("Disable DNS validation; rely on embedded fingerprint")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("require-dns")
                            .long("require-dns")
                            .help("Require DNS validation; if domain missing, fail. Not strict (no DNSSEC required).")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("require-strict-dns")
                            .long("require-strict-dns")
                            .help("Require strict DNSSEC validation; if domain missing, fail.")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("ignore-dns")
                            .long("ignore-dns")
                            .help("Ignore DNS validation entirely.")
                            .action(ArgAction::SetTrue),
                    ),
                )
                .subcommand(
                    Command::new("lookup")
                        .about("Look up another agent's public key and DNS info from their domain")
                        .arg(
                            Arg::new("domain")
                                .required(true)
                                .help("Domain to look up (e.g., agent.example.com)"),
                        )
                        .arg(
                            Arg::new("no-dns")
                                .long("no-dns")
                                .help("Skip DNS TXT record lookup")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("strict")
                                .long("strict")
                                .help("Require DNSSEC validation for DNS lookup")
                                .action(ArgAction::SetTrue),
                        ),
                ),
        )

        .subcommand(
            Command::new("task")
            .about(" work with a JACS  Agent task")
            .subcommand(
                Command::new("create")
                    .about(" create a new JACS Task file, either by embedding or parsing a document")
                    .arg(
                        Arg::new("agent-file")
                            .short('a')
                            .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("filename")
                            .short('f')
                            .help("Path to input file. Must be JSON")
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("name")
                            .short('n')
                            .required(true)
                            .help("name of task")
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("description")
                            .short('d')
                            .required(true)
                            .help("description of task")
                            .value_parser(value_parser!(String)),
                    )
                )
            )

        .subcommand(
            Command::new("document")
                .about(" work with a general JACS document")
                .subcommand(
                    Command::new("create")
                        .about(" create a new JACS file, either by embedding or parsing a document")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to input file. Must be JSON")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. ")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("attach")
                                .help("Path to file or directory for file attachments")
                                .long("attach")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("embed")
                                .short('e')
                                .help("Embed documents or keep the documents external")
                                .long("embed")
                                .value_parser(value_parser!(bool)),
                        ),
                )
                .subcommand(
                    Command::new("update")
                        .about("create a new version of document. requires both the original JACS file and the modified jacs metadata")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("new")
                                .short('n')
                                .required(true)
                                .help("Path to new version of document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. Filenames will always end with \"json\"")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("attach")
                                .help("Path to file or directory for file attachments")
                                .long("attach")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("embed")
                                .short('e')
                                .help("Embed documents or keep the documents external")
                                .long("embed")
                                .value_parser(value_parser!(bool)),
                        )
                        ,
                )
                .subcommand(
                    Command::new("check-agreement")
                        .about("given a document, provide alist of agents that should sign document")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )

                )
                .subcommand(
                    Command::new("create-agreement")
                        .about("given a document, provide alist of agents that should sign document")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                                Arg::new("agentids")
                                .short('i')
                                .long("agentids")
                                .value_name("VALUES")
                                .help("Comma-separated list of agent ids")
                                .value_delimiter(',')
                                .required(true)
                                .action(clap::ArgAction::Set),
                            )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. Filenames will always end with \"json\"")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )

                ).subcommand(
                    Command::new("sign-agreement")
                        .about("given a document, sign the agreement section")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. Filenames will always end with \"json\"")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )

                )
                .subcommand(
                    Command::new("verify")
                        .about(" verify a documents hash, siginatures, and schema")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to input file. Must be JSON")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to validate")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        ),
                )
                .subcommand(
                    Command::new("extract")
                        .about(" given  documents, extract embedded contents if any")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to input file. Must be JSON")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to validate")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        ),
                )
        )
        .subcommand(
            Command::new("key")
                .about("Work with JACS cryptographic keys")
                .subcommand(
                    Command::new("reencrypt")
                        .about("Re-encrypt the private key with a new password")
                )
        )
        .subcommand(
            Command::new("mcp")
                .about("Start the built-in JACS MCP server (stdio transport)")
                .subcommand(
                    Command::new("install")
                        .about("Deprecated: MCP is now built into the jacs binary")
                        .hide(true)
                )
                .subcommand(
                    Command::new("run")
                        .about("Deprecated: use `jacs mcp` directly")
                        .hide(true)
                ),
        )
        .subcommand(
            Command::new("a2a")
                .about("A2A (Agent-to-Agent) trust and discovery commands")
                .subcommand(
                    Command::new("assess")
                        .about("Assess trust level of a remote A2A Agent Card")
                        .arg(
                            Arg::new("source")
                                .required(true)
                                .help("Path to Agent Card JSON file or URL"),
                        )
                        .arg(
                            Arg::new("policy")
                                .long("policy")
                                .short('p')
                                .value_parser(["open", "verified", "strict"])
                                .default_value("verified")
                                .help("Trust policy to apply (default: verified)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("Output result as JSON"),
                        ),
                )
                .subcommand(
                    Command::new("trust")
                        .about("Add a remote A2A agent to the local trust store")
                        .arg(
                            Arg::new("source")
                                .required(true)
                                .help("Path to Agent Card JSON file or URL"),
                        ),
                )
                .subcommand(
                    Command::new("discover")
                        .about("Discover a remote A2A agent via its well-known Agent Card")
                        .arg(
                            Arg::new("url")
                                .required(true)
                                .help("Base URL of the agent (e.g. https://agent.example.com)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("Output the full Agent Card as JSON"),
                        )
                        .arg(
                            Arg::new("policy")
                                .long("policy")
                                .short('p')
                                .value_parser(["open", "verified", "strict"])
                                .default_value("verified")
                                .help("Trust policy to apply against the discovered card"),
                        ),
                )
                .subcommand(
                    Command::new("serve")
                        .about("Serve this agent's .well-known endpoints for A2A discovery")
                        .arg(
                            Arg::new("port")
                                .long("port")
                                .value_parser(value_parser!(u16))
                                .default_value("8080")
                                .help("Port to listen on (default: 8080)"),
                        )
                        .arg(
                            Arg::new("host")
                                .long("host")
                                .default_value("127.0.0.1")
                                .help("Host to bind to (default: 127.0.0.1)"),
                        ),
                )
                .subcommand(
                    Command::new("quickstart")
                        .about("Create/load an agent and start serving A2A endpoints (password required)")
                        .after_help(quickstart_password_bootstrap_help())
                        .arg(
                            Arg::new("name")
                                .long("name")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("Agent name used for first-time quickstart creation"),
                        )
                        .arg(
                            Arg::new("domain")
                                .long("domain")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("Agent domain used for DNS/public-key verification workflows"),
                        )
                        .arg(
                            Arg::new("description")
                                .long("description")
                                .value_parser(value_parser!(String))
                                .help("Optional human-readable agent description"),
                        )
                        .arg(
                            Arg::new("port")
                                .long("port")
                                .value_parser(value_parser!(u16))
                                .default_value("8080")
                                .help("Port to listen on (default: 8080)"),
                        )
                        .arg(
                            Arg::new("host")
                                .long("host")
                                .default_value("127.0.0.1")
                                .help("Host to bind to (default: 127.0.0.1)"),
                        )
                        .arg(
                            Arg::new("algorithm")
                                .long("algorithm")
                                .short('a')
                                .value_parser(["pq2025", "ring-Ed25519", "RSA-PSS"])
                                .help("Signing algorithm (default: pq2025)"),
                        ),
                ),
        )
        .subcommand(
            Command::new("quickstart")
                .about("Create or load a persistent agent for instant sign/verify (password required)")
                .after_help(quickstart_password_bootstrap_help())
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("Agent name used for first-time quickstart creation"),
                )
                .arg(
                    Arg::new("domain")
                        .long("domain")
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("Agent domain used for DNS/public-key verification workflows"),
                )
                .arg(
                    Arg::new("description")
                        .long("description")
                        .value_parser(value_parser!(String))
                        .help("Optional human-readable agent description"),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .short('a')
                        .value_parser(["ed25519", "rsa-pss", "pq2025"])
                        .default_value("pq2025")
                        .help("Signing algorithm (default: pq2025)"),
                )
                .arg(
                    Arg::new("sign")
                        .long("sign")
                        .help("Sign JSON from stdin and print signed document to stdout")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .value_parser(value_parser!(String))
                        .help("Sign a JSON file instead of reading from stdin (used with --sign)"),
                )
        )
        .subcommand(
            Command::new("init")
                .about("Initialize JACS by creating both config and agent (with keys)")
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .short('y')
                        .action(ArgAction::SetTrue)
                        .help("Automatically set the new agent ID in jacs.config.json without prompting"),
                )
        )
        .subcommand(
            Command::new("attest")
                .about("Create and verify attestation documents")
                .subcommand(
                    Command::new("create")
                        .about("Create a signed attestation")
                        .arg(
                            Arg::new("subject-type")
                                .long("subject-type")
                                .value_parser(["agent", "artifact", "workflow", "identity"])
                                .help("Type of subject being attested"),
                        )
                        .arg(
                            Arg::new("subject-id")
                                .long("subject-id")
                                .value_parser(value_parser!(String))
                                .help("Identifier of the subject"),
                        )
                        .arg(
                            Arg::new("subject-digest")
                                .long("subject-digest")
                                .value_parser(value_parser!(String))
                                .help("SHA-256 digest of the subject"),
                        )
                        .arg(
                            Arg::new("claims")
                                .long("claims")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("JSON array of claims, e.g. '[{\"name\":\"reviewed\",\"value\":true}]'"),
                        )
                        .arg(
                            Arg::new("evidence")
                                .long("evidence")
                                .value_parser(value_parser!(String))
                                .help("JSON array of evidence references"),
                        )
                        .arg(
                            Arg::new("from-document")
                                .long("from-document")
                                .value_parser(value_parser!(String))
                                .help("Lift attestation from an existing signed document file"),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_parser(value_parser!(String))
                                .help("Write attestation to file instead of stdout"),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify an attestation document")
                        .arg(
                            Arg::new("file")
                                .help("Path to the attestation JSON file")
                                .required(true)
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("full")
                                .long("full")
                                .action(ArgAction::SetTrue)
                                .help("Use full verification (evidence + derivation chain)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("Output result as JSON"),
                        )
                        .arg(
                            Arg::new("key-dir")
                                .long("key-dir")
                                .value_parser(value_parser!(String))
                                .help("Directory containing public keys for verification"),
                        )
                        .arg(
                            Arg::new("max-depth")
                                .long("max-depth")
                                .value_parser(value_parser!(u32))
                                .help("Maximum derivation chain depth"),
                        ),
                )
                .subcommand(
                    Command::new("export-dsse")
                        .about("Export an attestation as a DSSE envelope for in-toto/SLSA")
                        .arg(
                            Arg::new("file")
                                .help("Path to the signed attestation JSON file")
                                .required(true)
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_parser(value_parser!(String))
                                .help("Write DSSE envelope to file instead of stdout"),
                        ),
                )
                .subcommand_required(true)
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a signed JACS document (no agent required)")
                .arg(
                    Arg::new("file")
                        .help("Path to the signed JACS JSON file")
                        .required_unless_present("remote")
                        .value_parser(value_parser!(String)),
                )
                .arg(
                    Arg::new("remote")
                        .long("remote")
                        .value_parser(value_parser!(String))
                        .help("Fetch document from URL before verifying"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Output result as JSON"),
                )
                .arg(
                    Arg::new("key-dir")
                        .long("key-dir")
                        .value_parser(value_parser!(String))
                        .help("Directory containing public keys for verification"),
                )
        )
        .arg_required_else_help(true)
        .get_matches();

    match matches.subcommand() {
        Some(("version", _sub_matches)) => {
            println!("{}", env!("CARGO_PKG_DESCRIPTION"));
            println!(
                "{} version: {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        Some(("config", config_matches)) => match config_matches.subcommand() {
            Some(("create", _create_matches)) => {
                // Call the refactored handler function
                handle_config_create()?;
            }
            Some(("read", _read_matches)) => {
                let config = load_config_12factor_optional(Some("./jacs.config.json"))?;
                println!("{}", config);
            }
            _ => println!("please enter subcommand see jacs config --help"),
        },
        Some(("agent", agent_matches)) => match agent_matches.subcommand() {
            Some(("dns", sub_m)) => {
                let domain = sub_m.get_one::<String>("domain").cloned();
                let agent_id_arg = sub_m.get_one::<String>("agent-id").cloned();
                let ttl = *sub_m.get_one::<u32>("ttl").unwrap();
                let enc = sub_m
                    .get_one::<String>("encoding")
                    .map(|s| s.as_str())
                    .unwrap_or("base64");
                let provider = sub_m
                    .get_one::<String>("provider")
                    .map(|s| s.as_str())
                    .unwrap_or("plain");

                // Load agent from optional path, supporting non-strict DNS for propagation
                let agent_file = sub_m.get_one::<String>("agent-file").cloned();
                let non_strict = *sub_m.get_one::<bool>("no-dns").unwrap_or(&false);
                let ignore_dns = *sub_m.get_one::<bool>("ignore-dns").unwrap_or(&false);
                let require_strict = *sub_m
                    .get_one::<bool>("require-strict-dns")
                    .unwrap_or(&false);
                let require_dns = *sub_m.get_one::<bool>("require-dns").unwrap_or(&false);
                let agent: Agent = load_agent_with_cli_dns_policy(
                    agent_file,
                    ignore_dns,
                    require_strict,
                    require_dns,
                    non_strict,
                )
                .expect("Provide --agent-file or ensure config points to a readable agent");
                let agent_id = agent_id_arg.unwrap_or_else(|| agent.get_id().unwrap_or_default());
                let pk = agent.get_public_key().expect("public key");
                let digest = match enc {
                    "hex" => dns_bootstrap::pubkey_digest_hex(&pk),
                    _ => dns_bootstrap::pubkey_digest_b64(&pk),
                };
                let domain_final = domain
                    .or_else(|| {
                        agent
                            .config
                            .as_ref()
                            .and_then(|c| c.jacs_agent_domain().clone())
                    })
                    .expect("domain required via --domain or jacs_agent_domain in config");

                let rr = dns_bootstrap::build_dns_record(
                    &domain_final,
                    ttl,
                    &agent_id,
                    &digest,
                    if enc == "hex" {
                        dns_bootstrap::DigestEncoding::Hex
                    } else {
                        dns_bootstrap::DigestEncoding::Base64
                    },
                );

                println!("Plain/BIND:\n{}", dns_bootstrap::emit_plain_bind(&rr));
                match provider {
                    "aws" => println!(
                        "\nRoute53 change-batch JSON:\n{}",
                        dns_bootstrap::emit_route53_change_batch(&rr)
                    ),
                    "azure" => println!(
                        "\nAzure CLI:\n{}",
                        dns_bootstrap::emit_azure_cli(
                            &rr,
                            "$RESOURCE_GROUP",
                            &domain_final,
                            "_v1.agent.jacs"
                        )
                    ),
                    "cloudflare" => println!(
                        "\nCloudflare curl:\n{}",
                        dns_bootstrap::emit_cloudflare_curl(&rr, "$ZONE_ID")
                    ),
                    _ => {}
                }
                println!(
                    "\nChecklist: Ensure DNSSEC is enabled for {domain} and DS is published at registrar.",
                    domain = domain_final
                );
            }
            Some(("create", create_matches)) => {
                // Parse args for the specific agent create command
                let filename = create_matches.get_one::<String>("filename");
                let create_keys = *create_matches.get_one::<bool>("create-keys").unwrap();

                // Call the refactored handler function
                handle_agent_create(filename, create_keys)?;
            }
            Some(("verify", verify_matches)) => {
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let non_strict = *verify_matches.get_one::<bool>("no-dns").unwrap_or(&false);
                let require_dns = *verify_matches
                    .get_one::<bool>("require-dns")
                    .unwrap_or(&false);
                let require_strict = *verify_matches
                    .get_one::<bool>("require-strict-dns")
                    .unwrap_or(&false);
                let ignore_dns = *verify_matches
                    .get_one::<bool>("ignore-dns")
                    .unwrap_or(&false);
                let mut agent: Agent = load_agent_with_cli_dns_policy(
                    agentfile.cloned(),
                    ignore_dns,
                    require_strict,
                    require_dns,
                    non_strict,
                )
                .expect("agent file");
                agent
                    .verify_self_signature()
                    .expect("signature verification");
                println!(
                    "Agent {} signature verified OK.",
                    agent.get_lookup_id().expect("jacsId")
                );
            }
            Some(("lookup", lookup_matches)) => {
                let domain = lookup_matches
                    .get_one::<String>("domain")
                    .expect("domain required");
                let skip_dns = *lookup_matches.get_one::<bool>("no-dns").unwrap_or(&false);
                let strict_dns = *lookup_matches.get_one::<bool>("strict").unwrap_or(&false);

                println!("Agent Lookup: {}\n", domain);

                // Fetch public key from well-known endpoint
                println!("Public Key (/.well-known/jacs-pubkey.json):");
                let url = format!("https://{}/.well-known/jacs-pubkey.json", domain);
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .expect("HTTP client");
                match client.get(&url).send() {
                    Ok(response) => {
                        if response.status().is_success() {
                            match response.json::<serde_json::Value>() {
                                Ok(json) => {
                                    println!(
                                        "  Agent ID: {}",
                                        json.get("agentId")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Not specified")
                                    );
                                    println!(
                                        "  Algorithm: {}",
                                        json.get("algorithm")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Not specified")
                                    );
                                    println!(
                                        "  Public Key Hash: {}",
                                        json.get("publicKeyHash")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Not specified")
                                    );
                                    if let Some(pk) = json.get("publicKey").and_then(|v| v.as_str())
                                    {
                                        let preview = if pk.len() > 60 {
                                            format!("{}...", &pk[..60])
                                        } else {
                                            pk.to_string()
                                        };
                                        println!("  Public Key: {}", preview);
                                    }
                                }
                                Err(e) => println!("  Error parsing response: {}", e),
                            }
                        } else {
                            println!("  HTTP error: {}", response.status());
                        }
                    }
                    Err(e) => println!("  Error fetching: {}", e),
                }

                println!();

                // DNS TXT record lookup
                if !skip_dns {
                    println!("DNS TXT Record (_v1.agent.jacs.{}):", domain);
                    let owner = format!("_v1.agent.jacs.{}", domain.trim_end_matches('.'));
                    let lookup_result = if strict_dns {
                        dns_bootstrap::resolve_txt_dnssec(&owner)
                    } else {
                        dns_bootstrap::resolve_txt_insecure(&owner)
                    };
                    match lookup_result {
                        Ok(txt) => {
                            // Parse the TXT record
                            match dns_bootstrap::parse_agent_txt(&txt) {
                                Ok(parsed) => {
                                    println!("  Version: {}", parsed.v);
                                    println!("  Agent ID: {}", parsed.jacs_agent_id);
                                    println!("  Algorithm: {:?}", parsed.alg);
                                    println!("  Encoding: {:?}", parsed.enc);
                                    println!("  Public Key Hash: {}", parsed.digest);
                                }
                                Err(e) => println!("  Error parsing TXT: {}", e),
                            }
                            println!("  Raw TXT: {}", txt);
                        }
                        Err(e) => {
                            println!("  No DNS TXT record found: {}", e);
                            if strict_dns {
                                println!("  (Strict DNSSEC validation was required)");
                            }
                        }
                    }
                } else {
                    println!("DNS TXT Record: Skipped (--no-dns)");
                }
            }
            _ => println!("please enter subcommand see jacs agent --help"),
        },

        // Some(("task", task_matches)) => match task_matches.subcommand() {
        //     Some(("create", create_matches)) => {
        //         let agentfile = create_matches.get_one::<String>("agent-file");
        //         let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
        //         let name = create_matches.get_one::<String>("name").expect("REASON");
        //         let description = create_matches
        //             .get_one::<String>("description")
        //             .expect("REASON");
        //         println!(
        //             "{}",
        //             create_task(&mut agent, name.to_string(), description.to_string()).unwrap()
        //         );
        //     }
        //     _ => println!("please enter subcommand see jacs task --help"),
        // },
        Some(("document", document_matches)) => match document_matches.subcommand() {
            Some(("create", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let outputfilename = create_matches.get_one::<String>("output");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches
                    .get_one::<String>("attach")
                    .map(|s| s.as_str());
                let embed: Option<bool> = create_matches.get_one::<bool>("embed").copied();

                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");

                let _attachment_links = agent.parse_attachement_arg(attachments);
                let _ = create_documents(
                    &mut agent,
                    filename,
                    directory,
                    outputfilename,
                    attachments,
                    embed,
                    no_save,
                    schema,
                );
            }
            // TODO copy for sharing
            // Some(("copy", create_matches)) => {
            Some(("update", create_matches)) => {
                let new_filename = create_matches.get_one::<String>("new").unwrap();
                let original_filename = create_matches.get_one::<String>("filename").unwrap();
                let outputfilename = create_matches.get_one::<String>("output");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches
                    .get_one::<String>("attach")
                    .map(|s| s.as_str());
                let embed: Option<bool> = create_matches.get_one::<bool>("embed").copied();

                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");

                let attachment_links = agent.parse_attachement_arg(attachments);
                update_documents(
                    &mut agent,
                    new_filename,
                    original_filename,
                    outputfilename,
                    attachment_links,
                    embed,
                    no_save,
                    schema,
                )?;
            }
            Some(("sign-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = create_matches.get_one::<String>("schema");
                let _no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);

                // Use updated set_file_list with storage
                sign_documents(&mut agent, schema, filename, directory)?;
            }
            Some(("check-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = create_matches.get_one::<String>("schema");

                // Use updated set_file_list with storage
                let _files: Vec<String> = default_set_file_list(filename, directory, None)
                    .expect("Failed to determine file list");
                check_agreement(&mut agent, schema, filename, directory)?;
            }
            Some(("create-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");

                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentids: Vec<String> = create_matches // Corrected reference to create_matches
                    .get_many::<String>("agentids")
                    .unwrap_or_default()
                    .map(|s| s.to_string())
                    .collect();

                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                // Use updated set_file_list with storage
                let _ = create_agreement(&mut agent, agentids, filename, schema, no_save, directory);
            }

            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let _verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = verify_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                verify_documents(&mut agent, schema, filename, directory)?;
            }

            Some(("extract", extract_matches)) => {
                let filename = extract_matches.get_one::<String>("filename");
                let directory = extract_matches.get_one::<String>("directory");
                let _verbose = *extract_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = extract_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = extract_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                let _files: Vec<String> = default_set_file_list(filename, directory, None)
                    .expect("Failed to determine file list");
                // extract the contents but do not save
                extract_documents(&mut agent, schema, filename, directory)?;
            }

            _ => println!("please enter subcommand see jacs document --help"),
        },
        Some(("key", key_matches)) => match key_matches.subcommand() {
            Some(("reencrypt", _reencrypt_matches)) => {
                use jacs::crypt::aes_encrypt::password_requirements;
                use jacs::simple::SimpleAgent;

                // Load the agent first to find the key file
                let agent = SimpleAgent::load(None, None).map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to load agent: {}", e),
                    ))
                })?;

                println!("Re-encrypting private key.\n");

                // Get old password
                println!("Enter current password:");
                let old_password = read_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error reading password: {}", e),
                    ))
                })?;

                if old_password.is_empty() {
                    eprintln!("Error: current password cannot be empty.");
                    process::exit(1);
                }

                // Get new password
                println!("\n{}", password_requirements());
                println!("\nEnter new password:");
                let new_password = read_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error reading password: {}", e),
                    ))
                })?;

                println!("Confirm new password:");
                let new_password_confirm = read_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error reading password: {}", e),
                    ))
                })?;

                if new_password != new_password_confirm {
                    eprintln!("Error: new passwords do not match.");
                    process::exit(1);
                }

                agent.reencrypt_key(&old_password, &new_password).map_err(
                    |e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Re-encryption failed: {}", e),
                        ))
                    },
                )?;

                println!("Private key re-encrypted successfully.");
            }
            _ => println!("please enter subcommand see jacs key --help"),
        },
        #[cfg(feature = "mcp")]
        Some(("mcp", mcp_matches)) => {
            match mcp_matches.subcommand() {
                Some(("install", _)) => {
                    eprintln!("`jacs mcp install` is no longer needed.");
                    eprintln!("MCP is built into the jacs binary. Use `jacs mcp` to serve.");
                    process::exit(0);
                }
                Some(("run", _)) => {
                    eprintln!("`jacs mcp run` is no longer needed.");
                    eprintln!("Use `jacs mcp` directly to start the MCP server.");
                    process::exit(0);
                }
                _ => {
                    let agent = jacs_mcp::load_agent_from_config_env()?;
                    let server = jacs_mcp::JacsMcpServer::new(agent);
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(jacs_mcp::serve_stdio(server))?;
                }
            }
        }
        #[cfg(not(feature = "mcp"))]
        Some(("mcp", _)) => {
            eprintln!("MCP support not compiled. Install with default features: cargo install jacs-cli");
            process::exit(1);
        }
        Some(("a2a", a2a_matches)) => match a2a_matches.subcommand() {
            Some(("assess", assess_matches)) => {
                use jacs::a2a::AgentCard;
                use jacs::a2a::trust::{A2ATrustPolicy, assess_a2a_agent};

                let source = assess_matches.get_one::<String>("source").unwrap();
                let policy_str = assess_matches
                    .get_one::<String>("policy")
                    .map(|s| s.as_str())
                    .unwrap_or("verified");
                let json_output = *assess_matches.get_one::<bool>("json").unwrap_or(&false);

                let policy = A2ATrustPolicy::from_str_loose(policy_str)
                    .map_err(|e| Box::<dyn Error>::from(format!("Invalid policy: {}", e)))?;

                // Load the Agent Card from file or URL
                let card_json = if source.starts_with("http://") || source.starts_with("https://") {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .map_err(|e| format!("HTTP client error: {}", e))?;
                    client
                        .get(source.as_str())
                        .send()
                        .map_err(|e| format!("Fetch failed: {}", e))?
                        .text()
                        .map_err(|e| format!("Read body failed: {}", e))?
                } else {
                    std::fs::read_to_string(source)
                        .map_err(|e| format!("Read file failed: {}", e))?
                };

                let card: AgentCard = serde_json::from_str(&card_json)
                    .map_err(|e| format!("Invalid Agent Card JSON: {}", e))?;

                // Create an empty agent for assessment context
                let agent = jacs::get_empty_agent();
                let assessment = assess_a2a_agent(&agent, &card, policy);

                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&assessment)
                            .expect("assessment serialization")
                    );
                } else {
                    println!("Agent:       {}", card.name);
                    println!(
                        "Agent ID:    {}",
                        assessment.agent_id.as_deref().unwrap_or("(not specified)")
                    );
                    println!("Policy:      {}", assessment.policy);
                    println!("Trust Level: {}", assessment.trust_level);
                    println!(
                        "Allowed:     {}",
                        if assessment.allowed { "YES" } else { "NO" }
                    );
                    println!("JACS Ext:    {}", assessment.jacs_registered);
                    println!("Reason:      {}", assessment.reason);
                    if !assessment.allowed {
                        process::exit(1);
                    }
                }
            }
            Some(("trust", trust_matches)) => {
                use jacs::a2a::AgentCard;
                use jacs::trust;

                let source = trust_matches.get_one::<String>("source").unwrap();

                // Load the Agent Card from file or URL
                let card_json = if source.starts_with("http://") || source.starts_with("https://") {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .map_err(|e| format!("HTTP client error: {}", e))?;
                    client
                        .get(source.as_str())
                        .send()
                        .map_err(|e| format!("Fetch failed: {}", e))?
                        .text()
                        .map_err(|e| format!("Read body failed: {}", e))?
                } else {
                    std::fs::read_to_string(source)
                        .map_err(|e| format!("Read file failed: {}", e))?
                };

                let card: AgentCard = serde_json::from_str(&card_json)
                    .map_err(|e| format!("Invalid Agent Card JSON: {}", e))?;

                // Extract agent ID and version from metadata
                let agent_id = card
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("jacsId"))
                    .and_then(|v| v.as_str())
                    .ok_or("Agent Card has no jacsId in metadata")?;
                let agent_version = card
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("jacsVersion"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let key = format!("{}:{}", agent_id, agent_version);

                // Add to trust store with the card JSON as the public key PEM
                // (the trust store stores agent metadata; public key comes from
                //  well-known endpoints or DNS in practice)
                trust::trust_a2a_card(&key, &card_json)?;

                println!("Trusted agent '{}' ({})", card.name, agent_id);
                println!("  Version: {}", agent_version);
                println!("  Added to local trust store with key: {}", key);
            }
            Some(("discover", discover_matches)) => {
                use jacs::a2a::AgentCard;
                use jacs::a2a::trust::{A2ATrustPolicy, assess_a2a_agent};

                let base_url = discover_matches.get_one::<String>("url").unwrap();
                let json_output = *discover_matches.get_one::<bool>("json").unwrap_or(&false);
                let policy_str = discover_matches
                    .get_one::<String>("policy")
                    .map(|s| s.as_str())
                    .unwrap_or("verified");

                let policy = A2ATrustPolicy::from_str_loose(policy_str)
                    .map_err(|e| Box::<dyn Error>::from(format!("Invalid policy: {}", e)))?;

                // Construct the well-known URL
                let trimmed = base_url.trim_end_matches('/');
                let card_url = format!("{}/.well-known/agent-card.json", trimmed);

                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| format!("HTTP client error: {}", e))?;

                let response = client
                    .get(&card_url)
                    .send()
                    .map_err(|e| format!("Failed to fetch {}: {}", card_url, e))?;

                if !response.status().is_success() {
                    eprintln!(
                        "Failed to discover agent at {}: HTTP {}",
                        card_url,
                        response.status()
                    );
                    process::exit(1);
                }

                let card_json = response
                    .text()
                    .map_err(|e| format!("Read body failed: {}", e))?;

                let card: AgentCard = serde_json::from_str(&card_json)
                    .map_err(|e| format!("Invalid Agent Card JSON at {}: {}", card_url, e))?;

                if json_output {
                    // Print the full Agent Card
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&card).expect("card serialization")
                    );
                } else {
                    // Human-readable summary
                    println!("Discovered A2A Agent: {}", card.name);
                    println!("  Description: {}", card.description);
                    println!("  Version:     {}", card.version);
                    println!("  Protocol:    {}", card.protocol_versions.join(", "));

                    // Show interfaces
                    for iface in &card.supported_interfaces {
                        println!("  Endpoint:    {} ({})", iface.url, iface.protocol_binding);
                    }

                    // Show skills
                    if !card.skills.is_empty() {
                        println!("  Skills:");
                        for skill in &card.skills {
                            println!("    - {} ({})", skill.name, skill.id);
                        }
                    }

                    // JACS extension check
                    let has_jacs = card
                        .capabilities
                        .extensions
                        .as_ref()
                        .map(|exts| exts.iter().any(|e| e.uri == jacs::a2a::JACS_EXTENSION_URI))
                        .unwrap_or(false);
                    println!("  JACS:        {}", if has_jacs { "YES" } else { "NO" });

                    // Trust assessment
                    let agent = jacs::get_empty_agent();
                    let assessment = assess_a2a_agent(&agent, &card, policy);
                    println!(
                        "  Trust:       {} ({})",
                        assessment.trust_level, assessment.reason
                    );
                    if !assessment.allowed {
                        println!(
                            "  WARNING:     Agent not allowed under '{}' policy",
                            policy_str
                        );
                    }
                }
            }
            Some(("serve", serve_matches)) => {
                use jacs::simple::SimpleAgent;

                let port = *serve_matches.get_one::<u16>("port").unwrap();
                let host = serve_matches
                    .get_one::<String>("host")
                    .map(|s| s.as_str())
                    .unwrap_or("127.0.0.1");

                // Load or quickstart the agent
                ensure_cli_private_key_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::other(format!(
                        "Password bootstrap failed: {}\n\n{}",
                        e,
                        quickstart_password_bootstrap_help()
                    )))
                })?;
                let (agent, info) = SimpleAgent::quickstart(
                    "jacs-agent",
                    "localhost",
                    Some("JACS A2A agent"),
                    None,
                    None,
                )
                .map_err(|e| wrap_quickstart_error_with_password_help("Failed to load agent", e))?;

                // Export the Agent Card for display
                let agent_card = agent.export_agent_card().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to export Agent Card: {}", e),
                    ))
                })?;

                // Generate well-known documents via public API
                let documents =
                    agent
                        .generate_well_known_documents(None)
                        .map_err(|e| -> Box<dyn Error> {
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to generate well-known documents: {}", e),
                            ))
                        })?;

                // Build a lookup map: path -> JSON body
                let mut routes: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for (path, value) in &documents {
                    routes.insert(
                        path.clone(),
                        serde_json::to_string_pretty(value).unwrap_or_default(),
                    );
                }

                let addr = format!("{}:{}", host, port);
                let server = tiny_http::Server::http(&addr)
                    .map_err(|e| format!("Failed to start server on {}: {}", addr, e))?;

                println!("Serving A2A well-known endpoints at http://{}", addr);
                println!("  Agent: {} ({})", agent_card.name, info.agent_id);
                println!("  Endpoints:");
                for path in routes.keys() {
                    println!("    http://{}{}", addr, path);
                }
                println!("\nPress Ctrl+C to stop.");

                for request in server.incoming_requests() {
                    let url = request.url().to_string();
                    if let Some(body) = routes.get(&url) {
                        let response = tiny_http::Response::from_string(body.clone()).with_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        let _ = request.respond(response);
                    } else {
                        let response =
                            tiny_http::Response::from_string("{\"error\": \"not found\"}")
                                .with_status_code(404)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"application/json"[..],
                                    )
                                    .unwrap(),
                                );
                        let _ = request.respond(response);
                    }
                }
            }
            Some(("quickstart", qs_matches)) => {
                use jacs::simple::SimpleAgent;

                let port = *qs_matches.get_one::<u16>("port").unwrap();
                let host = qs_matches
                    .get_one::<String>("host")
                    .map(|s| s.as_str())
                    .unwrap_or("127.0.0.1");
                let algorithm = qs_matches
                    .get_one::<String>("algorithm")
                    .map(|s| s.as_str());
                let name = qs_matches
                    .get_one::<String>("name")
                    .map(|s| s.as_str())
                    .unwrap_or("jacs-agent");
                let domain = qs_matches
                    .get_one::<String>("domain")
                    .map(|s| s.as_str())
                    .unwrap_or("localhost");
                let description = qs_matches
                    .get_one::<String>("description")
                    .map(|s| s.as_str());

                // Create or load the agent via quickstart
                ensure_cli_private_key_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::other(format!(
                        "Password bootstrap failed: {}\n\n{}",
                        e,
                        quickstart_password_bootstrap_help()
                    )))
                })?;
                let (agent, info) =
                    SimpleAgent::quickstart(name, domain, description, algorithm, None).map_err(
                        |e| {
                            wrap_quickstart_error_with_password_help(
                                "Failed to quickstart agent",
                                e,
                            )
                        },
                    )?;

                // Export the Agent Card
                let agent_card = agent.export_agent_card().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to export Agent Card: {}", e),
                    ))
                })?;

                // Generate well-known documents
                let documents =
                    agent
                        .generate_well_known_documents(None)
                        .map_err(|e| -> Box<dyn Error> {
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to generate well-known documents: {}", e),
                            ))
                        })?;

                // Build route map
                let mut routes: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for (path, value) in &documents {
                    routes.insert(
                        path.clone(),
                        serde_json::to_string_pretty(value).unwrap_or_default(),
                    );
                }

                let addr = format!("{}:{}", host, port);
                let server = tiny_http::Server::http(&addr)
                    .map_err(|e| format!("Failed to start server on {}: {}", addr, e))?;

                println!("A2A Quickstart");
                println!("==============");
                println!("Agent: {} ({})", agent_card.name, info.agent_id);
                println!("Algorithm: {}", algorithm.unwrap_or("pq2025"));
                println!();
                println!("Discovery URL: http://{}/.well-known/agent-card.json", addr);
                println!();
                println!("Endpoints:");
                for path in routes.keys() {
                    println!("  http://{}{}", addr, path);
                }
                println!();
                println!("Press Ctrl+C to stop.");

                for request in server.incoming_requests() {
                    let url = request.url().to_string();
                    if let Some(body) = routes.get(&url) {
                        let response = tiny_http::Response::from_string(body.clone()).with_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        let _ = request.respond(response);
                    } else {
                        let response =
                            tiny_http::Response::from_string("{\"error\": \"not found\"}")
                                .with_status_code(404)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"application/json"[..],
                                    )
                                    .unwrap(),
                                );
                        let _ = request.respond(response);
                    }
                }
            }
            _ => println!("please enter subcommand see jacs a2a --help"),
        },
        Some(("quickstart", qs_matches)) => {
            use jacs::simple::SimpleAgent;

            let algorithm = qs_matches
                .get_one::<String>("algorithm")
                .map(|s| s.as_str());
            let name = qs_matches
                .get_one::<String>("name")
                .map(|s| s.as_str())
                .unwrap_or("jacs-agent");
            let domain = qs_matches
                .get_one::<String>("domain")
                .map(|s| s.as_str())
                .unwrap_or("localhost");
            let description = qs_matches
                .get_one::<String>("description")
                .map(|s| s.as_str());
            let do_sign = *qs_matches.get_one::<bool>("sign").unwrap_or(&false);
            let sign_file = qs_matches.get_one::<String>("file");

            ensure_cli_private_key_password().map_err(|e| -> Box<dyn Error> {
                Box::new(std::io::Error::other(format!(
                    "Password bootstrap failed: {}\n\n{}",
                    e,
                    quickstart_password_bootstrap_help()
                )))
            })?;
            let (agent, info) = SimpleAgent::quickstart(name, domain, description, algorithm, None)
                .map_err(|e| wrap_quickstart_error_with_password_help("Quickstart failed", e))?;

            if do_sign {
                // Sign mode: read JSON, sign it, print signed document
                let input = if let Some(file_path) = sign_file {
                    std::fs::read_to_string(file_path)?
                } else {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    buf
                };

                let value: serde_json::Value = serde_json::from_str(&input)
                    .map_err(|e| format!("Invalid JSON input: {}", e))?;

                let signed = agent.sign_message(&value).map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Signing failed: {}", e),
                    ))
                })?;

                println!("{}", signed.raw);
            } else {
                // Info mode: print agent details
                println!("JACS agent ready ({})", info.algorithm);
                println!("  Agent ID: {}", info.agent_id);
                println!("  Version:  {}", info.version);
                println!("  Config:   {}", info.config_path);
                println!("  Keys:     {}", info.key_directory);
                println!();
                println!("Sign something:");
                println!("  echo '{{\"hello\":\"world\"}}' | jacs quickstart --sign");
            }
        }
        #[cfg(feature = "attestation")]
        Some(("attest", attest_matches)) => {
            use jacs::attestation::types::*;
            use jacs::simple::SimpleAgent;

            match attest_matches.subcommand() {
                Some(("create", create_matches)) => {
                    // Ensure password is available for signing
                    ensure_cli_private_key_password()?;

                    // Load agent
                    let agent = match SimpleAgent::load(None, None) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("Failed to load agent: {}", e);
                            eprintln!("Run `jacs quickstart` first to create an agent.");
                            process::exit(1);
                        }
                    };

                    // Parse claims (required)
                    let claims_str = create_matches
                        .get_one::<String>("claims")
                        .expect("claims is required");
                    let claims: Vec<Claim> = serde_json::from_str(claims_str).map_err(|e| {
                        format!(
                            "Invalid claims JSON: {}. \
                             Provide a JSON array like '[{{\"name\":\"reviewed\",\"value\":true}}]'",
                            e
                        )
                    })?;

                    // Parse optional evidence
                    let evidence: Vec<EvidenceRef> =
                        if let Some(ev_str) = create_matches.get_one::<String>("evidence") {
                            serde_json::from_str(ev_str)
                                .map_err(|e| format!("Invalid evidence JSON: {}", e))?
                        } else {
                            vec![]
                        };

                    let att_json = if let Some(doc_path) =
                        create_matches.get_one::<String>("from-document")
                    {
                        // Lift from existing signed document
                        let doc_content = std::fs::read_to_string(doc_path).map_err(|e| {
                            format!("Failed to read document '{}': {}", doc_path, e)
                        })?;
                        let result =
                            agent
                                .lift_to_attestation(&doc_content, &claims)
                                .map_err(|e| {
                                    format!("Failed to lift document to attestation: {}", e)
                                })?;
                        result.raw
                    } else {
                        // Build from scratch: need subject-type, subject-id, subject-digest
                        let subject_type_str = create_matches
                            .get_one::<String>("subject-type")
                            .ok_or("--subject-type is required when not using --from-document")?;
                        let subject_id = create_matches
                            .get_one::<String>("subject-id")
                            .ok_or("--subject-id is required when not using --from-document")?;
                        let subject_digest = create_matches
                            .get_one::<String>("subject-digest")
                            .ok_or("--subject-digest is required when not using --from-document")?;

                        let subject_type = match subject_type_str.as_str() {
                            "agent" => SubjectType::Agent,
                            "artifact" => SubjectType::Artifact,
                            "workflow" => SubjectType::Workflow,
                            "identity" => SubjectType::Identity,
                            other => {
                                return Err(format!("Unknown subject type: '{}'", other).into());
                            }
                        };

                        let subject = AttestationSubject {
                            subject_type,
                            id: subject_id.clone(),
                            digests: DigestSet {
                                sha256: subject_digest.clone(),
                                sha512: None,
                                additional: std::collections::HashMap::new(),
                            },
                        };

                        let result = agent
                            .create_attestation(&subject, &claims, &evidence, None, None)
                            .map_err(|e| format!("Failed to create attestation: {}", e))?;
                        result.raw
                    };

                    // Output to file or stdout
                    if let Some(output_path) = create_matches.get_one::<String>("output") {
                        std::fs::write(output_path, &att_json).map_err(|e| {
                            format!("Failed to write output file '{}': {}", output_path, e)
                        })?;
                        eprintln!("Attestation written to {}", output_path);
                    } else {
                        println!("{}", att_json);
                    }
                }
                Some(("verify", verify_matches)) => {
                    let file_path = verify_matches
                        .get_one::<String>("file")
                        .expect("file is required");
                    let full = *verify_matches.get_one::<bool>("full").unwrap_or(&false);
                    let json_output = *verify_matches.get_one::<bool>("json").unwrap_or(&false);
                    let key_dir = verify_matches.get_one::<String>("key-dir");
                    let max_depth = verify_matches.get_one::<u32>("max-depth");

                    // Set key directory if specified
                    if let Some(kd) = key_dir {
                        // SAFETY: CLI is single-threaded at this point
                        unsafe { std::env::set_var("JACS_KEY_DIRECTORY", kd) };
                    }

                    // Set max derivation depth if specified
                    if let Some(depth) = max_depth {
                        // SAFETY: CLI is single-threaded at this point
                        unsafe {
                            std::env::set_var("JACS_MAX_DERIVATION_DEPTH", depth.to_string())
                        };
                    }

                    // Read the attestation file
                    let att_content = std::fs::read_to_string(file_path).map_err(|e| {
                        format!("Failed to read attestation file '{}': {}", file_path, e)
                    })?;

                    // Load or create ephemeral agent for verification
                    ensure_cli_private_key_password().ok();
                    let agent = match SimpleAgent::load(None, None) {
                        Ok(a) => a,
                        Err(_) => {
                            let (a, _) = SimpleAgent::ephemeral(Some("ed25519"))
                                .map_err(|e| format!("Failed to create verifier: {}", e))?;
                            a
                        }
                    };

                    // Load the attestation document into agent storage first
                    let att_value: serde_json::Value = serde_json::from_str(&att_content)
                        .map_err(|e| format!("Invalid attestation JSON: {}", e))?;
                    let doc_key = format!(
                        "{}:{}",
                        att_value["jacsId"].as_str().unwrap_or("unknown"),
                        att_value["jacsVersion"].as_str().unwrap_or("unknown")
                    );

                    // We need to store the document so verify can find it by key.
                    // Use verify() which parses and stores the doc, then verify attestation.
                    let verify_result = agent.verify(&att_content);
                    if let Err(e) = &verify_result {
                        if json_output {
                            let out = serde_json::json!({
                                "valid": false,
                                "error": e.to_string(),
                            });
                            println!("{}", serde_json::to_string_pretty(&out).unwrap());
                        } else {
                            eprintln!("Verification error: {}", e);
                        }
                        process::exit(1);
                    }

                    // Now do attestation-specific verification
                    let att_result = if full {
                        agent.verify_attestation_full(&doc_key)
                    } else {
                        agent.verify_attestation(&doc_key)
                    };

                    match att_result {
                        Ok(r) => {
                            if json_output {
                                println!("{}", serde_json::to_string_pretty(&r).unwrap());
                            } else {
                                println!(
                                    "Status:    {}",
                                    if r.valid { "VALID" } else { "INVALID" }
                                );
                                println!(
                                    "Signature: {}",
                                    if r.crypto.signature_valid {
                                        "valid"
                                    } else {
                                        "INVALID"
                                    }
                                );
                                println!(
                                    "Hash:      {}",
                                    if r.crypto.hash_valid {
                                        "valid"
                                    } else {
                                        "INVALID"
                                    }
                                );
                                if !r.crypto.signer_id.is_empty() {
                                    println!("Signer:    {}", r.crypto.signer_id);
                                }
                                if !r.evidence.is_empty() {
                                    println!("Evidence:  {} items checked", r.evidence.len());
                                }
                                if !r.errors.is_empty() {
                                    for err in &r.errors {
                                        eprintln!("  Error: {}", err);
                                    }
                                }
                            }
                            if !r.valid {
                                process::exit(1);
                            }
                        }
                        Err(e) => {
                            if json_output {
                                let out = serde_json::json!({
                                    "valid": false,
                                    "error": e.to_string(),
                                });
                                println!("{}", serde_json::to_string_pretty(&out).unwrap());
                            } else {
                                eprintln!("Attestation verification error: {}", e);
                            }
                            process::exit(1);
                        }
                    }
                }
                Some(("export-dsse", export_matches)) => {
                    let file_path = export_matches
                        .get_one::<String>("file")
                        .expect("file argument required");
                    let output_path = export_matches.get_one::<String>("output");

                    let attestation_json = std::fs::read_to_string(file_path).unwrap_or_else(|e| {
                        eprintln!("Cannot read {}: {}", file_path, e);
                        process::exit(1);
                    });

                    let (agent, _info) = SimpleAgent::ephemeral(Some("ring-Ed25519"))
                        .unwrap_or_else(|e| {
                            eprintln!("Failed to create agent: {}", e);
                            process::exit(1);
                        });

                    match agent.export_dsse(&attestation_json) {
                        Ok(envelope_json) => {
                            if let Some(out_path) = output_path {
                                std::fs::write(out_path, &envelope_json).unwrap_or_else(|e| {
                                    eprintln!("Cannot write to {}: {}", out_path, e);
                                    process::exit(1);
                                });
                                println!("DSSE envelope written to {}", out_path);
                            } else {
                                println!("{}", envelope_json);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to export DSSE envelope: {}", e);
                            process::exit(1);
                        }
                    }
                }
                _ => {
                    eprintln!(
                        "Use 'jacs attest create', 'jacs attest verify', or 'jacs attest export-dsse'. See --help."
                    );
                    process::exit(1);
                }
            }
        }
        Some(("verify", verify_matches)) => {
            use jacs::simple::SimpleAgent;
            use serde_json::json;

            let file_path = verify_matches.get_one::<String>("file");
            let remote_url = verify_matches.get_one::<String>("remote");
            let json_output = *verify_matches.get_one::<bool>("json").unwrap_or(&false);
            let key_dir = verify_matches.get_one::<String>("key-dir");

            // Optionally set key directory env var so the agent resolves keys from there
            if let Some(kd) = key_dir {
                // SAFETY: CLI is single-threaded at this point
                unsafe { std::env::set_var("JACS_KEY_DIRECTORY", kd) };
            }

            // Get the document content
            let document = if let Some(url) = remote_url {
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .map_err(|e| format!("HTTP client error: {}", e))?;
                let resp = client
                    .get(url)
                    .send()
                    .map_err(|e| format!("Fetch failed: {}", e))?;
                if !resp.status().is_success() {
                    eprintln!("HTTP error: {}", resp.status());
                    process::exit(1);
                }
                resp.text()
                    .map_err(|e| format!("Read body failed: {}", e))?
            } else if let Some(path) = file_path {
                std::fs::read_to_string(path).map_err(|e| format!("Read file failed: {}", e))?
            } else {
                eprintln!("Provide a file path or --remote <url>");
                process::exit(1);
            };

            // Try to load an existing agent (from config in cwd or env vars).
            // This gives access to the agent's own keys for verifying self-signed docs.
            // Fall back to an ephemeral agent if no config is available.
            let agent = if std::path::Path::new("./jacs.config.json").exists() {
                if let Err(e) = ensure_cli_private_key_password() {
                    eprintln!("Warning: Password bootstrap failed: {}", e);
                    eprintln!("{}", quickstart_password_bootstrap_help());
                }
                match SimpleAgent::load(None, None) {
                    Ok(a) => a,
                    Err(e) => {
                        let lower = e.to_string().to_lowercase();
                        if lower.contains("password")
                            || lower.contains("decrypt")
                            || lower.contains("private key")
                        {
                            eprintln!(
                                "Warning: Could not load local agent from ./jacs.config.json: {}",
                                e
                            );
                            eprintln!("{}", quickstart_password_bootstrap_help());
                        }
                        let (a, _) = SimpleAgent::ephemeral(Some("ed25519"))
                            .map_err(|e| format!("Failed to create verifier: {}", e))?;
                        a
                    }
                }
            } else {
                let (a, _) = SimpleAgent::ephemeral(Some("ed25519"))
                    .map_err(|e| format!("Failed to create verifier: {}", e))?;
                a
            };

            match agent.verify(&document) {
                Ok(r) => {
                    if json_output {
                        let out = json!({
                            "valid": r.valid,
                            "signerId": r.signer_id,
                            "timestamp": r.timestamp,
                        });
                        println!("{}", serde_json::to_string_pretty(&out).unwrap());
                    } else {
                        println!("Status:    {}", if r.valid { "VALID" } else { "INVALID" });
                        println!(
                            "Signer:    {}",
                            if r.signer_id.is_empty() {
                                "(unknown)"
                            } else {
                                &r.signer_id
                            }
                        );
                        if !r.timestamp.is_empty() {
                            println!("Signed at: {}", r.timestamp);
                        }
                    }
                    if !r.valid {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    if json_output {
                        let out = json!({
                            "valid": false,
                            "error": e.to_string(),
                        });
                        println!("{}", serde_json::to_string_pretty(&out).unwrap());
                    } else {
                        eprintln!("Verification error: {}", e);
                    }
                    process::exit(1);
                }
            }
        }
        Some(("init", init_matches)) => {
            let auto_yes = *init_matches.get_one::<bool>("yes").unwrap_or(&false);
            println!("--- Running Config Creation ---");
            handle_config_create()?;
            println!("\n--- Running Agent Creation (with keys) ---");
            handle_agent_create_auto(None, true, auto_yes)?;
            println!("\n--- JACS Initialization Complete ---");
        }
        _ => {
            // This branch should ideally be unreachable after adding arg_required_else_help(true)
            eprintln!("Invalid command or no subcommand provided. Use --help for usage.");
            process::exit(1); // Exit with error if this branch is reached
        }
    }

    Ok(())
}
