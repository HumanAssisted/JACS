//! Thin filesystem/terminal boundary around the portable JACS core.
//!
//! Cryptography, encrypted material validation, and rotation are delegated to
//! `jacs-core` and the shared `jacs-mcp::vault` adapter.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, Command, CommandFactory, Parser, Subcommand, ValueEnum};
use jacs_core::{AgentMaterial, CoreAgent, SigningAlgorithm, strict_json::parse_strict_json_slice};
use jacs_mcp::vault;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
pub const PASSWORD_ENV: &str = "JACS_PRIVATE_KEY_PASSWORD";
pub const NEW_PASSWORD_ENV: &str = "JACS_NEW_PRIVATE_KEY_PASSWORD";

#[derive(Parser)]
#[command(
    name = "jacs",
    version,
    about = "Portable signatures and encrypted agent keys",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Create an encrypted agent (ML-DSA-87 by default).
    Create {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "pq2025")]
        algorithm: Algorithm,
    },
    /// Unlock an agent for one operation and sign a JSON message.
    Sign {
        #[arg(long)]
        agent: PathBuf,
        /// JSON filename, or - to read stdin.
        #[arg(long)]
        input: String,
        /// Write signed JSON to a new file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify signed JSON using a separately trusted public key or agent bundle.
    Verify {
        #[command(flatten)]
        trust: TrustInput,
        #[arg(long)]
        input: String,
    },
    /// Rotate keys while preserving the identity and proving the key transition.
    Rotate {
        #[arg(long)]
        agent: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Defaults to pq2025. A post-quantum identity cannot be downgraded.
        #[arg(long, value_enum)]
        algorithm: Option<Algorithm>,
    },
    /// Re-encrypt an agent with a new password without changing its identity.
    Reencrypt(RewrapInput),
    /// Import an encrypted transfer bundle under a new local password.
    Import {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export an agent as an encrypted transfer bundle under a new password.
    Export(RewrapInput),
    /// Serve the focused MCP tools over stdio.
    Mcp {
        #[arg(long, value_enum, default_value = "verify-only")]
        profile: McpProfile,
        /// Required for local-sign; never accepted for verify-only.
        #[arg(long)]
        agent: Option<PathBuf>,
    },
}

#[derive(Args)]
struct RewrapInput {
    #[arg(long)]
    agent: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct TrustInput {
    /// A trusted encrypted agent bundle; verification does not unlock it.
    #[arg(long)]
    agent: Option<PathBuf>,
    /// Trusted public identity JSON with algorithm, public_key (base64), agent_id.
    #[arg(long)]
    public_identity: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Algorithm {
    Pq2025,
    Ed25519,
    Es256,
}

impl From<Algorithm> for SigningAlgorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::Pq2025 => Self::Pq2025,
            Algorithm::Ed25519 => Self::Ed25519,
            Algorithm::Es256 => Self::Es256,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum McpProfile {
    VerifyOnly,
    LocalSign,
}

pub fn build_cli() -> Command {
    Cli::command()
}

/// Stable, sanitized command errors. Never include input JSON or passwords.
pub struct CliError {
    pub code: &'static str,
    pub message: String,
}

fn failure(code: &'static str, message: impl Into<String>) -> CliError {
    CliError {
        code,
        message: message.into(),
    }
}

fn vault_error(error: vault::VaultError) -> CliError {
    failure("vault", error.to_string())
}

/// Structured diagnostics always go to stderr, including for MCP.
pub fn initialize_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        )
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .json()
        .try_init();
}

/// Execute one CLI request. False means verification failed; no retry occurs.
pub fn execute(cli: Cli) -> Result<bool, CliError> {
    match cli.command {
        Operation::Create { output, algorithm } => {
            let password = password(PASSWORD_ENV, "New agent password: ", true)?;
            let material =
                vault::create_material(algorithm.into(), &password).map_err(vault_error)?;
            save_material(&output, &material)?;
        }
        Operation::Sign {
            agent,
            input,
            output,
        } => {
            let material = vault::read_material(&agent).map_err(vault_error)?;
            let message = read_json(&input)?;
            let password = password(PASSWORD_ENV, "Agent password: ", false)?;
            let mut unlocked = vault::unlock(&material, &password).map_err(vault_error)?;
            let signed = unlocked.sign_message(&message);
            unlocked.clear_secrets();
            let signed = signed.map_err(|_| failure("sign", "Could not sign the JSON message"))?;
            write_json(&signed, output.as_deref())?;
        }
        Operation::Verify { trust, input } => {
            let signed = read_json(&input)?;
            let (key, algorithm, expected_id) = trusted_identity(trust)?;
            let result = CoreAgent::verify_with_key(&signed, &key, algorithm);
            let (valid, signer_id) = match result {
                Ok(result) => (
                    result.valid && result.signer_id == expected_id,
                    result.signer_id,
                ),
                Err(_) => (false, String::new()),
            };
            if !valid {
                tracing::warn!("JACS signature or trusted identity verification failed");
            }
            write_json(&json!({"valid": valid, "signer_id": signer_id}), None)?;
            return Ok(valid);
        }
        Operation::Rotate {
            agent,
            output,
            algorithm,
        } => {
            let material = vault::read_material(&agent).map_err(vault_error)?;
            let old_password = password(PASSWORD_ENV, "Current agent password: ", false)?;
            let new_password = password(NEW_PASSWORD_ENV, "New agent password: ", true)?;
            let rotated = vault::rotate(
                &material,
                &old_password,
                &new_password,
                algorithm.map(Into::into),
            )
            .map_err(vault_error)?;
            save_material(&output, &rotated)?;
        }
        Operation::Reencrypt(input) | Operation::Export(input) => {
            rewrap(&input.agent, &input.output)?;
        }
        Operation::Import { input, output } => rewrap(&input, &output)?,
        Operation::Mcp { profile, agent } => {
            let server = match (profile, agent) {
                (McpProfile::VerifyOnly, None) => jacs_mcp::JacsMcpServer::verify_only(),
                (McpProfile::LocalSign, Some(path)) => {
                    let password = password(PASSWORD_ENV, "Agent password: ", false)?;
                    // Optional destination password is captured once at startup;
                    // tool parameters can never supply or read it.
                    let new_password = optional_env_secret(NEW_PASSWORD_ENV)?;
                    jacs_mcp::JacsMcpServer::local_sign(path, password, new_password)
                        .map_err(|_| failure("mcp", "Could not unlock the configured MCP agent"))?
                }
                _ => {
                    return Err(failure(
                        "usage",
                        "--agent is required only with --profile local-sign",
                    ));
                }
            };
            tracing::info!("Starting JACS MCP stdio server");
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| failure("mcp", "Could not start the MCP runtime"))?
                .block_on(jacs_mcp::serve_stdio(server))
                .map_err(|_| failure("mcp", "MCP stdio session failed"))?;
        }
    }
    Ok(true)
}

fn rewrap(input: &Path, output: &Path) -> Result<(), CliError> {
    let material = vault::read_material(input).map_err(vault_error)?;
    let old_password = password(PASSWORD_ENV, "Current or transfer password: ", false)?;
    let new_password = password(NEW_PASSWORD_ENV, "New local or transfer password: ", true)?;
    let rewrapped =
        vault::reencrypt(&material, &old_password, &new_password).map_err(vault_error)?;
    save_material(output, &rewrapped)
}

fn save_material(path: &Path, material: &AgentMaterial) -> Result<(), CliError> {
    vault::write_material(path, material).map_err(vault_error)?;
    // Public metadata only. This can be shared as verify --public-identity input.
    let public_key = STANDARD.encode(&material.public_key);
    write_json(
        &json!({
            "agent_id": material.agent["jacsId"],
            "agent_version": material.agent["jacsVersion"],
            "algorithm": material.algorithm,
            "public_key": public_key,
            "output": path,
        }),
        None,
    )
}

fn trusted_identity(trust: TrustInput) -> Result<(Vec<u8>, SigningAlgorithm, String), CliError> {
    if let Some(path) = trust.agent {
        let material = vault::read_material(&path).map_err(vault_error)?;
        let id = material.agent["jacsId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| failure("trust", "Trusted identity has no agent id"))?
            .to_owned();
        Ok((material.public_key, material.algorithm, id))
    } else if let Some(path) = trust.public_identity {
        let public = read_json_path(&path)?;
        let id = public["agent_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| failure("trust", "Public identity requires an agent_id"))?
            .to_owned();
        let algorithm = public["algorithm"]
            .as_str()
            .and_then(SigningAlgorithm::from_wire_str)
            .ok_or_else(|| failure("trust", "Invalid public identity algorithm"))?;
        let key = public["public_key"]
            .as_str()
            .and_then(|encoded| STANDARD.decode(encoded).ok())
            .ok_or_else(|| failure("trust", "Invalid public identity key"))?;
        Ok((key, algorithm, id))
    } else {
        Err(failure(
            "trust",
            "A separately trusted identity is required",
        ))
    }
}

fn optional_env_secret(name: &str) -> Result<Option<Zeroizing<String>>, CliError> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(Some(Zeroizing::new(value))),
        Ok(_) => Err(failure("password", format!("{name} must not be empty"))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(failure(
            "password",
            format!("{name} must contain valid UTF-8"),
        )),
    }
}

fn password(name: &str, prompt: &str, confirm: bool) -> Result<Zeroizing<String>, CliError> {
    if let Some(value) = optional_env_secret(name)? {
        return Ok(value);
    }
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|_| failure("password", format!("A terminal or {name} is required")))?,
    );
    if value.is_empty() {
        return Err(failure("password", "Password must not be empty"));
    }
    if confirm {
        let confirmation = Zeroizing::new(
            rpassword::prompt_password("Confirm password: ")
                .map_err(|_| failure("password", "Could not read password confirmation"))?,
        );
        if *value != *confirmation {
            return Err(failure("password", "Passwords do not match"));
        }
    }
    Ok(value)
}

fn read_json(input: &str) -> Result<Value, CliError> {
    if input == "-" {
        decode_json(std::io::stdin().lock())
    } else {
        read_json_path(Path::new(input))
    }
}

fn read_json_path(path: &Path) -> Result<Value, CliError> {
    decode_json(
        std::fs::File::open(path).map_err(|_| failure("input", "Could not open JSON input"))?,
    )
}

fn decode_json(reader: impl Read) -> Result<Value, CliError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("input", "Could not read JSON input"))?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(failure("input", "JSON input exceeds the 4 MiB limit"));
    }
    parse_strict_json_slice(&bytes)
        .map_err(|_| failure("input", "Input must be unambiguous I-JSON"))
}

fn write_json(value: &Value, output: Option<&Path>) -> Result<(), CliError> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| failure("output", "Could not encode JSON output"))?;
    bytes.push(b'\n');
    if let Some(path) = output {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|_| failure("output", "Output must be a new writable file"))?;
        file.write_all(&bytes)
            .map_err(|_| failure("output", "Could not write JSON output"))?;
    } else {
        std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(|_| failure("output", "Could not write JSON output"))?;
    }
    Ok(())
}
