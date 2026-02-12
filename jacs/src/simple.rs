//! Simplified JACS API for common operations.
//!
//! This module provides a clean, developer-friendly API for the most common
//! JACS operations: creating agents, signing messages/files, and verification.
//!
//! # IMPORTANT: Signing is Sacred
//!
//! **Signing a document is a permanent, irreversible cryptographic commitment.**
//!
//! When an agent signs a document:
//! - The signature creates proof that binds the signer to the content forever
//! - The signer cannot deny having signed (non-repudiation)
//! - Anyone can verify the signature at any time
//! - The signer is accountable for what they signed
//!
//! **Always review documents carefully before signing.** Do not sign:
//! - Content you haven't read or don't understand
//! - Documents whose implications you haven't considered
//! - Anything you wouldn't want permanently associated with your identity
//!
//! # Quick Start (Instance-based API - Recommended)
//!
//! ```rust,ignore
//! use jacs::simple::SimpleAgent;
//!
//! // Create a new agent identity
//! let agent = SimpleAgent::create("my-agent", None, None)?;
//!
//! // Sign a message (REVIEW CONTENT FIRST!)
//! let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
//!
//! // Verify the signed document
//! let result = agent.verify(&signed.raw)?;
//! assert!(result.valid);
//! ```
//!
//! # Loading an Existing Agent
//!
//! ```rust,ignore
//! use jacs::simple::SimpleAgent;
//!
//! // Load from default config path
//! let agent = SimpleAgent::load(None)?;
//!
//! // Or from a specific config
//! let agent = SimpleAgent::load(Some("./my-agent/jacs.config.json"))?;
//! ```
//!
//! # Design Philosophy
//!
//! This API is a facade over the existing JACS functionality, designed for:
//! - **Simplicity**: 6 core operations cover 90% of use cases
//! - **Safety**: Errors include actionable guidance
//! - **Consistency**: Same API shape across Rust, Python, Go, and NPM
//! - **Thread Safety**: Instance-based design avoids global mutable state
//! - **Signing Gravity**: Documentation emphasizes the sacred nature of signing

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::create_minimal_blank_agent;
use crate::error::JacsError;
use crate::mime::mime_from_extension;
use crate::schema::utils::{ValueExt, check_document_size};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info, warn};

// =============================================================================
// Diagnostics (standalone, no agent required)
// =============================================================================

/// Returns diagnostic information about the JACS installation.
/// Does not require a loaded agent.
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

// =============================================================================
// Verify link constants (HAI / public verification URLs)
// =============================================================================

/// Maximum length for a full verify URL (scheme + host + path + ?s=...) to stay within
/// typical HTTP GET URL limits (e.g. 2048 chars in many clients/servers).
pub const MAX_VERIFY_URL_LEN: usize = 2048;

/// Maximum UTF-8 byte length of a JACS document that can be encoded into a verify link
/// while staying under MAX_VERIFY_URL_LEN (base64 expands by ~4/3; with typical base URL
/// the `s` parameter is limited to 2020 chars).
pub const MAX_VERIFY_DOCUMENT_BYTES: usize = 1515;

const DEFAULT_PRIVATE_KEY_FILENAME: &str = "jacs.private.pem.enc";
const DEFAULT_PUBLIC_KEY_FILENAME: &str = "jacs.public.pem";

/// Generate a cryptographically secure random password that meets JACS requirements.
/// (8+ chars, uppercase, lowercase, digit, special character.)
fn generate_secure_password() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let charset: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    // Guarantee complexity: start with one of each required class
    let mut password = String::with_capacity(32);
    password.push(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[rng.random_range(0..26)] as char);
    password.push(b"abcdefghijklmnopqrstuvwxyz"[rng.random_range(0..26)] as char);
    password.push(b"0123456789"[rng.random_range(0..10)] as char);
    password.push(b"!@#$%^&*()-_=+"[rng.random_range(0..14)] as char);
    // Fill rest with random charset
    for _ in 4..32 {
        password.push(charset[rng.random_range(0..charset.len())] as char);
    }
    password
}

fn build_agent_document(
    agent_type: &str,
    name: &str,
    description: &str,
) -> Result<Value, JacsError> {
    let template =
        create_minimal_blank_agent(agent_type.to_string(), None, None, None).map_err(|e| {
            JacsError::Internal {
                message: format!("Failed to create minimal agent template: {}", e),
            }
        })?;

    let mut agent_json: Value =
        serde_json::from_str(&template).map_err(|e| JacsError::Internal {
            message: format!("Failed to parse minimal agent template JSON: {}", e),
        })?;

    let obj = agent_json
        .as_object_mut()
        .ok_or_else(|| JacsError::Internal {
            message: "Generated minimal agent template is not a JSON object".to_string(),
        })?;

    obj.insert("name".to_string(), json!(name));
    obj.insert("description".to_string(), json!(description));
    Ok(agent_json)
}

/// Build a verification URL for a signed JACS document (e.g. for hai.ai or custom verifier).
///
/// Encodes `document` as URL-safe base64 and appends it as the `s` query parameter.
/// Returns an error if the resulting URL would exceed [`MAX_VERIFY_URL_LEN`].
///
/// # Example
/// ```ignore
/// let url = jacs::simple::generate_verify_link(r#"{"signed":...}"#, "https://hai.ai")?;
/// // => "https://hai.ai/jacs/verify?s=eyJzaWduZWQi..."
/// ```
pub fn generate_verify_link(document: &str, base_url: &str) -> Result<String, JacsError> {
    let base = base_url.trim_end_matches('/');
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(document.as_bytes());
    let path_and_query = format!("/jacs/verify?s={}", encoded);
    let full_url = format!("{}{}", base, path_and_query);
    if full_url.len() > MAX_VERIFY_URL_LEN {
        return Err(JacsError::ValidationError(format!(
            "Verify URL would exceed max length ({}). Document size must be at most {} UTF-8 bytes.",
            MAX_VERIFY_URL_LEN, MAX_VERIFY_DOCUMENT_BYTES
        )));
    }
    Ok(full_url)
}

// =============================================================================
// Types
// =============================================================================

/// Information about a created or loaded agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Unique identifier for the agent (UUID).
    pub agent_id: String,
    /// Human-readable name of the agent.
    pub name: String,
    /// Path to the public key file.
    pub public_key_path: String,
    /// Path to the configuration file.
    pub config_path: String,
    /// Agent version string.
    #[serde(default)]
    pub version: String,
    /// Signing algorithm used.
    #[serde(default)]
    pub algorithm: String,
    /// Path to the private key file.
    #[serde(default)]
    pub private_key_path: String,
    /// Data directory path.
    #[serde(default)]
    pub data_directory: String,
    /// Key directory path.
    #[serde(default)]
    pub key_directory: String,
    /// Agent domain (if configured).
    #[serde(default)]
    pub domain: String,
    /// DNS TXT record to publish (if domain was configured).
    #[serde(default)]
    pub dns_record: String,
    /// Whether the agent was registered with HAI.
    #[serde(default)]
    pub hai_registered: bool,
}

/// A signed JACS document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDocument {
    /// The full JSON string of the signed JACS document.
    pub raw: String,
    /// Unique identifier for this document (UUID).
    pub document_id: String,
    /// ID of the agent that signed this document.
    pub agent_id: String,
    /// ISO 8601 timestamp of when the document was signed.
    pub timestamp: String,
}

/// Result of verifying a signed document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the signature is valid.
    pub valid: bool,
    /// The original data that was signed (extracted from the document).
    pub data: Value,
    /// ID of the agent that signed the document.
    pub signer_id: String,
    /// Name of the signer (if available in trust store).
    pub signer_name: Option<String>,
    /// ISO 8601 timestamp of when the document was signed.
    pub timestamp: String,
    /// Any file attachments included in the document.
    pub attachments: Vec<Attachment>,
    /// Error messages if verification failed.
    pub errors: Vec<String>,
}

impl VerificationResult {
    /// Creates a failed verification result with the given error message.
    ///
    /// This is a convenience constructor for creating a `VerificationResult`
    /// that represents a failed verification.
    ///
    /// # Arguments
    ///
    /// * `error` - The error message describing why verification failed
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with `valid: false` and the error in the `errors` field.
    #[must_use]
    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            data: json!(null),
            signer_id: String::new(),
            signer_name: None,
            timestamp: String::new(),
            attachments: vec![],
            errors: vec![error],
        }
    }

    /// Creates a successful verification result.
    ///
    /// # Arguments
    ///
    /// * `data` - The verified data/content
    /// * `signer_id` - The ID of the agent that signed the document
    /// * `timestamp` - The timestamp when the document was signed
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with `valid: true` and no errors.
    #[must_use]
    pub fn success(data: Value, signer_id: String, timestamp: String) -> Self {
        Self {
            valid: true,
            data,
            signer_id,
            signer_name: None,
            timestamp,
            attachments: vec![],
            errors: vec![],
        }
    }
}

/// A file attachment in a signed document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Original filename.
    pub filename: String,
    /// MIME type of the file.
    pub mime_type: String,
    /// File content (decoded if it was embedded).
    #[serde(with = "base64_bytes")]
    pub content: Vec<u8>,
    /// SHA-256 hash of the original file.
    pub hash: String,
    /// Whether the file was embedded (true) or referenced (false).
    pub embedded: bool,
}

// Custom serialization for Vec<u8> as base64
mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Setup instructions for publishing a JACS agent's DNS record, enabling DNSSEC,
/// and registering with HAI.ai.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupInstructions {
    /// BIND-format DNS record line (e.g. `_v1.agent.jacs.example.com. 3600 IN TXT "..."`)
    pub dns_record_bind: String,
    /// The raw TXT record value (without the owner/TTL/class prefix).
    pub dns_record_value: String,
    /// The DNS owner name (e.g. `_v1.agent.jacs.example.com.`)
    pub dns_owner: String,
    /// Provider-specific CLI/API commands keyed by provider name.
    pub provider_commands: std::collections::HashMap<String, String>,
    /// Provider-specific DNSSEC guidance keyed by provider name.
    pub dnssec_instructions: std::collections::HashMap<String, String>,
    /// Guidance about domain ownership requirements.
    pub tld_requirement: String,
    /// JSON payload for `/.well-known/jacs-agent.json`.
    pub well_known_json: String,
    /// HAI.ai registration URL.
    pub hai_registration_url: String,
    /// JSON payload to POST to HAI.ai for registration.
    pub hai_registration_payload: String,
    /// Human-readable instructions for HAI.ai registration.
    pub hai_registration_instructions: String,
    /// Human-readable summary of all setup steps.
    pub summary: String,
}

// =============================================================================
// Programmatic Creation Parameters
// =============================================================================

/// Parameters for programmatic agent creation.
///
/// Provides full control over agent creation without interactive prompts.
/// Use `CreateAgentParams::builder()` for a fluent API, or construct directly.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::CreateAgentParams;
///
/// let params = CreateAgentParams::builder()
///     .name("my-agent")
///     .password("MyStr0ng!Pass#2024")
///     .algorithm("pq2025")
///     .build();
///
/// let (agent, info) = SimpleAgent::create_with_params(params)?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAgentParams {
    /// Human-readable name for the agent (required).
    pub name: String,
    /// Password for encrypting the private key.
    /// If empty, falls back to JACS_PRIVATE_KEY_PASSWORD env var.
    #[serde(default)]
    pub password: String,
    /// Signing algorithm. Default: "pq2025".
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Directory for data storage. Default: "./jacs_data".
    #[serde(default = "default_data_directory")]
    pub data_directory: String,
    /// Directory for keys. Default: "./jacs_keys".
    #[serde(default = "default_key_directory")]
    pub key_directory: String,
    /// Path to the config file. Default: "./jacs.config.json".
    #[serde(default = "default_config_path")]
    pub config_path: String,
    /// Agent type (e.g., "ai", "human", "hybrid"). Default: "ai".
    #[serde(default = "default_agent_type")]
    pub agent_type: String,
    /// Description of the agent's purpose.
    #[serde(default)]
    pub description: String,
    /// Agent domain for DNSSEC fingerprint (optional).
    #[serde(default)]
    pub domain: String,
    /// Default storage backend. Default: "fs".
    #[serde(default = "default_storage")]
    pub default_storage: String,
    /// HAI API key for registration (optional).
    #[serde(default)]
    pub hai_api_key: String,
    /// HAI endpoint URL (optional).
    #[serde(default)]
    pub hai_endpoint: String,
}

fn default_algorithm() -> String {
    "pq2025".to_string()
}
fn default_data_directory() -> String {
    "./jacs_data".to_string()
}
fn default_key_directory() -> String {
    "./jacs_keys".to_string()
}
fn default_config_path() -> String {
    "./jacs.config.json".to_string()
}
fn default_agent_type() -> String {
    "ai".to_string()
}
fn default_storage() -> String {
    "fs".to_string()
}

/// Resolve strict mode: explicit parameter wins, then env var, then false.
fn resolve_strict(explicit: Option<bool>) -> bool {
    if let Some(s) = explicit {
        return s;
    }
    std::env::var("JACS_STRICT_MODE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

impl Default for CreateAgentParams {
    fn default() -> Self {
        Self {
            name: String::new(),
            password: String::new(),
            algorithm: default_algorithm(),
            data_directory: default_data_directory(),
            key_directory: default_key_directory(),
            config_path: default_config_path(),
            agent_type: default_agent_type(),
            description: String::new(),
            domain: String::new(),
            default_storage: default_storage(),
            hai_api_key: String::new(),
            hai_endpoint: String::new(),
        }
    }
}

impl CreateAgentParams {
    /// Returns a new builder for `CreateAgentParams`.
    pub fn builder() -> CreateAgentParamsBuilder {
        CreateAgentParamsBuilder::default()
    }
}

/// Fluent builder for `CreateAgentParams`.
#[derive(Debug, Clone, Default)]
pub struct CreateAgentParamsBuilder {
    params: CreateAgentParams,
}

impl CreateAgentParamsBuilder {
    pub fn name(mut self, name: &str) -> Self {
        self.params.name = name.to_string();
        self
    }
    pub fn password(mut self, password: &str) -> Self {
        self.params.password = password.to_string();
        self
    }
    pub fn algorithm(mut self, algorithm: &str) -> Self {
        self.params.algorithm = algorithm.to_string();
        self
    }
    pub fn data_directory(mut self, dir: &str) -> Self {
        self.params.data_directory = dir.to_string();
        self
    }
    pub fn key_directory(mut self, dir: &str) -> Self {
        self.params.key_directory = dir.to_string();
        self
    }
    pub fn config_path(mut self, path: &str) -> Self {
        self.params.config_path = path.to_string();
        self
    }
    pub fn agent_type(mut self, agent_type: &str) -> Self {
        self.params.agent_type = agent_type.to_string();
        self
    }
    pub fn description(mut self, desc: &str) -> Self {
        self.params.description = desc.to_string();
        self
    }
    pub fn domain(mut self, domain: &str) -> Self {
        self.params.domain = domain.to_string();
        self
    }
    pub fn default_storage(mut self, storage: &str) -> Self {
        self.params.default_storage = storage.to_string();
        self
    }
    pub fn hai_api_key(mut self, key: &str) -> Self {
        self.params.hai_api_key = key.to_string();
        self
    }
    pub fn hai_endpoint(mut self, endpoint: &str) -> Self {
        self.params.hai_endpoint = endpoint.to_string();
        self
    }

    /// Build the `CreateAgentParams`. Name is required.
    pub fn build(self) -> CreateAgentParams {
        self.params
    }
}

/// Information returned from HAI registration during agent creation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistrationInfo {
    /// DNS TXT record to publish (if domain was provided).
    #[serde(default)]
    pub dns_record: String,
    /// Route53-specific DNS record (if applicable).
    #[serde(default)]
    pub dns_route53: String,
    /// Whether HAI registration succeeded.
    #[serde(default)]
    pub hai_registered: bool,
    /// Error from HAI registration (if any).
    #[serde(default)]
    pub hai_error: String,
}

/// Mutex to prevent concurrent environment variable stomping during creation.
static CREATE_MUTEX: Mutex<()> = Mutex::new(());

/// Status of a single signer in a multi-party agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerStatus {
    /// Unique identifier of the signing agent.
    pub agent_id: String,
    /// Whether this agent has signed the agreement.
    pub signed: bool,
    /// ISO 8601 timestamp when the agent signed (if signed).
    pub signed_at: Option<String>,
}

/// Status of a multi-party agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementStatus {
    /// Whether all required parties have signed.
    pub complete: bool,
    /// List of signers and their status.
    pub signers: Vec<SignerStatus>,
    /// List of agent IDs that haven't signed yet.
    pub pending: Vec<String>,
}

// =============================================================================
// SimpleAgent - Instance-based API (Recommended)
// =============================================================================

/// A wrapper around the JACS Agent that provides a simplified, instance-based API.
///
/// This struct owns an Agent instance and provides methods for common operations
/// like signing and verification. Unlike the deprecated module-level functions,
/// `SimpleAgent` does not use global mutable state, making it thread-safe when
/// used with appropriate synchronization.
///
/// # Thread Safety
///
/// `SimpleAgent` uses interior mutability via `Mutex` to allow safe concurrent
/// access to the underlying Agent. Multiple threads can share a `SimpleAgent`
/// wrapped in an `Arc`.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use std::sync::Arc;
///
/// // Create and share across threads
/// let agent = Arc::new(SimpleAgent::create("my-agent", None, None)?);
///
/// let agent_clone = Arc::clone(&agent);
/// std::thread::spawn(move || {
///     let signed = agent_clone.sign_message(&serde_json::json!({"thread": 1})).unwrap();
/// });
/// ```
pub struct SimpleAgent {
    agent: Mutex<Agent>,
    config_path: Option<String>,
    /// When true, verification failures return `Err` instead of `Ok(valid=false)`.
    /// Resolved from explicit param > `JACS_STRICT_MODE` env var > false.
    strict: bool,
}

impl SimpleAgent {
    /// Returns whether this agent is in strict mode.
    pub fn is_strict(&self) -> bool {
        self.strict
    }

    /// Creates a new JACS agent with persistent identity.
    ///
    /// This generates cryptographic keys, creates configuration files, and saves
    /// them to the current working directory.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the agent
    /// * `purpose` - Optional description of the agent's purpose
    /// * `key_algorithm` - Signing algorithm: "ed25519" (default), "rsa-pss", or "pq2025"
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` instance ready for use, along with `AgentInfo` containing
    /// the agent ID, name, and file paths.
    ///
    /// # Files Created
    ///
    /// * `./jacs.config.json` - Configuration file
    /// * `./jacs.agent.json` - Signed agent identity (in jacs_data/agent/)
    /// * `./jacs_keys/` - Directory containing public and private keys
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::create("my-agent", Some("Signing documents"), None)?;
    /// println!("Agent created successfully");
    /// ```
    #[must_use = "agent creation result must be checked for errors"]
    pub fn create(
        name: &str,
        purpose: Option<&str>,
        key_algorithm: Option<&str>,
    ) -> Result<(Self, AgentInfo), JacsError> {
        let algorithm = key_algorithm.unwrap_or("ed25519");

        info!(
            "Creating new agent '{}' with algorithm '{}'",
            name, algorithm
        );

        // Create directories if they don't exist
        let keys_dir = Path::new("./jacs_keys");
        let data_dir = Path::new("./jacs_data");

        fs::create_dir_all(keys_dir).map_err(|e| JacsError::DirectoryCreateFailed {
            path: keys_dir.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
        fs::create_dir_all(data_dir).map_err(|e| JacsError::DirectoryCreateFailed {
            path: data_dir.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;

        // Create a minimal agent JSON
        let agent_type = "ai";
        let description = purpose.unwrap_or("JACS agent");

        let agent_json = build_agent_document(agent_type, name, description)?;

        // Create the agent
        let mut agent = crate::get_empty_agent();

        // Create agent with keys
        let instance = agent
            .create_agent_and_load(&agent_json.to_string(), true, Some(algorithm))
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to create agent: {}", e),
            })?;

        // Extract agent info
        let agent_id = instance["jacsId"].as_str().unwrap_or("unknown").to_string();
        let version = instance["jacsVersion"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        // Save the agent
        let lookup_id = format!("{}:{}", agent_id, version);
        agent.save().map_err(|e| JacsError::Internal {
            message: format!("Failed to save agent: {}", e),
        })?;

        // Create minimal config file (only required fields; defaults handle the rest)
        let config_json = json!({
            "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
            "jacs_agent_id_and_version": lookup_id,
            "jacs_agent_key_algorithm": algorithm
        });

        let config_path = "./jacs.config.json";
        let config_str =
            serde_json::to_string_pretty(&config_json).map_err(|e| JacsError::Internal {
                message: format!("Failed to serialize config: {}", e),
            })?;
        fs::write(config_path, config_str).map_err(|e| JacsError::Internal {
            message: format!("Failed to write config: {}", e),
        })?;

        info!("Agent '{}' created successfully with ID {}", name, agent_id);

        let info = AgentInfo {
            agent_id,
            name: name.to_string(),
            public_key_path: format!("./jacs_keys/{}", DEFAULT_PUBLIC_KEY_FILENAME),
            config_path: config_path.to_string(),
            version,
            algorithm: algorithm.to_string(),
            private_key_path: format!("./jacs_keys/{}", DEFAULT_PRIVATE_KEY_FILENAME),
            data_directory: "./jacs_data".to_string(),
            key_directory: "./jacs_keys".to_string(),
            domain: String::new(),
            dns_record: String::new(),
            hai_registered: false,
        };

        Ok((
            Self {
                agent: Mutex::new(agent),
                config_path: Some(config_path.to_string()),
                strict: resolve_strict(None),
            },
            info,
        ))
    }

    /// Creates a new JACS agent with full programmatic control.
    ///
    /// Unlike `create()`, this method accepts all parameters explicitly, making it
    /// suitable for non-interactive use from bindings and automation.
    ///
    /// # Arguments
    ///
    /// * `params` - `CreateAgentParams` with all creation parameters
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` instance and `AgentInfo` with the created agent's details.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::{SimpleAgent, CreateAgentParams};
    ///
    /// let params = CreateAgentParams::builder()
    ///     .name("my-agent")
    ///     .password("MyStr0ng!Pass#2024")
    ///     .algorithm("pq2025")
    ///     .data_directory("/tmp/test_data")
    ///     .key_directory("/tmp/test_keys")
    ///     .config_path("/tmp/test.config.json")
    ///     .build();
    ///
    /// let (agent, info) = SimpleAgent::create_with_params(params)?;
    /// ```
    #[must_use = "agent creation result must be checked for errors"]
    pub fn create_with_params(params: CreateAgentParams) -> Result<(Self, AgentInfo), JacsError> {
        struct EnvRestoreGuard {
            previous: Vec<(String, Option<String>)>,
        }

        impl Drop for EnvRestoreGuard {
            fn drop(&mut self) {
                for (key, value) in &self.previous {
                    unsafe {
                        if let Some(v) = value {
                            std::env::set_var(key, v);
                        } else {
                            std::env::remove_var(key);
                        }
                    }
                }
            }
        }

        // Acquire creation mutex to prevent concurrent env var stomping
        let _lock = CREATE_MUTEX.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire creation lock: {}", e),
        })?;

        // Resolve password: params > env var > error
        let password = if !params.password.is_empty() {
            params.password.clone()
        } else {
            std::env::var("JACS_PRIVATE_KEY_PASSWORD").unwrap_or_default()
        };

        if password.is_empty() {
            return Err(JacsError::ConfigError(
                "Password is required for agent creation. \
                Either pass it in CreateAgentParams.password or set the JACS_PRIVATE_KEY_PASSWORD environment variable."
                    .to_string(),
            ));
        }

        let algorithm = if params.algorithm.is_empty() {
            "pq2025".to_string()
        } else {
            params.algorithm.clone()
        };

        info!(
            "Creating new agent '{}' with algorithm '{}' (programmatic)",
            params.name, algorithm
        );

        // Create directories (including agent/ and public_keys/ subdirs that save() expects)
        let keys_dir = Path::new(&params.key_directory);
        let data_dir = Path::new(&params.data_directory);

        fs::create_dir_all(keys_dir).map_err(|e| JacsError::DirectoryCreateFailed {
            path: keys_dir.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
        fs::create_dir_all(data_dir.join("agent")).map_err(|e| {
            JacsError::DirectoryCreateFailed {
                path: data_dir.join("agent").to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;
        fs::create_dir_all(data_dir.join("public_keys")).map_err(|e| {
            JacsError::DirectoryCreateFailed {
                path: data_dir.join("public_keys").to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;

        let env_keys = [
            "JACS_PRIVATE_KEY_PASSWORD",
            "JACS_DATA_DIRECTORY",
            "JACS_KEY_DIRECTORY",
            "JACS_AGENT_KEY_ALGORITHM",
            "JACS_DEFAULT_STORAGE",
            "JACS_AGENT_PRIVATE_KEY_FILENAME",
            "JACS_AGENT_PUBLIC_KEY_FILENAME",
        ];
        let previous_env = env_keys
            .iter()
            .map(|k| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        let _env_restore_guard = EnvRestoreGuard {
            previous: previous_env,
        };

        // Set env vars for the keystore layer (within the mutex lock)
        // SAFETY: We hold CREATE_MUTEX, ensuring no concurrent env var access
        unsafe {
            std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", &password);
            std::env::set_var("JACS_DATA_DIRECTORY", &params.data_directory);
            std::env::set_var("JACS_KEY_DIRECTORY", &params.key_directory);
            std::env::set_var("JACS_AGENT_KEY_ALGORITHM", &algorithm);
            std::env::set_var("JACS_DEFAULT_STORAGE", &params.default_storage);
            std::env::set_var(
                "JACS_AGENT_PRIVATE_KEY_FILENAME",
                DEFAULT_PRIVATE_KEY_FILENAME,
            );
            std::env::set_var(
                "JACS_AGENT_PUBLIC_KEY_FILENAME",
                DEFAULT_PUBLIC_KEY_FILENAME,
            );
        }

        // Create a minimal agent JSON
        let description = if params.description.is_empty() {
            "JACS agent".to_string()
        } else {
            params.description.clone()
        };

        let agent_json = build_agent_document(&params.agent_type, &params.name, &description)?;

        // Create the agent
        let mut agent = crate::get_empty_agent();

        let instance = agent
            .create_agent_and_load(&agent_json.to_string(), true, Some(&algorithm))
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to create agent: {}", e),
            })?;

        // Extract agent info
        let agent_id = instance["jacsId"].as_str().unwrap_or("unknown").to_string();
        let version = instance["jacsVersion"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        let lookup_id = format!("{}:{}", agent_id, version);

        // Resolve the config: if one already exists at config_path, read it
        // and only update the agent ID. Log differences between existing values
        // and params so the caller knows. If no config exists, create one fresh.
        let config_path = Path::new(&params.config_path);
        let config_str = if config_path.exists() {
            let existing_str =
                fs::read_to_string(config_path).map_err(|e| JacsError::Internal {
                    message: format!(
                        "Failed to read existing config '{}': {}",
                        params.config_path, e
                    ),
                })?;
            let mut existing: serde_json::Value =
                serde_json::from_str(&existing_str).map_err(|e| JacsError::Internal {
                    message: format!("Failed to parse existing config: {}", e),
                })?;

            // Log differences between existing config and params
            let check = |field: &str, existing_val: Option<&str>, param_val: &str| {
                if let Some(ev) = existing_val {
                    if ev != param_val {
                        warn!(
                            "Config '{}' differs: existing='{}', param='{}'. Keeping existing value.",
                            field, ev, param_val
                        );
                    }
                }
            };
            check(
                "jacs_data_directory",
                existing.get("jacs_data_directory").and_then(|v| v.as_str()),
                &params.data_directory,
            );
            check(
                "jacs_key_directory",
                existing.get("jacs_key_directory").and_then(|v| v.as_str()),
                &params.key_directory,
            );
            check(
                "jacs_agent_key_algorithm",
                existing
                    .get("jacs_agent_key_algorithm")
                    .and_then(|v| v.as_str()),
                &algorithm,
            );
            check(
                "jacs_default_storage",
                existing
                    .get("jacs_default_storage")
                    .and_then(|v| v.as_str()),
                &params.default_storage,
            );

            // Only update the agent ID (the new agent we just created)
            if let Some(obj) = existing.as_object_mut() {
                obj.insert("jacs_agent_id_and_version".to_string(), json!(lookup_id));
            }

            let updated_str =
                serde_json::to_string_pretty(&existing).map_err(|e| JacsError::Internal {
                    message: format!("Failed to serialize updated config: {}", e),
                })?;
            fs::write(config_path, &updated_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to write config to '{}': {}", params.config_path, e),
            })?;
            info!(
                "Updated existing config '{}' with new agent ID {}",
                params.config_path, lookup_id
            );
            updated_str
        } else {
            // No config exists -- create config with all required fields
            let mut config_map = serde_json::Map::new();
            config_map.insert(
                "$schema".to_string(),
                json!("https://hai.ai/schemas/jacs.config.schema.json"),
            );
            config_map.insert("jacs_agent_id_and_version".to_string(), json!(lookup_id));
            config_map.insert("jacs_agent_key_algorithm".to_string(), json!(algorithm));
            config_map.insert(
                "jacs_data_directory".to_string(),
                json!(params.data_directory),
            );
            config_map.insert(
                "jacs_key_directory".to_string(),
                json!(params.key_directory),
            );
            config_map.insert(
                "jacs_default_storage".to_string(),
                json!(params.default_storage),
            );
            config_map.insert(
                "jacs_agent_private_key_filename".to_string(),
                json!(DEFAULT_PRIVATE_KEY_FILENAME),
            );
            config_map.insert(
                "jacs_agent_public_key_filename".to_string(),
                json!(DEFAULT_PUBLIC_KEY_FILENAME),
            );
            let config_json = Value::Object(config_map);

            let new_str =
                serde_json::to_string_pretty(&config_json).map_err(|e| JacsError::Internal {
                    message: format!("Failed to serialize config: {}", e),
                })?;
            // Create parent directories if needed
            if let Some(parent) = config_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|e| JacsError::DirectoryCreateFailed {
                        path: parent.to_string_lossy().to_string(),
                        reason: e.to_string(),
                    })?;
                }
            }
            fs::write(config_path, &new_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to write config to '{}': {}", params.config_path, e),
            })?;
            info!(
                "Created new config '{}' for agent {}",
                params.config_path, lookup_id
            );
            new_str
        };

        // Set the agent's in-memory config from the resolved config so save()
        // uses the correct data_directory and key_directory.
        let validated_config_value =
            crate::config::validate_config(&config_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to validate config: {}", e),
            })?;
        agent.config = Some(serde_json::from_value(validated_config_value).map_err(|e| {
            JacsError::Internal {
                message: format!("Failed to parse config: {}", e),
            }
        })?);

        // Save the agent (uses directories from the resolved config)
        agent.save().map_err(|e| JacsError::Internal {
            message: format!("Failed to save agent: {}", e),
        })?;

        // Handle DNS record generation if domain is set
        let mut dns_record = String::new();
        if !params.domain.is_empty() {
            if let Ok(pk) = agent.get_public_key() {
                let digest = crate::dns::bootstrap::pubkey_digest_b64(&pk);
                let rr = crate::dns::bootstrap::build_dns_record(
                    &params.domain,
                    3600,
                    &agent_id,
                    &digest,
                    crate::dns::bootstrap::DigestEncoding::Base64,
                );
                dns_record = crate::dns::bootstrap::emit_plain_bind(&rr);
            }
        }

        let private_key_path = format!("{}/{}", params.key_directory, DEFAULT_PRIVATE_KEY_FILENAME);
        let public_key_path = format!("{}/{}", params.key_directory, DEFAULT_PUBLIC_KEY_FILENAME);

        info!(
            "Agent '{}' created successfully with ID {} (programmatic)",
            params.name, agent_id
        );

        let info = AgentInfo {
            agent_id,
            name: params.name.clone(),
            public_key_path,
            config_path: params.config_path.clone(),
            version,
            algorithm: algorithm.clone(),
            private_key_path,
            data_directory: params.data_directory.clone(),
            key_directory: params.key_directory.clone(),
            domain: params.domain.clone(),
            dns_record,
            hai_registered: false,
        };

        Ok((
            Self {
                agent: Mutex::new(agent),
                config_path: Some(params.config_path),
                strict: resolve_strict(None),
            },
            info,
        ))
    }

    /// Loads an existing agent from a configuration file.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the configuration file (default: "./jacs.config.json")
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None, None)?;  // Load from ./jacs.config.json
    /// // or with strict mode:
    /// let agent = SimpleAgent::load(Some("./my-agent/jacs.config.json"), Some(true))?;
    /// ```
    #[must_use = "agent loading result must be checked for errors"]
    pub fn load(config_path: Option<&str>, strict: Option<bool>) -> Result<Self, JacsError> {
        let path = config_path.unwrap_or("./jacs.config.json");

        debug!("Loading agent from config: {}", path);

        if !Path::new(path).exists() {
            return Err(JacsError::ConfigNotFound {
                path: path.to_string(),
            });
        }

        let mut agent = crate::get_empty_agent();
        agent
            .load_by_config(path.to_string())
            .map_err(|e| JacsError::ConfigInvalid {
                field: "config".to_string(),
                reason: e.to_string(),
            })?;

        info!("Agent loaded successfully from {}", path);

        Ok(Self {
            agent: Mutex::new(agent),
            config_path: Some(path.to_string()),
            strict: resolve_strict(strict),
        })
    }

    /// Creates an ephemeral in-memory agent. No config file, no directories,
    /// no environment variables, no password needed.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Signing algorithm: "ed25519" (default), "rsa-pss", or "pq2025"
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` instance with in-memory keys, along with `AgentInfo`.
    /// Keys are lost when the agent is dropped.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let (agent, info) = SimpleAgent::ephemeral(None)?;
    /// let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
    /// ```
    #[must_use = "ephemeral agent result must be checked for errors"]
    pub fn ephemeral(algorithm: Option<&str>) -> Result<(Self, AgentInfo), JacsError> {
        // Map user-friendly names to internal algorithm strings
        let algo = match algorithm.unwrap_or("ed25519") {
            "ed25519" => "ring-Ed25519",
            "rsa-pss" => "RSA-PSS",
            "pq2025" => "pq2025",
            other => other,
        };

        let mut agent = Agent::ephemeral(algo).map_err(|e| JacsError::Internal {
            message: format!("Failed to create ephemeral agent: {}", e),
        })?;

        let agent_json = build_agent_document("ai", "ephemeral", "Ephemeral JACS agent")?;
        let instance = agent
            .create_agent_and_load(&agent_json.to_string(), true, Some(algo))
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to initialize ephemeral agent: {}", e),
            })?;

        let agent_id = instance["jacsId"].as_str().unwrap_or("").to_string();
        let version = instance["jacsVersion"].as_str().unwrap_or("").to_string();
        let info = AgentInfo {
            agent_id,
            name: "ephemeral".to_string(),
            public_key_path: String::new(),
            config_path: String::new(),
            version,
            algorithm: algo.to_string(),
            private_key_path: String::new(),
            data_directory: String::new(),
            key_directory: String::new(),
            domain: String::new(),
            dns_record: String::new(),
            hai_registered: false,
        };

        Ok((
            Self {
                agent: Mutex::new(agent),
                config_path: None,
                strict: resolve_strict(None),
            },
            info,
        ))
    }

    /// Zero-config persistent agent creation.
    ///
    /// If a config file already exists at `config_path` (default: `./jacs.config.json`),
    /// loads the existing agent. Otherwise, creates a new persistent agent with keys
    /// on disk and a minimal config file.
    ///
    /// If `JACS_PRIVATE_KEY_PASSWORD` is not set, a secure random password is
    /// generated and written to `<key_directory>/.jacs_password` (mode 0600).
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Signing algorithm (default: "ed25519"). Also: "rsa-pss", "pq2025"
    /// * `config_path` - Config file path (default: "./jacs.config.json")
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` with persistent keys on disk, along with `AgentInfo`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let (agent, info) = SimpleAgent::quickstart(None, None)?;
    /// let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
    /// // Keys and config are saved to disk -- the same agent is loaded next time.
    /// ```
    #[must_use = "quickstart result must be checked for errors"]
    pub fn quickstart(
        algorithm: Option<&str>,
        config_path: Option<&str>,
    ) -> Result<(Self, AgentInfo), JacsError> {
        let config = config_path.unwrap_or("./jacs.config.json");

        // If config already exists, load the existing agent
        if Path::new(config).exists() {
            info!(
                "quickstart: found existing config at {}, loading agent",
                config
            );
            let agent = Self::load(Some(config), None)?;

            // Build AgentInfo from the loaded agent
            let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
                message: format!("Failed to acquire agent lock: {}", e),
            })?;
            let agent_value = inner
                .get_value()
                .cloned()
                .ok_or(JacsError::AgentNotLoaded)?;
            let agent_id = agent_value["jacsId"].as_str().unwrap_or("").to_string();
            let version = agent_value["jacsVersion"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let (algo, key_dir, data_dir) = if let Some(ref cfg) = inner.config {
                let a = cfg
                    .jacs_agent_key_algorithm()
                    .as_deref()
                    .unwrap_or("")
                    .to_string();
                let k = cfg
                    .jacs_key_directory()
                    .as_deref()
                    .unwrap_or("./jacs_keys")
                    .to_string();
                let d = cfg
                    .jacs_data_directory()
                    .as_deref()
                    .unwrap_or("./jacs_data")
                    .to_string();
                (a, k, d)
            } else {
                (
                    String::new(),
                    "./jacs_keys".to_string(),
                    "./jacs_data".to_string(),
                )
            };
            drop(inner);

            let info = AgentInfo {
                agent_id,
                name: "jacs-agent".to_string(),
                public_key_path: format!("{}/{}", key_dir, DEFAULT_PUBLIC_KEY_FILENAME),
                config_path: config.to_string(),
                version,
                algorithm: algo,
                private_key_path: format!("{}/{}", key_dir, DEFAULT_PRIVATE_KEY_FILENAME),
                data_directory: data_dir,
                key_directory: key_dir,
                domain: String::new(),
                dns_record: String::new(),
                hai_registered: false,
            };

            return Ok((agent, info));
        }

        // No existing config -- create a new persistent agent
        info!(
            "quickstart: no config at {}, creating new persistent agent",
            config
        );

        // Ensure password is available
        let password = match std::env::var("JACS_PRIVATE_KEY_PASSWORD") {
            Ok(pw) if !pw.is_empty() => pw,
            _ => {
                // Auto-generate a secure password and save it
                let generated = generate_secure_password();
                let keys_dir = Path::new("./jacs_keys");
                fs::create_dir_all(keys_dir).map_err(|e| JacsError::DirectoryCreateFailed {
                    path: keys_dir.to_string_lossy().to_string(),
                    reason: e.to_string(),
                })?;
                let password_file = keys_dir.join(".jacs_password");
                fs::write(&password_file, &generated).map_err(|e| JacsError::Internal {
                    message: format!("Failed to write password file: {}", e),
                })?;
                // Set restrictive permissions (Unix only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    let _ = std::fs::set_permissions(&password_file, perms);
                }
                info!(
                    "quickstart: generated password saved to {}",
                    password_file.display()
                );
                // Set env var for the current process so create() can use it
                unsafe {
                    std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", &generated);
                }
                generated
            }
        };

        // Use create_with_params for full control
        let algo = match algorithm.unwrap_or("ed25519") {
            "ed25519" => "ring-Ed25519",
            "rsa-pss" => "RSA-PSS",
            "pq2025" => "pq2025",
            other => other,
        };

        let params = CreateAgentParams {
            name: "jacs-agent".to_string(),
            password,
            algorithm: algo.to_string(),
            config_path: config.to_string(),
            ..Default::default()
        };

        Self::create_with_params(params)
    }

    /// Verifies the loaded agent's own identity.
    ///
    /// This checks:
    /// 1. Self-signature validity
    /// 2. Document hash integrity
    /// 3. DNS TXT record (if domain is configured)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify_self()?;
    /// assert!(result.valid);
    /// ```
    #[must_use = "self-verification result must be checked"]
    pub fn verify_self(&self) -> Result<VerificationResult, JacsError> {
        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Verify self-signature
        let sig_result = agent.verify_self_signature();
        let hash_result = agent.verify_self_hash();

        let mut errors = Vec::new();

        if let Err(e) = sig_result {
            errors.push(format!("Signature verification failed: {}", e));
        }

        if let Err(e) = hash_result {
            errors.push(format!("Hash verification failed: {}", e));
        }

        let valid = errors.is_empty();

        // In strict mode, verification failure is a hard error
        if self.strict && !valid {
            return Err(JacsError::SignatureVerificationFailed {
                reason: errors.join("; "),
            });
        }

        // Extract agent info
        let agent_value = agent.get_value().cloned().unwrap_or(json!({}));
        let agent_id = agent_value.get_str_or("jacsId", "");
        let agent_name = agent_value.get_str("name");
        let timestamp = agent_value.get_str_or("jacsVersionDate", "");

        Ok(VerificationResult {
            valid,
            data: agent_value,
            signer_id: agent_id.clone(),
            signer_name: agent_name,
            timestamp,
            attachments: vec![],
            errors,
        })
    }

    /// Updates the current agent with new data and re-signs it.
    ///
    /// This function expects a complete agent document (not partial updates).
    /// Use `export_agent()` to get the current document, modify it, then pass it here.
    /// The function will create a new version, re-sign, and re-hash the document.
    ///
    /// # Arguments
    ///
    /// * `new_agent_data` - Complete agent document as a JSON string
    ///
    /// # Returns
    ///
    /// The updated and re-signed agent document as a JSON string.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Get current agent, modify, and update
    /// let agent_doc: serde_json::Value = serde_json::from_str(&agent.export_agent()?)?;
    /// let mut modified = agent_doc.clone();
    /// modified["jacsAgentType"] = json!("updated-service");
    /// let updated = agent.update_agent(&modified.to_string())?;
    /// println!("Agent updated with new version");
    /// ```
    #[must_use = "updated agent JSON must be used or stored"]
    pub fn update_agent(&self, new_agent_data: &str) -> Result<String, JacsError> {
        // Check document size before processing
        check_document_size(new_agent_data)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        agent
            .update_self(new_agent_data)
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to update agent: {}", e),
            })
    }

    /// Updates an existing document with new data and re-signs it.
    ///
    /// Use `sign_message()` to create a document first, then use this to update it.
    /// The function will create a new version, re-sign, and re-hash the document.
    ///
    /// # Arguments
    ///
    /// * `document_id` - The document ID (jacsId) to update
    /// * `new_data` - The updated document as a JSON string
    /// * `attachments` - Optional list of file paths to attach
    /// * `embed` - If true, embed attachment contents
    ///
    /// # Returns
    ///
    /// A `SignedDocument` with the updated document.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Create a document first
    /// let signed = agent.sign_message(&json!({"status": "pending"}))?;
    ///
    /// // Later, update it
    /// let doc: serde_json::Value = serde_json::from_str(&signed.raw)?;
    /// let mut modified = doc.clone();
    /// modified["content"]["status"] = json!("approved");
    /// let updated = agent.update_document(
    ///     &signed.document_id,
    ///     &modified.to_string(),
    ///     None,
    ///     None
    /// )?;
    /// println!("Document updated with new version");
    /// ```
    #[must_use = "updated document must be used or stored"]
    pub fn update_document(
        &self,
        document_id: &str,
        new_data: &str,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<SignedDocument, JacsError> {
        // Check document size before processing
        check_document_size(new_data)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let jacs_doc = agent
            .update_document(document_id, new_data, attachments, embed)
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to update document: {}", e),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "agentID"], "");

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs arbitrary data as a JACS message.
    ///
    /// # IMPORTANT: Signing is Sacred
    ///
    /// **Signing a document is an irreversible, permanent commitment.** Once signed:
    /// - The signature creates cryptographic proof binding you to the content
    /// - You cannot deny having signed (non-repudiation)
    /// - The signed document can be verified by anyone forever
    /// - You are accountable for the content you signed
    ///
    /// **Before signing, always:**
    /// - Read and understand the complete document content
    /// - Verify the data represents your actual intent
    /// - Confirm you have authority to make this commitment
    ///
    /// The data can be a JSON object, string, or any serializable value.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign (will be JSON-serialized)
    ///
    /// # Returns
    ///
    /// A `SignedDocument` containing the full signed document.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// // Review data carefully before signing!
    /// let signed = agent.sign_message(&json!({"action": "approve", "amount": 100}))?;
    /// println!("Document ID: {}", signed.document_id);
    /// ```
    #[must_use = "signed document must be used or stored"]
    pub fn sign_message(&self, data: &Value) -> Result<SignedDocument, JacsError> {
        debug!("sign_message() called");

        // Wrap the data in a minimal document structure
        let doc_content = json!({
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": data
        });

        // Check document size before processing
        let doc_string = doc_content.to_string();
        check_document_size(&doc_string)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let jacs_doc = agent
            .create_document_and_load(&doc_string, None, None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!(
                    "{}. Ensure the agent is properly initialized with load() or create() and has valid keys.",
                    e
                ),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "agentID"], "");

        info!("Message signed: document_id={}", jacs_doc.id);

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs a file with optional content embedding.
    ///
    /// # IMPORTANT: Signing is Sacred
    ///
    /// **Signing a file is an irreversible, permanent commitment.** Your signature:
    /// - Cryptographically binds you to the file's exact contents
    /// - Cannot be revoked or denied (non-repudiation)
    /// - Creates permanent proof that you attested to this file
    /// - Makes you accountable for the file content forever
    ///
    /// **Before signing any file:**
    /// - Review the complete file contents
    /// - Verify the file has not been tampered with
    /// - Confirm you intend to attest to this specific file
    /// - Understand your signature is permanent and verifiable
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to sign
    /// * `embed` - If true, embed file content; if false, store only hash reference
    ///
    /// # Returns
    ///
    /// A `SignedDocument` containing the signed file reference or embedded content.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Review file before signing! Embed the file content
    /// let signed = agent.sign_file("contract.pdf", true)?;
    ///
    /// // Or just reference it by hash
    /// let signed = agent.sign_file("large-video.mp4", false)?;
    /// ```
    #[must_use = "signed document must be used or stored"]
    pub fn sign_file(&self, file_path: &str, embed: bool) -> Result<SignedDocument, JacsError> {
        // Check file exists
        if !Path::new(file_path).exists() {
            return Err(JacsError::FileNotFound {
                path: file_path.to_string(),
            });
        }

        let mime_type = mime_from_extension(file_path);
        let filename = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Create document with file attachment
        let doc_content = json!({
            "jacsType": "file",
            "jacsLevel": "raw",
            "filename": filename,
            "mimetype": mime_type
        });

        let attachment = vec![file_path.to_string()];

        let jacs_doc = agent
            .create_document_and_load(&doc_content.to_string(), Some(attachment), Some(embed))
            .map_err(|e| JacsError::SigningFailed {
                reason: format!(
                    "File signing failed for '{}': {}. Verify the file exists and the agent has valid keys.",
                    file_path, e
                ),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "agentID"], "");

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs multiple messages in a batch operation.
    ///
    /// # IMPORTANT: Each Signature is Sacred
    ///
    /// **Every signature in the batch is an irreversible, permanent commitment.**
    /// Batch signing is convenient, but each document is independently signed with
    /// full cryptographic weight. Before batch signing:
    /// - Review ALL messages in the batch
    /// - Verify each message represents your intent
    /// - Understand you are making multiple permanent commitments
    ///
    /// This is more efficient than calling `sign_message` repeatedly because it
    /// amortizes the overhead of acquiring locks and key operations across all
    /// messages.
    ///
    /// # Arguments
    ///
    /// * `messages` - A slice of JSON values to sign
    ///
    /// # Returns
    ///
    /// A vector of `SignedDocument` objects, one for each input message, in the
    /// same order as the input slice.
    ///
    /// # Errors
    ///
    /// Returns an error if signing any message fails. In case of failure,
    /// documents created before the failure are still stored but the partial
    /// results are not returned (all-or-nothing return semantics).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Review ALL messages before batch signing!
    /// let messages = vec![
    ///     json!({"action": "approve", "item": 1}),
    ///     json!({"action": "approve", "item": 2}),
    ///     json!({"action": "reject", "item": 3}),
    /// ];
    ///
    /// let refs: Vec<&serde_json::Value> = messages.iter().collect();
    /// let signed_docs = agent.sign_messages_batch(&refs)?;
    ///
    /// for doc in &signed_docs {
    ///     println!("Signed document: {}", doc.document_id);
    /// }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - The agent lock is acquired once for the entire batch
    /// - Key decryption overhead is amortized across all messages
    /// - For very large batches, consider splitting into smaller chunks
    pub fn sign_messages_batch(
        &self,
        messages: &[&Value],
    ) -> Result<Vec<SignedDocument>, JacsError> {
        use crate::agent::document::DocumentTraits;
        use tracing::info;

        if messages.is_empty() {
            return Ok(Vec::new());
        }

        info!(batch_size = messages.len(), "Signing batch of messages");

        // Prepare all document JSON strings
        let doc_strings: Vec<String> = messages
            .iter()
            .map(|data| {
                let doc_content = json!({
                    "jacsType": "message",
                    "jacsLevel": "raw",
                    "content": data
                });
                doc_content.to_string()
            })
            .collect();

        // Check size of each document before processing
        for doc_str in &doc_strings {
            check_document_size(doc_str)?;
        }

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Convert to slice of &str for the batch API
        let doc_refs: Vec<&str> = doc_strings.iter().map(|s| s.as_str()).collect();

        // Use the batch document creation API
        let jacs_docs = agent
            .create_documents_batch(&doc_refs)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!(
                    "Batch signing failed: {}. Ensure the agent is properly initialized with load() or create() and has valid keys.",
                    e
                ),
            })?;

        // Convert to SignedDocument results
        let mut results = Vec::with_capacity(jacs_docs.len());
        for jacs_doc in jacs_docs {
            let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
                message: format!("Failed to serialize document: {}", e),
            })?;

            let timestamp = jacs_doc
                .value
                .get_path_str_or(&["jacsSignature", "date"], "");
            let agent_id = jacs_doc
                .value
                .get_path_str_or(&["jacsSignature", "agentID"], "");

            results.push(SignedDocument {
                raw,
                document_id: jacs_doc.id,
                agent_id,
                timestamp,
            });
        }

        info!(
            batch_size = results.len(),
            "Batch message signing completed successfully"
        );

        Ok(results)
    }

    /// Verifies a signed document and extracts its content.
    ///
    /// This function auto-detects whether the document contains a message or file.
    ///
    /// # Arguments
    ///
    /// * `signed_document` - The JSON string of the signed document
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with the verification status and extracted content.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify(&signed_json)?;
    /// if result.valid {
    ///     println!("Content: {}", result.data);
    /// } else {
    ///     println!("Verification failed: {:?}", result.errors);
    /// }
    /// ```
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, signed_document: &str) -> Result<VerificationResult, JacsError> {
        debug!("verify() called");

        // Pre-check: if input doesn't look like JSON, give a helpful error
        let trimmed = signed_document.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('{') && !trimmed.starts_with('[') {
            return Err(JacsError::DocumentMalformed {
                field: "json".to_string(),
                reason: format!(
                    "Input does not appear to be a JSON document. \
                    If you have a document ID (e.g., 'uuid:version'), use verify_by_id() instead. \
                    Received: '{}'",
                    if trimmed.len() > 60 {
                        &trimmed[..60]
                    } else {
                        trimmed
                    }
                ),
            });
        }

        // Check document size before processing
        check_document_size(signed_document)?;

        // Parse the document to validate JSON
        let _: Value =
            serde_json::from_str(signed_document).map_err(|e| JacsError::DocumentMalformed {
                field: "json".to_string(),
                reason: e.to_string(),
            })?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Load the document
        let jacs_doc =
            agent
                .load_document(signed_document)
                .map_err(|e| JacsError::DocumentMalformed {
                    field: "document".to_string(),
                    reason: e.to_string(),
                })?;

        let document_key = jacs_doc.getkey();

        // Verify the signature
        let verification_result =
            agent.verify_document_signature(&document_key, None, None, None, None);

        let mut errors = Vec::new();
        if let Err(e) = verification_result {
            errors.push(e.to_string());
        }

        // Verify hash
        if let Err(e) = agent.verify_hash(&jacs_doc.value) {
            errors.push(format!("Hash verification failed: {}", e));
        }

        let valid = errors.is_empty();

        // In strict mode, verification failure is a hard error
        if self.strict && !valid {
            return Err(JacsError::SignatureVerificationFailed {
                reason: errors.join("; "),
            });
        }

        // Extract signer info
        let signer_id = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "agentID"], "");
        let timestamp = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "date"], "");

        info!("Document verified: valid={}, signer={}", valid, signer_id);

        // Extract original content
        let data = if let Some(content) = jacs_doc.value.get("content") {
            content.clone()
        } else {
            jacs_doc.value.clone()
        };

        // Extract attachments
        let attachments = extract_attachments(&jacs_doc.value);

        Ok(VerificationResult {
            valid,
            data,
            signer_id,
            signer_name: None, // TODO: Look up in trust store
            timestamp,
            attachments,
            errors,
        })
    }

    /// Re-encrypts the agent's private key from one password to another.
    ///
    /// This reads the encrypted private key file, decrypts with the old password,
    /// validates the new password, re-encrypts, and writes the updated file.
    ///
    /// # Arguments
    ///
    /// * `old_password` - The current password protecting the private key
    /// * `new_password` - The new password (must meet password requirements)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// agent.reencrypt_key("OldP@ss123!", "NewStr0ng!Pass#2025")?;
    /// println!("Key re-encrypted successfully");
    /// ```
    pub fn reencrypt_key(&self, old_password: &str, new_password: &str) -> Result<(), JacsError> {
        use crate::crypt::aes_encrypt::reencrypt_private_key;

        // Find the private key file
        let key_path = if let Some(ref config_path) = self.config_path {
            // Try to read config to find key directory
            let config_str =
                fs::read_to_string(config_path).map_err(|e| JacsError::FileReadFailed {
                    path: config_path.clone(),
                    reason: e.to_string(),
                })?;
            let config: Value =
                serde_json::from_str(&config_str).map_err(|e| JacsError::ConfigInvalid {
                    field: "json".to_string(),
                    reason: e.to_string(),
                })?;
            let key_dir = config["jacs_key_directory"]
                .as_str()
                .unwrap_or("./jacs_keys");
            let key_filename = config["jacs_agent_private_key_filename"]
                .as_str()
                .unwrap_or("jacs.private.pem.enc");
            format!("{}/{}", key_dir, key_filename)
        } else {
            "./jacs_keys/jacs.private.pem.enc".to_string()
        };

        info!("Re-encrypting private key at: {}", key_path);

        // Read encrypted key
        let encrypted_data = fs::read(&key_path).map_err(|e| JacsError::FileReadFailed {
            path: key_path.clone(),
            reason: e.to_string(),
        })?;

        // Re-encrypt
        let re_encrypted = reencrypt_private_key(&encrypted_data, old_password, new_password)
            .map_err(|e| JacsError::CryptoError(format!("Re-encryption failed: {}", e)))?;

        // Write back
        fs::write(&key_path, &re_encrypted).map_err(|e| JacsError::Internal {
            message: format!("Failed to write re-encrypted key to '{}': {}", key_path, e),
        })?;

        info!("Private key re-encrypted successfully");
        Ok(())
    }

    /// Verifies a signed document looked up by its document ID from storage.
    ///
    /// This is a convenience method for when you have a document ID (e.g., "uuid:version")
    /// rather than the full JSON string.
    ///
    /// # Arguments
    ///
    /// * `document_id` - The document ID in "uuid:version" format
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify_by_id("abc123:1")?;
    /// assert!(result.valid);
    /// ```
    #[must_use = "verification result must be checked"]
    pub fn verify_by_id(&self, document_id: &str) -> Result<VerificationResult, JacsError> {
        use crate::storage::StorageDocumentTraits;

        debug!("verify_by_id() called with id: {}", document_id);

        // Validate document_id format
        let parts: Vec<&str> = document_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(JacsError::DocumentMalformed {
                field: "document_id".to_string(),
                reason: format!(
                    "Expected format 'uuid:version', got '{}'. \
                    Use verify() with the full JSON document string instead.",
                    document_id
                ),
            });
        }

        // Load the document from storage
        let storage =
            crate::storage::MultiStorage::default_new().map_err(|e| JacsError::Internal {
                message: format!("Failed to initialize storage: {}", e),
            })?;

        let jacs_doc = storage
            .get_document(document_id)
            .map_err(|e| JacsError::Internal {
                message: format!(
                    "Failed to load document '{}' from storage: {}",
                    document_id, e
                ),
            })?;

        // Serialize the document value back to a JSON string for verify()
        let doc_str = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document '{}': {}", document_id, e),
        })?;

        self.verify(&doc_str)
    }

    /// Exports the agent's identity JSON for P2P exchange.
    #[must_use = "exported agent data must be used"]
    pub fn export_agent(&self) -> Result<String, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let value = agent
            .get_value()
            .cloned()
            .ok_or(JacsError::AgentNotLoaded)?;
        serde_json::to_string_pretty(&value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize agent: {}", e),
        })
    }

    /// Returns the agent's public key in PEM format.
    #[must_use = "public key data must be used"]
    pub fn get_public_key_pem(&self) -> Result<String, JacsError> {
        // Read from the standard key file location
        let key_path = "./jacs_keys/jacs.public.pem";
        fs::read_to_string(key_path).map_err(|e| {
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => {
                    "file does not exist. Run agent creation to generate keys first.".to_string()
                }
                std::io::ErrorKind::PermissionDenied => {
                    "permission denied. Check that the key file is readable.".to_string()
                }
                _ => e.to_string(),
            };
            JacsError::FileReadFailed {
                path: key_path.to_string(),
                reason,
            }
        })
    }

    /// Returns diagnostic information including loaded agent details.
    pub fn diagnostics(&self) -> serde_json::Value {
        let mut info = diagnostics(); // call the standalone version

        if let Ok(agent) = self.agent.lock() {
            if agent.ready() {
                info["agent_loaded"] = serde_json::json!(true);
                if let Some(value) = agent.get_value() {
                    info["agent_id"] =
                        serde_json::json!(value.get("jacsId").and_then(|v| v.as_str()));
                    info["agent_version"] =
                        serde_json::json!(value.get("jacsVersion").and_then(|v| v.as_str()));
                }
            }
            if let Some(config) = &agent.config {
                if let Some(dir) = config.jacs_data_directory().as_ref() {
                    info["data_directory"] = serde_json::json!(dir);
                }
                if let Some(dir) = config.jacs_key_directory().as_ref() {
                    info["key_directory"] = serde_json::json!(dir);
                }
                if let Some(storage) = config.jacs_default_storage().as_ref() {
                    info["default_storage"] = serde_json::json!(storage);
                }
                if let Some(algo) = config.jacs_agent_key_algorithm().as_ref() {
                    info["key_algorithm"] = serde_json::json!(algo);
                }
            }
        }

        info
    }

    /// Returns the path to the configuration file, if available.
    pub fn config_path(&self) -> Option<&str> {
        self.config_path.as_deref()
    }

    /// Returns setup instructions for publishing the agent's DNS record,
    /// enabling DNSSEC, and registering with HAI.ai.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to publish the DNS TXT record under
    /// * `ttl` - TTL in seconds for the DNS record (e.g. 3600)
    pub fn get_setup_instructions(
        &self,
        domain: &str,
        ttl: u32,
    ) -> Result<SetupInstructions, JacsError> {
        use crate::dns::bootstrap::{
            DigestEncoding, build_dns_record, dnssec_guidance, emit_azure_cli,
            emit_cloudflare_curl, emit_gcloud_dns, emit_plain_bind, emit_route53_change_batch,
            tld_requirement_text,
        };

        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to lock agent: {}", e),
        })?;

        let agent_value = agent.get_value().cloned().unwrap_or(json!({}));
        let agent_id = agent_value.get_str_or("jacsId", "");
        if agent_id.is_empty() {
            return Err(JacsError::AgentNotLoaded);
        }

        let pk = agent.get_public_key().map_err(|e| JacsError::Internal {
            message: format!("Failed to get public key: {}", e),
        })?;
        let digest = crate::dns::bootstrap::pubkey_digest_b64(&pk);
        let rr = build_dns_record(domain, ttl, &agent_id, &digest, DigestEncoding::Base64);

        let dns_record_bind = emit_plain_bind(&rr);
        let dns_record_value = rr.txt.clone();
        let dns_owner = rr.owner.clone();

        // Provider commands
        let mut provider_commands = std::collections::HashMap::new();
        provider_commands.insert("bind".to_string(), dns_record_bind.clone());
        provider_commands.insert("route53".to_string(), emit_route53_change_batch(&rr));
        provider_commands.insert("gcloud".to_string(), emit_gcloud_dns(&rr, "YOUR_ZONE_NAME"));
        provider_commands.insert(
            "azure".to_string(),
            emit_azure_cli(&rr, "YOUR_RG", domain, "_v1.agent.jacs"),
        );
        provider_commands.insert(
            "cloudflare".to_string(),
            emit_cloudflare_curl(&rr, "YOUR_ZONE_ID"),
        );

        // DNSSEC guidance per provider
        let mut dnssec_instructions = std::collections::HashMap::new();
        for name in &["aws", "cloudflare", "azure", "gcloud"] {
            dnssec_instructions.insert(name.to_string(), dnssec_guidance(name).to_string());
        }

        let tld_requirement = tld_requirement_text().to_string();

        // .well-known JSON
        let well_known = json!({
            "jacs_agent_id": agent_id,
            "jacs_public_key_hash": digest,
            "jacs_dns_record": dns_owner,
        });
        let well_known_json = serde_json::to_string_pretty(&well_known).unwrap_or_default();

        // HAI registration
        let hai_url =
            std::env::var("HAI_API_URL").unwrap_or_else(|_| "https://api.hai.ai".to_string());
        let hai_registration_url = format!("{}/v1/agents", hai_url.trim_end_matches('/'));
        let hai_payload = json!({
            "agent_id": agent_id,
            "public_key_hash": digest,
            "domain": domain,
        });
        let hai_registration_payload =
            serde_json::to_string_pretty(&hai_payload).unwrap_or_default();
        let hai_registration_instructions = format!(
            "POST the payload to {} with your HAI API key in the Authorization header.",
            hai_registration_url
        );

        // Build summary
        let summary = format!(
            "Setup instructions for agent {agent_id} on domain {domain}:\n\
             \n\
             1. DNS: Publish the following TXT record:\n\
             {bind}\n\
             \n\
             2. DNSSEC: {dnssec}\n\
             \n\
             3. Domain requirement: {tld}\n\
             \n\
             4. .well-known: Serve the well-known JSON at /.well-known/jacs-agent.json\n\
             \n\
             5. HAI registration: {hai_instr}",
            agent_id = agent_id,
            domain = domain,
            bind = dns_record_bind,
            dnssec = dnssec_guidance("aws"),
            tld = tld_requirement,
            hai_instr = hai_registration_instructions,
        );

        Ok(SetupInstructions {
            dns_record_bind,
            dns_record_value,
            dns_owner,
            provider_commands,
            dnssec_instructions,
            tld_requirement,
            well_known_json,
            hai_registration_url,
            hai_registration_payload,
            hai_registration_instructions,
            summary,
        })
    }

    /// Verifies multiple signed documents in a batch operation.
    ///
    /// This method processes each document sequentially, verifying signatures
    /// and hashes for each. All documents are processed regardless of individual
    /// failures, and results are returned for each input document.
    ///
    /// # Arguments
    ///
    /// * `documents` - A slice of JSON strings, each representing a signed JACS document
    ///
    /// # Returns
    ///
    /// A vector of `VerificationResult` in the same order as the input documents.
    /// Each result contains:
    /// - `valid`: Whether the signature and hash are valid
    /// - `data`: The extracted content from the document
    /// - `signer_id`: The ID of the signing agent
    /// - `errors`: Any error messages if verification failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// let documents = vec![
    ///     signed_doc1.as_str(),
    ///     signed_doc2.as_str(),
    ///     signed_doc3.as_str(),
    /// ];
    ///
    /// let results = agent.verify_batch(&documents);
    /// for (i, result) in results.iter().enumerate() {
    ///     if result.valid {
    ///         println!("Document {} verified successfully", i);
    ///     } else {
    ///         println!("Document {} failed: {:?}", i, result.errors);
    ///     }
    /// }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - Verification is sequential; for parallel verification, consider using
    ///   rayon's `par_iter()` externally or spawning threads
    /// - Each verification is independent and does not short-circuit on failure
    /// - The method acquires the agent lock once per document verification
    #[must_use]
    pub fn verify_batch(&self, documents: &[&str]) -> Vec<VerificationResult> {
        documents
            .iter()
            .map(|doc| match self.verify(doc) {
                Ok(result) => result,
                Err(e) => VerificationResult::failure(e.to_string()),
            })
            .collect()
    }

    // =========================================================================
    // Agreement Methods
    // =========================================================================

    /// Creates a multi-party agreement requiring signatures from specified agents.
    ///
    /// This creates an agreement on a document that must be signed by all specified
    /// agents before it is considered complete. Use this for scenarios requiring
    /// multi-party approval, such as contract signing or governance decisions.
    ///
    /// # Arguments
    ///
    /// * `document` - The document to create an agreement on (JSON string)
    /// * `agent_ids` - List of agent IDs required to sign the agreement
    /// * `question` - Optional question or purpose of the agreement
    /// * `context` - Optional additional context for signers
    ///
    /// # Returns
    ///
    /// A `SignedDocument` containing the agreement document.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let proposal = json!({"proposal": "Merge codebases A and B"});
    ///
    /// let agreement = agent.create_agreement(
    ///     &proposal.to_string(),
    ///     &["agent-1-uuid".to_string(), "agent-2-uuid".to_string()],
    ///     Some("Do you approve this merge?"),
    ///     Some("This will combine repositories A and B"),
    /// )?;
    /// println!("Agreement created: {}", agreement.document_id);
    /// ```
    #[must_use = "agreement document must be used or stored"]
    pub fn create_agreement(
        &self,
        document: &str,
        agent_ids: &[String],
        question: Option<&str>,
        context: Option<&str>,
    ) -> Result<SignedDocument, JacsError> {
        self.create_agreement_with_options(document, agent_ids, question, context, None)
    }

    /// Creates a multi-party agreement with extended options.
    ///
    /// Like `create_agreement`, but accepts `AgreementOptions` for timeout,
    /// quorum (M-of-N), and algorithm constraints.
    ///
    /// # Arguments
    ///
    /// * `document` - The document to create an agreement on (JSON string)
    /// * `agent_ids` - List of agent IDs required to sign
    /// * `question` - Optional prompt describing what agents are agreeing to
    /// * `context` - Optional context for the agreement
    /// * `options` - Optional `AgreementOptions` (timeout, quorum, algorithm constraints)
    pub fn create_agreement_with_options(
        &self,
        document: &str,
        agent_ids: &[String],
        question: Option<&str>,
        context: Option<&str>,
        options: Option<&crate::agent::agreement::AgreementOptions>,
    ) -> Result<SignedDocument, JacsError> {
        use crate::agent::agreement::{Agreement, AgreementOptions};

        debug!(
            "create_agreement_with_options() called with {} signers",
            agent_ids.len()
        );

        // Check document size before processing
        check_document_size(document)?;

        let default_opts = AgreementOptions::default();
        let opts = options.unwrap_or(&default_opts);

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // First create the document
        let jacs_doc = agent
            .create_document_and_load(document, None, None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!("Failed to create base document: {}", e),
            })?;

        // Then create the agreement on it
        let agreement_doc = agent
            .create_agreement_with_options(
                &jacs_doc.getkey(),
                agent_ids,
                question,
                context,
                None,
                opts,
            )
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to create agreement: {}", e),
            })?;

        let raw = serde_json::to_string(&agreement_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize agreement: {}", e),
        })?;

        let timestamp = agreement_doc
            .value
            .get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = agreement_doc
            .value
            .get_path_str_or(&["jacsSignature", "agentID"], "");

        info!("Agreement created: document_id={}", agreement_doc.id);

        Ok(SignedDocument {
            raw,
            document_id: agreement_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs an existing multi-party agreement as the current agent.
    ///
    /// # IMPORTANT: Signing Agreements is Sacred
    ///
    /// **Signing an agreement is a binding, irreversible commitment.** When you sign:
    /// - You cryptographically commit to the agreement terms
    /// - Your signature is permanent and cannot be revoked
    /// - All parties can verify your commitment forever
    /// - You are legally and ethically bound to the agreement content
    ///
    /// **Multi-party agreements are especially significant** because:
    /// - Your signature joins a binding consensus
    /// - Other parties rely on your commitment
    /// - Breaking the agreement may harm other signers
    ///
    /// **Before signing any agreement:**
    /// - Read the complete agreement document carefully
    /// - Verify all terms are acceptable to you
    /// - Confirm you have authority to bind yourself/your organization
    /// - Understand the obligations you are accepting
    ///
    /// When an agreement is created, each required signer must call this function
    /// to add their signature. The agreement is complete when all signers have signed.
    ///
    /// # Arguments
    ///
    /// * `document` - The agreement document to sign (JSON string)
    ///
    /// # Returns
    ///
    /// A `SignedDocument` with this agent's signature added.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Receive agreement from coordinator
    /// let agreement_json = receive_agreement_from_coordinator();
    ///
    /// // REVIEW CAREFULLY before signing!
    /// let signed = agent.sign_agreement(&agreement_json)?;
    ///
    /// // Send back to coordinator or pass to next signer
    /// send_to_coordinator(&signed.raw);
    /// ```
    #[must_use = "signed agreement must be used or stored"]
    pub fn sign_agreement(&self, document: &str) -> Result<SignedDocument, JacsError> {
        use crate::agent::agreement::Agreement;

        // Check document size before processing
        check_document_size(document)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Load the document
        let jacs_doc = agent
            .load_document(document)
            .map_err(|e| JacsError::DocumentMalformed {
                field: "document".to_string(),
                reason: e.to_string(),
            })?;

        // Sign the agreement
        let signed_doc = agent
            .sign_agreement(&jacs_doc.getkey(), None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!("Failed to sign agreement: {}", e),
            })?;

        let raw = serde_json::to_string(&signed_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize signed agreement: {}", e),
        })?;

        let timestamp = signed_doc
            .value
            .get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = signed_doc
            .value
            .get_path_str_or(&["jacsSignature", "agentID"], "");

        Ok(SignedDocument {
            raw,
            document_id: signed_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Checks the status of a multi-party agreement.
    ///
    /// Use this to determine which agents have signed and whether the agreement
    /// is complete (all required signatures collected).
    ///
    /// # Arguments
    ///
    /// * `document` - The agreement document to check (JSON string)
    ///
    /// # Returns
    ///
    /// An `AgreementStatus` with completion status and signer details.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// let status = agent.check_agreement(&agreement_json)?;
    /// if status.complete {
    ///     println!("All parties have signed!");
    /// } else {
    ///     println!("Waiting for signatures from: {:?}", status.pending);
    ///     for signer in &status.signers {
    ///         if signer.signed {
    ///             println!("  {}: signed at {:?}", signer.agent_id, signer.signed_at);
    ///         } else {
    ///             println!("  {}: pending", signer.agent_id);
    ///         }
    ///     }
    /// }
    /// ```
    #[must_use = "agreement status must be checked"]
    pub fn check_agreement(&self, document: &str) -> Result<AgreementStatus, JacsError> {
        // Check document size before processing
        check_document_size(document)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Load the document
        let jacs_doc = agent
            .load_document(document)
            .map_err(|e| JacsError::DocumentMalformed {
                field: "document".to_string(),
                reason: e.to_string(),
            })?;

        // Get the unsigned agents
        let unsigned =
            jacs_doc
                .agreement_unsigned_agents(None)
                .map_err(|e| JacsError::Internal {
                    message: format!("Failed to check unsigned agents: {}", e),
                })?;

        // Get all requested agents from the agreement
        let all_agents =
            jacs_doc
                .agreement_requested_agents(None)
                .map_err(|e| JacsError::Internal {
                    message: format!("Failed to get agreement agents: {}", e),
                })?;

        // Build signer status list
        let mut signers = Vec::new();
        let unsigned_set: std::collections::HashSet<&String> = unsigned.iter().collect();

        for agent_id in &all_agents {
            let signed = !unsigned_set.contains(agent_id);
            signers.push(SignerStatus {
                agent_id: agent_id.clone(),
                signed,
                signed_at: if signed {
                    // Try to get the signature timestamp from the document
                    // For simplicity, we use the document timestamp
                    Some(
                        jacs_doc
                            .value
                            .get_path_str_or(&["jacsSignature", "date"], "")
                            .to_string(),
                    )
                } else {
                    None
                },
            });
        }

        Ok(AgreementStatus {
            complete: unsigned.is_empty(),
            signers,
            pending: unsigned,
        })
    }

    /// Register the loaded agent with HAI.ai.
    ///
    /// POSTs the exported agent JSON to the HAI registration endpoint.
    /// If `preview` is true, returns a preview result without actually registering.
    ///
    /// # Arguments
    /// * `api_key` - HAI API key (or reads `HAI_API_KEY` env var if `None`)
    /// * `hai_url` - Base URL for HAI (e.g. `"https://hai.ai"`)
    /// * `preview` - If true, validate without registering
    #[cfg(not(target_arch = "wasm32"))]
    pub fn register_with_hai(
        &self,
        api_key: Option<&str>,
        hai_url: &str,
        preview: bool,
    ) -> Result<RegistrationInfo, Box<dyn std::error::Error>> {
        if preview {
            return Ok(RegistrationInfo {
                hai_registered: false,
                hai_error: "preview mode".to_string(),
                dns_record: String::new(),
                dns_route53: String::new(),
            });
        }

        let key = match api_key {
            Some(k) => k.to_string(),
            None => std::env::var("HAI_API_KEY")
                .map_err(|_| "No API key provided and HAI_API_KEY environment variable not set")?,
        };

        let agent_json = self.export_agent()?;

        let url = format!("{}/api/v1/agents/register", hai_url.trim_end_matches('/'));

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", key))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "agent_json": agent_json }))
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Ok(RegistrationInfo {
                hai_registered: false,
                hai_error: format!("HTTP {}: {}", status, body),
                dns_record: String::new(),
                dns_route53: String::new(),
            });
        }

        let body: Value = response.json()?;

        Ok(RegistrationInfo {
            hai_registered: true,
            hai_error: String::new(),
            dns_record: body
                .get("dns_record")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            dns_route53: body
                .get("dns_route53")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    }

    // =========================================================================
    // A2A Protocol Methods
    // =========================================================================

    /// Export this agent as an A2A Agent Card (v0.4.0).
    ///
    /// The Agent Card describes the agent's capabilities, skills, and
    /// cryptographic configuration for zero-config A2A discovery.
    pub fn export_agent_card(&self) -> Result<crate::a2a::AgentCard, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        crate::a2a::agent_card::export_agent_card(&agent).map_err(|e| JacsError::Internal {
            message: format!("Failed to export agent card: {}", e),
        })
    }

    /// Generate .well-known documents for A2A discovery.
    ///
    /// Creates all well-known endpoint documents including the signed Agent Card,
    /// JWKS, JACS descriptor, public key document, and extension descriptor.
    ///
    /// Returns a vector of (path, JSON value) tuples suitable for serving.
    pub fn generate_well_known_documents(
        &self,
        a2a_algorithm: Option<&str>,
    ) -> Result<Vec<(String, serde_json::Value)>, JacsError> {
        let agent_card = self.export_agent_card()?;

        let a2a_alg = a2a_algorithm.unwrap_or("ring-Ed25519");
        let dual_keys =
            crate::a2a::keys::create_jwk_keys(None, Some(a2a_alg)).map_err(|e| {
                JacsError::Internal {
                    message: format!("Failed to generate A2A keys: {}", e),
                }
            })?;

        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let agent_id = agent
            .get_id()
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to get agent ID: {}", e),
            })?;

        let jws = crate::a2a::extension::sign_agent_card_jws(
            &agent_card,
            &dual_keys.a2a_private_key,
            &dual_keys.a2a_algorithm,
            &agent_id,
        )
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to sign Agent Card: {}", e),
        })?;

        crate::a2a::extension::generate_well_known_documents(
            &agent,
            &agent_card,
            &dual_keys.a2a_public_key,
            &dual_keys.a2a_algorithm,
            &jws,
        )
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to generate well-known documents: {}", e),
        })
    }

    /// Wrap an A2A artifact with JACS provenance signature.
    ///
    /// This creates a signed envelope around arbitrary JSON content,
    /// binding the signer's identity to the artifact.
    ///
    /// # Arguments
    ///
    /// * `artifact_json` - JSON string of the artifact to wrap
    /// * `artifact_type` - Type label (e.g., "artifact", "message", "task")
    /// * `parent_signatures_json` - Optional JSON array of parent signatures for chain-of-custody
    ///
    /// # Returns
    ///
    /// JSON string of the wrapped, signed artifact.
    pub fn wrap_a2a_artifact(
        &self,
        artifact_json: &str,
        artifact_type: &str,
        parent_signatures_json: Option<&str>,
    ) -> Result<String, JacsError> {
        let artifact: Value =
            serde_json::from_str(artifact_json).map_err(|e| JacsError::DocumentMalformed {
                field: "artifact_json".to_string(),
                reason: format!("Invalid JSON: {}", e),
            })?;

        let parent_signatures: Option<Vec<Value>> = match parent_signatures_json {
            Some(json_str) => {
                let parsed: Vec<Value> = serde_json::from_str(json_str).map_err(|e| {
                    JacsError::DocumentMalformed {
                        field: "parent_signatures_json".to_string(),
                        reason: format!("Invalid JSON array: {}", e),
                    }
                })?;
                Some(parsed)
            }
            None => None,
        };

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let wrapped = crate::a2a::provenance::wrap_artifact_with_provenance(
            &mut agent,
            artifact,
            artifact_type,
            parent_signatures,
        )
        .map_err(|e| JacsError::SigningFailed {
            reason: format!("Failed to wrap artifact: {}", e),
        })?;

        serde_json::to_string_pretty(&wrapped).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize wrapped artifact: {}", e),
        })
    }

    /// Sign an A2A artifact with JACS provenance.
    ///
    /// This is an alias for [`wrap_a2a_artifact`](Self::wrap_a2a_artifact) and is
    /// the recommended primary API name.
    pub fn sign_artifact(
        &self,
        artifact_json: &str,
        artifact_type: &str,
        parent_signatures_json: Option<&str>,
    ) -> Result<String, JacsError> {
        self.wrap_a2a_artifact(artifact_json, artifact_type, parent_signatures_json)
    }

    /// Verify a JACS-wrapped A2A artifact.
    ///
    /// Returns a JSON string containing the verification result, including
    /// the verification status, signer identity, and the original artifact.
    ///
    /// # Arguments
    ///
    /// * `wrapped_json` - JSON string of the wrapped artifact to verify
    pub fn verify_a2a_artifact(&self, wrapped_json: &str) -> Result<String, JacsError> {
        let wrapped: Value =
            serde_json::from_str(wrapped_json).map_err(|e| JacsError::DocumentMalformed {
                field: "wrapped_json".to_string(),
                reason: format!("Invalid JSON: {}", e),
            })?;

        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let result = crate::a2a::provenance::verify_wrapped_artifact(&agent, &wrapped).map_err(
            |e| JacsError::SignatureVerificationFailed {
                reason: format!("A2A artifact verification error: {}", e),
            },
        )?;

        serde_json::to_string_pretty(&result).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize verification result: {}", e),
        })
    }
}

// =============================================================================
// Deprecated Module-Level Functions (for backward compatibility)
// =============================================================================
//
// These functions use thread-local storage to maintain compatibility with
// existing code that uses the module-level API. New code should use
// `SimpleAgent` directly.

use std::cell::RefCell;

thread_local! {
    /// Thread-local agent instance for deprecated module-level functions.
    /// This replaces the previous global `lazy_static!` singleton with thread-local
    /// storage, which is safer for concurrent use.
    static THREAD_AGENT: RefCell<Option<SimpleAgent>> = const { RefCell::new(None) };
}

/// Creates a new JACS agent with persistent identity.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::create()` instead.
///
/// # Example
///
/// ```rust,ignore
/// // Old way (deprecated)
/// use jacs::simple::create;
/// let info = create("my-agent", None, None)?;
///
/// // New way (recommended)
/// use jacs::simple::SimpleAgent;
/// let (agent, info) = SimpleAgent::create("my-agent", None, None)?;
/// ```
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::create() instead")]
pub fn create(
    name: &str,
    purpose: Option<&str>,
    key_algorithm: Option<&str>,
) -> Result<AgentInfo, JacsError> {
    let (agent, info) = SimpleAgent::create(name, purpose, key_algorithm)?;
    THREAD_AGENT.with(|cell| {
        *cell.borrow_mut() = Some(agent);
    });
    Ok(info)
}

/// Creates a new JACS agent with full programmatic control.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::create_with_params()` instead.
#[deprecated(
    since = "0.6.0",
    note = "Use SimpleAgent::create_with_params() instead"
)]
pub fn create_with_params(params: CreateAgentParams) -> Result<AgentInfo, JacsError> {
    let (agent, info) = SimpleAgent::create_with_params(params)?;
    THREAD_AGENT.with(|cell| {
        *cell.borrow_mut() = Some(agent);
    });
    Ok(info)
}

/// Loads an existing agent from a configuration file.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::load()` instead.
///
/// # Example
///
/// ```rust,ignore
/// // Old way (deprecated)
/// use jacs::simple::load;
/// load(None)?;
///
/// // New way (recommended)
/// use jacs::simple::SimpleAgent;
/// let agent = SimpleAgent::load(None)?;
/// ```
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::load() instead")]
pub fn load(config_path: Option<&str>) -> Result<(), JacsError> {
    let agent = SimpleAgent::load(config_path, None)?;
    THREAD_AGENT.with(|cell| {
        *cell.borrow_mut() = Some(agent);
    });
    Ok(())
}

/// Helper to execute a function with the thread-local agent.
fn with_thread_agent<F, T>(f: F) -> Result<T, JacsError>
where
    F: FnOnce(&SimpleAgent) -> Result<T, JacsError>,
{
    THREAD_AGENT.with(|cell| {
        let borrow = cell.borrow();
        let agent = borrow.as_ref().ok_or(JacsError::AgentNotLoaded)?;
        f(agent)
    })
}

/// Verifies the loaded agent's own identity.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::verify_self()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::verify_self() instead")]
pub fn verify_self() -> Result<VerificationResult, JacsError> {
    with_thread_agent(|agent| agent.verify_self())
}

/// Updates the current agent with new data and re-signs it.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::update_agent()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::update_agent() instead")]
pub fn update_agent(new_agent_data: &str) -> Result<String, JacsError> {
    with_thread_agent(|agent| agent.update_agent(new_agent_data))
}

/// Updates an existing document with new data and re-signs it.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::update_document()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::update_document() instead")]
pub fn update_document(
    document_id: &str,
    new_data: &str,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.update_document(document_id, new_data, attachments, embed))
}

/// Signs arbitrary data as a JACS message.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::sign_message()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::sign_message() instead")]
pub fn sign_message(data: &Value) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.sign_message(data))
}

/// Signs a file with optional content embedding.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::sign_file()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::sign_file() instead")]
pub fn sign_file(file_path: &str, embed: bool) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.sign_file(file_path, embed))
}

/// Verifies a signed document and extracts its content.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::verify()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::verify() instead")]
pub fn verify(signed_document: &str) -> Result<VerificationResult, JacsError> {
    with_thread_agent(|agent| agent.verify(signed_document))
}

/// Verifies a signed document looked up by ID from storage.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::verify_by_id()` instead.
#[deprecated(since = "0.6.0", note = "Use SimpleAgent::verify_by_id() instead")]
pub fn verify_by_id(document_id: &str) -> Result<VerificationResult, JacsError> {
    with_thread_agent(|agent| agent.verify_by_id(document_id))
}

/// Exports the current agent's identity JSON for P2P exchange.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::export_agent()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::export_agent() instead")]
pub fn export_agent() -> Result<String, JacsError> {
    with_thread_agent(|agent| agent.export_agent())
}

/// Returns the current agent's public key in PEM format.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::get_public_key_pem()` instead.
#[deprecated(
    since = "0.3.0",
    note = "Use SimpleAgent::get_public_key_pem() instead"
)]
pub fn get_public_key_pem() -> Result<String, JacsError> {
    with_thread_agent(|agent| agent.get_public_key_pem())
}

/// Creates a multi-party agreement requiring signatures from specified agents.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::create_agreement()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::create_agreement() instead")]
pub fn create_agreement(
    document: &str,
    agent_ids: &[String],
    question: Option<&str>,
    context: Option<&str>,
) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.create_agreement(document, agent_ids, question, context))
}

/// Signs an existing agreement as the current agent.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::sign_agreement()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::sign_agreement() instead")]
pub fn sign_agreement(document: &str) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.sign_agreement(document))
}

/// Checks the status of a multi-party agreement.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::check_agreement()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::check_agreement() instead")]
pub fn check_agreement(document: &str) -> Result<AgreementStatus, JacsError> {
    with_thread_agent(|agent| agent.check_agreement(document))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extracts file attachments from a JACS document.
fn extract_attachments(doc: &Value) -> Vec<Attachment> {
    let mut attachments = Vec::new();

    if let Some(files) = doc.get("jacsFiles").and_then(|f| f.as_array()) {
        for file in files {
            let filename = file["path"].as_str().unwrap_or("unknown").to_string();
            let mime_type = file["mimetype"]
                .as_str()
                .unwrap_or("application/octet-stream")
                .to_string();
            let hash = file["sha256"].as_str().unwrap_or("").to_string();
            let embedded = file["embed"].as_bool().unwrap_or(false);

            let content = if embedded {
                if let Some(contents_b64) = file["contents"].as_str() {
                    use base64::{Engine as _, engine::general_purpose::STANDARD};
                    STANDARD.decode(contents_b64).unwrap_or_default()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            attachments.push(Attachment {
                filename,
                mime_type,
                content,
                hash,
                embedded,
            });
        }
    }

    attachments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostics_returns_version() {
        let info = diagnostics();
        let version = info["jacs_version"].as_str().unwrap();
        assert!(!version.is_empty(), "jacs_version should not be empty");
        assert_eq!(info["agent_loaded"], false);
        assert!(info["os"].as_str().is_some());
        assert!(info["arch"].as_str().is_some());
    }

    #[test]
    fn test_agent_info_serialization() {
        let info = AgentInfo {
            agent_id: "test-id".to_string(),
            name: "Test Agent".to_string(),
            public_key_path: "./keys/public.pem".to_string(),
            config_path: "./config.json".to_string(),
            version: "v1".to_string(),
            algorithm: "pq2025".to_string(),
            private_key_path: "./keys/private.pem.enc".to_string(),
            data_directory: "./data".to_string(),
            key_directory: "./keys".to_string(),
            domain: String::new(),
            dns_record: String::new(),
            hai_registered: false,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-id"));
        assert!(json.contains("Test Agent"));
        assert!(json.contains("pq2025"));
    }

    #[test]
    fn test_create_agent_params_defaults() {
        let params = CreateAgentParams::default();
        assert_eq!(params.algorithm, "pq2025");
        assert_eq!(params.data_directory, "./jacs_data");
        assert_eq!(params.key_directory, "./jacs_keys");
        assert_eq!(params.config_path, "./jacs.config.json");
        assert_eq!(params.agent_type, "ai");
        assert_eq!(params.default_storage, "fs");
    }

    #[test]
    fn test_create_agent_params_builder() {
        let params = CreateAgentParams::builder()
            .name("test-agent")
            .password("test-pass")
            .algorithm("ring-Ed25519")
            .data_directory("/tmp/data")
            .key_directory("/tmp/keys")
            .build();

        assert_eq!(params.name, "test-agent");
        assert_eq!(params.password, "test-pass");
        assert_eq!(params.algorithm, "ring-Ed25519");
        assert_eq!(params.data_directory, "/tmp/data");
        assert_eq!(params.key_directory, "/tmp/keys");
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            valid: true,
            data: json!({"test": "data"}),
            signer_id: "agent-123".to_string(),
            signer_name: Some("Test Agent".to_string()),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            attachments: vec![],
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("agent-123"));
    }

    #[test]
    fn test_signed_document_serialization() {
        let doc = SignedDocument {
            raw: r#"{"test":"doc"}"#.to_string(),
            document_id: "doc-456".to_string(),
            agent_id: "agent-789".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("doc-456"));
        assert!(json.contains("agent-789"));
    }

    #[test]
    fn test_attachment_serialization() {
        let att = Attachment {
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            content: b"hello world".to_vec(),
            hash: "abc123".to_string(),
            embedded: true,
        };

        let json = serde_json::to_string(&att).unwrap();
        assert!(json.contains("test.txt"));
        assert!(json.contains("text/plain"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_thread_agent_not_loaded() {
        // Clear the thread-local agent
        THREAD_AGENT.with(|cell| {
            *cell.borrow_mut() = None;
        });

        // Trying to use deprecated functions without loading should fail
        #[allow(deprecated)]
        let result = verify_self();
        assert!(result.is_err());

        match result {
            Err(JacsError::AgentNotLoaded) => (),
            _ => panic!("Expected AgentNotLoaded error"),
        }
    }

    #[test]
    fn test_simple_agent_load_missing_config() {
        let result = SimpleAgent::load(Some("/nonexistent/path/config.json"), None);
        assert!(result.is_err());

        match result {
            Err(JacsError::ConfigNotFound { path }) => {
                assert!(path.contains("nonexistent"));
            }
            _ => panic!("Expected ConfigNotFound error"),
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_load_missing_config() {
        let result = load(Some("/nonexistent/path/config.json"));
        assert!(result.is_err());

        match result {
            Err(JacsError::ConfigNotFound { path }) => {
                assert!(path.contains("nonexistent"));
            }
            _ => panic!("Expected ConfigNotFound error"),
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_sign_file_missing_file() {
        // Without a loaded agent, this should fail with AgentNotLoaded
        THREAD_AGENT.with(|cell| {
            *cell.borrow_mut() = None;
        });
        let result = sign_file("/nonexistent/file.txt", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_result_with_errors() {
        let result = VerificationResult {
            valid: false,
            data: json!(null),
            signer_id: "".to_string(),
            signer_name: None,
            timestamp: "".to_string(),
            attachments: vec![],
            errors: vec!["Signature invalid".to_string(), "Hash mismatch".to_string()],
        };

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].contains("Signature"));
        assert!(result.errors[1].contains("Hash"));
    }

    #[test]
    fn test_extract_attachments_empty() {
        let doc = json!({});
        let attachments = extract_attachments(&doc);
        assert!(attachments.is_empty());
    }

    #[test]
    fn test_extract_attachments_with_files() {
        let doc = json!({
            "jacsFiles": [
                {
                    "path": "document.pdf",
                    "mimetype": "application/pdf",
                    "sha256": "abcdef123456",
                    "embed": false
                },
                {
                    "path": "image.png",
                    "mimetype": "image/png",
                    "sha256": "fedcba654321",
                    "embed": true,
                    "contents": "SGVsbG8gV29ybGQ="
                }
            ]
        });

        let attachments = extract_attachments(&doc);
        assert_eq!(attachments.len(), 2);

        assert_eq!(attachments[0].filename, "document.pdf");
        assert_eq!(attachments[0].mime_type, "application/pdf");
        assert!(!attachments[0].embedded);
        assert!(attachments[0].content.is_empty());

        assert_eq!(attachments[1].filename, "image.png");
        assert_eq!(attachments[1].mime_type, "image/png");
        assert!(attachments[1].embedded);
        assert!(!attachments[1].content.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_public_key_pem_not_found() {
        // Without a loaded agent, this should fail with AgentNotLoaded
        THREAD_AGENT.with(|cell| {
            *cell.borrow_mut() = None;
        });

        // This should fail because no agent is loaded
        let result = get_public_key_pem();
        assert!(result.is_err());
    }

    #[test]
    fn test_simple_agent_struct_has_config_path() {
        // Test that SimpleAgent can store and return config path
        // Note: We can't fully test create/load without a valid config,
        // but we can verify the struct design
        let result = SimpleAgent::load(Some("./nonexistent.json"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_result_failure_constructor() {
        // Test that VerificationResult::failure creates a valid failure result
        let result = VerificationResult::failure("Test error message".to_string());
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("Test error message"));
        assert_eq!(result.signer_id, "");
        assert!(result.signer_name.is_none());
    }

    #[test]
    fn test_verification_result_success_constructor() {
        let data = json!({"message": "hello"});
        let signer_id = "agent-123".to_string();
        let timestamp = "2024-01-15T10:30:00Z".to_string();

        let result =
            VerificationResult::success(data.clone(), signer_id.clone(), timestamp.clone());

        assert!(result.valid);
        assert_eq!(result.data, data);
        assert_eq!(result.signer_id, signer_id);
        assert!(result.signer_name.is_none());
        assert_eq!(result.timestamp, timestamp);
        assert!(result.attachments.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_verification_result_failure_has_null_data() {
        let result = VerificationResult::failure("error".to_string());
        assert_eq!(result.data, json!(null));
        assert!(result.timestamp.is_empty());
        assert!(result.attachments.is_empty());
    }

    #[test]
    fn test_verify_non_json_returns_helpful_error() {
        // Create a dummy SimpleAgent for testing verify() pre-check
        // The pre-check happens before agent lock, so we need a valid agent struct
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: false,
        };

        // Plain text that's not JSON
        let result = agent.verify("not-json-at-all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("verify_by_id"),
            "Error should suggest verify_by_id(): {}",
            err_str
        );
    }

    #[test]
    fn test_verify_uuid_like_input_returns_helpful_error() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: false,
        };

        // A document ID like "uuid:version"
        let result = agent.verify("550e8400-e29b-41d4-a716-446655440000:1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("verify_by_id"),
            "Error for UUID-like input should suggest verify_by_id(): {}",
            err_str
        );
    }

    #[test]
    fn test_verify_empty_string_returns_error() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: false,
        };

        // Empty string should fail at JSON parse, not at pre-check
        let result = agent.verify("");
        assert!(result.is_err());
    }

    #[test]
    fn test_register_with_hai_preview() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: false,
        };

        let result = agent
            .register_with_hai(None, "https://hai.ai", true)
            .expect("preview should succeed");
        assert!(!result.hai_registered);
        assert_eq!(result.hai_error, "preview mode");
        assert!(result.dns_record.is_empty());
        assert!(result.dns_route53.is_empty());
    }

    #[test]
    fn test_setup_instructions_serialization() {
        let instr = SetupInstructions {
            dns_record_bind: "example.com. 3600 IN TXT \"test\"".to_string(),
            dns_record_value: "test".to_string(),
            dns_owner: "_v1.agent.jacs.example.com.".to_string(),
            provider_commands: std::collections::HashMap::new(),
            dnssec_instructions: std::collections::HashMap::new(),
            tld_requirement: "You must own a domain".to_string(),
            well_known_json: "{}".to_string(),
            hai_registration_url: "https://api.hai.ai/v1/agents".to_string(),
            hai_registration_payload: "{}".to_string(),
            hai_registration_instructions: "POST to the URL".to_string(),
            summary: "Setup summary".to_string(),
        };

        let json = serde_json::to_string(&instr).unwrap();
        assert!(json.contains("dns_record_bind"));
        assert!(json.contains("_v1.agent.jacs.example.com."));
        assert!(json.contains("hai_registration_url"));
    }

    #[test]
    fn test_get_setup_instructions_requires_loaded_agent() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: false,
        };

        let result = agent.get_setup_instructions("example.com", 3600);
        assert!(result.is_err(), "should fail without a loaded agent");
    }

    #[test]
    fn test_resolve_strict_defaults_to_false() {
        // With no explicit param and no env var, strict should be false
        assert!(!resolve_strict(None));
    }

    #[test]
    fn test_resolve_strict_explicit_overrides() {
        assert!(resolve_strict(Some(true)));
        assert!(!resolve_strict(Some(false)));
    }

    #[test]
    fn test_resolve_strict_env_var() {
        // SAFETY: Tests run single-threaded (serial_test or #[test] default)
        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "true");
        }
        assert!(resolve_strict(None));

        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "1");
        }
        assert!(resolve_strict(None));

        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "false");
        }
        assert!(!resolve_strict(None));

        // Explicit overrides env var
        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "true");
        }
        assert!(!resolve_strict(Some(false)));

        unsafe {
            std::env::remove_var("JACS_STRICT_MODE");
        }
    }

    #[test]
    fn test_simple_agent_is_strict_accessor() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: true,
        };
        assert!(agent.is_strict());

        let agent2 = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: false,
        };
        assert!(!agent2.is_strict());
    }

    #[test]
    fn test_verify_non_json_strict_still_returns_err() {
        // Strict mode shouldn't change behavior for malformed input — it should
        // still return Err(DocumentMalformed), not SignatureVerificationFailed
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,
            strict: true,
        };

        let result = agent.verify("not-json-at-all");
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { .. }) => {} // expected
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[test]
    fn test_simple_ephemeral_default_ed25519() {
        let (agent, info) = SimpleAgent::ephemeral(None).unwrap();
        assert!(!info.agent_id.is_empty());
        assert_eq!(info.algorithm, "ring-Ed25519");
        assert_eq!(info.name, "ephemeral");
        assert!(info.config_path.is_empty());
        assert!(info.public_key_path.is_empty());
        // Verify self works
        let result = agent.verify_self().unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_simple_ephemeral_pq2025() {
        let (agent, info) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
        assert_eq!(info.algorithm, "pq2025");
        let result = agent.verify_self().unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_simple_ephemeral_sign_and_verify() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let msg = serde_json::json!({"hello": "world"});
        let signed = agent.sign_message(&msg).unwrap();
        assert!(!signed.raw.is_empty());
        // Verify the signed document
        let result = agent.verify(&signed.raw).unwrap();
        assert!(
            result.valid,
            "Signed message should verify: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_simple_ephemeral_no_files() {
        let temp = std::env::temp_dir().join("jacs_simple_ephemeral_no_files");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let (_agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let entries: Vec<_> = std::fs::read_dir(&temp).unwrap().collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir_all(&temp);
    }

    // =========================================================================
    // A2A Protocol Method Tests
    // =========================================================================

    #[test]
    fn test_export_agent_card() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let card = agent.export_agent_card().unwrap();
        assert!(!card.name.is_empty());
        assert!(!card.protocol_versions.is_empty());
        assert_eq!(card.protocol_versions[0], "0.4.0");
        assert!(!card.supported_interfaces.is_empty());
    }

    #[test]
    fn test_wrap_and_verify_a2a_artifact() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let artifact = r#"{"text": "hello from A2A"}"#;

        let wrapped = agent
            .wrap_a2a_artifact(artifact, "message", None)
            .unwrap();

        // Wrapped should be valid JSON with JACS fields
        let wrapped_value: Value = serde_json::from_str(&wrapped).unwrap();
        assert!(wrapped_value.get("jacsId").is_some());
        assert!(wrapped_value.get("jacsSignature").is_some());
        assert_eq!(wrapped_value["jacsType"], "a2a-message");

        // Verify the wrapped artifact
        let result_json = agent.verify_a2a_artifact(&wrapped).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
        assert_eq!(result["status"], "SelfSigned");
    }

    #[test]
    fn test_sign_artifact_alias() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let artifact = r#"{"data": "test"}"#;

        // sign_artifact should produce the same structure as wrap_a2a_artifact
        let signed = agent.sign_artifact(artifact, "artifact", None).unwrap();
        let value: Value = serde_json::from_str(&signed).unwrap();
        assert!(value.get("jacsId").is_some());
        assert_eq!(value["jacsType"], "a2a-artifact");

        // And it should verify
        let result_json = agent.verify_a2a_artifact(&signed).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
    }

    #[test]
    fn test_wrap_a2a_artifact_with_parent_signatures() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();

        // Create a first artifact
        let first = agent
            .wrap_a2a_artifact(r#"{"step": 1}"#, "task", None)
            .unwrap();

        // Use the first as a parent signature for a second
        let parents = format!("[{}]", first);
        let second = agent
            .wrap_a2a_artifact(r#"{"step": 2}"#, "task", Some(&parents))
            .unwrap();

        let second_value: Value = serde_json::from_str(&second).unwrap();
        assert!(second_value.get("jacsParentSignatures").is_some());
        let parent_sigs = second_value["jacsParentSignatures"]
            .as_array()
            .unwrap();
        assert_eq!(parent_sigs.len(), 1);
    }

    #[test]
    fn test_wrap_a2a_artifact_invalid_json() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let result = agent.wrap_a2a_artifact("not json", "artifact", None);
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert_eq!(field, "artifact_json");
            }
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_a2a_artifact_invalid_json() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let result = agent.verify_a2a_artifact("not json");
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert_eq!(field, "wrapped_json");
            }
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[test]
    fn test_wrap_a2a_artifact_pq2025() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
        let artifact = r#"{"quantum": "safe"}"#;

        let wrapped = agent
            .wrap_a2a_artifact(artifact, "artifact", None)
            .unwrap();
        let result_json = agent.verify_a2a_artifact(&wrapped).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
    }

    #[test]
    fn test_export_agent_card_has_jacs_extension() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let card = agent.export_agent_card().unwrap();

        let extensions = card.capabilities.extensions.unwrap();
        assert!(!extensions.is_empty());
        assert_eq!(
            extensions[0].uri,
            crate::a2a::JACS_EXTENSION_URI
        );
    }
}
