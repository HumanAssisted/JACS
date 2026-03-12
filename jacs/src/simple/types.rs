//! Type definitions for the simplified JACS API.
//!
//! Contains all public types returned by or passed to [`super::SimpleAgent`] methods:
//! agent info, signed documents, verification results, agreement status,
//! creation parameters, key rotation results, and migration results.

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::schema::utils::ValueExt;
use crate::storage::MultiStorage;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

impl SignedDocument {
    pub(crate) fn from_jacs_document(
        jacs_doc: JACSDocument,
        serialized_kind: &str,
    ) -> Result<Self, JacsError> {
        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize {}: {}", serialized_kind, e),
        })?;

        let timestamp = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = jacs_doc
            .value
            .get_path_str_or(&["jacsSignature", "agentID"], "");

        Ok(Self {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    }
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

/// Setup instructions for publishing a JACS agent's DNS record and enabling DNSSEC.
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
    /// Optional pre-configured storage backend.
    ///
    /// When `Some`, the agent will use this storage backend instead of
    /// creating one from `default_storage` and `data_directory`. This is
    /// useful for testing (in-memory backends) or when the caller has
    /// already configured storage with specific options.
    ///
    /// When `None` (the default), the agent creates its own storage from
    /// the `default_storage` type and `data_directory`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::storage::MultiStorage;
    /// use jacs::simple::CreateAgentParams;
    ///
    /// let memory_storage = MultiStorage::new("memory".to_string())?;
    /// let params = CreateAgentParams::builder()
    ///     .name("test-agent")
    ///     .password("secret")
    ///     .storage(memory_storage)
    ///     .build();
    /// ```
    #[serde(skip)]
    pub storage: Option<MultiStorage>,
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
            storage: None,
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
    pub fn default_storage(mut self, storage_type: &str) -> Self {
        self.params.default_storage = storage_type.to_string();
        self
    }
    /// Set a pre-configured storage backend.
    ///
    /// When set, the agent will use this storage instead of creating one
    /// from `default_storage` and `data_directory`. Useful for in-memory
    /// testing or custom storage configurations.
    pub fn storage(mut self, storage: MultiStorage) -> Self {
        self.params.storage = Some(storage);
        self
    }
    /// Build the `CreateAgentParams`. Name is required.
    pub fn build(self) -> CreateAgentParams {
        self.params
    }
}

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
// Key Rotation
// =============================================================================

/// Result of a key rotation operation.
///
/// Returned by [`super::SimpleAgent::rotate()`] after successfully generating new keys,
/// archiving old keys, and producing a new self-signed agent document.
///
/// The `signed_agent_json` field contains the complete, self-signed agent document
/// with the new version and new public key. This is the document that should be
/// sent to HAI for re-registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    /// The agent's stable identity (unchanged across rotations).
    pub jacs_id: String,
    /// The version string of the agent before rotation.
    pub old_version: String,
    /// The new version string assigned during rotation.
    pub new_version: String,
    /// PEM-encoded public key for the new keypair.
    pub new_public_key_pem: String,
    /// SHA-256 hash of the new public key (hex-encoded).
    pub new_public_key_hash: String,
    /// The complete, self-signed agent JSON document with the new version.
    pub signed_agent_json: String,
}

/// Result of a legacy agent migration operation.
///
/// Returned by [`super::SimpleAgent::migrate_agent()`] after successfully patching
/// a pre-schema-change agent document to include required `iat` and `jti`
/// fields in `jacsSignature`, then re-signing it as a new version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateResult {
    /// The agent's stable identity (unchanged across migrations).
    pub jacs_id: String,
    /// The version string of the agent before migration.
    pub old_version: String,
    /// The new version string assigned during migration (after re-signing).
    pub new_version: String,
    /// Fields that were patched in the raw JSON before loading (e.g. `["iat", "jti"]`).
    pub patched_fields: Vec<String>,
}
