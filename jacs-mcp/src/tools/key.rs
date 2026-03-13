//! Key management tools: create agent, reencrypt key, export agent card,
//! generate well-known, export agent.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Parameters for creating a new JACS agent programmatically.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAgentProgrammaticParams {
    /// Name for the new agent.
    #[schemars(description = "Name for the new agent")]
    pub name: String,

    /// Password for encrypting the private key.
    #[schemars(
        description = "Password for encrypting the private key. Must be at least 8 characters with uppercase, lowercase, digit, and special character."
    )]
    pub password: String,

    /// Cryptographic algorithm. Default: "pq2025" (ML-DSA-87, FIPS-204).
    #[schemars(
        description = "Cryptographic algorithm: 'pq2025' (default, post-quantum), 'ring-Ed25519', or 'RSA-PSS'"
    )]
    pub algorithm: Option<String>,

    /// Directory for data files. Default: "./jacs_data".
    #[schemars(description = "Directory for data files (default: ./jacs_data)")]
    pub data_directory: Option<String>,

    /// Directory for key files. Default: "./jacs_keys".
    #[schemars(description = "Directory for key files (default: ./jacs_keys)")]
    pub key_directory: Option<String>,

    /// Optional agent type (e.g., "ai", "human").
    #[schemars(description = "Agent type (default: 'ai')")]
    pub agent_type: Option<String>,

    /// Optional description of the agent.
    #[schemars(description = "Description of the agent")]
    pub description: Option<String>,
}

/// Result of creating an agent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAgentProgrammaticResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The new agent's ID (UUID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// The agent name.
    pub name: String,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for re-encrypting the agent's private key.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReencryptKeyParams {
    /// Current password for the private key.
    #[schemars(description = "Current password for the private key")]
    pub old_password: String,

    /// New password to encrypt the private key with.
    #[schemars(
        description = "New password. Must be at least 8 characters with uppercase, lowercase, digit, and special character."
    )]
    pub new_password: String,
}

/// Result of re-encrypting the private key.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReencryptKeyResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for exporting the local agent's A2A Agent Card (no params needed).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExportAgentCardParams {}

/// Result of exporting the Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExportAgentCardResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The Agent Card as a JSON string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_card: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for generating well-known documents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GenerateWellKnownParams {
    /// Optional A2A signing algorithm override (default: ring-Ed25519).
    #[schemars(description = "A2A signing algorithm override (default: ring-Ed25519)")]
    pub a2a_algorithm: Option<String>,
}

/// Result of generating well-known documents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GenerateWellKnownResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The well-known documents as a JSON array of {path, document} objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<String>,

    /// Number of documents generated.
    pub count: usize,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for exporting the local agent's full JSON document (no params needed).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExportAgentParams {}

/// Result of exporting the agent document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExportAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The full agent JSON document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_json: Option<String>,

    /// The agent's ID (UUID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the key management family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_create_agent",
            "Create a new JACS agent with cryptographic keys. This is the programmatic \
             equivalent of 'jacs create'. Returns agent ID and key paths. \
             SECURITY: Requires JACS_MCP_ALLOW_REGISTRATION=true environment variable.",
            schema_map::<CreateAgentProgrammaticParams>(),
        ),
        Tool::new(
            "jacs_reencrypt_key",
            "Re-encrypt the agent's private key with a new password. Use this to rotate \
             the password protecting the private key without changing the key itself.",
            schema_map::<ReencryptKeyParams>(),
        ),
        Tool::new(
            "jacs_export_agent_card",
            "Export this agent's A2A Agent Card as JSON. The Agent Card describes the \
             agent's capabilities, endpoints, and identity for A2A discovery.",
            schema_map::<ExportAgentCardParams>(),
        ),
        Tool::new(
            "jacs_generate_well_known",
            "Generate all .well-known documents for A2A discovery. Returns an array of \
             {path, document} objects that can be served at each path for agent discovery.",
            schema_map::<GenerateWellKnownParams>(),
        ),
        Tool::new(
            "jacs_export_agent",
            "Export the local agent's full JACS JSON document. This includes the agent's \
             identity, public key hash, and signed metadata.",
            schema_map::<ExportAgentParams>(),
        ),
    ]
}
