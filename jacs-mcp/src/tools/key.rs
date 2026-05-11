//! Key management tools: reencrypt key, export agent card,
//! generate well-known, export agent.
//!
//! Note: `jacs_create_agent` was moved to `document.rs` per PRD Section 5.1.1
//! (Issue 013).

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request/Response Types
// =============================================================================

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

/// Parameters for rotating the agent's cryptographic keys.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RotateKeysParams {
    /// Signing algorithm for the new keys. If omitted, keeps the current algorithm.
    #[schemars(
        description = "Signing algorithm for the new keys (ring-Ed25519, pq2025). If omitted, keeps the current algorithm."
    )]
    pub algorithm: Option<String>,
}

/// Result of rotating the agent's keys.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RotateKeysResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent's stable identity (unchanged across rotations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_id: Option<String>,

    /// The version string before rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_version: Option<String>,

    /// The new version string assigned during rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_version: Option<String>,

    /// SHA-256 hash of the new public key (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_public_key_hash: Option<String>,

    /// Whether a transition proof was generated.
    pub has_transition_proof: bool,

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
            "jacs_reencrypt_key",
            "Re-encrypt the agent's private key with a new password. Use this to rotate \
             the password protecting the private key without changing the key itself.",
            schema_map::<ReencryptKeyParams>(),
        ),
        Tool::new(
            "jacs_rotate_keys",
            "Rotate the agent's cryptographic keys. Generates a new keypair, signs a \
             transition proof with the old key, re-signs the agent document and config \
             with the new key. Optionally change the signing algorithm.",
            schema_map::<RotateKeysParams>(),
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
