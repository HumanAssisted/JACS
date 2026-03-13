//! State management tools: sign, verify, load, update, list, adopt.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// =============================================================================
// Helper: schema generation
// =============================================================================

fn schema_map<T: JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
    let schema = schemars::schema_for!(T);
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    }
}

// =============================================================================
// Request/Response Types
// =============================================================================

/// Parameters for signing an agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignStateParams {
    /// Path to the file to sign.
    #[schemars(description = "Path to the file to sign as agent state")]
    pub file_path: String,

    /// The type of agent state.
    #[schemars(description = "Type of agent state: memory, skill, plan, config, or hook")]
    pub state_type: String,

    /// Human-readable name for this state document.
    #[schemars(description = "Human-readable name for this state document")]
    pub name: String,

    /// Optional description of the state document.
    #[schemars(description = "Optional description of what this state document contains")]
    pub description: Option<String>,

    /// Optional framework identifier (e.g., "claude-code", "openclaw").
    #[schemars(description = "Optional framework identifier (e.g., 'claude-code', 'openclaw')")]
    pub framework: Option<String>,

    /// Optional tags for categorization.
    #[schemars(description = "Optional tags for categorization")]
    pub tags: Option<Vec<String>>,

    /// Whether to embed file content inline. Always true for hooks.
    #[schemars(
        description = "Whether to embed file content inline (default false, always true for hooks)"
    )]
    pub embed: Option<bool>,
}

/// Result of signing an agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignStateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the signed state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The state type that was signed.
    pub state_type: String,

    /// The name of the state document.
    pub name: String,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for verifying an agent state file or document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyStateParams {
    /// Path to the original file to verify against.
    #[schemars(
        description = "DEPRECATED for MCP security: direct file-path verification is disabled. Use jacs_id."
    )]
    pub file_path: Option<String>,

    /// JACS document ID to verify.
    #[schemars(description = "JACS document ID to verify (uuid:version)")]
    pub jacs_id: Option<String>,
}

/// Result of verifying an agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyStateResult {
    /// Whether the verification succeeded overall.
    pub success: bool,

    /// Whether the file hash matches the signed hash.
    pub hash_match: bool,

    /// Whether the document signature is valid.
    pub signature_valid: bool,

    /// Information about the signing agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_info: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for loading a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadStateParams {
    /// Path to the file to load.
    #[schemars(
        description = "DEPRECATED for MCP security: direct file-path loading is disabled. Use jacs_id."
    )]
    pub file_path: Option<String>,

    /// JACS document ID to load.
    #[schemars(description = "JACS document ID to load (uuid:version)")]
    pub jacs_id: Option<String>,

    /// Whether to require verification before loading (default true).
    #[schemars(description = "Whether to require verification before loading (default true)")]
    pub require_verified: Option<bool>,
}

/// Result of loading a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadStateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The loaded content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Whether the document was verified.
    pub verified: bool,

    /// Any warnings about the loaded state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for updating a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpdateStateParams {
    /// Path to the file to update.
    #[schemars(
        description = "DEPRECATED for MCP security: direct file-path updates are disabled. Use jacs_id."
    )]
    pub file_path: String,

    /// JACS document ID to update (uuid:version).
    #[schemars(description = "JACS document ID to update (uuid:version)")]
    pub jacs_id: Option<String>,

    /// New content to write to the file. If omitted, re-signs current content.
    #[schemars(
        description = "New embedded content for the JACS state document. If omitted, re-signs current embedded content."
    )]
    pub new_content: Option<String>,
}

/// Result of updating a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpdateStateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The new JACS document version ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_version_id: Option<String>,

    /// The new SHA-256 hash of the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_hash: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for listing signed agent state documents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListStateParams {
    /// Filter by state type.
    #[schemars(description = "Filter by state type: memory, skill, plan, config, or hook")]
    pub state_type: Option<String>,

    /// Filter by framework.
    #[schemars(description = "Filter by framework identifier")]
    pub framework: Option<String>,

    /// Filter by tags (documents must have all specified tags).
    #[schemars(description = "Filter by tags (documents must have all specified tags)")]
    pub tags: Option<Vec<String>>,
}

/// A summary entry for a signed agent state document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StateListEntry {
    /// The JACS document ID.
    pub jacs_document_id: String,

    /// The state type.
    pub state_type: String,

    /// The document name.
    pub name: String,

    /// The framework, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,

    /// Tags on the document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Result of listing signed agent state documents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListStateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The list of state documents.
    pub documents: Vec<StateListEntry>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for adopting an external agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AdoptStateParams {
    /// Path to the file to adopt and sign.
    #[schemars(description = "Path to the file to adopt and sign as agent state")]
    pub file_path: String,

    /// The type of agent state.
    #[schemars(description = "Type of agent state: memory, skill, plan, config, or hook")]
    pub state_type: String,

    /// Human-readable name for this state document.
    #[schemars(description = "Human-readable name for this adopted state document")]
    pub name: String,

    /// Optional URL where the content was obtained from.
    #[schemars(description = "Optional URL where the content was originally obtained")]
    pub source_url: Option<String>,

    /// Optional description of the state document.
    #[schemars(description = "Optional description of what this adopted state document contains")]
    pub description: Option<String>,
}

/// Result of adopting an external agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AdoptStateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the adopted state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The state type that was adopted.
    pub state_type: String,

    /// The name of the adopted state document.
    pub name: String,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the state family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_sign_state",
            "Sign an agent state file (memory, skill, plan, config, or hook) to create \
             a cryptographically signed JACS document. This establishes provenance and \
             integrity for the file's contents.",
            schema_map::<SignStateParams>(),
        ),
        Tool::new(
            "jacs_verify_state",
            "Verify the integrity and authenticity of a signed agent state. Checks both \
             the file hash and the cryptographic signature.",
            schema_map::<VerifyStateParams>(),
        ),
        Tool::new(
            "jacs_load_state",
            "Load a signed agent state document and optionally verify it before returning \
             the content.",
            schema_map::<LoadStateParams>(),
        ),
        Tool::new(
            "jacs_update_state",
            "Update a previously signed agent state file. Writes new content (if provided), \
             recomputes the SHA-256 hash, and creates a new signed version.",
            schema_map::<UpdateStateParams>(),
        ),
        Tool::new(
            "jacs_list_state",
            "List signed agent state documents, with optional filtering by type, framework, \
             or tags.",
            schema_map::<ListStateParams>(),
        ),
        Tool::new(
            "jacs_adopt_state",
            "Adopt an external file as signed agent state. Like sign_state but marks the \
             origin as 'adopted' and optionally records the source URL.",
            schema_map::<AdoptStateParams>(),
        ),
    ]
}
