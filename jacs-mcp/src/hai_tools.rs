//! HAI MCP tools for LLM integration.
//!
//! This module provides MCP tools that allow LLMs to interact with HAI services:
//!
//! - `fetch_agent_key` - Fetch a public key from HAI's key distribution service
//! - `register_agent` - Register the local agent with HAI
//! - `verify_agent` - Verify another agent's attestation level
//! - `check_agent_status` - Check registration status with HAI
//! - `unregister_agent` - Unregister an agent from HAI
//!
//! # Security Features
//!
//! - **Registration Authorization**: The `register_agent` tool requires explicit enablement
//!   via `JACS_MCP_ALLOW_REGISTRATION=true` environment variable. This prevents prompt
//!   injection attacks from registering agents without user consent.
//!
//! - **Preview Mode by Default**: Even when enabled, registration defaults to preview mode
//!   unless `preview=false` is explicitly set.

use jacs::schema::agentstate_crud;
use jacs_binding_core::hai::HaiClient;
use jacs_binding_core::{AgentWrapper, fetch_remote_key};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo, Tool, ToolsCapability};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

// =============================================================================
// Request/Response Types
// =============================================================================

// =============================================================================
// Helper Functions
// =============================================================================

/// Validates that a string is a valid UUID format.
/// Returns an error message if invalid, None if valid.
fn validate_agent_id(agent_id: &str) -> Result<(), String> {
    if agent_id.is_empty() {
        return Err("agent_id cannot be empty".to_string());
    }

    // Try parsing as UUID
    match Uuid::parse_str(agent_id) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!(
            "Invalid agent_id format '{}'. Expected UUID format (e.g., '550e8400-e29b-41d4-a716-446655440000')",
            agent_id
        )),
    }
}

/// Check if registration is allowed via environment variable.
/// Registration requires explicit opt-in for security.
fn is_registration_allowed() -> bool {
    std::env::var("JACS_MCP_ALLOW_REGISTRATION")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

/// Check if unregistration is allowed via environment variable.
fn is_unregistration_allowed() -> bool {
    std::env::var("JACS_MCP_ALLOW_UNREGISTRATION")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

// =============================================================================
// Request/Response Types
// =============================================================================

/// Parameters for fetching an agent's public key from HAI.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FetchAgentKeyParams {
    /// The unique identifier of the agent whose key to fetch.
    #[schemars(description = "The JACS agent ID (UUID format)")]
    pub agent_id: String,

    /// The version of the key to fetch. Use "latest" for the most recent version.
    #[schemars(description = "Key version to fetch, or 'latest' for most recent")]
    pub version: Option<String>,
}

/// Result of fetching an agent's public key.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FetchAgentKeyResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent ID.
    pub agent_id: String,

    /// The key version.
    pub version: String,

    /// The cryptographic algorithm (e.g., "ed25519", "pq-dilithium").
    pub algorithm: String,

    /// The SHA-256 hash of the public key.
    pub public_key_hash: String,

    /// The public key in base64 encoding.
    pub public_key_base64: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for registering the local agent with HAI.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterAgentParams {
    /// Whether to run in preview mode (validate without registering).
    #[schemars(description = "If true, validates registration without actually registering")]
    pub preview: Option<bool>,
}

/// Result of agent registration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The registered agent's JACS ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// The JACS document ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_id: Option<String>,

    /// Whether DNS verification was successful.
    pub dns_verified: bool,

    /// Whether this was a preview-only operation.
    pub preview_mode: bool,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for verifying another agent's attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyAgentParams {
    /// The agent ID to verify.
    #[schemars(description = "The JACS agent ID to verify")]
    pub agent_id: String,

    /// The version to verify (defaults to "latest").
    #[schemars(description = "Agent version to verify, or 'latest'")]
    pub version: Option<String>,
}

/// Result of agent verification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyAgentResult {
    /// Whether the verification succeeded.
    pub success: bool,

    /// The agent ID that was verified.
    pub agent_id: String,

    /// The attestation level (0-3).
    /// - Level 0: No attestation
    /// - Level 1: Key registered with HAI
    /// - Level 2: DNS verified
    /// - Level 3: Full HAI signature attestation
    pub attestation_level: u8,

    /// Human-readable description of the attestation level.
    pub attestation_description: String,

    /// Whether the agent's public key was found.
    pub key_found: bool,

    /// Error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for checking agent registration status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgentStatusParams {
    /// Optional agent ID to check. If not provided, checks the local agent.
    #[schemars(description = "Agent ID to check status for. If omitted, checks the local agent.")]
    pub agent_id: Option<String>,
}

/// Result of checking agent status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgentStatusResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent ID that was checked.
    pub agent_id: String,

    /// Whether the agent is registered with HAI.
    pub registered: bool,

    /// HAI registration ID (if registered).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,

    /// When the agent was registered (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<String>,

    /// Number of HAI signatures on the registration.
    pub signature_count: usize,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for unregistering an agent from HAI.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UnregisterAgentParams {
    /// Whether to run in preview mode (validate without unregistering).
    #[schemars(description = "If true, validates unregistration without actually unregistering")]
    pub preview: Option<bool>,
}

/// Result of agent unregistration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UnregisterAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The unregistered agent's JACS ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Whether this was a preview-only operation.
    pub preview_mode: bool,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Agent Management Request/Response Types
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

/// Parameters for the JACS security audit tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JacsAuditParams {
    /// Optional path to jacs config file.
    #[schemars(description = "Optional path to jacs.config.json")]
    pub config_path: Option<String>,

    /// Optional number of recent documents to re-verify.
    #[schemars(description = "Number of recent documents to re-verify (default from config)")]
    pub recent_n: Option<u32>,
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

// =============================================================================
// Agent State Request/Response Types
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
        description = "Path to the file to verify (at least one of file_path or jacs_id required)"
    )]
    pub file_path: Option<String>,

    /// JACS document ID to verify.
    #[schemars(
        description = "JACS document ID to verify (at least one of file_path or jacs_id required)"
    )]
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
        description = "Path to the file to load (at least one of file_path or jacs_id required)"
    )]
    pub file_path: Option<String>,

    /// JACS document ID to load.
    #[schemars(
        description = "JACS document ID to load (at least one of file_path or jacs_id required)"
    )]
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
    #[schemars(description = "Path to the file to update (must have been previously signed)")]
    pub file_path: String,

    /// New content to write to the file. If omitted, re-signs current content.
    #[schemars(
        description = "New content to write to the file. If omitted, re-signs current file content."
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
// Document Sign/Verify Request/Response Types
// =============================================================================

/// Parameters for verifying a raw signed JACS document string.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyDocumentParams {
    /// The full JACS signed document as a JSON string.
    #[schemars(description = "The full signed JACS document JSON string to verify")]
    pub document: String,
}

/// Result of verifying a signed document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyDocumentResult {
    /// Whether the operation completed without error.
    pub success: bool,

    /// Whether the document's hash and signature are valid.
    pub valid: bool,

    /// The signer's agent ID, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for signing arbitrary content as a JACS document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignDocumentParams {
    /// The JSON content string to sign.
    #[schemars(description = "The JSON content to sign as a JACS document")]
    pub content: String,

    /// Optional MIME type of the content (default: "application/json").
    #[schemars(description = "MIME type of the content (default: 'application/json')")]
    pub content_type: Option<String>,
}

/// Result of signing a document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignDocumentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The full signed JACS document as a JSON string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_document: Option<String>,

    /// SHA-256 hash of the signed document content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    /// The JACS document ID assigned to the signed document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if signing failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Message Request/Response Types
// =============================================================================

/// Parameters for sending a signed message to another agent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageSendParams {
    /// The recipient agent's ID (UUID format).
    #[schemars(description = "The JACS agent ID of the recipient (UUID format)")]
    pub recipient_agent_id: String,

    /// The message content to send.
    #[schemars(description = "The message content to send")]
    pub content: String,

    /// The MIME type of the content (default: "text/plain").
    #[schemars(description = "MIME type of the content (default: 'text/plain')")]
    pub content_type: Option<String>,
}

/// Result of sending a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageSendResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The full signed message JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_message: Option<String>,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for updating an existing signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageUpdateParams {
    /// The JACS document ID of the message to update.
    #[schemars(description = "JACS document ID of the message to update")]
    pub jacs_id: String,

    /// The new message content.
    #[schemars(description = "Updated message content")]
    pub content: String,

    /// The MIME type of the content (default: "text/plain").
    #[schemars(description = "MIME type of the content (default: 'text/plain')")]
    pub content_type: Option<String>,
}

/// Result of updating a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageUpdateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the updated message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The full updated signed message JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_message: Option<String>,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for agreeing to (co-signing) a received message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageAgreeParams {
    /// The full signed message JSON document to agree to.
    #[schemars(description = "The full signed JSON document to agree to")]
    pub signed_message: String,
}

/// Result of agreeing to a message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageAgreeResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The document ID of the original message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_document_id: Option<String>,

    /// The document ID of the agreement document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement_document_id: Option<String>,

    /// The full signed agreement JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_agreement: Option<String>,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for receiving and verifying a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageReceiveParams {
    /// The full signed message JSON document received from another agent.
    #[schemars(description = "The full signed JSON document received from another agent")]
    pub signed_message: String,
}

/// Result of receiving and verifying a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageReceiveResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The sender's agent ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_agent_id: Option<String>,

    /// The extracted message content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// The content MIME type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The message timestamp (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    /// Whether the cryptographic signature is valid.
    pub signature_valid: bool,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Agreement Types — Multi-party cryptographic agreements
// =============================================================================

/// Parameters for creating a multi-party agreement.
///
/// An agreement is a document that multiple agents must sign. Use this when agents
/// need to formally commit to a shared decision — for example, approving a deployment,
/// authorizing a data transfer, or reaching consensus on a proposal.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAgreementParams {
    /// The document to create an agreement for, as a JSON string.
    /// This is the content all parties will be agreeing to.
    #[schemars(
        description = "JSON document that all parties will agree to. Can be any valid JSON object."
    )]
    pub document: String,

    /// List of agent IDs (UUIDs) that must sign this agreement.
    /// Include your own agent ID if you want to be a required signer.
    #[schemars(
        description = "List of agent IDs (UUIDs) that are parties to this agreement"
    )]
    pub agent_ids: Vec<String>,

    /// A human-readable question summarizing what signers are agreeing to.
    #[schemars(description = "Question for signers, e.g. 'Do you approve deploying model v2?'")]
    pub question: Option<String>,

    /// Additional context to help signers make their decision.
    #[schemars(description = "Additional context for signers")]
    pub context: Option<String>,

    /// ISO 8601 deadline. The agreement expires if not fully signed by this time.
    /// Example: "2025-12-31T23:59:59Z"
    #[schemars(
        description = "ISO 8601 deadline after which the agreement expires. Example: '2025-12-31T23:59:59Z'"
    )]
    pub timeout: Option<String>,

    /// Minimum number of signatures required (M-of-N). If omitted, ALL agents must sign.
    /// For example, quorum=2 with 3 agent_ids means any 2 of 3 signers is sufficient.
    #[schemars(
        description = "Minimum signatures required (M-of-N). If omitted, all agents must sign."
    )]
    pub quorum: Option<u32>,

    /// Only allow agents using these algorithms to sign.
    /// Values: "RSA-PSS", "ring-Ed25519", "pq-dilithium", "pq2025"
    #[schemars(
        description = "Only allow these signing algorithms. Values: 'RSA-PSS', 'ring-Ed25519', 'pq-dilithium', 'pq2025'"
    )]
    pub required_algorithms: Option<Vec<String>>,

    /// Minimum cryptographic strength: "classical" (any algorithm) or "post-quantum" (pq-dilithium, pq2025 only).
    #[schemars(
        description = "Minimum crypto strength: 'classical' or 'post-quantum'"
    )]
    pub minimum_strength: Option<String>,
}

/// Result of creating an agreement.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAgreementResult {
    pub success: bool,

    /// The JACS document ID of the agreement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement_id: Option<String>,

    /// The full signed agreement JSON. Pass this to other agents for signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_agreement: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for signing an existing agreement.
///
/// Use this after receiving an agreement document from another agent.
/// Your agent will cryptographically co-sign it, adding your signature
/// to the agreement's signature list.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignAgreementParams {
    /// The full signed agreement JSON document to co-sign.
    #[schemars(
        description = "The full agreement JSON to sign. Obtained from jacs_create_agreement or from another agent."
    )]
    pub signed_agreement: String,

    /// Optional custom agreement field name (default: 'jacsAgreement').
    #[schemars(description = "Custom agreement field name (default: 'jacsAgreement')")]
    pub agreement_fieldname: Option<String>,
}

/// Result of signing an agreement.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignAgreementResult {
    pub success: bool,

    /// The updated agreement JSON with your signature added.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_agreement: Option<String>,

    /// Number of signatures now on the agreement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_count: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for checking agreement status.
///
/// Use this to see how many agents have signed, whether quorum is met,
/// and whether the agreement has expired.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgreementParams {
    /// The full signed agreement JSON document to check.
    #[schemars(
        description = "The agreement JSON to check status of"
    )]
    pub signed_agreement: String,

    /// Optional custom agreement field name (default: 'jacsAgreement').
    #[schemars(description = "Custom agreement field name (default: 'jacsAgreement')")]
    pub agreement_fieldname: Option<String>,
}

/// Result of checking an agreement's status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgreementResult {
    pub success: bool,

    /// Whether the agreement is complete (quorum met, not expired, all signatures valid).
    pub complete: bool,

    /// Total agents required to sign.
    pub total_agents: usize,

    /// Number of valid signatures collected.
    pub signatures_collected: usize,

    /// Minimum signatures required (quorum). Equals total_agents if no quorum set.
    pub signatures_required: usize,

    /// Whether quorum has been met.
    pub quorum_met: bool,

    /// Whether the agreement has expired (past timeout).
    pub expired: bool,

    /// List of agent IDs that have signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<Vec<String>>,

    /// List of agent IDs that have NOT signed yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Vec<String>>,

    /// Timeout deadline (if set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Format a SystemTime as an ISO 8601 UTC timestamp string.
fn format_iso8601(t: std::time::SystemTime) -> String {
    let d = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // Simple conversion: seconds -> year/month/day/hour/min/sec
    // Using a basic algorithm that handles dates from 1970 onwards
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since epoch
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let leap = is_leap(y);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// =============================================================================
// MCP Server
// =============================================================================

/// HAI MCP Server providing tools for agent registration, verification, and key management.
#[derive(Clone)]
#[allow(dead_code)]
pub struct HaiMcpServer {
    /// The local agent identity.
    agent: Arc<AgentWrapper>,
    /// HAI client for API calls.
    hai_client: Arc<HaiClient>,
    /// Tool router for MCP tool dispatch.
    tool_router: ToolRouter<Self>,
    /// Whether registration is allowed (from JACS_MCP_ALLOW_REGISTRATION env var).
    registration_allowed: bool,
    /// Whether unregistration is allowed (from JACS_MCP_ALLOW_UNREGISTRATION env var).
    unregistration_allowed: bool,
}

#[allow(dead_code)]
impl HaiMcpServer {
    /// Create a new HAI MCP server with the given agent and HAI endpoint.
    ///
    /// # Arguments
    ///
    /// * `agent` - The local JACS agent wrapper
    /// * `hai_endpoint` - Base URL for the HAI API (e.g., "https://api.hai.ai")
    /// * `api_key` - Optional API key for HAI authentication
    ///
    /// # Environment Variables
    ///
    /// * `JACS_MCP_ALLOW_REGISTRATION` - Set to "true" to enable the register_agent tool
    /// * `JACS_MCP_ALLOW_UNREGISTRATION` - Set to "true" to enable the unregister_agent tool
    pub fn new(agent: AgentWrapper, hai_endpoint: &str, api_key: Option<&str>) -> Self {
        let mut client = HaiClient::new(hai_endpoint);
        if let Some(key) = api_key {
            client = client.with_api_key(key);
        }

        let registration_allowed = is_registration_allowed();
        let unregistration_allowed = is_unregistration_allowed();

        if registration_allowed {
            tracing::info!("Agent registration is ENABLED (JACS_MCP_ALLOW_REGISTRATION=true)");
        } else {
            tracing::info!(
                "Agent registration is DISABLED. Set JACS_MCP_ALLOW_REGISTRATION=true to enable."
            );
        }

        Self {
            agent: Arc::new(agent),
            hai_client: Arc::new(client),
            tool_router: Self::tool_router(),
            registration_allowed,
            unregistration_allowed,
        }
    }

    /// Get the list of available tools for LLM discovery.
    pub fn tools() -> Vec<Tool> {
        vec![
            Tool::new(
                "fetch_agent_key",
                "Fetch a public key from HAI's key distribution service. Use this to obtain \
                 trusted public keys for verifying agent signatures.",
                Self::fetch_agent_key_schema(),
            ),
            Tool::new(
                "register_agent",
                "Register the local agent with HAI. This establishes the agent's identity \
                 in the HAI network and enables attestation services. \
                 SECURITY: Requires JACS_MCP_ALLOW_REGISTRATION=true environment variable. \
                 Defaults to preview mode (set preview=false to actually register).",
                Self::register_agent_schema(),
            ),
            Tool::new(
                "verify_agent",
                "Verify another agent's attestation level with HAI. Returns the trust level \
                 (0-3) indicating how well the agent's identity has been verified.",
                Self::verify_agent_schema(),
            ),
            Tool::new(
                "check_agent_status",
                "Check the registration status of an agent with HAI. Returns whether the \
                 agent is registered and relevant registration details.",
                Self::check_agent_status_schema(),
            ),
            Tool::new(
                "unregister_agent",
                "Unregister the local agent from HAI. This removes the agent's registration \
                 and associated attestations. SECURITY: Requires JACS_MCP_ALLOW_UNREGISTRATION=true.",
                Self::unregister_agent_schema(),
            ),
            Tool::new(
                "jacs_sign_state",
                "Sign an agent state file (memory, skill, plan, config, or hook) to create \
                 a cryptographically signed JACS document. This establishes provenance and \
                 integrity for the file's contents.",
                Self::jacs_sign_state_schema(),
            ),
            Tool::new(
                "jacs_verify_state",
                "Verify the integrity and authenticity of a signed agent state. Checks both \
                 the file hash and the cryptographic signature.",
                Self::jacs_verify_state_schema(),
            ),
            Tool::new(
                "jacs_load_state",
                "Load a signed agent state document and optionally verify it before returning \
                 the content.",
                Self::jacs_load_state_schema(),
            ),
            Tool::new(
                "jacs_update_state",
                "Update a previously signed agent state file. Writes new content (if provided), \
                 recomputes the SHA-256 hash, and creates a new signed version.",
                Self::jacs_update_state_schema(),
            ),
            Tool::new(
                "jacs_list_state",
                "List signed agent state documents, with optional filtering by type, framework, \
                 or tags.",
                Self::jacs_list_state_schema(),
            ),
            Tool::new(
                "jacs_adopt_state",
                "Adopt an external file as signed agent state. Like sign_state but marks the \
                 origin as 'adopted' and optionally records the source URL.",
                Self::jacs_adopt_state_schema(),
            ),
            Tool::new(
                "jacs_create_agent",
                "Create a new JACS agent with cryptographic keys. This is the programmatic \
                 equivalent of 'jacs create'. Returns agent ID and key paths. \
                 SECURITY: Requires JACS_MCP_ALLOW_REGISTRATION=true environment variable.",
                Self::jacs_create_agent_schema(),
            ),
            Tool::new(
                "jacs_reencrypt_key",
                "Re-encrypt the agent's private key with a new password. Use this to rotate \
                 the password protecting the private key without changing the key itself.",
                Self::jacs_reencrypt_key_schema(),
            ),
            Tool::new(
                "jacs_audit",
                "Run a read-only JACS security audit and health checks. Returns a JSON report \
                 with risks, health_checks, summary, and overall_status. Does not modify state. \
                 Optional: config_path, recent_n (number of recent documents to re-verify).",
                Self::jacs_audit_schema(),
            ),
            Tool::new(
                "jacs_message_send",
                "Create and cryptographically sign a message for sending to another agent. \
                 Returns the signed JACS document that can be transmitted to the recipient.",
                Self::jacs_message_send_schema(),
            ),
            Tool::new(
                "jacs_message_update",
                "Update and re-sign an existing message document with new content.",
                Self::jacs_message_update_schema(),
            ),
            Tool::new(
                "jacs_message_agree",
                "Verify and co-sign (agree to) a received signed message. Creates an agreement \
                 document that references the original message.",
                Self::jacs_message_agree_schema(),
            ),
            Tool::new(
                "jacs_message_receive",
                "Verify a received signed message and extract its content, sender ID, and timestamp. \
                 Use this to validate authenticity before processing a message from another agent.",
                Self::jacs_message_receive_schema(),
            ),
            // --- Agreement tools ---
            Tool::new(
                "jacs_create_agreement",
                "Create a multi-party cryptographic agreement. Use this when multiple agents need \
                 to formally agree on something — like approving a deployment, authorizing a data \
                 transfer, or ratifying a decision. You specify which agents must sign, an optional \
                 quorum (e.g., 2-of-3), a timeout deadline, and algorithm constraints. Returns a \
                 signed agreement document to pass to other agents for co-signing.",
                Self::jacs_create_agreement_schema(),
            ),
            Tool::new(
                "jacs_sign_agreement",
                "Co-sign an existing agreement. Use this after receiving an agreement document from \
                 another agent. Your cryptographic signature is added to the agreement. The updated \
                 document can then be passed to the next signer or checked for completion.",
                Self::jacs_sign_agreement_schema(),
            ),
            Tool::new(
                "jacs_check_agreement",
                "Check the status of an agreement: how many agents have signed, whether quorum is \
                 met, whether it has expired, and which agents still need to sign. Use this to \
                 decide whether an agreement is complete and ready to act on.",
                Self::jacs_check_agreement_schema(),
            ),
            // --- Document sign/verify tools ---
            Tool::new(
                "jacs_sign_document",
                "Sign arbitrary JSON content to create a cryptographically signed JACS document. \
                 Use this for attestation -- when you want to prove that content was signed by \
                 this agent. Returns the signed envelope with hash and document ID.",
                Self::jacs_sign_document_schema(),
            ),
            Tool::new(
                "jacs_verify_document",
                "Verify a signed JACS document given its full JSON string. Checks both the \
                 content hash and cryptographic signature. Use this when you have a signed \
                 document in memory (e.g. from an approval context or message payload) and \
                 need to confirm its integrity and authenticity.",
                Self::jacs_verify_document_schema(),
            ),
        ]
    }

    fn fetch_agent_key_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(FetchAgentKeyParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn register_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(RegisterAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn verify_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(VerifyAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn check_agent_status_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(CheckAgentStatusParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn unregister_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(UnregisterAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_sign_state_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(SignStateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_verify_state_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(VerifyStateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_load_state_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(LoadStateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_update_state_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(UpdateStateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_list_state_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(ListStateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_adopt_state_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(AdoptStateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_create_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(CreateAgentProgrammaticParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_reencrypt_key_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(ReencryptKeyParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_audit_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(JacsAuditParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_message_send_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(MessageSendParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_message_update_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(MessageUpdateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_message_agree_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(MessageAgreeParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_message_receive_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(MessageReceiveParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_create_agreement_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(CreateAgreementParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_sign_agreement_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(SignAgreementParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_check_agreement_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(CheckAgreementParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_sign_document_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(SignDocumentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_verify_document_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(VerifyDocumentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }
}

// Implement the tool router for the server
#[tool_router]
impl HaiMcpServer {
    /// Fetch a public key from HAI's key distribution service.
    ///
    /// This tool retrieves the public key for a specific agent from HAI,
    /// allowing verification of that agent's signatures.
    #[tool(
        name = "fetch_agent_key",
        description = "Fetch a public key from HAI's key distribution service for verifying agent signatures."
    )]
    pub async fn fetch_agent_key(
        &self,
        Parameters(params): Parameters<FetchAgentKeyParams>,
    ) -> String {
        // Validate agent_id format
        if let Err(e) = validate_agent_id(&params.agent_id) {
            let result = FetchAgentKeyResult {
                success: false,
                agent_id: params.agent_id.clone(),
                version: params
                    .version
                    .clone()
                    .unwrap_or_else(|| "latest".to_string()),
                algorithm: String::new(),
                public_key_hash: String::new(),
                public_key_base64: String::new(),
                error: Some(e),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let version = params.version.as_deref().unwrap_or("latest");

        let result = match fetch_remote_key(&params.agent_id, version) {
            Ok(key_info) => FetchAgentKeyResult {
                success: true,
                agent_id: key_info.agent_id,
                version: key_info.version,
                algorithm: key_info.algorithm,
                public_key_hash: key_info.public_key_hash,
                public_key_base64: base64_encode(&key_info.public_key),
                error: None,
            },
            Err(e) => FetchAgentKeyResult {
                success: false,
                agent_id: params.agent_id.clone(),
                version: version.to_string(),
                algorithm: String::new(),
                public_key_hash: String::new(),
                public_key_base64: String::new(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Register the local agent with HAI.
    ///
    /// This establishes the agent's identity in the HAI network and enables
    /// attestation services.
    ///
    /// # Security
    ///
    /// Registration requires `JACS_MCP_ALLOW_REGISTRATION=true` environment variable.
    /// This prevents prompt injection attacks from registering agents without user consent.
    /// Registration defaults to preview mode (preview=true) for additional safety.
    #[tool(
        name = "register_agent",
        description = "Register the local JACS agent with HAI to establish identity and enable attestation."
    )]
    pub async fn register_agent(
        &self,
        Parameters(params): Parameters<RegisterAgentParams>,
    ) -> String {
        // Security check: Registration must be explicitly enabled
        if !self.registration_allowed {
            let result = RegisterAgentResult {
                success: false,
                agent_id: None,
                jacs_id: None,
                dns_verified: false,
                preview_mode: true,
                message: "Registration is disabled for security. \
                          To enable, set JACS_MCP_ALLOW_REGISTRATION=true environment variable \
                          when starting the MCP server."
                    .to_string(),
                error: Some("REGISTRATION_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Default to preview mode for additional safety
        let preview = params.preview.unwrap_or(true);

        if preview {
            let result = RegisterAgentResult {
                success: true,
                agent_id: None,
                jacs_id: None,
                dns_verified: false,
                preview_mode: true,
                message: "Preview mode: Agent would be registered with HAI. \
                          Set preview=false to actually register. \
                          WARNING: Registration is a significant action that establishes \
                          your agent's identity in the HAI network."
                    .to_string(),
                error: None,
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let result = match self.hai_client.register(&self.agent).await {
            Ok(reg) => RegisterAgentResult {
                success: true,
                agent_id: Some(reg.agent_id),
                jacs_id: Some(reg.jacs_id),
                dns_verified: reg.dns_verified,
                preview_mode: false,
                message: format!(
                    "Successfully registered with HAI. {} signature(s) received.",
                    reg.signatures.len()
                ),
                error: None,
            },
            Err(e) => RegisterAgentResult {
                success: false,
                agent_id: None,
                jacs_id: None,
                dns_verified: false,
                preview_mode: false,
                message: "Registration failed".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Verify another agent's attestation level with HAI.
    ///
    /// Returns the trust level indicating how well the agent's identity
    /// has been verified:
    /// - Level 0: No attestation
    /// - Level 1: Key registered with HAI
    /// - Level 2: DNS verified (key hash matches DNS TXT record)
    /// - Level 3: Full HAI signature attestation (HAI has signed the registration)
    #[tool(
        name = "verify_agent",
        description = "Verify another agent's attestation level (0-3) with HAI."
    )]
    pub async fn verify_agent(&self, Parameters(params): Parameters<VerifyAgentParams>) -> String {
        // Validate agent_id format
        if let Err(e) = validate_agent_id(&params.agent_id) {
            let result = VerifyAgentResult {
                success: false,
                agent_id: params.agent_id.clone(),
                attestation_level: 0,
                attestation_description: "Level 0: Invalid agent ID format".to_string(),
                key_found: false,
                error: Some(e),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let version = params.version.as_deref().unwrap_or("latest");

        // First, try to fetch the key to determine attestation level
        let key_result = fetch_remote_key(&params.agent_id, version);

        let (attestation_level, attestation_description, key_found) = match &key_result {
            Ok(_key_info) => {
                // Key found - at minimum Level 1
                // Now check for higher levels

                // Check for Level 3: HAI signature attestation
                // Query the status endpoint to see if HAI has signed the registration
                match self.hai_client.status(&self.agent).await {
                    Ok(status) if !status.hai_signatures.is_empty() => (
                        3u8,
                        format!(
                            "Level 3: Full HAI attestation ({} signature(s))",
                            status.hai_signatures.len()
                        ),
                        true,
                    ),
                    Ok(status) if status.registered => {
                        // Registered but no HAI signatures yet
                        // Check for Level 2: DNS verification
                        // For now, we report Level 1 if we can't verify DNS
                        // DNS verification would require fetching the agent document
                        // and checking if dns_verified is true
                        (
                            1u8,
                            "Level 1: Public key registered with HAI key service".to_string(),
                            true,
                        )
                    }
                    _ => {
                        // Status check failed or not registered
                        // Fall back to Level 1 since we have the key
                        (
                            1u8,
                            "Level 1: Public key registered with HAI key service".to_string(),
                            true,
                        )
                    }
                }
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("not found") || error_str.contains("404") {
                    (
                        0u8,
                        "Level 0: Agent not found in HAI key service".to_string(),
                        false,
                    )
                } else {
                    // Network or other error - can't determine level
                    (
                        0u8,
                        format!("Level 0: Unable to verify ({})", error_str),
                        false,
                    )
                }
            }
        };

        let result = VerifyAgentResult {
            success: key_found || key_result.is_ok(),
            agent_id: params.agent_id,
            attestation_level,
            attestation_description,
            key_found,
            error: key_result.err().map(|e| e.to_string()),
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Check the registration status of an agent with HAI.
    #[tool(
        name = "check_agent_status",
        description = "Check if an agent is registered with HAI and get registration details."
    )]
    pub async fn check_agent_status(
        &self,
        Parameters(params): Parameters<CheckAgentStatusParams>,
    ) -> String {
        // If no agent_id provided, check the local agent
        let check_local = params.agent_id.is_none();

        let result = if check_local {
            // Check status of the local agent
            match self.hai_client.status(&self.agent).await {
                Ok(status) => CheckAgentStatusResult {
                    success: true,
                    agent_id: status.agent_id,
                    registered: status.registered,
                    registration_id: if status.registration_id.is_empty() {
                        None
                    } else {
                        Some(status.registration_id)
                    },
                    registered_at: if status.registered_at.is_empty() {
                        None
                    } else {
                        Some(status.registered_at)
                    },
                    signature_count: status.hai_signatures.len(),
                    error: None,
                },
                Err(e) => CheckAgentStatusResult {
                    success: false,
                    agent_id: "local".to_string(),
                    registered: false,
                    registration_id: None,
                    registered_at: None,
                    signature_count: 0,
                    error: Some(e.to_string()),
                },
            }
        } else {
            // For a remote agent, we can only check if their key exists
            let agent_id = params.agent_id.unwrap();

            // Validate agent_id format
            if let Err(e) = validate_agent_id(&agent_id) {
                return serde_json::to_string_pretty(&CheckAgentStatusResult {
                    success: false,
                    agent_id,
                    registered: false,
                    registration_id: None,
                    registered_at: None,
                    signature_count: 0,
                    error: Some(e),
                })
                .unwrap_or_else(|e| format!("Error: {}", e));
            }

            match fetch_remote_key(&agent_id, "latest") {
                Ok(_) => CheckAgentStatusResult {
                    success: true,
                    agent_id: agent_id.clone(),
                    registered: true,
                    registration_id: None, // Not available for remote agents
                    registered_at: None,
                    signature_count: 0,
                    error: None,
                },
                Err(e) => {
                    let error_str = e.to_string();
                    let registered = !error_str.contains("not found") && !error_str.contains("404");
                    CheckAgentStatusResult {
                        success: !registered, // Success if we got a clear "not found"
                        agent_id,
                        registered,
                        registration_id: None,
                        registered_at: None,
                        signature_count: 0,
                        error: if registered { Some(error_str) } else { None },
                    }
                }
            }
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Unregister the local agent from HAI.
    ///
    /// This removes the agent's registration and associated attestations.
    ///
    /// # Security
    ///
    /// Unregistration requires `JACS_MCP_ALLOW_UNREGISTRATION=true` environment variable.
    #[tool(
        name = "unregister_agent",
        description = "Unregister the local JACS agent from HAI."
    )]
    pub async fn unregister_agent(
        &self,
        Parameters(params): Parameters<UnregisterAgentParams>,
    ) -> String {
        // Security check: Unregistration must be explicitly enabled
        if !self.unregistration_allowed {
            let result = UnregisterAgentResult {
                success: false,
                agent_id: None,
                preview_mode: true,
                message: "Unregistration is disabled for security. \
                          To enable, set JACS_MCP_ALLOW_UNREGISTRATION=true environment variable \
                          when starting the MCP server."
                    .to_string(),
                error: Some("UNREGISTRATION_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Default to preview mode for safety
        let preview = params.preview.unwrap_or(true);

        if preview {
            let result = UnregisterAgentResult {
                success: true,
                agent_id: None,
                preview_mode: true,
                message: "Preview mode: Agent would be unregistered from HAI. \
                          Set preview=false to actually unregister. \
                          WARNING: Unregistration removes your agent's identity from the HAI network."
                    .to_string(),
                error: None,
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Note: HaiClient doesn't currently have an unregister method
        // This is a placeholder for when that functionality is added
        let result = UnregisterAgentResult {
            success: false,
            agent_id: None,
            preview_mode: false,
            message: "Unregistration is not yet implemented in the HAI API. \
                      Please contact HAI support to unregister your agent."
                .to_string(),
            error: Some("NOT_IMPLEMENTED".to_string()),
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Sign an agent state file to create a cryptographically signed JACS document.
    ///
    /// Reads the file, creates an agent state document with metadata, and signs it
    /// using the local agent's keys. For hooks, content is always embedded.
    #[tool(
        name = "jacs_sign_state",
        description = "Sign an agent state file (memory/skill/plan/config/hook) to create a signed JACS document."
    )]
    pub async fn jacs_sign_state(&self, Parameters(params): Parameters<SignStateParams>) -> String {
        let embed = params.embed.unwrap_or(false);

        // Create the agent state document with file reference
        let mut doc = match agentstate_crud::create_agentstate_with_file(
            &params.state_type,
            &params.name,
            &params.file_path,
            embed,
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = SignStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to create agent state document".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Set optional fields
        if let Some(desc) = &params.description {
            doc["jacsAgentStateDescription"] = serde_json::json!(desc);
        }

        if let Some(framework) = &params.framework {
            if let Err(e) = agentstate_crud::set_agentstate_framework(&mut doc, framework) {
                let result = SignStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to set framework".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        if let Some(tags) = &params.tags {
            let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
            if let Err(e) = agentstate_crud::set_agentstate_tags(&mut doc, tag_refs) {
                let result = SignStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to set tags".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        // Set origin as "authored" for directly signed state
        let _ = agentstate_crud::set_agentstate_origin(&mut doc, "authored", None);

        // Sign the document via create_document (no_save=true to avoid filesystem writes)
        let doc_string = doc.to_string();
        let result = match self.agent.create_document(
            &doc_string,
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            Some(embed || params.state_type == "hook"),
        ) {
            Ok(signed_doc_string) => {
                // Extract the JACS document ID from the signed document
                let doc_id = serde_json::from_str::<serde_json::Value>(&signed_doc_string)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                    .unwrap_or_else(|| "unknown".to_string());

                SignStateResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    state_type: params.state_type,
                    name: params.name,
                    message: format!(
                        "Successfully signed agent state file '{}'",
                        params.file_path
                    ),
                    error: None,
                }
            }
            Err(e) => SignStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Failed to sign document".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Verify the integrity and authenticity of a signed agent state.
    ///
    /// Checks both the file content hash against the signed hash and verifies
    /// the cryptographic signature on the document.
    #[tool(
        name = "jacs_verify_state",
        description = "Verify a signed agent state's file hash and cryptographic signature."
    )]
    pub async fn jacs_verify_state(
        &self,
        Parameters(params): Parameters<VerifyStateParams>,
    ) -> String {
        // At least one of file_path or jacs_id must be provided
        if params.file_path.is_none() && params.jacs_id.is_none() {
            let result = VerifyStateResult {
                success: false,
                hash_match: false,
                signature_valid: false,
                signing_info: None,
                message: "At least one of file_path or jacs_id must be provided".to_string(),
                error: Some("MISSING_PARAMETER".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // If jacs_id is provided, verify the document by ID from storage
        if let Some(jacs_id) = &params.jacs_id {
            match self.agent.verify_document_by_id(jacs_id) {
                Ok(valid) => {
                    let result = VerifyStateResult {
                        success: true,
                        hash_match: valid,
                        signature_valid: valid,
                        signing_info: None,
                        message: if valid {
                            format!("Document '{}' verified successfully", jacs_id)
                        } else {
                            format!("Document '{}' signature verification failed", jacs_id)
                        },
                        error: None,
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
                Err(e) => {
                    let result = VerifyStateResult {
                        success: false,
                        hash_match: false,
                        signature_valid: false,
                        signing_info: None,
                        message: format!("Failed to verify document '{}': {}", jacs_id, e),
                        error: Some(e.to_string()),
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
            }
        }

        // file_path-based verification: read the file and check if a signed
        // document exists for it by looking at the stored state documents.
        // Since document index is not yet available, we create a minimal
        // verification based on file hash.
        let file_path = params.file_path.as_deref().unwrap();
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                let result = VerifyStateResult {
                    success: false,
                    hash_match: false,
                    signature_valid: false,
                    signing_info: None,
                    message: format!("Failed to read file '{}'", file_path),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Compute current file hash
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let current_hash = format!("{:x}", hasher.finalize());

        // Check for a .jacs.json sidecar file that might hold the signed document
        let sidecar_path = format!("{}.jacs.json", file_path);
        if let Ok(sidecar_content) = std::fs::read_to_string(&sidecar_path) {
            // Parse the sidecar document
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&sidecar_content) {
                // Verify file hash using agentstate_crud
                let hash_match = match agentstate_crud::verify_agentstate_file_hash(&doc) {
                    Ok(matches) => matches,
                    Err(_) => false,
                };

                // Verify document signature
                let signature_valid = match self.agent.verify_document(&sidecar_content) {
                    Ok(valid) => valid,
                    Err(_) => false,
                };

                let signing_info = doc.get("jacsSignature").map(|s| s.to_string());

                let result = VerifyStateResult {
                    success: true,
                    hash_match,
                    signature_valid,
                    signing_info,
                    message: format!(
                        "Verification complete: hash_match={}, signature_valid={}",
                        hash_match, signature_valid
                    ),
                    error: None,
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        // No sidecar found - report what we can
        let result = VerifyStateResult {
            success: true,
            hash_match: false,
            signature_valid: false,
            signing_info: None,
            message: format!(
                "No signed document found for '{}'. Current file SHA-256: {}. \
                 Use jacs_sign_state to create a signed document first.",
                file_path, current_hash
            ),
            error: None,
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Load a signed agent state document and optionally verify it.
    ///
    /// Returns the content of the state along with verification status.
    #[tool(
        name = "jacs_load_state",
        description = "Load a signed agent state document, optionally verifying before returning content."
    )]
    pub async fn jacs_load_state(&self, Parameters(params): Parameters<LoadStateParams>) -> String {
        // At least one of file_path or jacs_id must be provided
        if params.file_path.is_none() && params.jacs_id.is_none() {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: None,
                message: "At least one of file_path or jacs_id must be provided".to_string(),
                error: Some("MISSING_PARAMETER".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let require_verified = params.require_verified.unwrap_or(true);

        // Loading by jacs_id is not yet implemented (requires document index)
        if params.file_path.is_none() {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: None,
                message: "Loading by JACS ID alone is not yet implemented. \
                         Please provide a file_path."
                    .to_string(),
                error: Some("NOT_YET_IMPLEMENTED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let file_path = params.file_path.as_deref().unwrap();

        // Read the file content
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                let result = LoadStateResult {
                    success: false,
                    content: None,
                    verified: false,
                    warnings: None,
                    message: format!("Failed to read file '{}'", file_path),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut warnings = Vec::new();
        let mut verified = false;

        // Check for sidecar signed document
        let sidecar_path = format!("{}.jacs.json", file_path);
        if let Ok(sidecar_content) = std::fs::read_to_string(&sidecar_path) {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&sidecar_content) {
                // Verify hash
                match agentstate_crud::verify_agentstate_file_hash(&doc) {
                    Ok(true) => {
                        verified = true;
                    }
                    Ok(false) => {
                        warnings.push(
                            "File content hash does not match signed hash. \
                             File may have been modified since signing."
                                .to_string(),
                        );
                    }
                    Err(e) => {
                        warnings.push(format!("Could not verify file hash: {}", e));
                    }
                }

                // Verify signature
                match self.agent.verify_document(&sidecar_content) {
                    Ok(true) => {}
                    Ok(false) => {
                        verified = false;
                        warnings.push("Document signature verification failed.".to_string());
                    }
                    Err(e) => {
                        verified = false;
                        warnings.push(format!("Could not verify document signature: {}", e));
                    }
                }
            }
        } else {
            warnings.push(format!(
                "No signed document found at '{}'. Content is unverified.",
                sidecar_path
            ));
        }

        if require_verified && !verified {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: if warnings.is_empty() {
                    None
                } else {
                    Some(warnings)
                },
                message: "Verification required but content could not be verified.".to_string(),
                error: Some("VERIFICATION_FAILED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let result = LoadStateResult {
            success: true,
            content: Some(content),
            verified,
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
            message: if verified {
                format!("Successfully loaded and verified '{}'", file_path)
            } else {
                format!("Loaded '{}' without full verification", file_path)
            },
            error: None,
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Update a previously signed agent state file.
    ///
    /// If new_content is provided, writes it to the file first. Then recomputes
    /// the SHA-256 hash and creates a new signed version of the document.
    #[tool(
        name = "jacs_update_state",
        description = "Update a previously signed agent state file with new content and re-sign."
    )]
    pub async fn jacs_update_state(
        &self,
        Parameters(params): Parameters<UpdateStateParams>,
    ) -> String {
        // If new content is provided, write it to the file
        if let Some(new_content) = &params.new_content {
            if let Err(e) = std::fs::write(&params.file_path, new_content) {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: format!("Failed to write new content to '{}'", params.file_path),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        // Read the (possibly updated) file content
        let content = match std::fs::read_to_string(&params.file_path) {
            Ok(c) => c,
            Err(e) => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: format!("Failed to read file '{}'", params.file_path),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Compute new SHA-256 hash
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let new_hash = format!("{:x}", hasher.finalize());

        // Check for existing sidecar document to get metadata for the update
        let sidecar_path = format!("{}.jacs.json", params.file_path);
        let existing_doc = std::fs::read_to_string(&sidecar_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

        // Extract metadata before potentially consuming the document
        let state_type = existing_doc
            .as_ref()
            .and_then(|d| {
                d.get("jacsAgentStateType")
                    .and_then(|t| t.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "config".to_string());

        let state_name = existing_doc
            .as_ref()
            .and_then(|d| {
                d.get("jacsAgentStateName")
                    .and_then(|n| n.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| {
                std::path::Path::new(&params.file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unnamed")
                    .to_string()
            });

        if let Some(mut doc) = existing_doc {
            // Update the file hash in the document
            if let Some(files) = doc.get_mut("jacsFiles").and_then(|f| f.as_array_mut()) {
                for file_entry in files.iter_mut() {
                    if let Some(obj) = file_entry.as_object_mut() {
                        obj.insert(
                            "sha256".to_string(),
                            serde_json::Value::String(new_hash.clone()),
                        );
                        // Update embedded content if it was embedded
                        if obj.get("embed").and_then(|e| e.as_bool()).unwrap_or(false) {
                            obj.insert(
                                "contents".to_string(),
                                serde_json::Value::String(content.clone()),
                            );
                        }
                    }
                }
            }

            // If content was embedded at the document level, update it
            if doc.get("jacsAgentStateContent").is_some() {
                doc["jacsAgentStateContent"] = serde_json::json!(content);
            }

            // Extract the document key for update
            let doc_key = doc
                .get("id")
                .and_then(|id| id.as_str())
                .map(String::from)
                .unwrap_or_default();

            // Try to update the existing document
            let doc_string = doc.to_string();
            match self
                .agent
                .update_document(&doc_key, &doc_string, None, None)
            {
                Ok(updated_doc_string) => {
                    let version_id = serde_json::from_str::<serde_json::Value>(&updated_doc_string)
                        .ok()
                        .and_then(|v| {
                            v.get("jacsVersion")
                                .and_then(|ver| ver.as_str())
                                .map(String::from)
                                .or_else(|| {
                                    v.get("id").and_then(|id| id.as_str()).map(String::from)
                                })
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    let result = UpdateStateResult {
                        success: true,
                        jacs_document_version_id: Some(version_id),
                        new_hash: Some(new_hash),
                        message: format!(
                            "Successfully updated and re-signed '{}'",
                            params.file_path
                        ),
                        error: None,
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
                Err(e) => {
                    // Fall through to create a new document if update fails
                    tracing::warn!(
                        "Failed to update existing document ({}), creating new signed version",
                        e
                    );
                }
            }
        }

        // No existing sidecar or update failed - create a fresh signed document

        // Create fresh document
        match agentstate_crud::create_agentstate_with_file(
            &state_type,
            &state_name,
            &params.file_path,
            false,
        ) {
            Ok(doc) => {
                let doc_string = doc.to_string();
                match self
                    .agent
                    .create_document(&doc_string, None, None, true, None, Some(false))
                {
                    Ok(signed_doc_string) => {
                        let version_id =
                            serde_json::from_str::<serde_json::Value>(&signed_doc_string)
                                .ok()
                                .and_then(|v| {
                                    v.get("id").and_then(|id| id.as_str()).map(String::from)
                                })
                                .unwrap_or_else(|| "unknown".to_string());

                        let result = UpdateStateResult {
                            success: true,
                            jacs_document_version_id: Some(version_id),
                            new_hash: Some(new_hash),
                            message: format!(
                                "Created new signed version for '{}'",
                                params.file_path
                            ),
                            error: None,
                        };
                        serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|e| format!("Error: {}", e))
                    }
                    Err(e) => {
                        let result = UpdateStateResult {
                            success: false,
                            jacs_document_version_id: None,
                            new_hash: Some(new_hash),
                            message: "Failed to create new signed document".to_string(),
                            error: Some(e.to_string()),
                        };
                        serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|e| format!("Error: {}", e))
                    }
                }
            }
            Err(e) => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: Some(new_hash),
                    message: "Failed to create agent state document for re-signing".to_string(),
                    error: Some(e),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// List signed agent state documents.
    ///
    /// Currently returns a placeholder since document indexing is not yet
    /// implemented. Will be fully functional once document storage lookup is added.
    #[tool(
        name = "jacs_list_state",
        description = "List signed agent state documents, with optional filtering."
    )]
    pub async fn jacs_list_state(
        &self,
        Parameters(_params): Parameters<ListStateParams>,
    ) -> String {
        // Document indexing/listing is not yet implemented.
        // This will be connected to the document storage layer when available.
        let result = ListStateResult {
            success: true,
            documents: Vec::new(),
            message: "Agent state document listing is not yet fully implemented. \
                     Documents are signed and stored but a centralized index is pending. \
                     Use jacs_verify_state with a file_path to check individual files."
                .to_string(),
            error: None,
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Adopt an external file as signed agent state.
    ///
    /// Like sign_state but sets the origin to "adopted" and optionally records
    /// the source URL where the content was obtained.
    #[tool(
        name = "jacs_adopt_state",
        description = "Adopt an external file as signed agent state, marking it with 'adopted' origin."
    )]
    pub async fn jacs_adopt_state(
        &self,
        Parameters(params): Parameters<AdoptStateParams>,
    ) -> String {
        // Create the agent state document with file reference
        let mut doc = match agentstate_crud::create_agentstate_with_file(
            &params.state_type,
            &params.name,
            &params.file_path,
            false, // don't embed by default for adopted state
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = AdoptStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to create agent state document".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Set description if provided
        if let Some(desc) = &params.description {
            doc["jacsAgentStateDescription"] = serde_json::json!(desc);
        }

        // Set origin as "adopted" with optional source URL
        if let Err(e) = agentstate_crud::set_agentstate_origin(
            &mut doc,
            "adopted",
            params.source_url.as_deref(),
        ) {
            let result = AdoptStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Failed to set adopted origin".to_string(),
                error: Some(e),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Sign the document
        let doc_string = doc.to_string();
        let result = match self.agent.create_document(
            &doc_string,
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            Some(false),
        ) {
            Ok(signed_doc_string) => {
                let doc_id = serde_json::from_str::<serde_json::Value>(&signed_doc_string)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                    .unwrap_or_else(|| "unknown".to_string());

                AdoptStateResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    state_type: params.state_type,
                    name: params.name,
                    message: format!(
                        "Successfully adopted and signed state file '{}' (origin: adopted{})",
                        params.file_path,
                        params
                            .source_url
                            .as_ref()
                            .map(|u| format!(", source: {}", u))
                            .unwrap_or_default()
                    ),
                    error: None,
                }
            }
            Err(e) => AdoptStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Failed to sign adopted document".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Create a new JACS agent programmatically.
    ///
    /// This is the programmatic equivalent of `jacs create`. It generates
    /// a new agent with cryptographic keys and returns the agent info.
    /// Requires JACS_MCP_ALLOW_REGISTRATION=true for security.
    #[tool(
        name = "jacs_create_agent",
        description = "Create a new JACS agent with cryptographic keys (programmatic)."
    )]
    pub async fn jacs_create_agent(
        &self,
        Parameters(params): Parameters<CreateAgentProgrammaticParams>,
    ) -> String {
        // Require explicit opt-in for agent creation (same gate as registration)
        if !self.registration_allowed {
            let result = CreateAgentProgrammaticResult {
                success: false,
                agent_id: None,
                name: params.name,
                message: "Agent creation is disabled. Set JACS_MCP_ALLOW_REGISTRATION=true \
                          environment variable to enable."
                    .to_string(),
                error: Some("REGISTRATION_NOT_ALLOWED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let result = match jacs_binding_core::create_agent_programmatic(
            &params.name,
            &params.password,
            params.algorithm.as_deref(),
            params.data_directory.as_deref(),
            params.key_directory.as_deref(),
            None, // config_path
            params.agent_type.as_deref(),
            params.description.as_deref(),
            None, // domain
            None, // default_storage
        ) {
            Ok(info_json) => {
                // Parse the info JSON to extract agent_id
                let agent_id = serde_json::from_str::<serde_json::Value>(&info_json)
                    .ok()
                    .and_then(|v| v.get("agent_id").and_then(|a| a.as_str()).map(String::from));

                CreateAgentProgrammaticResult {
                    success: true,
                    agent_id,
                    name: params.name,
                    message: "Agent created successfully".to_string(),
                    error: None,
                }
            }
            Err(e) => CreateAgentProgrammaticResult {
                success: false,
                agent_id: None,
                name: params.name,
                message: "Failed to create agent".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Re-encrypt the agent's private key with a new password.
    ///
    /// Decrypts the private key with the old password and re-encrypts it
    /// with the new password. The key itself does not change.
    #[tool(
        name = "jacs_reencrypt_key",
        description = "Re-encrypt the agent's private key with a new password."
    )]
    pub async fn jacs_reencrypt_key(
        &self,
        Parameters(params): Parameters<ReencryptKeyParams>,
    ) -> String {
        let result = match self
            .agent
            .reencrypt_key(&params.old_password, &params.new_password)
        {
            Ok(()) => ReencryptKeyResult {
                success: true,
                message: "Private key re-encrypted successfully with new password".to_string(),
                error: None,
            },
            Err(e) => ReencryptKeyResult {
                success: false,
                message: "Failed to re-encrypt private key".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Run a read-only JACS security audit. Returns JSON with risks, health_checks, summary.
    #[tool(
        name = "jacs_audit",
        description = "Run a read-only JACS security audit and health checks."
    )]
    pub async fn jacs_audit(&self, Parameters(params): Parameters<JacsAuditParams>) -> String {
        match jacs_binding_core::audit(params.config_path.as_deref(), params.recent_n) {
            Ok(json) => json,
            Err(e) => serde_json::json!({
                "error": true,
                "message": e.to_string()
            })
            .to_string(),
        }
    }

    /// Create and sign a message document for sending to another agent.
    ///
    /// Builds a JSON message envelope with sender/recipient IDs, content, timestamp,
    /// and a unique message ID, then signs it using the local agent's keys.
    #[tool(
        name = "jacs_message_send",
        description = "Create and sign a message for sending to another agent."
    )]
    pub async fn jacs_message_send(
        &self,
        Parameters(params): Parameters<MessageSendParams>,
    ) -> String {
        // Validate recipient agent ID
        if let Err(e) = validate_agent_id(&params.recipient_agent_id) {
            let result = MessageSendResult {
                success: false,
                jacs_document_id: None,
                signed_message: None,
                error: Some(e),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Get the sender's agent ID from the loaded agent
        let sender_id = match self.agent.get_agent_json() {
            Ok(json_str) => serde_json::from_str::<serde_json::Value>(&json_str)
                .ok()
                .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                .unwrap_or_else(|| "unknown".to_string()),
            Err(_) => "unknown".to_string(),
        };

        let content_type = params
            .content_type
            .unwrap_or_else(|| "text/plain".to_string());
        let message_id = Uuid::new_v4().to_string();
        let timestamp = format_iso8601(std::time::SystemTime::now());

        // Build the message document
        let message_doc = serde_json::json!({
            "jacsMessageId": message_id,
            "jacsMessageSenderId": sender_id,
            "jacsMessageRecipientId": params.recipient_agent_id,
            "jacsMessageContent": params.content,
            "jacsMessageContentType": content_type,
            "jacsMessageTimestamp": timestamp,
        });

        let doc_string = message_doc.to_string();

        // Sign the document
        let result = match self.agent.create_document(
            &doc_string,
            None,  // custom_schema
            None,  // outputfilename
            true,  // no_save
            None,  // attachments
            None,  // embed
        ) {
            Ok(signed_doc_string) => {
                let doc_id = serde_json::from_str::<serde_json::Value>(&signed_doc_string)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                    .unwrap_or_else(|| "unknown".to_string());

                MessageSendResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    signed_message: Some(signed_doc_string),
                    error: None,
                }
            }
            Err(e) => MessageSendResult {
                success: false,
                jacs_document_id: None,
                signed_message: None,
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Update and re-sign an existing message document with new content.
    ///
    /// Loads the message by its JACS document ID, replaces the content fields,
    /// and creates a new signed version.
    #[tool(
        name = "jacs_message_update",
        description = "Update and re-sign an existing message document with new content."
    )]
    pub async fn jacs_message_update(
        &self,
        Parameters(params): Parameters<MessageUpdateParams>,
    ) -> String {
        // Load the existing document by ID
        let existing_doc_string: Option<String> = match self.agent.verify_document_by_id(&params.jacs_id) {
            Ok(true) => {
                // Document verified, now retrieve it. We need the stored document.
                // Use get_agent_json to get agent context, then load via ID.
                // The verify_document_by_id already loaded it; we need to get it from storage.
                // Fall through to attempt update_document with the new content.
                None
            }
            Ok(false) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Existing document '{}' failed signature verification",
                        params.jacs_id
                    )),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
            Err(e) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Failed to load document '{}': {}",
                        params.jacs_id, e
                    )),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let content_type = params
            .content_type
            .unwrap_or_else(|| "text/plain".to_string());
        let timestamp = format_iso8601(std::time::SystemTime::now());

        // Build the updated message content
        let updated_doc = serde_json::json!({
            "jacsMessageContent": params.content,
            "jacsMessageContentType": content_type,
            "jacsMessageTimestamp": timestamp,
        });

        let _ = existing_doc_string; // consumed above

        let doc_string = updated_doc.to_string();
        let result = match self
            .agent
            .update_document(&params.jacs_id, &doc_string, None, None)
        {
            Ok(updated_doc_string) => {
                let doc_id = serde_json::from_str::<serde_json::Value>(&updated_doc_string)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                    .unwrap_or_else(|| params.jacs_id.clone());

                MessageUpdateResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    signed_message: Some(updated_doc_string),
                    error: None,
                }
            }
            Err(e) => MessageUpdateResult {
                success: false,
                jacs_document_id: None,
                signed_message: None,
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Co-sign (agree to) a received signed message.
    ///
    /// Verifies the original message's signature, then creates an agreement document
    /// that references the original and is signed by the local agent.
    #[tool(
        name = "jacs_message_agree",
        description = "Verify and co-sign a received message, creating a signed agreement document."
    )]
    pub async fn jacs_message_agree(
        &self,
        Parameters(params): Parameters<MessageAgreeParams>,
    ) -> String {
        // Verify the original document's signature first
        match self.agent.verify_document(&params.signed_message) {
            Ok(true) => {} // Signature valid, proceed
            Ok(false) => {
                let result = MessageAgreeResult {
                    success: false,
                    original_document_id: None,
                    agreement_document_id: None,
                    signed_agreement: None,
                    error: Some(
                        "Original message signature verification failed".to_string(),
                    ),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
            Err(e) => {
                let result = MessageAgreeResult {
                    success: false,
                    original_document_id: None,
                    agreement_document_id: None,
                    signed_agreement: None,
                    error: Some(format!("Failed to verify original message: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        // Extract the original document ID
        let original_doc_id = serde_json::from_str::<serde_json::Value>(&params.signed_message)
            .ok()
            .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
            .unwrap_or_else(|| "unknown".to_string());

        // Get our agent ID
        let our_agent_id = match self.agent.get_agent_json() {
            Ok(json_str) => serde_json::from_str::<serde_json::Value>(&json_str)
                .ok()
                .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                .unwrap_or_else(|| "unknown".to_string()),
            Err(_) => "unknown".to_string(),
        };

        let timestamp = format_iso8601(std::time::SystemTime::now());

        // Create an agreement document that references the original
        let agreement_doc = serde_json::json!({
            "jacsAgreementType": "message_acknowledgment",
            "jacsAgreementOriginalDocumentId": original_doc_id,
            "jacsAgreementAgentId": our_agent_id,
            "jacsAgreementTimestamp": timestamp,
        });

        let doc_string = agreement_doc.to_string();

        // Sign the agreement document
        let result = match self.agent.create_document(
            &doc_string,
            None,  // custom_schema
            None,  // outputfilename
            true,  // no_save
            None,  // attachments
            None,  // embed
        ) {
            Ok(signed_agreement_string) => {
                let agreement_id =
                    serde_json::from_str::<serde_json::Value>(&signed_agreement_string)
                        .ok()
                        .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                        .unwrap_or_else(|| "unknown".to_string());

                MessageAgreeResult {
                    success: true,
                    original_document_id: Some(original_doc_id),
                    agreement_document_id: Some(agreement_id),
                    signed_agreement: Some(signed_agreement_string),
                    error: None,
                }
            }
            Err(e) => MessageAgreeResult {
                success: false,
                original_document_id: Some(original_doc_id),
                agreement_document_id: None,
                signed_agreement: None,
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Verify and extract content from a received signed message.
    ///
    /// Checks the cryptographic signature, then extracts the message content,
    /// sender ID, content type, and timestamp.
    #[tool(
        name = "jacs_message_receive",
        description = "Verify a received signed message and extract its content and sender information."
    )]
    pub async fn jacs_message_receive(
        &self,
        Parameters(params): Parameters<MessageReceiveParams>,
    ) -> String {
        // Verify the document's signature
        let signature_valid = match self.agent.verify_document(&params.signed_message) {
            Ok(valid) => valid,
            Err(e) => {
                let result = MessageReceiveResult {
                    success: false,
                    sender_agent_id: None,
                    content: None,
                    content_type: None,
                    timestamp: None,
                    signature_valid: false,
                    error: Some(format!("Failed to verify message signature: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Parse the document to extract fields
        let doc: serde_json::Value = match serde_json::from_str(&params.signed_message) {
            Ok(v) => v,
            Err(e) => {
                let result = MessageReceiveResult {
                    success: false,
                    sender_agent_id: None,
                    content: None,
                    content_type: None,
                    timestamp: None,
                    signature_valid,
                    error: Some(format!("Failed to parse message JSON: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Extract message fields
        let sender_agent_id = doc
            .get("jacsMessageSenderId")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| {
                // Fall back to signature's agentID
                doc.get("jacsSignature")
                    .and_then(|s| s.get("agentID"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        let content = doc
            .get("jacsMessageContent")
            .and_then(|v| v.as_str())
            .map(String::from);

        let content_type = doc
            .get("jacsMessageContentType")
            .and_then(|v| v.as_str())
            .map(String::from);

        let timestamp = doc
            .get("jacsMessageTimestamp")
            .and_then(|v| v.as_str())
            .map(String::from);

        let result = MessageReceiveResult {
            success: true,
            sender_agent_id,
            content,
            content_type,
            timestamp,
            signature_valid,
            error: if !signature_valid {
                Some("Message signature is INVALID — content may have been tampered with".to_string())
            } else {
                None
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    // =========================================================================
    // Agreement tools — multi-party cryptographic agreements
    // =========================================================================

    /// Create a multi-party agreement that other agents can co-sign.
    ///
    /// The agreement specifies which agents must sign, optional quorum (M-of-N),
    /// timeout, and algorithm constraints. The returned document should be passed
    /// to other agents for signing via `jacs_sign_agreement`.
    #[tool(
        name = "jacs_create_agreement",
        description = "Create a multi-party cryptographic agreement. Specify which agents must sign, \
                       optional quorum (e.g., 2-of-3), timeout deadline, and algorithm constraints. \
                       Returns a signed agreement document to pass to other agents for co-signing."
    )]
    pub async fn jacs_create_agreement(
        &self,
        Parameters(params): Parameters<CreateAgreementParams>,
    ) -> String {
        // Create the base document first
        let signed_doc = match self.agent.create_document(
            &params.document,
            None,  // custom_schema
            None,  // outputfilename
            true,  // no_save
            None,  // attachments
            None,  // embed
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = CreateAgreementResult {
                    success: false,
                    agreement_id: None,
                    signed_agreement: None,
                    error: Some(format!("Failed to create document: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Create the agreement on the document
        let result = match self.agent.create_agreement_with_options(
            &signed_doc,
            params.agent_ids,
            params.question,
            params.context,
            None, // agreement_fieldname (use default)
            params.timeout,
            params.quorum,
            params.required_algorithms,
            params.minimum_strength,
        ) {
            Ok(agreement_string) => {
                let agreement_id =
                    serde_json::from_str::<serde_json::Value>(&agreement_string)
                        .ok()
                        .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                        .unwrap_or_else(|| "unknown".to_string());

                CreateAgreementResult {
                    success: true,
                    agreement_id: Some(agreement_id),
                    signed_agreement: Some(agreement_string),
                    error: None,
                }
            }
            Err(e) => CreateAgreementResult {
                success: false,
                agreement_id: None,
                signed_agreement: None,
                error: Some(format!("Failed to create agreement: {}", e)),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Co-sign an existing agreement.
    ///
    /// Adds this agent's cryptographic signature to the agreement. The agent's
    /// algorithm must satisfy any constraints specified when the agreement was created.
    #[tool(
        name = "jacs_sign_agreement",
        description = "Co-sign an existing agreement. Adds your agent's cryptographic signature. \
                       The agreement may have algorithm constraints that your agent must satisfy."
    )]
    pub async fn jacs_sign_agreement(
        &self,
        Parameters(params): Parameters<SignAgreementParams>,
    ) -> String {
        let result = match self.agent.sign_agreement(
            &params.signed_agreement,
            params.agreement_fieldname,
        ) {
            Ok(signed_string) => {
                // Count signatures
                let sig_count = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&signed_string) {
                    v.get("jacsAgreement")
                        .and_then(|a| a.get("signatures"))
                        .and_then(|s| s.as_array())
                        .map(|arr| arr.len())
                        .unwrap_or(0)
                } else {
                    0
                };

                SignAgreementResult {
                    success: true,
                    signed_agreement: Some(signed_string),
                    signature_count: Some(sig_count),
                    error: None,
                }
            }
            Err(e) => SignAgreementResult {
                success: false,
                signed_agreement: None,
                signature_count: None,
                error: Some(format!("Failed to sign agreement: {}", e)),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Check the status of an agreement.
    ///
    /// Returns whether quorum is met, which agents have signed, whether the
    /// agreement has expired, and how many more signatures are needed.
    #[tool(
        name = "jacs_check_agreement",
        description = "Check agreement status: who has signed, whether quorum is met, \
                       whether it has expired, and who still needs to sign."
    )]
    pub async fn jacs_check_agreement(
        &self,
        Parameters(params): Parameters<CheckAgreementParams>,
    ) -> String {
        // Parse the agreement to extract status without full verification
        let doc: serde_json::Value = match serde_json::from_str(&params.signed_agreement) {
            Ok(v) => v,
            Err(e) => {
                let result = CheckAgreementResult {
                    success: false,
                    complete: false,
                    total_agents: 0,
                    signatures_collected: 0,
                    signatures_required: 0,
                    quorum_met: false,
                    expired: false,
                    signed_by: None,
                    unsigned: None,
                    timeout: None,
                    error: Some(format!("Failed to parse agreement JSON: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let fieldname = params
            .agreement_fieldname
            .unwrap_or_else(|| "jacsAgreement".to_string());

        let agreement = match doc.get(&fieldname) {
            Some(a) => a,
            None => {
                let result = CheckAgreementResult {
                    success: false,
                    complete: false,
                    total_agents: 0,
                    signatures_collected: 0,
                    signatures_required: 0,
                    quorum_met: false,
                    expired: false,
                    signed_by: None,
                    unsigned: None,
                    timeout: None,
                    error: Some(format!("No '{}' field found in document", fieldname)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Extract agent IDs
        let agent_ids: Vec<String> = agreement
            .get("agentIDs")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        // Extract signatures
        let signatures = agreement
            .get("signatures")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let signed_by: Vec<String> = signatures
            .iter()
            .filter_map(|sig| sig.get("agentID").and_then(|v| v.as_str()).map(String::from))
            .collect();

        let signed_set: std::collections::HashSet<&str> =
            signed_by.iter().map(|s| s.as_str()).collect();
        let unsigned: Vec<String> = agent_ids
            .iter()
            .filter(|id| !signed_set.contains(id.as_str()))
            .cloned()
            .collect();

        // Quorum
        let quorum = agreement
            .get("quorum")
            .and_then(|v| v.as_u64())
            .map(|q| q as usize)
            .unwrap_or(agent_ids.len());
        let quorum_met = signed_by.len() >= quorum;

        // Timeout
        let timeout_str = agreement
            .get("timeout")
            .and_then(|v| v.as_str())
            .map(String::from);
        let expired = timeout_str
            .as_ref()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|deadline| chrono::Utc::now() > deadline)
            .unwrap_or(false);

        let complete = quorum_met && !expired;

        let result = CheckAgreementResult {
            success: true,
            complete,
            total_agents: agent_ids.len(),
            signatures_collected: signed_by.len(),
            signatures_required: quorum,
            quorum_met,
            expired,
            signed_by: Some(signed_by),
            unsigned: Some(unsigned),
            timeout: timeout_str,
            error: None,
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    // =========================================================================
    // Document Sign / Verify tools
    // =========================================================================

    /// Sign arbitrary JSON content to create a cryptographically signed JACS document.
    #[tool(
        name = "jacs_sign_document",
        description = "Sign arbitrary JSON content to create a signed JACS document for attestation."
    )]
    pub async fn jacs_sign_document(
        &self,
        Parameters(params): Parameters<SignDocumentParams>,
    ) -> String {
        // Validate content is valid JSON
        let content_value: serde_json::Value = match serde_json::from_str(&params.content) {
            Ok(v) => v,
            Err(e) => {
                let result = SignDocumentResult {
                    success: false,
                    signed_document: None,
                    content_hash: None,
                    jacs_document_id: None,
                    message: "Content is not valid JSON".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Wrap content in a JACS-compatible envelope if it doesn't already have jacsType
        let doc_to_sign = if content_value.get("jacsType").is_some() {
            params.content.clone()
        } else {
            let wrapper = serde_json::json!({
                "jacsType": "document",
                "jacsLevel": "raw",
                "content": content_value,
            });
            wrapper.to_string()
        };

        // Sign via create_document (no_save=true)
        match self
            .agent
            .create_document(&doc_to_sign, None, None, true, None, None)
        {
            Ok(signed_doc_string) => {
                // Extract document ID and compute content hash
                let doc_id = serde_json::from_str::<serde_json::Value>(&signed_doc_string)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from));

                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(signed_doc_string.as_bytes());
                    format!("{:x}", hasher.finalize())
                };

                let result = SignDocumentResult {
                    success: true,
                    signed_document: Some(signed_doc_string),
                    content_hash: Some(hash),
                    jacs_document_id: doc_id,
                    message: "Document signed successfully".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = SignDocumentResult {
                    success: false,
                    signed_document: None,
                    content_hash: None,
                    jacs_document_id: None,
                    message: "Failed to sign document".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Verify a signed JACS document given its full JSON string.
    #[tool(
        name = "jacs_verify_document",
        description = "Verify a signed JACS document's hash and cryptographic signature."
    )]
    pub async fn jacs_verify_document(
        &self,
        Parameters(params): Parameters<VerifyDocumentParams>,
    ) -> String {
        if params.document.is_empty() {
            let result = VerifyDocumentResult {
                success: false,
                valid: false,
                signer_id: None,
                message: "Document string is empty".to_string(),
                error: Some("EMPTY_DOCUMENT".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Try verify_signature first (works for both self-signed and external docs)
        match self.agent.verify_signature(&params.document, None) {
            Ok(valid) => {
                // Try to extract signer ID from the document
                let signer_id = serde_json::from_str::<serde_json::Value>(&params.document)
                    .ok()
                    .and_then(|v| {
                        v.get("jacsSignature")
                            .and_then(|sig| sig.get("agentId").or_else(|| sig.get("agentID")))
                            .and_then(|id| id.as_str())
                            .map(String::from)
                    });

                let result = VerifyDocumentResult {
                    success: true,
                    valid,
                    signer_id,
                    message: if valid {
                        "Document verified successfully".to_string()
                    } else {
                        "Document signature verification failed".to_string()
                    },
                    error: None,
                };
                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = VerifyDocumentResult {
                    success: false,
                    valid: false,
                    signer_id: None,
                    message: format!("Verification failed: {}", e),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }
}

// Implement the tool handler for the server
#[tool_handler(router = self.tool_router)]
impl ServerHandler for HaiMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "jacs-mcp".to_string(),
                title: Some("JACS MCP Server with HAI Integration".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                icons: None,
                website_url: Some("https://hai.ai".to_string()),
            },
            instructions: Some(
                "This MCP server provides data provenance and cryptographic signing for \
                 agent state files and agent-to-agent messaging, plus optional HAI.ai \
                 integration for key distribution and attestation. \
                 \
                 Agent state tools: jacs_sign_state (sign files), jacs_verify_state \
                 (verify integrity), jacs_load_state (load with verification), \
                 jacs_update_state (update and re-sign), jacs_list_state (list signed docs), \
                 jacs_adopt_state (adopt external files). \
                 \
                 Messaging tools: jacs_message_send (create and sign a message), \
                 jacs_message_update (update and re-sign a message), \
                 jacs_message_agree (co-sign/agree to a message), \
                 jacs_message_receive (verify and extract a received message). \
                 \
                 Agent management: jacs_create_agent (create new agent with keys), \
                 jacs_reencrypt_key (rotate private key password). \
                 \
                 Security: jacs_audit (read-only security audit and health checks). \
                 \
                 HAI tools: fetch_agent_key (get public keys), register_agent (register \
                 with HAI), verify_agent (check attestation 0-3), check_agent_status \
                 (registration info), unregister_agent (remove registration)."
                    .to_string(),
            ),
        }
    }
}

// =============================================================================
// Base64 Encoding Helper
// =============================================================================

fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding using the standard alphabet
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_agent_key_params_schema() {
        let schema = schemars::schema_for!(FetchAgentKeyParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("agent_id"));
        assert!(json.contains("version"));
    }

    #[test]
    fn test_register_agent_params_schema() {
        let schema = schemars::schema_for!(RegisterAgentParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("preview"));
    }

    #[test]
    fn test_verify_agent_params_schema() {
        let schema = schemars::schema_for!(VerifyAgentParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("agent_id"));
    }

    #[test]
    fn test_check_agent_status_params_schema() {
        let schema = schemars::schema_for!(CheckAgentStatusParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("agent_id"));
    }

    #[test]
    fn test_unregister_agent_params_schema() {
        let schema = schemars::schema_for!(UnregisterAgentParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("preview"));
    }

    #[test]
    fn test_tools_list() {
        let tools = HaiMcpServer::tools();
        assert_eq!(tools.len(), 23, "HaiMcpServer should expose 23 tools");

        let names: Vec<&str> = tools.iter().map(|t| &*t.name).collect();
        assert!(names.contains(&"fetch_agent_key"));
        assert!(names.contains(&"register_agent"));
        assert!(names.contains(&"verify_agent"));
        assert!(names.contains(&"check_agent_status"));
        assert!(names.contains(&"unregister_agent"));
        assert!(names.contains(&"jacs_sign_state"));
        assert!(names.contains(&"jacs_verify_state"));
        assert!(names.contains(&"jacs_load_state"));
        assert!(names.contains(&"jacs_update_state"));
        assert!(names.contains(&"jacs_list_state"));
        assert!(names.contains(&"jacs_adopt_state"));
        assert!(names.contains(&"jacs_create_agent"));
        assert!(names.contains(&"jacs_reencrypt_key"));
        assert!(names.contains(&"jacs_audit"));
        assert!(names.contains(&"jacs_message_send"));
        assert!(names.contains(&"jacs_message_update"));
        assert!(names.contains(&"jacs_message_agree"));
        assert!(names.contains(&"jacs_message_receive"));
        assert!(names.contains(&"jacs_create_agreement"));
        assert!(names.contains(&"jacs_sign_agreement"));
        assert!(names.contains(&"jacs_check_agreement"));
        assert!(names.contains(&"jacs_sign_document"));
        assert!(names.contains(&"jacs_verify_document"));
    }

    #[test]
    fn test_jacs_audit_returns_risks_and_health_checks() {
        let json = jacs_binding_core::audit(None, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("risks").is_some(),
            "jacs_audit response should have risks"
        );
        assert!(
            v.get("health_checks").is_some(),
            "jacs_audit response should have health_checks"
        );
    }

    #[test]
    fn test_sign_state_params_schema() {
        let schema = schemars::schema_for!(SignStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("state_type"));
        assert!(json.contains("name"));
        assert!(json.contains("embed"));
    }

    #[test]
    fn test_verify_state_params_schema() {
        let schema = schemars::schema_for!(VerifyStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("jacs_id"));
    }

    #[test]
    fn test_load_state_params_schema() {
        let schema = schemars::schema_for!(LoadStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("require_verified"));
    }

    #[test]
    fn test_update_state_params_schema() {
        let schema = schemars::schema_for!(UpdateStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("new_content"));
    }

    #[test]
    fn test_list_state_params_schema() {
        let schema = schemars::schema_for!(ListStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("state_type"));
        assert!(json.contains("framework"));
        assert!(json.contains("tags"));
    }

    #[test]
    fn test_adopt_state_params_schema() {
        let schema = schemars::schema_for!(AdoptStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("state_type"));
        assert!(json.contains("name"));
        assert!(json.contains("source_url"));
    }

    #[test]
    fn test_create_agent_params_schema() {
        let schema = schemars::schema_for!(CreateAgentProgrammaticParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("name"));
        assert!(json.contains("password"));
        assert!(json.contains("algorithm"));
        assert!(json.contains("data_directory"));
        assert!(json.contains("key_directory"));
    }

    #[test]
    fn test_reencrypt_key_params_schema() {
        let schema = schemars::schema_for!(ReencryptKeyParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("old_password"));
        assert!(json.contains("new_password"));
    }

    #[test]
    fn test_validate_agent_id_valid() {
        assert!(validate_agent_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_agent_id("123e4567-e89b-12d3-a456-426614174000").is_ok());
    }

    #[test]
    fn test_validate_agent_id_invalid() {
        assert!(validate_agent_id("").is_err());
        assert!(validate_agent_id("not-a-uuid").is_err());
        assert!(validate_agent_id("12345").is_err());
        assert!(validate_agent_id("550e8400-e29b-41d4-a716").is_err()); // Too short
    }

    #[test]
    fn test_is_registration_allowed_default() {
        // When env var is not set, should return false
        // SAFETY: This test runs in isolation and modifies test-specific env vars
        unsafe {
            std::env::remove_var("JACS_MCP_ALLOW_REGISTRATION");
        }
        assert!(!is_registration_allowed());
    }

    #[test]
    fn test_is_unregistration_allowed_default() {
        // When env var is not set, should return false
        // SAFETY: This test runs in isolation and modifies test-specific env vars
        unsafe {
            std::env::remove_var("JACS_MCP_ALLOW_UNREGISTRATION");
        }
        assert!(!is_unregistration_allowed());
    }

    #[test]
    fn test_message_send_params_schema() {
        let schema = schemars::schema_for!(MessageSendParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("recipient_agent_id"));
        assert!(json.contains("content"));
        assert!(json.contains("content_type"));
    }

    #[test]
    fn test_message_update_params_schema() {
        let schema = schemars::schema_for!(MessageUpdateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("jacs_id"));
        assert!(json.contains("content"));
        assert!(json.contains("content_type"));
    }

    #[test]
    fn test_message_agree_params_schema() {
        let schema = schemars::schema_for!(MessageAgreeParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_message"));
    }

    #[test]
    fn test_message_receive_params_schema() {
        let schema = schemars::schema_for!(MessageReceiveParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_message"));
    }

    #[test]
    fn test_format_iso8601() {
        // Unix epoch should produce 1970-01-01T00:00:00Z
        let epoch = std::time::UNIX_EPOCH;
        assert_eq!(format_iso8601(epoch), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_create_agreement_params_schema() {
        let schema = schemars::schema_for!(CreateAgreementParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("document"));
        assert!(json.contains("agent_ids"));
        assert!(json.contains("timeout"));
        assert!(json.contains("quorum"));
        assert!(json.contains("required_algorithms"));
        assert!(json.contains("minimum_strength"));
    }

    #[test]
    fn test_sign_agreement_params_schema() {
        let schema = schemars::schema_for!(SignAgreementParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_agreement"));
        assert!(json.contains("agreement_fieldname"));
    }

    #[test]
    fn test_check_agreement_params_schema() {
        let schema = schemars::schema_for!(CheckAgreementParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_agreement"));
    }

    #[test]
    fn test_tool_list_includes_agreement_tools() {
        // Verify the 3 new agreement tools are in the tool list
        let tools = HaiMcpServer::tools();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(names.contains(&"jacs_create_agreement"), "Missing jacs_create_agreement");
        assert!(names.contains(&"jacs_sign_agreement"), "Missing jacs_sign_agreement");
        assert!(names.contains(&"jacs_check_agreement"), "Missing jacs_check_agreement");
    }
}
