//! JACS MCP tools for data provenance and cryptographic signing.
//!
//! This module provides MCP tools for agent state signing, verification,
//! messaging, agreements, A2A interoperability, and trust store management.

use jacs::schema::agentstate_crud;
use jacs::validation::require_relative_path_safe;
use jacs_binding_core::AgentWrapper;
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

/// Check if untrusting agents is allowed via environment variable.
/// Untrusting requires explicit opt-in to prevent prompt injection attacks
/// from removing trusted agents without user consent.
fn is_untrust_allowed() -> bool {
    std::env::var("JACS_MCP_ALLOW_UNTRUST")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

/// Build a stable storage lookup key (`jacsId:jacsVersion`) from a signed document.
fn extract_document_lookup_key(doc: &serde_json::Value) -> Option<String> {
    let id = doc
        .get("jacsId")
        .or_else(|| doc.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let version = doc
        .get("jacsVersion")
        .or_else(|| doc.get("version"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    match (id, version) {
        (Some(i), Some(v)) => Some(format!("{}:{}", i, v)),
        (Some(i), None) => Some(i.to_string()),
        _ => None,
    }
}

/// Parse a signed document JSON string and return its stable lookup key.
fn extract_document_lookup_key_from_str(document_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(document_json)
        .ok()
        .and_then(|v| extract_document_lookup_key(&v))
}

/// Pull embedded state content from a signed agent-state document.
fn extract_embedded_state_content(doc: &serde_json::Value) -> Option<String> {
    doc.get("jacsAgentStateContent")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            doc.get("jacsFiles")
                .and_then(|v| v.as_array())
                .and_then(|files| files.first())
                .and_then(|file| file.get("contents"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
}

/// Update embedded state content and keep per-file content hashes in sync.
fn update_embedded_state_content(doc: &mut serde_json::Value, new_content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(new_content.as_bytes());
    let new_hash = format!("{:x}", hasher.finalize());

    doc["jacsAgentStateContent"] = serde_json::json!(new_content);

    if let Some(files) = doc.get_mut("jacsFiles").and_then(|v| v.as_array_mut()) {
        for file in files {
            if let Some(obj) = file.as_object_mut() {
                obj.insert("embed".to_string(), serde_json::json!(true));
                obj.insert("contents".to_string(), serde_json::json!(new_content));
                obj.insert("sha256".to_string(), serde_json::json!(new_hash.clone()));
            }
        }
    }

    new_hash
}

fn value_string(doc: &serde_json::Value, field: &str) -> Option<String> {
    doc.get(field).and_then(|v| v.as_str()).map(str::to_string)
}

fn value_string_vec(doc: &serde_json::Value, field: &str) -> Option<Vec<String>> {
    doc.get(field).and_then(|v| v.as_array()).map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect::<Vec<_>>()
    })
}

/// Extract verification validity from `verify_a2a_artifact` details JSON.
/// Defaults to `false` on malformed/missing fields to avoid optimistic trust.
fn extract_verify_a2a_valid(details_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(details_json)
        .ok()
        .and_then(|v| v.get("valid").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

// =============================================================================
// Request/Response Types
// =============================================================================

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
// Trust Store Request/Response Types
// =============================================================================

/// Parameters for adding an agent to the local trust store.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TrustAgentParams {
    /// The full agent JSON document to trust.
    #[schemars(description = "The full JACS agent JSON document to add to the trust store")]
    pub agent_json: String,
}

/// Result of trusting an agent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TrustAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The trusted agent's ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for removing an agent from the trust store.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UntrustAgentParams {
    /// The agent ID (UUID) to remove from the trust store.
    #[schemars(description = "The JACS agent ID (UUID format) to remove from the trust store")]
    pub agent_id: String,
}

/// Result of untrusting an agent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UntrustAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent ID that was removed.
    pub agent_id: String,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for listing trusted agents (no parameters required).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListTrustedAgentsParams {}

/// Result of listing trusted agents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListTrustedAgentsResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// List of trusted agent IDs.
    pub agent_ids: Vec<String>,

    /// Number of trusted agents.
    pub count: usize,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for checking if an agent is trusted.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IsTrustedParams {
    /// The agent ID (UUID) to check.
    #[schemars(description = "The JACS agent ID (UUID format) to check trust status for")]
    pub agent_id: String,
}

/// Result of checking trust status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IsTrustedResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent ID that was checked.
    pub agent_id: String,

    /// Whether the agent is in the trust store.
    pub trusted: bool,

    /// Human-readable status message.
    pub message: String,
}

/// Parameters for getting a trusted agent's details.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetTrustedAgentParams {
    /// The agent ID (UUID) to retrieve from the trust store.
    #[schemars(description = "The JACS agent ID (UUID format) to retrieve from the trust store")]
    pub agent_id: String,
}

/// Result of getting a trusted agent's details.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetTrustedAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent ID.
    pub agent_id: String,

    /// The full agent JSON document from the trust store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_json: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// A2A Artifact Wrapping/Verification Request/Response Types
// =============================================================================

/// Parameters for wrapping an A2A artifact with JACS provenance.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WrapA2aArtifactParams {
    /// The artifact JSON content to wrap and sign.
    #[schemars(description = "The A2A artifact JSON content to wrap with JACS provenance")]
    pub artifact_json: String,

    /// The artifact type identifier (e.g., "a2a-artifact", "message", "task-result").
    #[schemars(
        description = "Artifact type identifier (e.g., 'a2a-artifact', 'message', 'task-result')"
    )]
    pub artifact_type: String,

    /// Optional parent signatures JSON array for chain-of-custody.
    #[schemars(
        description = "Optional JSON array of parent signatures for chain-of-custody provenance"
    )]
    pub parent_signatures: Option<String>,
}

/// Result of wrapping an A2A artifact.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WrapA2aArtifactResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The wrapped artifact as a JSON string with JACS provenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_artifact: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for verifying a JACS-wrapped A2A artifact.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyA2aArtifactParams {
    /// The wrapped artifact JSON to verify.
    #[schemars(description = "The JACS-wrapped A2A artifact JSON to verify")]
    pub wrapped_artifact: String,
}

/// Result of verifying a wrapped A2A artifact.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyA2aArtifactResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// Whether the artifact's signature and hash are valid.
    pub valid: bool,

    /// The verification result details as JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_details: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for assessing trust level of a remote A2A agent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AssessA2aAgentParams {
    /// The Agent Card JSON of the remote agent to assess.
    #[schemars(description = "The A2A Agent Card JSON of the remote agent to assess")]
    pub agent_card_json: String,

    /// Trust policy to apply: "open", "verified", or "strict".
    #[schemars(
        description = "Trust policy: 'open' (accept all), 'verified' (require JACS), or 'strict' (require trust store)"
    )]
    pub policy: Option<String>,
}

/// Result of assessing an A2A agent's trust level.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AssessA2aAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// Whether the agent is allowed under the specified policy.
    pub allowed: bool,

    /// The trust level: "Untrusted", "JacsVerified", or "ExplicitlyTrusted".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,

    /// The policy that was applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,

    /// Reason for the assessment result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the assessment failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Agent Card & Well-Known Request/Response Types
// =============================================================================

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
    #[schemars(description = "List of agent IDs (UUIDs) that are parties to this agreement")]
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
    /// Values: "RSA-PSS", "ring-Ed25519", "pq2025"
    #[schemars(
        description = "Only allow these signing algorithms. Values: 'RSA-PSS', 'ring-Ed25519', 'pq2025'"
    )]
    pub required_algorithms: Option<Vec<String>>,

    /// Minimum cryptographic strength: "classical" (any algorithm) or "post-quantum" (pq2025 only).
    #[schemars(description = "Minimum crypto strength: 'classical' or 'post-quantum'")]
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
    #[schemars(description = "The agreement JSON to check status of")]
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
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
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
// Attestation Request/Response Types (feature-gated)
// =============================================================================

/// Parameters for creating an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestCreateParams {
    /// JSON string with subject, claims, and optional evidence/derivation/policyContext.
    #[schemars(
        description = "JSON string containing attestation parameters: { subject: { type, id, digests }, claims: [{ name, value, confidence?, assuranceLevel? }], evidence?: [...], derivation?: {...}, policyContext?: {...} }"
    )]
    pub params_json: String,
}

/// Parameters for verifying an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestVerifyParams {
    /// The document key in "jacsId:jacsVersion" format.
    #[schemars(description = "Document key in 'jacsId:jacsVersion' format")]
    pub document_key: String,

    /// Whether to perform full verification (including evidence and chain).
    #[serde(default)]
    #[schemars(description = "Set to true for full-tier verification (evidence + chain checks)")]
    pub full: bool,
}

/// Parameters for exporting an attestation as a DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestExportDsseParams {
    /// The signed attestation document JSON string.
    #[schemars(description = "JSON string of the signed attestation document to export as DSSE")]
    pub attestation_json: String,
}

/// Parameters for lifting a signed document to an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestLiftParams {
    /// The signed document JSON string.
    #[schemars(description = "JSON string of the existing signed JACS document to lift")]
    pub signed_doc_json: String,

    /// Claims JSON string (array of claim objects).
    #[schemars(
        description = "JSON array of claim objects: [{ name, value, confidence?, assuranceLevel? }]"
    )]
    pub claims_json: String,
}

// =============================================================================
// MCP Server
// =============================================================================

/// JACS MCP Server providing tools for data provenance, cryptographic signing,
/// messaging, agreements, A2A interoperability, and trust store management.
#[derive(Clone)]
#[allow(dead_code)]
pub struct JacsMcpServer {
    /// The local agent identity.
    agent: Arc<AgentWrapper>,
    /// Tool router for MCP tool dispatch.
    tool_router: ToolRouter<Self>,
    /// Whether agent creation is allowed (from JACS_MCP_ALLOW_REGISTRATION env var).
    registration_allowed: bool,
    /// Whether untrusting agents is allowed (from JACS_MCP_ALLOW_UNTRUST env var).
    untrust_allowed: bool,
}

#[allow(dead_code)]
impl JacsMcpServer {
    /// Create a new JACS MCP server with the given agent.
    ///
    /// # Arguments
    ///
    /// * `agent` - The local JACS agent wrapper
    ///
    /// # Environment Variables
    ///
    /// * `JACS_MCP_ALLOW_REGISTRATION` - Set to "true" to enable the jacs_create_agent tool
    /// * `JACS_MCP_ALLOW_UNTRUST` - Set to "true" to enable the jacs_untrust_agent tool
    pub fn new(agent: AgentWrapper) -> Self {
        let registration_allowed = is_registration_allowed();
        let untrust_allowed = is_untrust_allowed();

        if registration_allowed {
            tracing::info!("Agent creation is ENABLED (JACS_MCP_ALLOW_REGISTRATION=true)");
        } else {
            tracing::info!(
                "Agent creation is DISABLED. Set JACS_MCP_ALLOW_REGISTRATION=true to enable."
            );
        }

        Self {
            agent: Arc::new(agent),
            tool_router: Self::tool_router(),
            registration_allowed,
            untrust_allowed,
        }
    }

    /// Get the list of available tools for LLM discovery.
    pub fn tools() -> Vec<Tool> {
        vec![
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
            // --- A2A artifact tools ---
            Tool::new(
                "jacs_wrap_a2a_artifact",
                "Wrap an A2A artifact with JACS provenance. Signs the artifact JSON, binding \
                 this agent's identity to the content. Optionally include parent signatures \
                 for chain-of-custody provenance.",
                Self::jacs_wrap_a2a_artifact_schema(),
            ),
            Tool::new(
                "jacs_verify_a2a_artifact",
                "Verify a JACS-wrapped A2A artifact. Checks the cryptographic signature and \
                 hash to confirm the artifact was signed by the claimed agent and has not \
                 been tampered with.",
                Self::jacs_verify_a2a_artifact_schema(),
            ),
            Tool::new(
                "jacs_assess_a2a_agent",
                "Assess the trust level of a remote A2A agent given its Agent Card. Applies \
                 a trust policy (open, verified, or strict) and returns whether the agent is \
                 allowed and at what trust level.",
                Self::jacs_assess_a2a_agent_schema(),
            ),
            // --- Agent Card & well-known tools ---
            Tool::new(
                "jacs_export_agent_card",
                "Export this agent's A2A Agent Card as JSON. The Agent Card describes the \
                 agent's capabilities, endpoints, and identity for A2A discovery.",
                Self::jacs_export_agent_card_schema(),
            ),
            Tool::new(
                "jacs_generate_well_known",
                "Generate all .well-known documents for A2A discovery. Returns an array of \
                 {path, document} objects that can be served at each path for agent discovery.",
                Self::jacs_generate_well_known_schema(),
            ),
            Tool::new(
                "jacs_export_agent",
                "Export the local agent's full JACS JSON document. This includes the agent's \
                 identity, public key hash, and signed metadata.",
                Self::jacs_export_agent_schema(),
            ),
            // --- Trust store tools ---
            Tool::new(
                "jacs_trust_agent",
                "Add an agent to the local trust store. The agent's self-signature is \
                 cryptographically verified before it is trusted. Pass the full agent JSON \
                 document. Returns the trusted agent ID on success.",
                Self::jacs_trust_agent_schema(),
            ),
            Tool::new(
                "jacs_untrust_agent",
                "Remove an agent from the local trust store. \
                 SECURITY: Requires JACS_MCP_ALLOW_UNTRUST=true environment variable to prevent \
                 prompt injection attacks from removing trusted agents without user consent.",
                Self::jacs_untrust_agent_schema(),
            ),
            Tool::new(
                "jacs_list_trusted_agents",
                "List all agent IDs currently in the local trust store. Returns the count \
                 and a list of trusted agent IDs.",
                Self::jacs_list_trusted_agents_schema(),
            ),
            Tool::new(
                "jacs_is_trusted",
                "Check whether a specific agent is in the local trust store. Returns a boolean \
                 indicating trust status.",
                Self::jacs_is_trusted_schema(),
            ),
            Tool::new(
                "jacs_get_trusted_agent",
                "Retrieve the full agent JSON document for a trusted agent from the local \
                 trust store. Fails if the agent is not trusted.",
                Self::jacs_get_trusted_agent_schema(),
            ),
            // --- Attestation tools ---
            Tool::new(
                "jacs_attest_create",
                "Create a signed attestation document. Provide a JSON string with: subject \
                 (type, id, digests), claims (name, value, confidence, assuranceLevel), and \
                 optional evidence, derivation, and policyContext. Requires the attestation \
                 feature.",
                Self::jacs_attest_create_schema(),
            ),
            Tool::new(
                "jacs_attest_verify",
                "Verify an attestation document. Provide a document_key in 'jacsId:jacsVersion' \
                 format. Set full=true for full-tier verification including evidence and \
                 derivation chain checks. Requires the attestation feature.",
                Self::jacs_attest_verify_schema(),
            ),
            Tool::new(
                "jacs_attest_lift",
                "Lift an existing signed JACS document into an attestation. Provide the signed \
                 document JSON and a JSON array of claims to attach. Requires the attestation \
                 feature.",
                Self::jacs_attest_lift_schema(),
            ),
            Tool::new(
                "jacs_attest_export_dsse",
                "Export an attestation as a DSSE envelope for in-toto/SLSA compatibility. \
                 Provide the signed attestation document JSON. Returns a DSSE envelope with \
                 payloadType, payload, and signatures. Requires the attestation feature.",
                Self::jacs_attest_export_dsse_schema(),
            ),
        ]
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

    fn jacs_wrap_a2a_artifact_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(WrapA2aArtifactParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_verify_a2a_artifact_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(VerifyA2aArtifactParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_assess_a2a_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(AssessA2aAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_export_agent_card_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(ExportAgentCardParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_generate_well_known_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(GenerateWellKnownParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_export_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(ExportAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_trust_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(TrustAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_untrust_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(UntrustAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_list_trusted_agents_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(ListTrustedAgentsParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_is_trusted_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(IsTrustedParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_get_trusted_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(GetTrustedAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_attest_create_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(AttestCreateParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_attest_verify_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(AttestVerifyParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_attest_lift_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(AttestLiftParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn jacs_attest_export_dsse_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(AttestExportDsseParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }
}

// Implement the tool router for the server
#[tool_router]
impl JacsMcpServer {
    /// Sign an agent state file to create a cryptographically signed JACS document.
    ///
    /// Reads the file, creates an agent state document with metadata, and signs it
    /// using the local agent's keys. For hooks, content is always embedded.
    #[tool(
        name = "jacs_sign_state",
        description = "Sign an agent state file (memory/skill/plan/config/hook) to create a signed JACS document."
    )]
    pub async fn jacs_sign_state(&self, Parameters(params): Parameters<SignStateParams>) -> String {
        // Security: Validate file_path to prevent path traversal attacks via prompt injection.
        if let Err(e) = require_relative_path_safe(&params.file_path) {
            let result = SignStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Path validation failed".to_string(),
                error: Some(format!("PATH_TRAVERSAL_BLOCKED: {}", e)),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Always embed state content for MCP-originated state documents so follow-up
        // reads/updates can operate purely on JACS documents without direct file I/O.
        let embed = params.embed.unwrap_or(true);

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

        // Sign and persist through JACS document storage so subsequent MCP calls can
        // reference only the JACS document ID (no sidecar/path coupling).
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
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&SignStateResult {
                            success: false,
                            jacs_document_id: None,
                            state_type: params.state_type,
                            name: params.name,
                            message: "Failed to determine the signed document ID".to_string(),
                            error: Some("DOCUMENT_ID_MISSING".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&SignStateResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        state_type: params.state_type,
                        name: params.name,
                        message: "Failed to persist signed state document".to_string(),
                        error: Some(e.to_string()),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

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
        // MCP policy: verification must resolve through JACS documents, not direct file paths.
        if params.jacs_id.is_none() && params.file_path.is_none() {
            let result = VerifyStateResult {
                success: false,
                hash_match: false,
                signature_valid: false,
                signing_info: None,
                message: "Missing state reference. Provide jacs_id (uuid:version).".to_string(),
                error: Some("MISSING_PARAMETER".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if params.jacs_id.is_none() {
            let result = VerifyStateResult {
                success: false,
                hash_match: false,
                signature_valid: false,
                signing_info: None,
                message: "file_path-based verification is disabled in MCP. Use jacs_id."
                    .to_string(),
                error: Some("FILESYSTEM_ACCESS_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let jacs_id = params.jacs_id.as_deref().unwrap_or_default();
        let doc_string = match self.agent.get_document_by_id(jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = VerifyStateResult {
                    success: false,
                    hash_match: false,
                    signature_valid: false,
                    signing_info: None,
                    message: format!("Failed to load document '{}'", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        match self.agent.verify_document(&doc_string) {
            Ok(valid) => {
                let signing_info = serde_json::from_str::<serde_json::Value>(&doc_string)
                    .ok()
                    .and_then(|doc| doc.get("jacsSignature").cloned())
                    .map(|sig| sig.to_string());

                let result = VerifyStateResult {
                    success: true,
                    hash_match: valid,
                    signature_valid: valid,
                    signing_info,
                    message: if valid {
                        format!("Document '{}' verified successfully", jacs_id)
                    } else {
                        format!("Document '{}' signature verification failed", jacs_id)
                    },
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
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
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Load a signed agent state document and optionally verify it.
    ///
    /// Returns the content of the state along with verification status.
    #[tool(
        name = "jacs_load_state",
        description = "Load a signed agent state document, optionally verifying before returning content."
    )]
    pub async fn jacs_load_state(&self, Parameters(params): Parameters<LoadStateParams>) -> String {
        if params.file_path.is_some() && params.jacs_id.is_none() {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: None,
                message: "file_path-based loading is disabled in MCP. Use jacs_id.".to_string(),
                error: Some("FILESYSTEM_ACCESS_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if params.jacs_id.is_none() {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: None,
                message: "Missing state reference. Provide jacs_id (uuid:version).".to_string(),
                error: Some("MISSING_PARAMETER".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let require_verified = params.require_verified.unwrap_or(true);
        let jacs_id = params.jacs_id.as_deref().unwrap_or_default();
        let mut warnings = Vec::new();
        let mut verified = false;

        let doc_string = match self.agent.get_document_by_id(jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = LoadStateResult {
                    success: false,
                    content: None,
                    verified,
                    warnings: if warnings.is_empty() {
                        None
                    } else {
                        Some(warnings)
                    },
                    message: format!("Failed to load state document '{}'", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        if require_verified {
            match self.agent.verify_document(&doc_string) {
                Ok(true) => {
                    verified = true;
                }
                Ok(false) => {
                    warnings.push("Document signature verification failed.".to_string());
                }
                Err(e) => {
                    warnings.push(format!("Could not verify document signature: {}", e));
                }
            }
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
                message: "Verification required but the state document could not be verified."
                    .to_string(),
                error: Some("VERIFICATION_FAILED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
            Ok(v) => v,
            Err(e) => {
                let result = LoadStateResult {
                    success: false,
                    content: None,
                    verified,
                    warnings: if warnings.is_empty() {
                        None
                    } else {
                        Some(warnings)
                    },
                    message: format!("State document '{}' is not valid JSON", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let content = extract_embedded_state_content(&doc);
        if content.is_none() {
            warnings.push(
                "State document does not contain embedded content. Re-sign with embed=true."
                    .to_string(),
            );
        }

        let result = LoadStateResult {
            success: true,
            content,
            verified,
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
            message: if require_verified && verified {
                format!("Successfully loaded and verified '{}'", jacs_id)
            } else {
                format!("Loaded '{}' from JACS storage", jacs_id)
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
        description = "Update a previously signed agent state document by jacs_id with new embedded content and re-sign."
    )]
    pub async fn jacs_update_state(
        &self,
        Parameters(params): Parameters<UpdateStateParams>,
    ) -> String {
        let jacs_id = match params.jacs_id.as_deref() {
            Some(id) => id,
            None => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: "file_path-based updates are disabled in MCP. Provide jacs_id."
                        .to_string(),
                    error: Some("FILESYSTEM_ACCESS_DISABLED".to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let existing_doc_string = match self.agent.get_document_by_id(jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: format!("Failed to load state document '{}'", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut doc = match serde_json::from_str::<serde_json::Value>(&existing_doc_string) {
            Ok(v) => v,
            Err(e) => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: format!("State document '{}' is not valid JSON", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let new_hash = params
            .new_content
            .as_deref()
            .map(|content| update_embedded_state_content(&mut doc, content));

        let updated_doc_string =
            match self
                .agent
                .update_document(jacs_id, &doc.to_string(), None, None)
            {
                Ok(doc) => doc,
                Err(e) => {
                    let result = UpdateStateResult {
                        success: false,
                        jacs_document_version_id: None,
                        new_hash,
                        message: format!("Failed to update and re-sign '{}'", jacs_id),
                        error: Some(e.to_string()),
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
            };

        let version_id = serde_json::from_str::<serde_json::Value>(&updated_doc_string)
            .ok()
            .and_then(|v| extract_document_lookup_key(&v))
            .unwrap_or_else(|| "unknown".to_string());

        let result = UpdateStateResult {
            success: true,
            jacs_document_version_id: Some(version_id),
            new_hash,
            message: format!("Successfully updated and re-signed '{}'", jacs_id),
            error: None,
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// List signed agent state documents.
    #[tool(
        name = "jacs_list_state",
        description = "List signed agent state documents, with optional filtering."
    )]
    pub async fn jacs_list_state(&self, Parameters(params): Parameters<ListStateParams>) -> String {
        let keys = match self.agent.list_document_keys() {
            Ok(keys) => keys,
            Err(e) => {
                let result = ListStateResult {
                    success: false,
                    documents: Vec::new(),
                    message: "Failed to enumerate stored documents".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut matched = Vec::new();

        for key in keys {
            let doc_string = match self.agent.get_document_by_id(&key) {
                Ok(doc) => doc,
                Err(_) => continue,
            };
            let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
                Ok(doc) => doc,
                Err(_) => continue,
            };

            if doc.get("jacsType").and_then(|v| v.as_str()) != Some("agentstate") {
                continue;
            }

            let state_type = value_string(&doc, "jacsAgentStateType").unwrap_or_default();
            if let Some(filter) = params.state_type.as_deref()
                && state_type != filter
            {
                continue;
            }

            let framework = value_string(&doc, "jacsAgentStateFramework");
            if let Some(filter) = params.framework.as_deref()
                && framework.as_deref() != Some(filter)
            {
                continue;
            }

            let tags = value_string_vec(&doc, "jacsAgentStateTags");
            if let Some(filter_tags) = params.tags.as_ref() {
                let doc_tags = tags.clone().unwrap_or_default();
                if !filter_tags
                    .iter()
                    .all(|tag| doc_tags.iter().any(|item| item == tag))
                {
                    continue;
                }
            }

            let name = value_string(&doc, "jacsAgentStateName").unwrap_or_else(|| key.clone());
            let version_date = value_string(&doc, "jacsVersionDate").unwrap_or_default();

            matched.push((
                version_date,
                key.clone(),
                StateListEntry {
                    jacs_document_id: key,
                    state_type,
                    name,
                    framework,
                    tags: tags.filter(|items| !items.is_empty()),
                },
            ));
        }

        matched.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let result = ListStateResult {
            success: true,
            documents: matched.into_iter().map(|(_, _, entry)| entry).collect(),
            message: match params.state_type.as_deref() {
                Some(filter) => format!("Listed agent state documents (state_type='{}').", filter),
                None => "Listed agent state documents.".to_string(),
            },
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
        // Security: Validate file_path to prevent path traversal attacks via prompt injection.
        if let Err(e) = require_relative_path_safe(&params.file_path) {
            let result = AdoptStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Path validation failed".to_string(),
                error: Some(format!("PATH_TRAVERSAL_BLOCKED: {}", e)),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Create the agent state document with file reference
        let mut doc = match agentstate_crud::create_agentstate_with_file(
            &params.state_type,
            &params.name,
            &params.file_path,
            true, // embed for MCP document-centric reads/updates
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
            Some(true),
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&AdoptStateResult {
                            success: false,
                            jacs_document_id: None,
                            state_type: params.state_type,
                            name: params.name,
                            message: "Failed to determine the adopted document ID".to_string(),
                            error: Some("DOCUMENT_ID_MISSING".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&AdoptStateResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        state_type: params.state_type,
                        name: params.name,
                        message: "Failed to persist adopted state document".to_string(),
                        error: Some(e.to_string()),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

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

        let sender_id = match self.agent.get_agent_id() {
            Ok(agent_id) => agent_id,
            Err(e) => {
                let result = MessageSendResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!("Failed to determine sender agent ID: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let content_type = params
            .content_type
            .unwrap_or_else(|| "text/plain".to_string());
        let message_id = Uuid::new_v4().to_string();
        let timestamp = format_iso8601(std::time::SystemTime::now());

        // Build the message document
        let message_doc = serde_json::json!({
            "jacsType": "message",
            "jacsLevel": "artifact",
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
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            None, // embed
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&MessageSendResult {
                            success: false,
                            jacs_document_id: None,
                            signed_message: Some(signed_doc_string),
                            error: Some("Failed to determine the signed message ID".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&MessageSendResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        signed_message: Some(signed_doc_string),
                        error: Some(format!("Failed to persist signed message: {}", e)),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

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
        match self.agent.verify_document_by_id(&params.jacs_id) {
            Ok(true) => {}
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

        let existing_doc_string = match self.agent.get_document_by_id(&params.jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Failed to load document '{}' for update: {}",
                        params.jacs_id, e
                    )),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut updated_doc = match serde_json::from_str::<serde_json::Value>(&existing_doc_string)
        {
            Ok(doc) => doc,
            Err(e) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Stored document '{}' is not valid JSON: {}",
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

        updated_doc["jacsType"] = serde_json::json!("message");
        updated_doc["jacsLevel"] = serde_json::json!("artifact");
        updated_doc["jacsMessageContent"] = serde_json::json!(params.content);
        updated_doc["jacsMessageContentType"] = serde_json::json!(content_type);
        updated_doc["jacsMessageTimestamp"] = serde_json::json!(timestamp);

        let doc_string = updated_doc.to_string();
        let result = match self
            .agent
            .update_document(&params.jacs_id, &doc_string, None, None)
        {
            Ok(updated_doc_string) => {
                let doc_id = extract_document_lookup_key_from_str(&updated_doc_string)
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
                    error: Some("Original message signature verification failed".to_string()),
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
        let original_doc_id = extract_document_lookup_key_from_str(&params.signed_message)
            .unwrap_or_else(|| "unknown".to_string());

        let our_agent_id = self
            .agent
            .get_agent_id()
            .unwrap_or_else(|_| "unknown".to_string());

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
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            None, // embed
        ) {
            Ok(signed_agreement_string) => {
                let agreement_id = extract_document_lookup_key_from_str(&signed_agreement_string)
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
                Some(
                    "Message signature is INVALID — content may have been tampered with"
                        .to_string(),
                )
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
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            None, // embed
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
                let agreement_id = extract_document_lookup_key_from_str(&agreement_string)
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
        let result = match self
            .agent
            .sign_agreement(&params.signed_agreement, params.agreement_fieldname)
        {
            Ok(signed_string) => {
                // Count signatures
                let sig_count =
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&signed_string) {
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
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Extract signatures
        let signatures = agreement
            .get("signatures")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let signed_by: Vec<String> = signatures
            .iter()
            .filter_map(|sig| {
                sig.get("agentID")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
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
                let doc_id = extract_document_lookup_key_from_str(&signed_doc_string);

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
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
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
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
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
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = VerifyDocumentResult {
                    success: false,
                    valid: false,
                    signer_id: None,
                    message: format!("Verification failed: {}", e),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // A2A Artifact Wrapping/Verification Tools
    // =========================================================================

    /// Wrap an A2A artifact with JACS provenance signature.
    #[tool(
        name = "jacs_wrap_a2a_artifact",
        description = "Wrap an A2A artifact with JACS provenance signature."
    )]
    pub async fn jacs_wrap_a2a_artifact(
        &self,
        Parameters(params): Parameters<WrapA2aArtifactParams>,
    ) -> String {
        if params.artifact_json.is_empty() {
            let result = WrapA2aArtifactResult {
                success: false,
                wrapped_artifact: None,
                message: "Artifact JSON is empty".to_string(),
                error: Some("EMPTY_ARTIFACT".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        #[allow(deprecated)]
        match self.agent.wrap_a2a_artifact(
            &params.artifact_json,
            &params.artifact_type,
            params.parent_signatures.as_deref(),
        ) {
            Ok(wrapped_json) => {
                let result = WrapA2aArtifactResult {
                    success: true,
                    wrapped_artifact: Some(wrapped_json),
                    message: "Artifact wrapped with JACS provenance".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = WrapA2aArtifactResult {
                    success: false,
                    wrapped_artifact: None,
                    message: "Failed to wrap artifact".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Verify a JACS-wrapped A2A artifact.
    #[tool(
        name = "jacs_verify_a2a_artifact",
        description = "Verify a JACS-wrapped A2A artifact's signature and hash."
    )]
    pub async fn jacs_verify_a2a_artifact(
        &self,
        Parameters(params): Parameters<VerifyA2aArtifactParams>,
    ) -> String {
        if params.wrapped_artifact.is_empty() {
            let result = VerifyA2aArtifactResult {
                success: false,
                valid: false,
                verification_details: None,
                message: "Wrapped artifact JSON is empty".to_string(),
                error: Some("EMPTY_ARTIFACT".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match self.agent.verify_a2a_artifact(&params.wrapped_artifact) {
            Ok(details_json) => {
                let valid = extract_verify_a2a_valid(&details_json);
                let result = VerifyA2aArtifactResult {
                    success: true,
                    valid,
                    verification_details: Some(details_json),
                    message: if valid {
                        "Artifact verified successfully".to_string()
                    } else {
                        "Artifact verification found issues".to_string()
                    },
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = VerifyA2aArtifactResult {
                    success: false,
                    valid: false,
                    verification_details: None,
                    message: "Artifact verification failed".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Assess the trust level of a remote A2A agent.
    #[tool(
        name = "jacs_assess_a2a_agent",
        description = "Assess trust level of a remote A2A agent given its Agent Card."
    )]
    pub async fn jacs_assess_a2a_agent(
        &self,
        Parameters(params): Parameters<AssessA2aAgentParams>,
    ) -> String {
        if params.agent_card_json.is_empty() {
            let result = AssessA2aAgentResult {
                success: false,
                allowed: false,
                trust_level: None,
                policy: None,
                reason: None,
                message: "Agent Card JSON is empty".to_string(),
                error: Some("EMPTY_AGENT_CARD".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let policy_str = params.policy.as_deref().unwrap_or("verified");

        match self
            .agent
            .assess_a2a_agent(&params.agent_card_json, policy_str)
        {
            Ok(assessment_json) => {
                // Parse the assessment to extract fields for our result type
                let assessment: serde_json::Value =
                    serde_json::from_str(&assessment_json).unwrap_or_default();
                let allowed = assessment
                    .get("allowed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let trust_level = assessment
                    .get("trust_level")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let policy = assessment
                    .get("policy")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let reason = assessment
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let result = AssessA2aAgentResult {
                    success: true,
                    allowed,
                    trust_level,
                    policy,
                    reason: reason.clone(),
                    message: reason.unwrap_or_else(|| "Assessment complete".to_string()),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = AssessA2aAgentResult {
                    success: false,
                    allowed: false,
                    trust_level: None,
                    policy: Some(policy_str.to_string()),
                    reason: None,
                    message: "Trust assessment failed".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // Agent Card & Well-Known Tools
    // =========================================================================

    /// Export this agent's A2A Agent Card.
    #[tool(
        name = "jacs_export_agent_card",
        description = "Export this agent's A2A Agent Card as JSON for discovery."
    )]
    pub async fn jacs_export_agent_card(
        &self,
        Parameters(_params): Parameters<ExportAgentCardParams>,
    ) -> String {
        match self.agent.export_agent_card() {
            Ok(card_json) => {
                let result = ExportAgentCardResult {
                    success: true,
                    agent_card: Some(card_json),
                    message: "Agent Card exported successfully".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = ExportAgentCardResult {
                    success: false,
                    agent_card: None,
                    message: "Failed to export Agent Card".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Generate all .well-known documents for A2A discovery.
    #[tool(
        name = "jacs_generate_well_known",
        description = "Generate .well-known documents for A2A agent discovery."
    )]
    pub async fn jacs_generate_well_known(
        &self,
        Parameters(params): Parameters<GenerateWellKnownParams>,
    ) -> String {
        match self
            .agent
            .generate_well_known_documents(params.a2a_algorithm.as_deref())
        {
            Ok(docs_json) => {
                // Parse to count documents
                let count = serde_json::from_str::<Vec<serde_json::Value>>(&docs_json)
                    .map(|v| v.len())
                    .unwrap_or(0);
                let result = GenerateWellKnownResult {
                    success: true,
                    documents: Some(docs_json),
                    count,
                    message: format!("{} well-known document(s) generated", count),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = GenerateWellKnownResult {
                    success: false,
                    documents: None,
                    count: 0,
                    message: "Failed to generate well-known documents".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Export the local agent's full JACS JSON document.
    #[tool(
        name = "jacs_export_agent",
        description = "Export the local agent's full JACS JSON document."
    )]
    pub async fn jacs_export_agent(
        &self,
        Parameters(_params): Parameters<ExportAgentParams>,
    ) -> String {
        match self.agent.get_agent_json() {
            Ok(agent_json) => {
                // Try to extract the agent ID from the JSON
                let agent_id = serde_json::from_str::<serde_json::Value>(&agent_json)
                    .ok()
                    .and_then(|v| v.get("jacsId").and_then(|id| id.as_str()).map(String::from));
                let result = ExportAgentResult {
                    success: true,
                    agent_json: Some(agent_json),
                    agent_id,
                    message: "Agent document exported successfully".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = ExportAgentResult {
                    success: false,
                    agent_json: None,
                    agent_id: None,
                    message: "Failed to export agent document".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // Trust Store Tools
    // =========================================================================

    /// Add an agent to the local trust store.
    ///
    /// The agent's self-signature is cryptographically verified before it is
    /// added. If verification fails, the agent is NOT trusted.
    #[tool(
        name = "jacs_trust_agent",
        description = "Add an agent to the local trust store after verifying its self-signature."
    )]
    pub async fn jacs_trust_agent(
        &self,
        Parameters(params): Parameters<TrustAgentParams>,
    ) -> String {
        if params.agent_json.is_empty() {
            let result = TrustAgentResult {
                success: false,
                agent_id: None,
                message: "Agent JSON is empty".to_string(),
                error: Some("EMPTY_AGENT_JSON".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match jacs_binding_core::trust_agent(&params.agent_json) {
            Ok(agent_id) => {
                let result = TrustAgentResult {
                    success: true,
                    agent_id: Some(agent_id.clone()),
                    message: format!("Agent {} added to trust store", agent_id),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = TrustAgentResult {
                    success: false,
                    agent_id: None,
                    message: "Failed to trust agent".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Remove an agent from the local trust store.
    ///
    /// # Security
    ///
    /// Untrusting requires `JACS_MCP_ALLOW_UNTRUST=true` environment variable.
    /// This prevents prompt injection attacks from removing trusted agents
    /// without user consent.
    #[tool(
        name = "jacs_untrust_agent",
        description = "Remove an agent from the local trust store. Requires JACS_MCP_ALLOW_UNTRUST=true."
    )]
    pub async fn jacs_untrust_agent(
        &self,
        Parameters(params): Parameters<UntrustAgentParams>,
    ) -> String {
        // Security check: Untrusting must be explicitly enabled
        if !self.untrust_allowed {
            let result = UntrustAgentResult {
                success: false,
                agent_id: params.agent_id.clone(),
                message: "Untrusting is disabled for security. \
                          To enable, set JACS_MCP_ALLOW_UNTRUST=true environment variable \
                          when starting the MCP server."
                    .to_string(),
                error: Some("UNTRUST_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if params.agent_id.is_empty() {
            let result = UntrustAgentResult {
                success: false,
                agent_id: params.agent_id.clone(),
                message: "Agent ID is empty".to_string(),
                error: Some("EMPTY_AGENT_ID".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match jacs_binding_core::untrust_agent(&params.agent_id) {
            Ok(()) => {
                let result = UntrustAgentResult {
                    success: true,
                    agent_id: params.agent_id.clone(),
                    message: format!("Agent {} removed from trust store", params.agent_id),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = UntrustAgentResult {
                    success: false,
                    agent_id: params.agent_id.clone(),
                    message: "Failed to untrust agent".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// List all trusted agent IDs in the local trust store.
    #[tool(
        name = "jacs_list_trusted_agents",
        description = "List all agent IDs in the local trust store."
    )]
    pub async fn jacs_list_trusted_agents(
        &self,
        Parameters(_params): Parameters<ListTrustedAgentsParams>,
    ) -> String {
        match jacs_binding_core::list_trusted_agents() {
            Ok(agent_ids) => {
                let count = agent_ids.len();
                let result = ListTrustedAgentsResult {
                    success: true,
                    agent_ids,
                    count,
                    message: format!("{} trusted agent(s) found", count),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = ListTrustedAgentsResult {
                    success: false,
                    agent_ids: vec![],
                    count: 0,
                    message: "Failed to list trusted agents".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Check whether a specific agent is in the local trust store.
    #[tool(
        name = "jacs_is_trusted",
        description = "Check whether a specific agent is in the local trust store."
    )]
    pub async fn jacs_is_trusted(&self, Parameters(params): Parameters<IsTrustedParams>) -> String {
        if params.agent_id.is_empty() {
            let result = IsTrustedResult {
                success: false,
                agent_id: params.agent_id.clone(),
                trusted: false,
                message: "Agent ID is empty".to_string(),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let trusted = jacs_binding_core::is_trusted(&params.agent_id);
        let result = IsTrustedResult {
            success: true,
            agent_id: params.agent_id.clone(),
            trusted,
            message: if trusted {
                format!("Agent {} is trusted", params.agent_id)
            } else {
                format!("Agent {} is NOT trusted", params.agent_id)
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Retrieve the full agent JSON document for a trusted agent.
    #[tool(
        name = "jacs_get_trusted_agent",
        description = "Retrieve the full agent JSON for a trusted agent from the local trust store."
    )]
    pub async fn jacs_get_trusted_agent(
        &self,
        Parameters(params): Parameters<GetTrustedAgentParams>,
    ) -> String {
        if params.agent_id.is_empty() {
            let result = GetTrustedAgentResult {
                success: false,
                agent_id: params.agent_id.clone(),
                agent_json: None,
                message: "Agent ID is empty".to_string(),
                error: Some("EMPTY_AGENT_ID".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match jacs_binding_core::get_trusted_agent(&params.agent_id) {
            Ok(agent_json) => {
                let result = GetTrustedAgentResult {
                    success: true,
                    agent_id: params.agent_id.clone(),
                    agent_json: Some(agent_json),
                    message: format!("Retrieved trusted agent {}", params.agent_id),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = GetTrustedAgentResult {
                    success: false,
                    agent_id: params.agent_id.clone(),
                    agent_json: None,
                    message: "Failed to get trusted agent".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // Attestation Tools (requires `attestation` feature)
    // =========================================================================

    /// Create a signed attestation document with subject, claims, and optional evidence.
    ///
    /// Requires the binary to be built with the `attestation` feature.
    #[tool(
        name = "jacs_attest_create",
        description = "Create a signed attestation document. Provide a JSON string with: subject (type, id, digests), claims (name, value, confidence, assuranceLevel), and optional evidence, derivation, and policyContext."
    )]
    pub async fn jacs_attest_create(
        &self,
        Parameters(params): Parameters<AttestCreateParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            match self.agent.create_attestation(&params.params_json) {
                Ok(result) => result,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "message": format!("Failed to create attestation: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }

    /// Verify an attestation document's cryptographic validity and optionally check evidence.
    ///
    /// Local tier: checks signature + hash only (fast).
    /// Full tier (full=true): also checks evidence digests, freshness, and derivation chain.
    #[tool(
        name = "jacs_attest_verify",
        description = "Verify an attestation document. Provide a document_key in 'jacsId:jacsVersion' format. Set full=true for evidence and chain verification."
    )]
    pub async fn jacs_attest_verify(
        &self,
        Parameters(params): Parameters<AttestVerifyParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            let result = if params.full {
                self.agent.verify_attestation_full(&params.document_key)
            } else {
                self.agent.verify_attestation(&params.document_key)
            };

            match result {
                Ok(json) => json,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "valid": false,
                        "message": format!("Failed to verify attestation: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "valid": false,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }

    /// Lift an existing signed document into an attestation with additional claims.
    ///
    /// Takes a signed JACS document and wraps it in an attestation that references
    /// the original document as its subject.
    #[tool(
        name = "jacs_attest_lift",
        description = "Lift an existing signed JACS document into an attestation. Provide the signed document JSON and a JSON array of claims."
    )]
    pub async fn jacs_attest_lift(
        &self,
        Parameters(params): Parameters<AttestLiftParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            match self
                .agent
                .lift_to_attestation(&params.signed_doc_json, &params.claims_json)
            {
                Ok(result) => result,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "message": format!("Failed to lift to attestation: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }
    /// Export a signed attestation as a DSSE (Dead Simple Signing Envelope) for
    /// in-toto/SLSA compatibility.
    #[tool(
        name = "jacs_attest_export_dsse",
        description = "Export an attestation as a DSSE envelope for in-toto/SLSA compatibility."
    )]
    pub async fn jacs_attest_export_dsse(
        &self,
        Parameters(params): Parameters<AttestExportDsseParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            match self.agent.export_attestation_dsse(&params.attestation_json) {
                Ok(result) => result,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "message": format!("Failed to export DSSE envelope: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }
}

// Implement the tool handler for the server
#[tool_handler(router = self.tool_router)]
impl ServerHandler for JacsMcpServer {
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
                title: Some("JACS MCP Server".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                icons: None,
                website_url: Some("https://humanassisted.github.io/JACS/".to_string()),
            },
            instructions: Some(
                "This MCP server provides data provenance and cryptographic signing for \
                 agent state files and agent-to-agent messaging. \
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
                 A2A artifacts: jacs_wrap_a2a_artifact (sign artifact with provenance), \
                 jacs_verify_a2a_artifact (verify wrapped artifact), \
                 jacs_assess_a2a_agent (assess remote agent trust level). \
                 \
                 A2A discovery: jacs_export_agent_card (export Agent Card), \
                 jacs_generate_well_known (generate .well-known documents), \
                 jacs_export_agent (export full agent JSON). \
                 \
                 Trust store: jacs_trust_agent (add agent to trust store), \
                 jacs_untrust_agent (remove from trust store, requires JACS_MCP_ALLOW_UNTRUST=true), \
                 jacs_list_trusted_agents (list all trusted agent IDs), \
                 jacs_is_trusted (check if agent is trusted), \
                 jacs_get_trusted_agent (get trusted agent JSON). \
                 \
                 Attestation: jacs_attest_create (create signed attestation with claims), \
                 jacs_attest_verify (verify attestation, optionally with evidence checks), \
                 jacs_attest_lift (lift signed document into attestation), \
                 jacs_attest_export_dsse (export attestation as DSSE envelope). \
                 \
                 Security: jacs_audit (read-only security audit and health checks)."
                    .to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tools_list() {
        let tools = JacsMcpServer::tools();
        assert_eq!(tools.len(), 33, "JacsMcpServer should expose 33 tools");

        let names: Vec<&str> = tools.iter().map(|t| &*t.name).collect();
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
        // A2A artifact tools
        assert!(names.contains(&"jacs_wrap_a2a_artifact"));
        assert!(names.contains(&"jacs_verify_a2a_artifact"));
        assert!(names.contains(&"jacs_assess_a2a_agent"));
        // Agent Card & well-known tools
        assert!(names.contains(&"jacs_export_agent_card"));
        assert!(names.contains(&"jacs_generate_well_known"));
        assert!(names.contains(&"jacs_export_agent"));
        // Trust store tools
        assert!(names.contains(&"jacs_trust_agent"));
        assert!(names.contains(&"jacs_untrust_agent"));
        assert!(names.contains(&"jacs_list_trusted_agents"));
        assert!(names.contains(&"jacs_is_trusted"));
        assert!(names.contains(&"jacs_get_trusted_agent"));
        // Attestation tools
        assert!(names.contains(&"jacs_attest_create"));
        assert!(names.contains(&"jacs_attest_verify"));
        assert!(names.contains(&"jacs_attest_lift"));
        assert!(names.contains(&"jacs_attest_export_dsse"));
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
        assert!(json.contains("jacs_id"));
        assert!(json.contains("new_content"));
    }

    fn make_test_server() -> JacsMcpServer {
        JacsMcpServer::new(AgentWrapper::new())
    }

    #[test]
    fn test_verify_state_rejects_file_path_only() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_verify_state(Parameters(VerifyStateParams {
            file_path: Some("state.json".to_string()),
            jacs_id: None,
        })));
        assert!(response.contains("FILESYSTEM_ACCESS_DISABLED"));
        assert!(response.contains("file_path-based verification is disabled"));
    }

    #[test]
    fn test_load_state_rejects_file_path_only() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_load_state(Parameters(LoadStateParams {
            file_path: Some("state.json".to_string()),
            jacs_id: None,
            require_verified: Some(true),
        })));
        assert!(response.contains("FILESYSTEM_ACCESS_DISABLED"));
        assert!(response.contains("file_path-based loading is disabled"));
    }

    #[test]
    fn test_update_state_requires_jacs_id() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_update_state(Parameters(UpdateStateParams {
            file_path: "state.json".to_string(),
            jacs_id: None,
            new_content: Some("{\"k\":\"v\"}".to_string()),
        })));
        assert!(response.contains("FILESYSTEM_ACCESS_DISABLED"));
        assert!(response.contains("file_path-based updates are disabled"));
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
    fn test_extract_verify_a2a_valid_true() {
        assert!(extract_verify_a2a_valid(r#"{"valid":true}"#));
    }

    #[test]
    fn test_extract_verify_a2a_valid_missing_defaults_false() {
        assert!(!extract_verify_a2a_valid(r#"{"status":"ok"}"#));
    }

    #[test]
    fn test_extract_verify_a2a_valid_invalid_json_defaults_false() {
        assert!(!extract_verify_a2a_valid("not-json"));
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
        let tools = JacsMcpServer::tools();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            names.contains(&"jacs_create_agreement"),
            "Missing jacs_create_agreement"
        );
        assert!(
            names.contains(&"jacs_sign_agreement"),
            "Missing jacs_sign_agreement"
        );
        assert!(
            names.contains(&"jacs_check_agreement"),
            "Missing jacs_check_agreement"
        );
    }

    // =========================================================================
    // Security: Path traversal prevention in sign_state / adopt_state
    // =========================================================================

    #[test]
    fn test_sign_state_rejects_absolute_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "/etc/passwd".to_string(),
            state_type: "memory".to_string(),
            name: "traversal-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
        assert!(
            response.contains("\"success\": false"),
            "Expected success: false in: {}",
            response
        );
    }

    #[test]
    fn test_sign_state_rejects_parent_traversal() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "data/../../../etc/shadow".to_string(),
            state_type: "hook".to_string(),
            name: "traversal-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: Some(true),
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
    }

    #[test]
    fn test_sign_state_rejects_windows_drive_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
            state_type: "config".to_string(),
            name: "traversal-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
    }

    #[test]
    fn test_adopt_state_rejects_absolute_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_adopt_state(Parameters(AdoptStateParams {
            file_path: "/etc/shadow".to_string(),
            state_type: "skill".to_string(),
            name: "traversal-test".to_string(),
            source_url: None,
            description: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
        assert!(
            response.contains("\"success\": false"),
            "Expected success: false in: {}",
            response
        );
    }

    #[test]
    fn test_adopt_state_rejects_parent_traversal() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_adopt_state(Parameters(AdoptStateParams {
            file_path: "skills/../../etc/passwd".to_string(),
            state_type: "skill".to_string(),
            name: "traversal-test".to_string(),
            source_url: Some("https://example.com".to_string()),
            description: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
    }

    #[test]
    fn test_sign_state_allows_safe_relative_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        // This should NOT be blocked by path validation (it will fail later
        // because the file doesn't exist, but NOT with PATH_TRAVERSAL_BLOCKED)
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "data/my-state.json".to_string(),
            state_type: "memory".to_string(),
            name: "safe-path-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: None,
        })));
        assert!(
            !response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Safe relative path should not be blocked: {}",
            response
        );
    }
}
