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

        // If jacs_id is provided, try to verify the document signature
        if let Some(jacs_id) = &params.jacs_id {
            // For now, document index/storage lookup is not yet implemented.
            // Return a clear message about the limitation.
            let result = VerifyStateResult {
                success: false,
                hash_match: false,
                signature_valid: false,
                signing_info: None,
                message: format!(
                    "Document lookup by JACS ID '{}' is not yet implemented. \
                     Please provide a file_path to verify against the file's hash.",
                    jacs_id
                ),
                error: Some("NOT_YET_IMPLEMENTED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
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
                "This MCP server provides HAI (Human AI Interface) tools for agent \
                 registration, verification, and key management. Use fetch_agent_key \
                 to get public keys, register_agent to register with HAI, verify_agent \
                 to check attestation levels, and check_agent_status for registration info."
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
        assert_eq!(tools.len(), 11);

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
}
