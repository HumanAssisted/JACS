//! Trust store tools: trust, untrust, list, check, get.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the trust store family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_trust_agent",
            "Add an agent to the local trust store. The agent's self-signature is \
             cryptographically verified before it is trusted. Pass the full agent JSON \
             document. Returns the trusted agent ID on success.",
            schema_map::<TrustAgentParams>(),
        ),
        Tool::new(
            "jacs_untrust_agent",
            "Remove an agent from the local trust store. \
             SECURITY: Requires JACS_MCP_ALLOW_UNTRUST=true environment variable to prevent \
             prompt injection attacks from removing trusted agents without user consent.",
            schema_map::<UntrustAgentParams>(),
        ),
        Tool::new(
            "jacs_list_trusted_agents",
            "List all agent IDs currently in the local trust store. Returns the count \
             and a list of trusted agent IDs.",
            schema_map::<ListTrustedAgentsParams>(),
        ),
        Tool::new(
            "jacs_is_trusted",
            "Check whether a specific agent is in the local trust store. Returns a boolean \
             indicating trust status.",
            schema_map::<IsTrustedParams>(),
        ),
        Tool::new(
            "jacs_get_trusted_agent",
            "Retrieve the full agent JSON document for a trusted agent from the local \
             trust store. Fails if the agent is not trusted.",
            schema_map::<GetTrustedAgentParams>(),
        ),
    ]
}
