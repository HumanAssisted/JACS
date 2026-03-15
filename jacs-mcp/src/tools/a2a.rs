//! A2A interoperability tools: wrap artifact, verify artifact, assess agent.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request/Response Types
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
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the A2A family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_wrap_a2a_artifact",
            "Wrap an A2A artifact with JACS provenance. Signs the artifact JSON, binding \
             this agent's identity to the content. Optionally include parent signatures \
             for chain-of-custody provenance.",
            schema_map::<WrapA2aArtifactParams>(),
        ),
        Tool::new(
            "jacs_verify_a2a_artifact",
            "Verify a JACS-wrapped A2A artifact. Checks the cryptographic signature and \
             hash to confirm the artifact was signed by the claimed agent and has not \
             been tampered with.",
            schema_map::<VerifyA2aArtifactParams>(),
        ),
        Tool::new(
            "jacs_assess_a2a_agent",
            "Assess the trust level of a remote A2A agent given its Agent Card. Applies \
             a trust policy (open, verified, or strict) and returns whether the agent is \
             allowed and at what trust level.",
            schema_map::<AssessA2aAgentParams>(),
        ),
    ]
}
