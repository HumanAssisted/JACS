//! Agreement tools: create, sign, check multi-party agreements.

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

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the agreements family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_create_agreement",
            "Create a multi-party cryptographic agreement. Use this when multiple agents need \
             to formally agree on something — like approving a deployment, authorizing a data \
             transfer, or ratifying a decision. You specify which agents must sign, an optional \
             quorum (e.g., 2-of-3), a timeout deadline, and algorithm constraints. Returns a \
             signed agreement document to pass to other agents for co-signing.",
            schema_map::<CreateAgreementParams>(),
        ),
        Tool::new(
            "jacs_sign_agreement",
            "Co-sign an existing agreement. Use this after receiving an agreement document from \
             another agent. Your cryptographic signature is added to the agreement. The updated \
             document can then be passed to the next signer or checked for completion.",
            schema_map::<SignAgreementParams>(),
        ),
        Tool::new(
            "jacs_check_agreement",
            "Check the status of an agreement: how many agents have signed, whether quorum is \
             met, whether it has expired, and which agents still need to sign. Use this to \
             decide whether an agreement is complete and ready to act on.",
            schema_map::<CheckAgreementParams>(),
        ),
    ]
}
