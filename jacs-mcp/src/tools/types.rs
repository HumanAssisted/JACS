//! Shared request/response types for tool families.
//!
//! Extracted from per-family modules to keep each tool module under 200 lines
//! (Issue 012 / TASK_038 acceptance criterion). Types are re-exported by their
//! respective family modules so downstream code is unaffected.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// =============================================================================
// Agreement Types (from agreements.rs)
// =============================================================================

/// Parameters for creating a multi-party agreement.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAgreementParams {
    #[schemars(
        description = "JSON document that all parties will agree to. Can be any valid JSON object."
    )]
    pub document: String,
    #[schemars(description = "List of agent IDs (UUIDs) that are parties to this agreement")]
    pub agent_ids: Vec<String>,
    #[schemars(description = "Question for signers, e.g. 'Do you approve deploying model v2?'")]
    pub question: Option<String>,
    #[schemars(description = "Additional context for signers")]
    pub context: Option<String>,
    #[schemars(
        description = "ISO 8601 deadline after which the agreement expires. Example: '2025-12-31T23:59:59Z'"
    )]
    pub timeout: Option<String>,
    #[schemars(
        description = "Minimum signatures required (M-of-N). If omitted, all agents must sign."
    )]
    pub quorum: Option<u32>,
    #[schemars(
        description = "Only allow these signing algorithms. Values: 'ring-Ed25519', 'pq2025'"
    )]
    pub required_algorithms: Option<Vec<String>>,
    #[schemars(description = "Minimum crypto strength: 'classical' or 'post-quantum'")]
    pub minimum_strength: Option<String>,
}

/// Result of creating an agreement.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAgreementResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_agreement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for signing an existing agreement.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignAgreementParams {
    #[schemars(
        description = "The full agreement JSON to sign. Obtained from jacs_create_agreement or from another agent."
    )]
    pub signed_agreement: String,
    #[schemars(description = "Custom agreement field name (default: 'jacsAgreement')")]
    pub agreement_fieldname: Option<String>,
}

/// Result of signing an agreement.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignAgreementResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_agreement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for checking agreement status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgreementParams {
    #[schemars(description = "The agreement JSON to check status of")]
    pub signed_agreement: String,
    #[schemars(description = "Custom agreement field name (default: 'jacsAgreement')")]
    pub agreement_fieldname: Option<String>,
}

/// Result of checking an agreement's status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgreementResult {
    pub success: bool,
    pub complete: bool,
    pub total_agents: usize,
    pub signatures_collected: usize,
    pub signatures_required: usize,
    pub quorum_met: bool,
    pub expired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
