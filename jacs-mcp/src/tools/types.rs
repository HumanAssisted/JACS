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

// =============================================================================
// Agreement v2 Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAgreementV2Params {
    #[schemars(
        description = "CreateAgreementV2 input object (camelCase keys). Fields: `title` (string), \
            `description` (string), `terms` (the agreement text the parties consent to), \
            `parties` (array of {agentId, agentType, role} where role is one of \"signer\", \
            \"witness\", \"notary\"), `signaturePolicy` (e.g. {\"quorum\": 2, \"requiredRoles\": \
            [\"signer\"]}), and optional `controllers`/`owners` (arrays of agent IDs). Returns a \
            signed `jacsType: \"agreement\"` document. Example: {\"title\":\"Deploy approval\", \
            \"terms\":\"Approve deploying model v2\",\"parties\":[{\"agentId\":\"<uuid>\", \
            \"agentType\":\"ai\",\"role\":\"signer\"}],\"signaturePolicy\":{\"quorum\":1}}."
    )]
    pub input: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApplyAgreementV2Params {
    #[schemars(
        description = "The full agreement v2 document JSON (the artifact returned by create or a \
            prior apply) that this mutation is applied to. Pass the document as a JSON string."
    )]
    pub agreement: String,
    #[schemars(
        description = "A typed AgreementV2Mutation object (camelCase keys). The `type` selects the \
            mutation and other fields are camelCase. Supported: \
            {\"type\":\"appendTranscript\",\"entry\":{\"jacsId\":\"...\",\"jacsVersion\":\"...\", \
            \"jacsSha256\":\"...\"}}, {\"type\":\"updateTerms\",\"terms\":\"...\"}, \
            {\"type\":\"setStatus\",\"status\":\"proposed\"}, {\"type\":\"addLink\",\"link\": \
            {\"jacsId\":\"...\",\"jacsVersion\":\"...\"}}, plus setParties/setPolicy/setOwners. \
            Emits a successor version."
    )]
    pub mutation: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignAgreementV2Params {
    #[schemars(
        description = "The full agreement v2 document JSON to add this agent's signature to. \
            Pass the document as a JSON string."
    )]
    pub agreement: String,
    #[schemars(
        description = "Signature role this agent signs as. One of: \"signer\" (a consenting \
            party), \"witness\" (attests it observed the signing), or \"notary\" (an authority \
            that certifies the agreement). Defaults to \"signer\"."
    )]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyAgreementV2Params {
    #[schemars(
        description = "The full agreement v2 document JSON to verify. The verifier recomputes the \
            agreement and transcript hashes, checks quorum/role/witness/notary requirements, and \
            validates each agreement signature. Read the top-level `valid` field of the result \
            (NOT `success`) to decide whether to trust the agreement."
    )]
    pub agreement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DetectAgreementV2BranchConflictParams {
    #[schemars(
        description = "The common-ancestor agreement v2 document JSON that both branches derive from."
    )]
    pub base: String,
    #[schemars(description = "One successor agreement v2 document JSON branched from `base`.")]
    pub left: String,
    #[schemars(
        description = "The other successor agreement v2 document JSON branched from `base`. The \
            result reports whether the two branches are transcript-only (auto-mergeable) or \
            conflict on consent-scope fields (terms, parties, policy, status, signatures)."
    )]
    pub right: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MergeAgreementV2TranscriptBranchesParams {
    #[schemars(
        description = "The common-ancestor agreement v2 document JSON both branches derive from."
    )]
    pub base: String,
    #[schemars(
        description = "One transcript-only successor agreement v2 document JSON branched from `base`."
    )]
    pub left: String,
    #[schemars(
        description = "The other transcript-only successor agreement v2 document JSON branched from \
            `base`. Both branches must differ from base only in appended transcript entries; \
            otherwise use detect-conflict then resolve-conflict. Emits a merged successor version."
    )]
    pub right: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResolveAgreementV2BranchConflictParams {
    #[schemars(
        description = "The common-ancestor agreement v2 document JSON both branches derive from."
    )]
    pub base: String,
    #[schemars(
        description = "The branch you are keeping and rebasing the resolution onto (agreement v2 \
            document JSON)."
    )]
    pub previous: String,
    #[schemars(
        description = "The divergent branch whose changes are being reconciled (agreement v2 \
            document JSON). It is recorded as a link on the resolved successor version."
    )]
    pub side_branch: String,
    #[schemars(
        description = "A typed AgreementV2Mutation object (camelCase keys, same shape as \
            jacs_apply_agreement_v2) that produces the agreed resolution, e.g. \
            {\"type\":\"updateTerms\",\"terms\":\"reconciled terms\"}."
    )]
    pub mutation: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AgreementV2DocumentResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AgreementV2ValueResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result envelope for `jacs_verify_agreement_v2`.
///
/// `success` means the verify operation EXECUTED (input parsed, verification ran).
/// `valid` is the cryptographic/structural verdict and is the authoritative
/// answer to "should this agreement be trusted". A caller must never read
/// `success: true` and assume the agreement is good — `valid` carries that.
/// On an execution/parse failure, `success` is false and `valid` is false.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyAgreementV2Result {
    pub success: bool,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
