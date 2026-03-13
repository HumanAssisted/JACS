//! Shared request/response types for tool families.
//!
//! Extracted from per-family modules to keep each tool module under 200 lines
//! (Issue 012 / TASK_038 acceptance criterion). Types are re-exported by their
//! respective family modules so downstream code is unaffected.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// =============================================================================
// State Types (from state.rs)
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
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,
    pub state_type: String,
    pub name: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for verifying an agent state file or document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyStateParams {
    #[schemars(
        description = "DEPRECATED for MCP security: direct file-path verification is disabled. Use jacs_id."
    )]
    pub file_path: Option<String>,
    #[schemars(description = "JACS document ID to verify (uuid:version)")]
    pub jacs_id: Option<String>,
}

/// Result of verifying an agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyStateResult {
    pub success: bool,
    pub hash_match: bool,
    pub signature_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_info: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for loading a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadStateParams {
    #[schemars(
        description = "DEPRECATED for MCP security: direct file-path loading is disabled. Use jacs_id."
    )]
    pub file_path: Option<String>,
    #[schemars(description = "JACS document ID to load (uuid:version)")]
    pub jacs_id: Option<String>,
    #[schemars(description = "Whether to require verification before loading (default true)")]
    pub require_verified: Option<bool>,
}

/// Result of loading a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadStateResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for updating a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpdateStateParams {
    #[schemars(
        description = "DEPRECATED for MCP security: direct file-path updates are disabled. Use jacs_id."
    )]
    pub file_path: String,
    #[schemars(description = "JACS document ID to update (uuid:version)")]
    pub jacs_id: Option<String>,
    #[schemars(
        description = "New embedded content for the JACS state document. If omitted, re-signs current embedded content."
    )]
    pub new_content: Option<String>,
}

/// Result of updating a signed agent state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpdateStateResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_hash: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for listing signed agent state documents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListStateParams {
    #[schemars(description = "Filter by state type: memory, skill, plan, config, or hook")]
    pub state_type: Option<String>,
    #[schemars(description = "Filter by framework identifier")]
    pub framework: Option<String>,
    #[schemars(description = "Filter by tags (documents must have all specified tags)")]
    pub tags: Option<Vec<String>>,
}

/// A summary entry for a signed agent state document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StateListEntry {
    pub jacs_document_id: String,
    pub state_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Result of listing signed agent state documents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListStateResult {
    pub success: bool,
    pub documents: Vec<StateListEntry>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for adopting an external agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AdoptStateParams {
    #[schemars(description = "Path to the file to adopt and sign as agent state")]
    pub file_path: String,
    #[schemars(description = "Type of agent state: memory, skill, plan, config, or hook")]
    pub state_type: String,
    #[schemars(description = "Human-readable name for this adopted state document")]
    pub name: String,
    #[schemars(description = "Optional URL where the content was originally obtained")]
    pub source_url: Option<String>,
    #[schemars(description = "Optional description of what this adopted state document contains")]
    pub description: Option<String>,
}

/// Result of adopting an external agent state file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AdoptStateResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,
    pub state_type: String,
    pub name: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Memory Types (from memory.rs)
// =============================================================================

/// Parameters for saving a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemorySaveParams {
    #[schemars(description = "Human-readable name for this memory")]
    pub name: String,
    #[schemars(description = "Memory content to save (text, JSON, markdown, etc.)")]
    pub content: String,
    #[schemars(description = "Optional description of what this memory contains")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[schemars(description = "Optional tags for categorization and filtering")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[schemars(description = "Optional framework identifier (e.g., 'claude-code', 'openai')")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Result of saving a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemorySaveResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,
    pub name: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for recalling (searching) memories.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryRecallParams {
    #[schemars(
        description = "Search query to match against memory name, content, and description"
    )]
    pub query: String,
    #[schemars(description = "Optional tag filter (memories must have all specified tags)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[schemars(description = "Maximum number of results to return (default: 10)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Result of recalling memories.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryRecallResult {
    pub success: bool,
    pub memories: Vec<MemoryEntry>,
    pub total: usize,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A single memory entry returned by recall or list operations.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryEntry {
    pub jacs_document_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Parameters for listing memories with optional filtering.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryListParams {
    #[schemars(description = "Optional tag filter (memories must have all specified tags)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[schemars(description = "Optional framework filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[schemars(description = "Maximum number of results to return (default: 20)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

/// Result of listing memories.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryListResult {
    pub success: bool,
    pub memories: Vec<MemoryEntry>,
    pub total: usize,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for forgetting (soft-deleting) a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryForgetParams {
    #[schemars(description = "JACS document ID of the memory to forget (uuid:version)")]
    pub jacs_id: String,
}

/// Result of forgetting a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryForgetResult {
    pub success: bool,
    pub jacs_document_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for updating an existing memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryUpdateParams {
    #[schemars(description = "JACS document ID of the memory to update (uuid:version)")]
    pub jacs_id: String,
    #[schemars(description = "New content for the memory (replaces existing content)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[schemars(description = "New name for the memory (replaces existing name)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[schemars(description = "New tags for the memory (replaces all existing tags)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Result of updating a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryUpdateResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Audit Types (from audit.rs)
// =============================================================================

/// Parameters for the JACS security audit tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JacsAuditParams {
    #[schemars(description = "Optional path to jacs.config.json")]
    pub config_path: Option<String>,
    #[schemars(description = "Number of recent documents to re-verify (default from config)")]
    pub recent_n: Option<u32>,
}

/// Parameters for recording an audit trail event.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditLogParams {
    #[schemars(
        description = "Action type for this audit entry (e.g., 'tool_use', 'data_access', 'sign', 'verify')"
    )]
    pub action: String,
    #[schemars(
        description = "What was acted upon (e.g., a JACS document ID or resource identifier)"
    )]
    pub target: Option<String>,
    #[schemars(description = "Additional JSON-formatted details about the event")]
    pub details: Option<String>,
    #[schemars(description = "Optional tags for categorizing this audit entry")]
    pub tags: Option<Vec<String>>,
}

/// Result of recording an audit trail event.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditLogResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,
    pub action: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for querying the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryParams {
    #[schemars(description = "Filter by action type (e.g., 'tool_use', 'data_access')")]
    pub action: Option<String>,
    #[schemars(description = "Filter by target resource identifier")]
    pub target: Option<String>,
    #[schemars(
        description = "ISO 8601 start time for the query range (e.g., '2025-01-01T00:00:00Z')"
    )]
    pub start_time: Option<String>,
    #[schemars(
        description = "ISO 8601 end time for the query range (e.g., '2025-12-31T23:59:59Z')"
    )]
    pub end_time: Option<String>,
    #[schemars(description = "Maximum number of results to return (default: 50)")]
    pub limit: Option<u32>,
    #[schemars(description = "Pagination offset (default: 0)")]
    pub offset: Option<u32>,
}

/// A single audit trail entry from a query.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryEntry {
    pub jacs_document_id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Result of querying the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryResult {
    pub success: bool,
    pub entries: Vec<AuditQueryEntry>,
    pub total: usize,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for exporting the audit trail as a signed bundle.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditExportParams {
    #[schemars(description = "ISO 8601 start time for the export range (required)")]
    pub start_time: String,
    #[schemars(description = "ISO 8601 end time for the export range (required)")]
    pub end_time: String,
    #[schemars(description = "Optional filter by action type")]
    pub action: Option<String>,
}

/// Result of exporting the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditExportResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_bundle: Option<String>,
    pub entry_count: usize,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

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
        description = "Only allow these signing algorithms. Values: 'RSA-PSS', 'ring-Ed25519', 'pq2025'"
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
