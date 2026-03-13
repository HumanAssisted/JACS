//! Audit tools: security audit and audit trail (log, query, export).

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request/Response Types
// =============================================================================

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

// ---------------------------------------------------------------------------
// Audit Trail: Log
// ---------------------------------------------------------------------------

/// Parameters for recording an audit trail event.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditLogParams {
    /// Action type (e.g., "tool_use", "data_access", "sign", "verify").
    #[schemars(
        description = "Action type for this audit entry (e.g., 'tool_use', 'data_access', 'sign', 'verify')"
    )]
    pub action: String,

    /// What was acted upon (e.g., document ID, file path).
    #[schemars(
        description = "What was acted upon (e.g., a JACS document ID or resource identifier)"
    )]
    pub target: Option<String>,

    /// Additional JSON details about the event.
    #[schemars(description = "Additional JSON-formatted details about the event")]
    pub details: Option<String>,

    /// Optional tags for categorization.
    #[schemars(description = "Optional tags for categorizing this audit entry")]
    pub tags: Option<Vec<String>>,
}

/// Result of recording an audit trail event.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditLogResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the audit entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The action that was recorded.
    pub action: String,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Audit Trail: Query
// ---------------------------------------------------------------------------

/// Parameters for querying the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryParams {
    /// Filter by action type.
    #[schemars(description = "Filter by action type (e.g., 'tool_use', 'data_access')")]
    pub action: Option<String>,

    /// Filter by target.
    #[schemars(description = "Filter by target resource identifier")]
    pub target: Option<String>,

    /// ISO 8601 start time.
    #[schemars(
        description = "ISO 8601 start time for the query range (e.g., '2025-01-01T00:00:00Z')"
    )]
    pub start_time: Option<String>,

    /// ISO 8601 end time.
    #[schemars(
        description = "ISO 8601 end time for the query range (e.g., '2025-12-31T23:59:59Z')"
    )]
    pub end_time: Option<String>,

    /// Max results (default: 50).
    #[schemars(description = "Maximum number of results to return (default: 50)")]
    pub limit: Option<u32>,

    /// Pagination offset.
    #[schemars(description = "Pagination offset (default: 0)")]
    pub offset: Option<u32>,
}

/// A single audit trail entry from a query.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryEntry {
    /// The JACS document ID.
    pub jacs_document_id: String,

    /// The action type.
    pub action: String,

    /// The target resource, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// When the event was recorded.
    pub timestamp: String,

    /// Additional details, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Result of querying the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The matching audit entries.
    pub entries: Vec<AuditQueryEntry>,

    /// Total number of matches (before pagination).
    pub total: usize,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Audit Trail: Export
// ---------------------------------------------------------------------------

/// Parameters for exporting the audit trail as a signed bundle.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditExportParams {
    /// ISO 8601 start time (required).
    #[schemars(description = "ISO 8601 start time for the export range (required)")]
    pub start_time: String,

    /// ISO 8601 end time (required).
    #[schemars(description = "ISO 8601 end time for the export range (required)")]
    pub end_time: String,

    /// Optional filter by action type.
    #[schemars(description = "Optional filter by action type")]
    pub action: Option<String>,
}

/// Result of exporting the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditExportResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The signed JACS document containing audit data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_bundle: Option<String>,

    /// Number of audit entries in the export.
    pub entry_count: usize,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the audit family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_audit",
            "Run a read-only JACS security audit and health checks. Returns a JSON report \
             with risks, health_checks, summary, and overall_status. Does not modify state. \
             Optional: config_path, recent_n (number of recent documents to re-verify).",
            schema_map::<JacsAuditParams>(),
        ),
        Tool::new(
            "jacs_audit_log",
            "Record a tool-use, data-access, or other event as a cryptographically signed \
             audit trail entry. The entry is stored as a private agentstate document with \
             type 'hook'. Use this to maintain a tamper-evident log of agent actions.",
            schema_map::<AuditLogParams>(),
        ),
        Tool::new(
            "jacs_audit_query",
            "Search the audit trail by action type, target, and/or time range. Returns \
             matching audit entries from the signed audit log. Supports pagination.",
            schema_map::<AuditQueryParams>(),
        ),
        Tool::new(
            "jacs_audit_export",
            "Export audit trail entries for a time period as a single signed JACS document. \
             The exported bundle contains all matching audit entries and can be verified \
             independently.",
            schema_map::<AuditExportParams>(),
        ),
    ]
}
