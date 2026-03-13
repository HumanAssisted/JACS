//! Audit tools: security audit and audit trail (log, query, export).

use rmcp::model::Tool;

use super::schema_map;
pub use super::types::{
    AuditExportParams, AuditExportResult, AuditLogParams, AuditLogResult, AuditQueryEntry,
    AuditQueryParams, AuditQueryResult, JacsAuditParams,
};

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
