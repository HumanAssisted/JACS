//! Audit tools: security audit.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::jacs_tools::JacsMcpServer;

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

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the audit family.
pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "jacs_audit",
        "Run a read-only JACS security audit and health checks. Returns a JSON report \
         with risks, health_checks, summary, and overall_status. Does not modify state. \
         Optional: config_path, recent_n (number of recent documents to re-verify).",
        schema_map::<JacsAuditParams>(),
    )]
}
