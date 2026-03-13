//! Per-family tool modules for jacs-mcp.
//!
//! Each module contains the request/response types, schema helpers, and
//! tool definitions for one tool family. The `all_tools()` function
//! combines tools from every family into a single `Vec<Tool>`.

pub mod a2a;
pub mod agreements;
pub mod attestation;
pub mod audit;
pub mod document;
pub mod key;
pub mod memory;
pub mod messaging;
pub mod search;
pub mod state;
pub mod trust;
pub mod types;

// Re-export all types so callers can use `tools::SignStateParams` etc.
// Types from state, memory, audit, and agreements are in types.rs.
// Other family modules define their types inline and are re-exported here.
#[allow(ambiguous_glob_reexports)]
pub use a2a::*;
#[allow(ambiguous_glob_reexports)]
pub use attestation::*;
#[allow(ambiguous_glob_reexports)]
pub use document::*;
#[allow(ambiguous_glob_reexports)]
pub use key::*;
#[allow(ambiguous_glob_reexports)]
pub use messaging::*;
#[allow(ambiguous_glob_reexports)]
pub use search::*;
#[allow(ambiguous_glob_reexports)]
pub use trust::*;
#[allow(ambiguous_glob_reexports)]
pub use types::*;

use rmcp::model::Tool;
use schemars::JsonSchema;

/// Shared helper: generate a JSON Schema map for a type implementing `JsonSchema`.
///
/// Used by all tool family modules to produce the `input_schema` for MCP tool
/// definitions. Centralised here to avoid duplication (was copy-pasted in all 11
/// modules — see Issue 011).
pub(crate) fn schema_map<T: JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
    let schema = schemars::schema_for!(T);
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    }
}

/// Combine tool definitions from all families into one list.
///
/// This is the single source of truth for the tool surface.
/// The order here determines the order tools appear in `listTools`.
///
/// Tool families are gated by feature flags (Issue 010 / TASK_039):
/// - `state-tools`: state management (sign, verify, load, update, list, adopt)
/// - `memory-tools`: memory persistence (save, recall, list, forget, update)
/// - `key-tools`: key/agent management (create agent, reencrypt, export, well-known)
/// - `audit-tools`: security audit + audit trail (audit, log, query, export)
/// - `search-tools`: unified search
///
/// All are included in the `core-tools` default feature.
/// Messaging, agreements, document, A2A, trust, and attestation tools are
/// always included (they have no separate feature gate yet).
pub fn all_tools() -> Vec<Tool> {
    let mut tools = Vec::new();
    #[cfg(feature = "state-tools")]
    tools.extend(state::tools());
    #[cfg(feature = "memory-tools")]
    tools.extend(memory::tools());
    #[cfg(feature = "key-tools")]
    tools.extend(key::tools());
    #[cfg(feature = "audit-tools")]
    tools.extend(audit::tools());
    #[cfg(feature = "search-tools")]
    tools.extend(search::tools());
    tools.extend(messaging::tools());
    tools.extend(agreements::tools());
    tools.extend(document::tools());
    tools.extend(a2a::tools());
    tools.extend(trust::tools());
    tools.extend(attestation::tools());
    tools
}
