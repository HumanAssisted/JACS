//! Per-family tool modules for jacs-mcp.
//!
//! Each module contains the request/response types, schema helpers, and
//! tool definitions for one tool family. The `all_tools()` function
//! combines tools from every compiled-in family into a single `Vec<Tool>`.
//!
//! ## Compile-time gating (Cargo features)
//!
//! Tool *registration* is gated by feature flags. The modules themselves are
//! always compiled so that handler code and type definitions remain available
//! (the `#[tool_router]` proc macro requires all handler parameter types to
//! exist unconditionally).
//!
//! The `core-tools` feature (enabled by default) registers the 7 core families
//! (28 tools). The 4 advanced families (14 tools) require explicit opt-in:
//!
//! - `agreement-tools`, `messaging-tools`, `a2a-tools`, `attestation-tools`
//!
//! The `full-tools` feature enables all 11 families (42 tools).
//!
//! ## Runtime gating (profiles)
//!
//! When compiled with `full-tools`, the runtime `Profile` controls which
//! tools are *registered* with the MCP client. See [`crate::profile`].

// All modules are always compiled to keep types available for handlers.
pub mod a2a;
pub mod agreements;
pub mod attestation;
pub mod audit;
pub mod common;
pub mod document;
pub mod key;
pub mod memory;
pub mod messaging;
pub mod search;
pub mod state;
pub mod trust;
pub mod types;

// Re-export visibility metadata helpers for tool response annotation.
pub use common::{annotate_response, inject_meta};

// Re-export all types so callers can use `tools::SignStateParams` etc.
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

/// Tool family classification for runtime profile filtering.
///
/// Each tool belongs to exactly one family. Core families are included in the
/// default profile; advanced families require explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolFamily {
    // Core families
    State,
    Document,
    Trust,
    Audit,
    Memory,
    Search,
    Key,
    // Advanced families
    Agreement,
    Messaging,
    A2a,
    Attestation,
}

impl ToolFamily {
    /// Whether this family is part of the core tool set.
    pub fn is_core(&self) -> bool {
        matches!(
            self,
            ToolFamily::State
                | ToolFamily::Document
                | ToolFamily::Trust
                | ToolFamily::Audit
                | ToolFamily::Memory
                | ToolFamily::Search
                | ToolFamily::Key
        )
    }
}

/// A tool paired with its family classification, used for runtime filtering.
#[derive(Debug, Clone)]
pub struct ClassifiedTool {
    pub tool: Tool,
    pub family: ToolFamily,
}

/// Combine tool definitions from all compiled-in families into one list.
///
/// This is the single source of truth for the tool surface.
/// The order here determines the order tools appear in `listTools`.
///
/// Tool families are gated by feature flags (Issue 010 / TASK_039):
///
/// **Core families** (enabled by `core-tools`, the default):
/// - `state-tools`: state management (sign, verify, load, update, list, adopt)
/// - `document-tools`: document signing, verification, agent creation
/// - `trust-tools`: trust store (trust, untrust, list, check, get)
/// - `audit-tools`: security audit + audit trail (audit, log, query, export)
/// - `memory-tools`: memory persistence (save, recall, list, forget, update)
/// - `search-tools`: unified search
/// - `key-tools`: key/agent management (reencrypt, export agent card, well-known, export agent)
///
/// **Advanced families** (explicit opt-in):
/// - `agreement-tools`: multi-party agreements
/// - `messaging-tools`: signed messaging
/// - `a2a-tools`: A2A interoperability
/// - `attestation-tools`: attestation (create, verify, lift, DSSE export)
pub fn all_tools() -> Vec<Tool> {
    all_classified_tools()
        .into_iter()
        .map(|ct| ct.tool)
        .collect()
}

/// Return all compiled-in tools with their family classification.
///
/// Used by [`crate::profile::Profile::filter_tools`] for runtime filtering.
/// Tool registration is gated by feature flags; modules are always compiled.
pub fn all_classified_tools() -> Vec<ClassifiedTool> {
    let mut tools = Vec::new();

    // Core families
    #[cfg(feature = "state-tools")]
    tools.extend(state::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::State,
    }));
    #[cfg(feature = "document-tools")]
    tools.extend(document::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Document,
    }));
    #[cfg(feature = "trust-tools")]
    tools.extend(trust::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Trust,
    }));
    #[cfg(feature = "audit-tools")]
    tools.extend(audit::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Audit,
    }));
    #[cfg(feature = "memory-tools")]
    tools.extend(memory::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Memory,
    }));
    #[cfg(feature = "search-tools")]
    tools.extend(search::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Search,
    }));
    #[cfg(feature = "key-tools")]
    tools.extend(key::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Key,
    }));

    // Advanced families
    #[cfg(feature = "messaging-tools")]
    tools.extend(messaging::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Messaging,
    }));
    #[cfg(feature = "agreement-tools")]
    tools.extend(agreements::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Agreement,
    }));
    #[cfg(feature = "a2a-tools")]
    tools.extend(a2a::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::A2a,
    }));
    #[cfg(feature = "attestation-tools")]
    tools.extend(attestation::tools().into_iter().map(|t| ClassifiedTool {
        tool: t,
        family: ToolFamily::Attestation,
    }));

    tools
}

/// Return the number of core tools compiled in.
pub fn core_tool_count() -> usize {
    all_classified_tools()
        .iter()
        .filter(|ct| ct.family.is_core())
        .count()
}

/// Return the total number of tools compiled in.
pub fn total_tool_count() -> usize {
    all_classified_tools().len()
}
