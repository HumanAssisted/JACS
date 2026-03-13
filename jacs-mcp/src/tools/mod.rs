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
pub mod state;
pub mod trust;

// Re-export all types so callers can use `tools::SignStateParams` etc.
// Each sub-module also exports a `tools()` fn that is called via qualified
// paths (e.g. `state::tools()`), so the name collision is harmless.
#[allow(ambiguous_glob_reexports)]
pub use a2a::*;
#[allow(ambiguous_glob_reexports)]
pub use agreements::*;
#[allow(ambiguous_glob_reexports)]
pub use attestation::*;
#[allow(ambiguous_glob_reexports)]
pub use audit::*;
#[allow(ambiguous_glob_reexports)]
pub use document::*;
#[allow(ambiguous_glob_reexports)]
pub use key::*;
#[allow(ambiguous_glob_reexports)]
pub use messaging::*;
#[allow(ambiguous_glob_reexports)]
pub use state::*;
#[allow(ambiguous_glob_reexports)]
pub use trust::*;

use rmcp::model::Tool;

/// Combine tool definitions from all families into one list.
///
/// This is the single source of truth for the tool surface.
/// The order here determines the order tools appear in `listTools`.
pub fn all_tools() -> Vec<Tool> {
    let mut tools = Vec::new();
    tools.extend(state::tools());
    tools.extend(key::tools());
    tools.extend(audit::tools());
    tools.extend(messaging::tools());
    tools.extend(agreements::tools());
    tools.extend(document::tools());
    tools.extend(a2a::tools());
    tools.extend(trust::tools());
    tools.extend(attestation::tools());
    tools
}
