//! Search tools: unified search across all document types.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Parameters for the unified search tool.
///
/// TODO(Issue 015): This should accept all `SearchQuery` fields from
/// `jacs::search::SearchQuery` (agent_id, field_filter, min_score) and
/// delegate to `SearchProvider::search()` instead of the manual iteration
/// in `jacs_tools.rs`. Deferred because `SearchProvider` is not yet wired
/// into `AgentWrapper`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Search query string.
    #[schemars(description = "Search query string to match against document content and names")]
    pub query: String,

    /// Optional filter by document type (e.g., "agentstate", "message").
    #[schemars(
        description = "Optional filter by JACS document type (e.g., 'agentstate', 'message', 'agreement')"
    )]
    pub jacs_type: Option<String>,

    /// Max results (default: 20).
    #[schemars(description = "Maximum number of results to return (default: 20)")]
    pub limit: Option<u32>,

    /// Pagination offset.
    #[schemars(description = "Pagination offset (default: 0)")]
    pub offset: Option<u32>,
}

/// A single search result entry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchResultEntry {
    /// The JACS document ID.
    pub jacs_document_id: String,

    /// The document type, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_type: Option<String>,

    /// The document name, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Matching text snippet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,

    /// Relevance score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,

    /// Which search method was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_method: Option<String>,
}

/// Result of a unified search.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The matching documents.
    pub results: Vec<SearchResultEntry>,

    /// Total number of matches (before pagination).
    pub total: usize,

    /// Which search method was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_method: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the search family.
pub fn tools() -> Vec<Tool> {
    vec![Tool::new(
        "jacs_search",
        "Search across all signed documents using the unified search interface. \
         Supports fulltext search with optional filtering by document type. Results \
         include relevance scores and matching snippets. The search method (fulltext, \
         vector, or hybrid) is chosen automatically based on the storage backend.",
        schema_map::<SearchParams>(),
    )]
}
