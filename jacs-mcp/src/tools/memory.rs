//! Memory tools: save, recall, list, forget, update.
//!
//! These are thin wrappers over the agentstate tool pattern with
//! `jacsAgentStateType` locked to `"memory"` and `visibility` locked
//! to `Private`. Content is always embedded inline (no file paths).

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

/// Parameters for saving a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemorySaveParams {
    /// Human-readable name for this memory.
    #[schemars(description = "Human-readable name for this memory")]
    pub name: String,

    /// The memory content to save.
    #[schemars(description = "Memory content to save (text, JSON, markdown, etc.)")]
    pub content: String,

    /// Optional description of the memory.
    #[schemars(description = "Optional description of what this memory contains")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional tags for categorization and filtering.
    #[schemars(description = "Optional tags for categorization and filtering")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Optional framework identifier (e.g., "claude-code").
    #[schemars(description = "Optional framework identifier (e.g., 'claude-code', 'openai')")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Result of saving a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemorySaveResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the saved memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The name of the saved memory.
    pub name: String,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for recalling (searching) memories.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryRecallParams {
    /// Search query to match against memory name, content, and description.
    #[schemars(
        description = "Search query to match against memory name, content, and description"
    )]
    pub query: String,

    /// Optional tag filter (memories must have all specified tags).
    #[schemars(description = "Optional tag filter (memories must have all specified tags)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Maximum number of results to return (default: 10).
    #[schemars(description = "Maximum number of results to return (default: 10)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Result of recalling memories.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryRecallResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// Matching memory entries.
    pub memories: Vec<MemoryEntry>,

    /// Total number of matches found.
    pub total: usize,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A single memory entry returned by recall or list operations.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryEntry {
    /// The JACS document ID.
    pub jacs_document_id: String,

    /// The memory name.
    pub name: String,

    /// The memory content (may be omitted in list views).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// The memory description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tags on the memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Framework identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Parameters for listing memories with optional filtering.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryListParams {
    /// Optional tag filter (memories must have all specified tags).
    #[schemars(description = "Optional tag filter (memories must have all specified tags)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Optional framework filter.
    #[schemars(description = "Optional framework filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,

    /// Maximum number of results to return (default: 20).
    #[schemars(description = "Maximum number of results to return (default: 20)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Pagination offset (default: 0).
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

/// Result of listing memories.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryListResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// Memory entries in the current page.
    pub memories: Vec<MemoryEntry>,

    /// Total number of memories matching the filters (before pagination).
    pub total: usize,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for forgetting (soft-deleting) a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryForgetParams {
    /// JACS document ID of the memory to forget (uuid:version).
    #[schemars(description = "JACS document ID of the memory to forget (uuid:version)")]
    pub jacs_id: String,
}

/// Result of forgetting a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryForgetResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID that was forgotten.
    pub jacs_document_id: String,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for updating an existing memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryUpdateParams {
    /// JACS document ID of the memory to update (uuid:version).
    #[schemars(description = "JACS document ID of the memory to update (uuid:version)")]
    pub jacs_id: String,

    /// New content for the memory (replaces existing content).
    #[schemars(description = "New content for the memory (replaces existing content)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// New name for the memory (replaces existing name).
    #[schemars(description = "New name for the memory (replaces existing name)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// New tags for the memory (replaces all existing tags).
    #[schemars(description = "New tags for the memory (replaces all existing tags)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Result of updating a memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryUpdateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The new JACS document version ID after update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the memory family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_memory_save",
            "Save a memory as a cryptographically signed private document. The memory is \
             stored as an agentstate document with type 'memory' and private visibility. \
             Use this to persist context, decisions, or learned information across sessions.",
            schema_map::<MemorySaveParams>(),
        ),
        Tool::new(
            "jacs_memory_recall",
            "Search saved memories by query string and optional tag filter. Returns matching \
             private memory documents. Use this to retrieve previously saved context or \
             information.",
            schema_map::<MemoryRecallParams>(),
        ),
        Tool::new(
            "jacs_memory_list",
            "List all saved memory documents with optional filtering by tags or framework. \
             Supports pagination via limit and offset parameters.",
            schema_map::<MemoryListParams>(),
        ),
        Tool::new(
            "jacs_memory_forget",
            "Mark a memory document as removed. The document's provenance chain is preserved \
             but the memory is no longer returned by recall or list operations.",
            schema_map::<MemoryForgetParams>(),
        ),
        Tool::new(
            "jacs_memory_update",
            "Update an existing memory with new content, name, or tags. Creates a new signed \
             version linked to the previous version.",
            schema_map::<MemoryUpdateParams>(),
        ),
    ]
}
