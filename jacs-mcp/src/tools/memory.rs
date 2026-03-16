//! Memory tools: save, recall, list, forget, update.
//!
//! These are thin wrappers over the agentstate tool pattern with
//! `jacsAgentStateType` locked to `"memory"` and `visibility` locked
//! to `Private`. Content is always embedded inline (no file paths).

use rmcp::model::Tool;

use super::schema_map;
pub use super::types::{
    MemoryEntry, MemoryForgetParams, MemoryForgetResult, MemoryListParams, MemoryListResult,
    MemoryRecallParams, MemoryRecallResult, MemorySaveParams, MemorySaveResult, MemoryUpdateParams,
    MemoryUpdateResult,
};

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
