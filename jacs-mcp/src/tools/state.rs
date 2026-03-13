//! State management tools: sign, verify, load, update, list, adopt.

use rmcp::model::Tool;

use super::schema_map;
pub use super::types::{
    AdoptStateParams, AdoptStateResult, ListStateParams, ListStateResult, LoadStateParams,
    LoadStateResult, SignStateParams, SignStateResult, StateListEntry, UpdateStateParams,
    UpdateStateResult, VerifyStateParams, VerifyStateResult,
};

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the state family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_sign_state",
            "Sign an agent state file (memory, skill, plan, config, or hook) to create \
             a cryptographically signed JACS document. This establishes provenance and \
             integrity for the file's contents.",
            schema_map::<SignStateParams>(),
        ),
        Tool::new(
            "jacs_verify_state",
            "Verify the integrity and authenticity of a signed agent state. Checks both \
             the file hash and the cryptographic signature.",
            schema_map::<VerifyStateParams>(),
        ),
        Tool::new(
            "jacs_load_state",
            "Load a signed agent state document and optionally verify it before returning \
             the content.",
            schema_map::<LoadStateParams>(),
        ),
        Tool::new(
            "jacs_update_state",
            "Update a previously signed agent state file. Writes new content (if provided), \
             recomputes the SHA-256 hash, and creates a new signed version.",
            schema_map::<UpdateStateParams>(),
        ),
        Tool::new(
            "jacs_list_state",
            "List signed agent state documents, with optional filtering by type, framework, \
             or tags.",
            schema_map::<ListStateParams>(),
        ),
        Tool::new(
            "jacs_adopt_state",
            "Adopt an external file as signed agent state. Like sign_state but marks the \
             origin as 'adopted' and optionally records the source URL.",
            schema_map::<AdoptStateParams>(),
        ),
    ]
}
