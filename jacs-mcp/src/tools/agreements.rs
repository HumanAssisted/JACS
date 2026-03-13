//! Agreement tools: create, sign, check multi-party agreements.

use rmcp::model::Tool;

use super::schema_map;
pub use super::types::{
    CheckAgreementParams, CheckAgreementResult, CreateAgreementParams, CreateAgreementResult,
    SignAgreementParams, SignAgreementResult,
};

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the agreements family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_create_agreement",
            "Create a multi-party cryptographic agreement. Use this when multiple agents need \
             to formally agree on something -- like approving a deployment, authorizing a data \
             transfer, or ratifying a decision. You specify which agents must sign, an optional \
             quorum (e.g., 2-of-3), a timeout deadline, and algorithm constraints. Returns a \
             signed agreement document to pass to other agents for co-signing.",
            schema_map::<CreateAgreementParams>(),
        ),
        Tool::new(
            "jacs_sign_agreement",
            "Co-sign an existing agreement. Use this after receiving an agreement document from \
             another agent. Your cryptographic signature is added to the agreement. The updated \
             document can then be passed to the next signer or checked for completion.",
            schema_map::<SignAgreementParams>(),
        ),
        Tool::new(
            "jacs_check_agreement",
            "Check the status of an agreement: how many agents have signed, whether quorum is \
             met, whether it has expired, and which agents still need to sign. Use this to \
             decide whether an agreement is complete and ready to act on.",
            schema_map::<CheckAgreementParams>(),
        ),
    ]
}
