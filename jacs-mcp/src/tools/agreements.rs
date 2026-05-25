//! Agreement tools: create, sign, check multi-party agreements.

use rmcp::model::Tool;

use super::schema_map;
pub use super::types::{
    AgreementV2DocumentResult, AgreementV2ValueResult, ApplyAgreementV2Params,
    CheckAgreementParams, CheckAgreementResult, CreateAgreementParams, CreateAgreementResult,
    CreateAgreementV2Params, DetectAgreementV2BranchConflictParams,
    MergeAgreementV2TranscriptBranchesParams, ResolveAgreementV2BranchConflictParams,
    SignAgreementParams, SignAgreementResult, SignAgreementV2Params, VerifyAgreementV2Params,
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
        Tool::new(
            "jacs_create_agreement_v2",
            "Create a standalone JACS agreement v2 document. Use this for the new intent/consent workflow: terms, parties, signature policy, transcript, links, controllers, and owners. Returns a signed agreement artifact.",
            schema_map::<CreateAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_apply_agreement_v2",
            "Apply a typed agreement v2 mutation and emit a successor version. Use this to append transcript entries, revise terms, change status, set parties/policy, add links, or set owners.",
            schema_map::<ApplyAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_sign_agreement_v2",
            "Add this agent's signer, witness, or notary signature to a standalone agreement v2 document.",
            schema_map::<SignAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_verify_agreement_v2",
            "Verify a standalone agreement v2 document's hashes, status, parties, transcript, and agreement signatures.",
            schema_map::<VerifyAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_detect_agreement_v2_branch_conflict",
            "Analyze two agreement v2 successor versions and report whether they are transcript-only auto-mergeable or conflict on consent-scope fields.",
            schema_map::<DetectAgreementV2BranchConflictParams>(),
        ),
        Tool::new(
            "jacs_merge_agreement_v2_transcript_branches",
            "Auto-merge two transcript-only agreement v2 branches and emit a successor version.",
            schema_map::<MergeAgreementV2TranscriptBranchesParams>(),
        ),
        Tool::new(
            "jacs_resolve_agreement_v2_branch_conflict",
            "Resolve an agreement v2 branch conflict by rebasing an explicit mutation over a previous version and side branch.",
            schema_map::<ResolveAgreementV2BranchConflictParams>(),
        ),
    ]
}
