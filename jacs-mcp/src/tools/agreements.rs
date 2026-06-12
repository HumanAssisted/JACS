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
            "(Legacy v1; prefer the jacs_*_agreement_v2 tools for new workflows.) Create a \
             multi-party cryptographic agreement attached as a jacsAgreement sidecar. Use this \
             when multiple agents need to formally agree on something -- like approving a \
             deployment, authorizing a data transfer, or ratifying a decision. You specify which \
             agents must sign, an optional quorum (e.g., 2-of-3), a timeout deadline, and \
             algorithm constraints. Returns a signed agreement document to pass to other agents \
             for co-signing.",
            schema_map::<CreateAgreementParams>(),
        ),
        Tool::new(
            "jacs_sign_agreement",
            "(Legacy v1; prefer jacs_sign_agreement_v2.) Co-sign an existing jacsAgreement \
             sidecar. Use this after receiving an agreement document from another agent. Your \
             cryptographic signature is added to the agreement. The updated document can then be \
             passed to the next signer or checked for completion.",
            schema_map::<SignAgreementParams>(),
        ),
        Tool::new(
            "jacs_check_agreement",
            "(Legacy v1; prefer jacs_verify_agreement_v2.) Check the status of a jacsAgreement \
             sidecar: how many agents have signed, whether quorum is met, whether it has expired, \
             and which agents still need to sign. Use this to decide whether an agreement is \
             complete and ready to act on.",
            schema_map::<CheckAgreementParams>(),
        ),
        Tool::new(
            "jacs_create_agreement_v2",
            "Create a standalone JACS agreement v2 document -- a self-contained, cryptographically \
             signed `jacsType: \"agreement\"` artifact (terms, parties, signature policy, optional \
             transcript, links, controllers, owners) with its own content hash and version chain. \
             This is the recommended intent/consent workflow (preferred over the legacy \
             jacs_create_agreement sidecar). Workflow: create -> each party signs \
             (jacs_sign_agreement_v2) -> verify (jacs_verify_agreement_v2) before acting. Provide \
             a CreateAgreementV2 input object with camelCase keys (title, description, terms, \
             parties[{agentId, agentType, role}], signaturePolicy). Returns the signed artifact.",
            schema_map::<CreateAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_apply_agreement_v2",
            "Apply a typed agreement v2 mutation to an existing agreement and emit a successor \
             version (the agreement keeps a version chain). The mutation is a camelCase object \
             whose `type` selects the operation: appendTranscript, updateTerms, setStatus, \
             setParties, setPolicy, addLink, or setOwners. Use this to evolve an agreement instead \
             of editing its JSON by hand. Does not add a signature -- use jacs_sign_agreement_v2 \
             for that.",
            schema_map::<ApplyAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_sign_agreement_v2",
            "Add this agent's cryptographic signature to a standalone agreement v2 document. The \
             `role` is one of \"signer\" (a consenting party), \"witness\" (attests it observed \
             the signing), or \"notary\" (an authority certifying the agreement); it defaults to \
             \"signer\". Call this once per party until the signature policy's quorum and required \
             roles are met, then verify with jacs_verify_agreement_v2.",
            schema_map::<SignAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_verify_agreement_v2",
            "Verify a standalone agreement v2 document: recompute the agreement and transcript \
             hashes, re-check quorum, required roles, witness/notary requirements, status, and \
             every agreement signature. ALWAYS read the result's top-level `valid` field (not \
             `success`, which only means the verify ran) to decide whether to trust the agreement.",
            schema_map::<VerifyAgreementV2Params>(),
        ),
        Tool::new(
            "jacs_detect_agreement_v2_branch_conflict",
            "Compare two agreement v2 successor versions that branched from the same `base` and \
             report whether they are transcript-only (auto-mergeable via \
             jacs_merge_agreement_v2_transcript_branches) or conflict on consent-scope fields \
             (terms, parties, policy, status, signatures), which require \
             jacs_resolve_agreement_v2_branch_conflict.",
            schema_map::<DetectAgreementV2BranchConflictParams>(),
        ),
        Tool::new(
            "jacs_merge_agreement_v2_transcript_branches",
            "Auto-merge two agreement v2 branches that differ from their common `base` only in \
             appended transcript entries, emitting a single merged successor version. If the \
             branches differ on consent-scope fields, this fails -- run \
             jacs_detect_agreement_v2_branch_conflict first, then resolve explicitly.",
            schema_map::<MergeAgreementV2TranscriptBranchesParams>(),
        ),
        Tool::new(
            "jacs_resolve_agreement_v2_branch_conflict",
            "Resolve a conflicting agreement v2 branch by rebasing an explicit resolving mutation \
             onto the `previous` branch you are keeping; the divergent `side_branch` is recorded \
             as a link on the new successor version. Use this when \
             jacs_detect_agreement_v2_branch_conflict reports a consent-scope conflict that cannot \
             auto-merge.",
            schema_map::<ResolveAgreementV2BranchConflictParams>(),
        ),
    ]
}
