//! Thin JSON wrappers for JACS agreement v2.
//!
//! This module intentionally delegates all agreement rules to `jacs::agreements::v2`.
//! Binding layers should call these wrappers rather than reimplementing hashes,
//! quorum logic, role checks, or version metadata.

use crate::{BindingCoreError, BindingResult};
use jacs::agent::Agent;
use jacs::agreements::v2::{
    AgreementV2Mutation, AgreementV2Role, CreateAgreementV2, apply_with_agent,
    detect_branch_conflict, merge_transcript_branches_with_agent,
    resolve_branch_conflict_with_agent, sign_with_agent, verify_with_agent,
};

pub(crate) const CTX_CREATE: &str = "Failed to create agreement v2";
pub(crate) const CTX_APPLY: &str = "Failed to update agreement v2";
pub(crate) const CTX_SIGN: &str = "Failed to sign agreement v2";
pub(crate) const CTX_VERIFY: &str = "Failed to verify agreement v2";
pub(crate) const CTX_DETECT: &str = "Failed to analyze agreement v2 branch conflict";
pub(crate) const CTX_MERGE: &str = "Failed to merge agreement v2 transcript branches";
pub(crate) const CTX_RESOLVE: &str = "Failed to resolve agreement v2 branch conflict";
pub(crate) const CTX_INVALID_CREATE_INPUT: &str = "Invalid agreement v2 create input";
pub(crate) const CTX_INVALID_MUTATION: &str = "Invalid agreement v2 mutation input";
pub(crate) const CTX_INVALID_RESOLUTION_MUTATION: &str =
    "Invalid agreement v2 branch resolution mutation input";
pub(crate) const CTX_SERIALIZE: &str = "Failed to serialize agreement v2";
pub(crate) const CTX_SERIALIZE_VERIFY: &str =
    "Failed to serialize agreement v2 verification report";
pub(crate) const CTX_SERIALIZE_BRANCH: &str = "Failed to serialize agreement v2 branch analysis";
pub(crate) const CTX_SERIALIZE_MERGED: &str = "Failed to serialize merged agreement v2";
pub(crate) const CTX_SERIALIZE_RESOLVED: &str = "Failed to serialize resolved agreement v2";

pub(crate) fn create_agreement_v2_json(
    agent: &mut Agent,
    input_json: &str,
) -> BindingResult<String> {
    let input: CreateAgreementV2 = serde_json::from_str(input_json).map_err(|e| {
        BindingCoreError::validation(format!("{}: {}", CTX_INVALID_CREATE_INPUT, e))
    })?;
    let document = jacs::agreements::v2::create_with_agent(agent, input)
        .map_err(|e| BindingCoreError::agreement_failed(format!("{}: {}", CTX_CREATE, e)))?;
    serde_json::to_string(&document.value)
        .map_err(|e| BindingCoreError::serialization_failed(format!("{}: {}", CTX_SERIALIZE, e)))
}

pub(crate) fn apply_agreement_v2_json(
    agent: &mut Agent,
    document_json: &str,
    mutation_json: &str,
) -> BindingResult<String> {
    let mutation: AgreementV2Mutation = serde_json::from_str(mutation_json)
        .map_err(|e| BindingCoreError::validation(format!("{}: {}", CTX_INVALID_MUTATION, e)))?;
    let document = apply_with_agent(agent, document_json, mutation)
        .map_err(|e| BindingCoreError::agreement_failed(format!("{}: {}", CTX_APPLY, e)))?;
    serde_json::to_string(&document.value)
        .map_err(|e| BindingCoreError::serialization_failed(format!("{}: {}", CTX_SERIALIZE, e)))
}

pub(crate) fn sign_agreement_v2_json(
    agent: &mut Agent,
    document_json: &str,
    role: &str,
) -> BindingResult<String> {
    let role = parse_agreement_v2_role(role)?;
    let document = sign_with_agent(agent, document_json, role)
        .map_err(|e| BindingCoreError::agreement_failed(format!("{}: {}", CTX_SIGN, e)))?;
    serde_json::to_string(&document.value)
        .map_err(|e| BindingCoreError::serialization_failed(format!("{}: {}", CTX_SERIALIZE, e)))
}

pub(crate) fn verify_agreement_v2_json(
    agent: &mut Agent,
    document_json: &str,
) -> BindingResult<String> {
    let report = verify_with_agent(agent, document_json)
        .map_err(|e| BindingCoreError::verification_failed(format!("{}: {}", CTX_VERIFY, e)))?;
    serde_json::to_string(&report).map_err(|e| {
        BindingCoreError::serialization_failed(format!("{}: {}", CTX_SERIALIZE_VERIFY, e))
    })
}

pub(crate) fn detect_agreement_v2_branch_conflict_json(
    base_document_json: &str,
    left_document_json: &str,
    right_document_json: &str,
) -> BindingResult<String> {
    let analysis =
        detect_branch_conflict(base_document_json, left_document_json, right_document_json)
            .map_err(|e| BindingCoreError::agreement_failed(format!("{}: {}", CTX_DETECT, e)))?;
    serde_json::to_string(&analysis).map_err(|e| {
        BindingCoreError::serialization_failed(format!("{}: {}", CTX_SERIALIZE_BRANCH, e))
    })
}

pub(crate) fn merge_agreement_v2_transcript_branches_json(
    agent: &mut Agent,
    base_document_json: &str,
    left_document_json: &str,
    right_document_json: &str,
) -> BindingResult<String> {
    let document = merge_transcript_branches_with_agent(
        agent,
        base_document_json,
        left_document_json,
        right_document_json,
    )
    .map_err(|e| BindingCoreError::agreement_failed(format!("{}: {}", CTX_MERGE, e)))?;
    serde_json::to_string(&document.value).map_err(|e| {
        BindingCoreError::serialization_failed(format!("{}: {}", CTX_SERIALIZE_MERGED, e))
    })
}

pub(crate) fn resolve_agreement_v2_branch_conflict_json(
    agent: &mut Agent,
    base_document_json: &str,
    previous_document_json: &str,
    side_branch_document_json: &str,
    mutation_json: &str,
) -> BindingResult<String> {
    let mutation: AgreementV2Mutation = serde_json::from_str(mutation_json).map_err(|e| {
        BindingCoreError::validation(format!("{}: {}", CTX_INVALID_RESOLUTION_MUTATION, e))
    })?;
    let document = resolve_branch_conflict_with_agent(
        agent,
        base_document_json,
        previous_document_json,
        side_branch_document_json,
        mutation,
    )
    .map_err(|e| BindingCoreError::agreement_failed(format!("{}: {}", CTX_RESOLVE, e)))?;
    serde_json::to_string(&document.value).map_err(|e| {
        BindingCoreError::serialization_failed(format!("{}: {}", CTX_SERIALIZE_RESOLVED, e))
    })
}

pub(crate) fn parse_agreement_v2_role(role: &str) -> BindingResult<AgreementV2Role> {
    match role {
        "signer" => Ok(AgreementV2Role::Signer),
        "witness" => Ok(AgreementV2Role::Witness),
        "notary" => Ok(AgreementV2Role::Notary),
        _ => Err(BindingCoreError::validation(format!(
            "Invalid agreement v2 signature role '{}'; expected signer, witness, or notary",
            role
        ))),
    }
}
