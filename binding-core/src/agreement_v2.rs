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

pub(crate) fn create_agreement_v2_json(
    agent: &mut Agent,
    input_json: &str,
) -> BindingResult<String> {
    let input: CreateAgreementV2 = serde_json::from_str(input_json).map_err(|e| {
        BindingCoreError::validation(format!("Invalid agreement v2 create input: {}", e))
    })?;
    let document = jacs::agreements::v2::create_with_agent(agent, input).map_err(|e| {
        BindingCoreError::agreement_failed(format!("Failed to create agreement v2: {}", e))
    })?;
    serde_json::to_string(&document.value).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize agreement v2: {}", e))
    })
}

pub(crate) fn apply_agreement_v2_json(
    agent: &mut Agent,
    document_json: &str,
    mutation_json: &str,
) -> BindingResult<String> {
    let mutation: AgreementV2Mutation = serde_json::from_str(mutation_json).map_err(|e| {
        BindingCoreError::validation(format!("Invalid agreement v2 mutation input: {}", e))
    })?;
    let document = apply_with_agent(agent, document_json, mutation).map_err(|e| {
        BindingCoreError::agreement_failed(format!("Failed to update agreement v2: {}", e))
    })?;
    serde_json::to_string(&document.value).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize agreement v2: {}", e))
    })
}

pub(crate) fn sign_agreement_v2_json(
    agent: &mut Agent,
    document_json: &str,
    role: &str,
) -> BindingResult<String> {
    let role = parse_role(role)?;
    let document = sign_with_agent(agent, document_json, role).map_err(|e| {
        BindingCoreError::agreement_failed(format!("Failed to sign agreement v2: {}", e))
    })?;
    serde_json::to_string(&document.value).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize agreement v2: {}", e))
    })
}

pub(crate) fn verify_agreement_v2_json(
    agent: &mut Agent,
    document_json: &str,
) -> BindingResult<String> {
    let report = verify_with_agent(agent, document_json).map_err(|e| {
        BindingCoreError::verification_failed(format!("Failed to verify agreement v2: {}", e))
    })?;
    serde_json::to_string(&report).map_err(|e| {
        BindingCoreError::serialization_failed(format!(
            "Failed to serialize agreement v2 verification report: {}",
            e
        ))
    })
}

pub(crate) fn detect_agreement_v2_branch_conflict_json(
    base_document_json: &str,
    left_document_json: &str,
    right_document_json: &str,
) -> BindingResult<String> {
    let analysis =
        detect_branch_conflict(base_document_json, left_document_json, right_document_json)
            .map_err(|e| {
                BindingCoreError::agreement_failed(format!(
                    "Failed to analyze agreement v2 branch conflict: {}",
                    e
                ))
            })?;
    serde_json::to_string(&analysis).map_err(|e| {
        BindingCoreError::serialization_failed(format!(
            "Failed to serialize agreement v2 branch analysis: {}",
            e
        ))
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
    .map_err(|e| {
        BindingCoreError::agreement_failed(format!(
            "Failed to merge agreement v2 transcript branches: {}",
            e
        ))
    })?;
    serde_json::to_string(&document.value).map_err(|e| {
        BindingCoreError::serialization_failed(format!(
            "Failed to serialize merged agreement v2: {}",
            e
        ))
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
        BindingCoreError::validation(format!(
            "Invalid agreement v2 branch resolution mutation input: {}",
            e
        ))
    })?;
    let document = resolve_branch_conflict_with_agent(
        agent,
        base_document_json,
        previous_document_json,
        side_branch_document_json,
        mutation,
    )
    .map_err(|e| {
        BindingCoreError::agreement_failed(format!(
            "Failed to resolve agreement v2 branch conflict: {}",
            e
        ))
    })?;
    serde_json::to_string(&document.value).map_err(|e| {
        BindingCoreError::serialization_failed(format!(
            "Failed to serialize resolved agreement v2: {}",
            e
        ))
    })
}

fn parse_role(role: &str) -> BindingResult<AgreementV2Role> {
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
