//! Attestation operations on SimpleAgent.
//!
//! These functions accept a `&SimpleAgent` reference and provide attestation
//! operations. They were previously methods on `SimpleAgent` and were moved
//! here as part of Phase 5 (narrow contract).

use crate::error::JacsError;
use crate::simple::SimpleAgent;
use crate::simple::types::SignedDocument;

/// Create a signed attestation document.
///
/// Wraps `Agent::create_attestation()` with SimpleAgent's mutex + error handling.
///
/// # Arguments
/// * `agent` - The SimpleAgent to use for signing
/// * `subject` - The attestation subject (who/what is being attested)
/// * `claims` - Claims about the subject (minimum 1 required by schema)
/// * `evidence` - Optional evidence references supporting the claims
/// * `derivation` - Optional derivation/transform receipt
/// * `policy_context` - Optional policy evaluation context
pub fn create(
    agent: &SimpleAgent,
    subject: &crate::attestation::types::AttestationSubject,
    claims: &[crate::attestation::types::Claim],
    evidence: &[crate::attestation::types::EvidenceRef],
    derivation: Option<&crate::attestation::types::Derivation>,
    policy_context: Option<&crate::attestation::types::PolicyContext>,
) -> Result<SignedDocument, JacsError> {
    use crate::attestation::AttestationTraits;
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let jacs_doc = inner
        .create_attestation(subject, claims, evidence, derivation, policy_context)
        .map_err(|e| JacsError::AttestationFailed {
            message: format!("Failed to create attestation: {}", e),
        })?;
    SignedDocument::from_jacs_document(jacs_doc, "attestation")
}

/// Verify an attestation using local (crypto-only) verification.
///
/// Fast path: checks signature + hash only. No network calls, no evidence checks.
///
/// # Arguments
/// * `agent` - The SimpleAgent to use for verification
/// * `document_key` - The document key in "id:version" format
pub fn verify(
    agent: &SimpleAgent,
    document_key: &str,
) -> Result<crate::attestation::types::AttestationVerificationResult, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    inner
        .verify_attestation_local_impl(document_key)
        .map_err(|e| JacsError::VerificationFailed {
            message: format!("Attestation local verification failed: {}", e),
        })
}

/// Verify an attestation using full verification.
///
/// Full path: checks signature + hash + evidence digests + freshness + derivation chain.
///
/// # Arguments
/// * `agent` - The SimpleAgent to use for verification
/// * `document_key` - The document key in "id:version" format
pub fn verify_full(
    agent: &SimpleAgent,
    document_key: &str,
) -> Result<crate::attestation::types::AttestationVerificationResult, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    inner
        .verify_attestation_full_impl(document_key)
        .map_err(|e| JacsError::VerificationFailed {
            message: format!("Attestation full verification failed: {}", e),
        })
}

/// Lift an existing signed document into an attestation.
///
/// Convenience wrapper that takes a signed JACS document JSON string
/// and produces a new attestation document referencing the original.
///
/// # Arguments
/// * `agent` - The SimpleAgent to use for signing
/// * `signed_document_json` - JSON string of the existing signed document
/// * `claims` - Claims about the document (minimum 1 required)
pub fn lift(
    agent: &SimpleAgent,
    signed_document_json: &str,
    claims: &[crate::attestation::types::Claim],
) -> Result<SignedDocument, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let jacs_doc = crate::attestation::migration::lift_to_attestation(
        &mut inner,
        signed_document_json,
        claims,
    )
    .map_err(|e| JacsError::AttestationFailed {
        message: format!("Failed to lift document to attestation: {}", e),
    })?;
    SignedDocument::from_jacs_document(jacs_doc, "attestation")
}

/// Create a signed attestation from a JSON params string.
///
/// Convenience method that accepts a JSON string with `subject`, `claims`,
/// `evidence` (optional), `derivation` (optional), and `policyContext` (optional).
pub fn create_from_json(
    agent: &SimpleAgent,
    params_json: &str,
) -> Result<SignedDocument, JacsError> {
    use crate::attestation::types::*;

    let params: serde_json::Value =
        serde_json::from_str(params_json).map_err(|e| JacsError::Internal {
            message: format!("Invalid JSON params: {}", e),
        })?;

    let subject: AttestationSubject =
        serde_json::from_value(params.get("subject").cloned().ok_or_else(|| {
            JacsError::Internal {
                message: "Missing required 'subject' field".into(),
            }
        })?)
        .map_err(|e| JacsError::Internal {
            message: format!("Invalid subject: {}", e),
        })?;

    let claims: Vec<Claim> =
        serde_json::from_value(params.get("claims").cloned().ok_or_else(|| {
            JacsError::Internal {
                message: "Missing required 'claims' field".into(),
            }
        })?)
        .map_err(|e| JacsError::Internal {
            message: format!("Invalid claims: {}", e),
        })?;

    let evidence: Vec<EvidenceRef> = match params.get("evidence") {
        Some(v) if !v.is_null() => {
            serde_json::from_value(v.clone()).map_err(|e| JacsError::Internal {
                message: format!("Invalid evidence: {}", e),
            })?
        }
        _ => vec![],
    };

    let derivation: Option<Derivation> = match params.get("derivation") {
        Some(v) if !v.is_null() => {
            Some(
                serde_json::from_value(v.clone()).map_err(|e| JacsError::Internal {
                    message: format!("Invalid derivation: {}", e),
                })?,
            )
        }
        _ => None,
    };

    let policy_context: Option<PolicyContext> = match params.get("policyContext") {
        Some(v) if !v.is_null() => {
            Some(
                serde_json::from_value(v.clone()).map_err(|e| JacsError::Internal {
                    message: format!("Invalid policyContext: {}", e),
                })?,
            )
        }
        _ => None,
    };

    create(
        agent,
        &subject,
        &claims,
        &evidence,
        derivation.as_ref(),
        policy_context.as_ref(),
    )
}

/// Lift a signed document into an attestation from a JSON claims string.
///
/// Convenience method that accepts claims as a JSON string.
pub fn lift_from_json(
    agent: &SimpleAgent,
    signed_doc_json: &str,
    claims_json: &str,
) -> Result<SignedDocument, JacsError> {
    use crate::attestation::types::Claim;

    let claims: Vec<Claim> =
        serde_json::from_str(claims_json).map_err(|e| JacsError::Internal {
            message: format!("Invalid claims JSON: {}", e),
        })?;

    lift(agent, signed_doc_json, &claims)
}

/// Export a signed attestation as a DSSE (Dead Simple Signing Envelope).
///
/// Produces an in-toto Statement wrapped in a DSSE envelope.
/// Export-only for v0.9.0 (no import).
///
/// # Arguments
/// * `attestation_json` - JSON string of the signed attestation document
///
/// # Returns
/// A DSSE envelope JSON string containing the in-toto Statement.
pub fn export_dsse(attestation_json: &str) -> Result<String, JacsError> {
    let att_value: serde_json::Value =
        serde_json::from_str(attestation_json).map_err(|e| JacsError::AttestationFailed {
            message: format!("Invalid attestation JSON: {}", e),
        })?;
    let envelope = crate::attestation::dsse::export_dsse(&att_value).map_err(|e| {
        JacsError::AttestationFailed {
            message: format!("Failed to export DSSE envelope: {}", e),
        }
    })?;
    serde_json::to_string(&envelope).map_err(|e| JacsError::Internal {
        message: format!("Failed to serialize DSSE envelope: {}", e),
    })
}
