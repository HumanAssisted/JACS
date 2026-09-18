//! A2A operations on SimpleAgent.
//!
//! These functions accept a `&SimpleAgent` reference and provide A2A protocol
//! operations. They were previously methods on `SimpleAgent` and were moved
//! here as part of Phase 5 (narrow contract).

use crate::error::JacsError;
use crate::simple::SimpleAgent;
use serde_json::Value;
use tracing::warn;

/// Export this agent as an A2A Agent Card (v0.4.0).
///
/// The Agent Card describes the agent's capabilities, skills, and
/// cryptographic configuration for zero-config A2A discovery.
pub fn export_agent_card(agent: &SimpleAgent) -> Result<crate::a2a::AgentCard, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    crate::a2a::agent_card::export_agent_card(&inner).map_err(|e| JacsError::Internal {
        message: format!("Failed to export agent card: {}", e),
    })
}

/// Generate .well-known documents for A2A discovery.
///
/// Creates the signed Agent Card, ES256 compatibility JWKS, the
/// native-root-signed compatibility binding, JACS descriptor, public key
/// document, and extension descriptor. The identity tuple is persisted and is
/// stable across calls and restarts.
///
/// `a2a_algorithm` is retained for source compatibility. Omit it or pass
/// `ES256`. The former `ring-Ed25519` choice is rejected because it minted an
/// unrelated ephemeral key and could not prove the card's claimed identity.
///
/// Returns a vector of (path, JSON value) tuples suitable for serving.
pub fn generate_well_known_documents(
    agent: &SimpleAgent,
    a2a_algorithm: Option<&str>,
) -> Result<Vec<(String, Value)>, JacsError> {
    if let Some(requested) = a2a_algorithm
        && !requested.eq_ignore_ascii_case("ES256")
    {
        return Err(JacsError::ValidationError(format!(
            "A2A well-known discovery uses the persisted compatibility key and fixed ES256 \
             algorithm; obsolete or unsupported explicit choice '{requested}' is rejected"
        )));
    }

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let key_directory = inner
        .key_paths()
        .ok_or(JacsError::AgentNotLoaded)?
        .key_directory
        .clone();

    crate::a2a::extension::generate_bound_well_known_documents(&mut inner, &key_directory, None)
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to generate well-known documents: {}", e),
        })
}

/// Wrap an A2A artifact with JACS provenance signature.
///
/// This creates a signed envelope around arbitrary JSON content,
/// binding the signer's identity to the artifact.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for signing
/// * `artifact_json` - JSON string of the artifact to wrap
/// * `artifact_type` - Type label (e.g., "artifact", "message", "task")
/// * `parent_signatures_json` - Optional JSON array of parent signatures for chain-of-custody
///
/// # Returns
///
/// JSON string of the wrapped, signed artifact.
#[deprecated(since = "0.9.0", note = "Use sign_artifact() instead")]
pub fn wrap_artifact(
    agent: &SimpleAgent,
    artifact_json: &str,
    artifact_type: &str,
    parent_signatures_json: Option<&str>,
) -> Result<String, JacsError> {
    if std::env::var("JACS_SHOW_DEPRECATIONS").is_ok() {
        warn!("wrap_artifact is deprecated, use sign_artifact instead");
    }

    let artifact: Value =
        jacs_core::strict_json::parse_strict_json(artifact_json).map_err(|e| {
            JacsError::DocumentMalformed {
                field: "artifact_json".to_string(),
                reason: format!("Invalid JSON: {}", e),
            }
        })?;

    let parent_signatures: Option<Vec<Value>> = match parent_signatures_json {
        Some(json_str) => {
            let parsed: Vec<Value> = jacs_core::strict_json::deserialize_strict_json(json_str)
                .map_err(|e| JacsError::DocumentMalformed {
                    field: "parent_signatures_json".to_string(),
                    reason: format!("Invalid JSON array: {}", e),
                })?;
            Some(parsed)
        }
        None => None,
    };

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    let wrapped = crate::a2a::provenance::wrap_artifact_with_provenance(
        &mut inner,
        artifact,
        artifact_type,
        parent_signatures,
    )
    .map_err(|e| JacsError::SigningFailed {
        reason: format!("Failed to wrap artifact: {}", e),
    })?;

    serde_json::to_string_pretty(&wrapped).map_err(|e| JacsError::Internal {
        message: format!("Failed to serialize wrapped artifact: {}", e),
    })
}

/// Sign an A2A artifact with JACS provenance.
///
/// This is the recommended primary API, replacing the deprecated
/// [`wrap_artifact`].
pub fn sign_artifact(
    agent: &SimpleAgent,
    artifact_json: &str,
    artifact_type: &str,
    parent_signatures_json: Option<&str>,
) -> Result<String, JacsError> {
    #[allow(deprecated)]
    wrap_artifact(agent, artifact_json, artifact_type, parent_signatures_json)
}

/// Verify a JACS-wrapped A2A artifact.
///
/// Returns a JSON string containing the verification result, including
/// the verification status, signer identity, and the original artifact.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for verification
/// * `wrapped_json` - JSON string of the wrapped artifact to verify
pub fn verify_artifact(agent: &SimpleAgent, wrapped_json: &str) -> Result<String, JacsError> {
    let wrapped: Value = jacs_core::strict_json::parse_strict_json(wrapped_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "wrapped_json".to_string(),
            reason: format!("Invalid JSON: {}", e),
        }
    })?;

    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    let result =
        crate::a2a::provenance::verify_wrapped_artifact(&inner, &wrapped).map_err(|e| {
            JacsError::SignatureVerificationFailed {
                reason: format!("A2A artifact verification error: {}", e),
            }
        })?;

    serde_json::to_string_pretty(&result).map_err(|e| JacsError::Internal {
        message: format!("Failed to serialize verification result: {}", e),
    })
}
