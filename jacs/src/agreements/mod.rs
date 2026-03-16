//! Agreement module: multi-party agreement operations on SimpleAgent.
//!
//! Gated behind the `agreements` feature flag.
//!
//! These functions accept a `&SimpleAgent` reference and delegate to the
//! underlying `Agent` agreement trait methods. They were previously methods
//! on `SimpleAgent` and were moved here as part of Phase 5 (narrow contract).

use crate::agent::agreement::{Agreement, AgreementOptions};
use crate::error::JacsError;
use crate::schema::utils::ValueExt;
use crate::simple::SimpleAgent;
use crate::simple::types::*;
use tracing::{debug, info};

/// Creates a multi-party agreement requiring signatures from specified agents.
///
/// This creates an agreement on a document that must be signed by all specified
/// agents before it is considered complete. Use this for scenarios requiring
/// multi-party approval, such as contract signing or governance decisions.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for signing
/// * `document` - The document to create an agreement on (JSON string)
/// * `agent_ids` - List of agent IDs required to sign the agreement
/// * `question` - Optional question or purpose of the agreement
/// * `context` - Optional additional context for signers
///
/// # Returns
///
/// A `SignedDocument` containing the agreement document.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use jacs::agreements;
/// use serde_json::json;
///
/// let agent = SimpleAgent::load(None, None)?;
/// let proposal = json!({"proposal": "Merge codebases A and B"});
///
/// let agreement = agreements::create(
///     &agent,
///     &proposal.to_string(),
///     &["agent-1-uuid".to_string(), "agent-2-uuid".to_string()],
///     Some("Do you approve this merge?"),
///     Some("This will combine repositories A and B"),
/// )?;
/// println!("Agreement created: {}", agreement.document_id);
/// ```
#[must_use = "agreement document must be used or stored"]
pub fn create(
    agent: &SimpleAgent,
    document: &str,
    agent_ids: &[String],
    question: Option<&str>,
    context: Option<&str>,
) -> Result<SignedDocument, JacsError> {
    create_with_options(agent, document, agent_ids, question, context, None)
}

/// Creates a multi-party agreement with extended options.
///
/// Like `create`, but accepts `AgreementOptions` for timeout,
/// quorum (M-of-N), and algorithm constraints.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for signing
/// * `document` - The document to create an agreement on (JSON string)
/// * `agent_ids` - List of agent IDs required to sign
/// * `question` - Optional prompt describing what agents are agreeing to
/// * `context` - Optional context for the agreement
/// * `options` - Optional `AgreementOptions` (timeout, quorum, algorithm constraints)
pub fn create_with_options(
    agent: &SimpleAgent,
    document: &str,
    agent_ids: &[String],
    question: Option<&str>,
    context: Option<&str>,
    options: Option<&AgreementOptions>,
) -> Result<SignedDocument, JacsError> {
    use crate::agent::document::DocumentTraits;
    use crate::schema::utils::check_document_size;

    debug!(
        "create_with_options() called with {} signers",
        agent_ids.len()
    );

    // Check document size before processing
    check_document_size(document)?;

    let default_opts = AgreementOptions::default();
    let opts = options.unwrap_or(&default_opts);

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    // First create the document
    let jacs_doc = inner
        .create_document_and_load(document, None, None)
        .map_err(|e| JacsError::SigningFailed {
            reason: format!("Failed to create base document: {}", e),
        })?;

    // Then create the agreement on it
    let agreement_doc = inner
        .create_agreement_with_options(&jacs_doc.getkey(), agent_ids, question, context, None, opts)
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to create agreement: {}", e),
        })?;

    info!("Agreement created: document_id={}", agreement_doc.id);

    SignedDocument::from_jacs_document(agreement_doc, "agreement")
}

/// Signs an existing multi-party agreement as the current agent.
///
/// # IMPORTANT: Signing Agreements is Sacred
///
/// **Signing an agreement is a binding, irreversible commitment.** When you sign:
/// - You cryptographically commit to the agreement terms
/// - Your signature is permanent and cannot be revoked
/// - All parties can verify your commitment forever
/// - You are legally and ethically bound to the agreement content
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for signing
/// * `document` - The agreement document to sign (JSON string)
///
/// # Returns
///
/// A `SignedDocument` with this agent's signature added.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use jacs::agreements;
///
/// let agent = SimpleAgent::load(None, None)?;
///
/// // REVIEW CAREFULLY before signing!
/// let signed = agreements::sign(&agent, &agreement_json)?;
/// ```
#[must_use = "signed agreement must be used or stored"]
pub fn sign(agent: &SimpleAgent, document: &str) -> Result<SignedDocument, JacsError> {
    use crate::agent::document::DocumentTraits;
    use crate::schema::utils::check_document_size;

    // Check document size before processing
    check_document_size(document)?;

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    // Load the document
    let jacs_doc = inner
        .load_document(document)
        .map_err(|e| JacsError::DocumentMalformed {
            field: "document".to_string(),
            reason: e.to_string(),
        })?;

    // Sign the agreement
    let signed_doc = inner
        .sign_agreement(&jacs_doc.getkey(), None)
        .map_err(|e| JacsError::SigningFailed {
            reason: format!("Failed to sign agreement: {}", e),
        })?;

    SignedDocument::from_jacs_document(signed_doc, "signed agreement")
}

/// Checks the status of a multi-party agreement.
///
/// Use this to determine which agents have signed and whether the agreement
/// is complete (all required signatures collected).
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for checking
/// * `document` - The agreement document to check (JSON string)
///
/// # Returns
///
/// An `AgreementStatus` with completion status and signer details.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use jacs::agreements;
///
/// let agent = SimpleAgent::load(None, None)?;
///
/// let status = agreements::check(&agent, &agreement_json)?;
/// if status.complete {
///     println!("All parties have signed!");
/// } else {
///     println!("Waiting for signatures from: {:?}", status.pending);
/// }
/// ```
#[must_use = "agreement status must be checked"]
pub fn check(agent: &SimpleAgent, document: &str) -> Result<AgreementStatus, JacsError> {
    use crate::agent::document::DocumentTraits;
    use crate::schema::utils::check_document_size;

    // Check document size before processing
    check_document_size(document)?;

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    // Load the document
    let jacs_doc = inner
        .load_document(document)
        .map_err(|e| JacsError::DocumentMalformed {
            field: "document".to_string(),
            reason: e.to_string(),
        })?;

    // Get the unsigned agents
    let unsigned = jacs_doc
        .agreement_unsigned_agents(None)
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to check unsigned agents: {}", e),
        })?;

    // Get all requested agents from the agreement
    let all_agents =
        jacs_doc
            .agreement_requested_agents(None)
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to get agreement agents: {}", e),
            })?;

    // Build signer status list
    let mut signers = Vec::new();
    let unsigned_set: std::collections::HashSet<&String> = unsigned.iter().collect();

    for agent_id in &all_agents {
        let signed = !unsigned_set.contains(agent_id);
        signers.push(SignerStatus {
            agent_id: agent_id.clone(),
            signed,
            signed_at: if signed {
                Some(
                    jacs_doc
                        .value
                        .get_path_str_or(&["jacsSignature", "date"], "")
                        .to_string(),
                )
            } else {
                None
            },
        });
    }

    Ok(AgreementStatus {
        complete: unsigned.is_empty(),
        signers,
        pending: unsigned,
    })
}
