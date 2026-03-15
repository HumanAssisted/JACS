//! Batch signing and verification operations on SimpleAgent.
//!
//! These functions accept a `&SimpleAgent` reference and provide batch
//! operations. They were previously methods on `SimpleAgent` and were moved
//! here as part of Phase 5 (narrow contract).

use crate::agent::document::DocumentTraits;
use crate::error::JacsError;
use crate::schema::utils::check_document_size;
use crate::simple::SimpleAgent;
use crate::simple::types::*;
use serde_json::{Value, json};
use tracing::info;

/// Signs multiple messages in a batch operation.
///
/// # IMPORTANT: Each Signature is Sacred
///
/// **Every signature in the batch is an irreversible, permanent commitment.**
/// Batch signing is convenient, but each document is independently signed with
/// full cryptographic weight. Before batch signing:
/// - Review ALL messages in the batch
/// - Verify each message represents your intent
/// - Understand you are making multiple permanent commitments
///
/// This is more efficient than calling `sign_message` repeatedly because it
/// amortizes the overhead of acquiring locks and key operations across all
/// messages.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for signing
/// * `messages` - A slice of JSON values to sign
///
/// # Returns
///
/// A vector of `SignedDocument` objects, one for each input message, in the
/// same order as the input slice.
///
/// # Errors
///
/// Returns an error if signing any message fails. In case of failure,
/// documents created before the failure are still stored but the partial
/// results are not returned (all-or-nothing return semantics).
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use jacs::simple::batch;
/// use serde_json::json;
///
/// let agent = SimpleAgent::load(None, None)?;
///
/// let messages = vec![
///     json!({"action": "approve", "item": 1}),
///     json!({"action": "approve", "item": 2}),
/// ];
///
/// let refs: Vec<&serde_json::Value> = messages.iter().collect();
/// let signed_docs = batch::sign_messages(&agent, &refs)?;
/// ```
pub fn sign_messages(
    agent: &SimpleAgent,
    messages: &[&Value],
) -> Result<Vec<SignedDocument>, JacsError> {
    if messages.is_empty() {
        return Ok(Vec::new());
    }

    info!(batch_size = messages.len(), "Signing batch of messages");

    // Prepare all document JSON strings
    let doc_strings: Vec<String> = messages
        .iter()
        .map(|data| {
            let doc_content = json!({
                "jacsType": "message",
                "jacsLevel": "raw",
                "content": data
            });
            doc_content.to_string()
        })
        .collect();

    // Check size of each document before processing
    for doc_str in &doc_strings {
        check_document_size(doc_str)?;
    }

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    // Convert to slice of &str for the batch API
    let doc_refs: Vec<&str> = doc_strings.iter().map(|s| s.as_str()).collect();

    // Use the batch document creation API
    let jacs_docs = inner
        .create_documents_batch(&doc_refs)
        .map_err(|e| JacsError::SigningFailed {
            reason: format!(
                "Batch signing failed: {}. Ensure the agent is properly initialized with load() or create() and has valid keys.",
                e
            ),
        })?;

    // Convert to SignedDocument results
    let mut results = Vec::with_capacity(jacs_docs.len());
    for jacs_doc in jacs_docs {
        results.push(SignedDocument::from_jacs_document(jacs_doc, "document")?);
    }

    info!(
        batch_size = results.len(),
        "Batch message signing completed successfully"
    );

    Ok(results)
}

/// Verifies multiple signed documents in a batch operation.
///
/// This function processes each document sequentially, verifying signatures
/// and hashes for each. All documents are processed regardless of individual
/// failures, and results are returned for each input document.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to use for verification
/// * `documents` - A slice of JSON strings, each representing a signed JACS document
///
/// # Returns
///
/// A vector of `VerificationResult` in the same order as the input documents.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use jacs::simple::batch;
///
/// let agent = SimpleAgent::load(None, None)?;
///
/// let documents = vec![signed_doc1.as_str(), signed_doc2.as_str()];
/// let results = batch::verify(&agent, &documents);
/// for (i, result) in results.iter().enumerate() {
///     if result.valid {
///         println!("Document {} verified successfully", i);
///     }
/// }
/// ```
#[must_use]
pub fn verify(agent: &SimpleAgent, documents: &[&str]) -> Vec<VerificationResult> {
    documents
        .iter()
        .map(|doc| match agent.verify(doc) {
            Ok(result) => result,
            Err(e) => VerificationResult::failure(e.to_string()),
        })
        .collect()
}
