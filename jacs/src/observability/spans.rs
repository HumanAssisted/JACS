//! Convenience span constructors for common JACS operations.
//!
//! These functions create entered `tracing` spans for the most frequent
//! operations in JACS: signing, verification, and document CRUD.  They
//! return a [`tracing::span::EnteredSpan`] guard — the span stays active
//! until the guard is dropped.
//!
//! # Example
//!
//! ```rust,ignore
//! use jacs::observability::spans;
//!
//! let _guard = spans::signing_span("agent-123", "ed25519");
//! // ... signing logic ...
//! // span closes when _guard is dropped
//! ```

use tracing::span::EnteredSpan;

/// Create an entered span for a cryptographic signing operation.
///
/// Records the `agent_id` and `algorithm` as span fields.
pub fn signing_span(agent_id: &str, algorithm: &str) -> EnteredSpan {
    let span = tracing::info_span!(
        "jacs.signing",
        agent_id = agent_id,
        algorithm = algorithm,
    );
    span.entered()
}

/// Create an entered span for a signature or document verification operation.
///
/// Records the `document_id` and `schema_version` as span fields.
pub fn verification_span(document_id: &str, schema_version: &str) -> EnteredSpan {
    let span = tracing::info_span!(
        "jacs.verification",
        document_id = document_id,
        schema_version = schema_version,
    );
    span.entered()
}

/// Create an entered span for a document CRUD operation.
///
/// Records the `operation` (create, read, update, delete) and `document_id`.
pub fn document_op_span(operation: &str, document_id: &str) -> EnteredSpan {
    let span = tracing::info_span!(
        "jacs.document_op",
        operation = operation,
        document_id = document_id,
    );
    span.entered()
}

/// Create an entered span for a key management operation.
///
/// Records the `operation` (generate, rotate, export, import) and `key_id`.
pub fn key_management_span(operation: &str, key_id: &str) -> EnteredSpan {
    let span = tracing::info_span!(
        "jacs.key_management",
        operation = operation,
        key_id = key_id,
    );
    span.entered()
}

/// Create an entered span for a storage operation.
///
/// Records the `backend` (filesystem, sqlite, etc.) and `operation`.
pub fn storage_span(backend: &str, operation: &str) -> EnteredSpan {
    let span = tracing::info_span!(
        "jacs.storage",
        backend = backend,
        operation = operation,
    );
    span.entered()
}

/// Create an entered span for a DNS verification operation.
///
/// Records the `domain` being verified.
pub fn dns_verification_span(domain: &str) -> EnteredSpan {
    let span = tracing::info_span!(
        "jacs.dns_verification",
        domain = domain,
    );
    span.entered()
}
