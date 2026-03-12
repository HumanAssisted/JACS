//! Unified Document API for JACS.
//!
//! This module defines the [`DocumentService`] trait — the single entry point
//! for all document CRUD, versioning, search, and visibility operations.
//!
//! # CRUD-as-Versioning Semantics
//!
//! JACS is append-only for signed provenance. "CRUD" does NOT mean mutable rows:
//!
//! | Operation | JACS Meaning |
//! |-----------|-------------|
//! | **Create** | Create and sign a new document version |
//! | **Read**   | Load a specific version, the latest version, or a logical document |
//! | **Update** | Create a successor version linked to the prior version (new signature, new version ID) |
//! | **Delete** | Tombstone, revoke visibility, or remove from a storage index — never destroys signed provenance |
//!
//! Storage backends implement this trait. JACS core provides a default
//! filesystem + sqlite implementation.

pub mod filesystem;
pub mod types;

pub use filesystem::FilesystemDocumentService;
pub use types::{
    CreateOptions, DocumentDiff, DocumentSummary, DocumentVisibility, ListFilter, UpdateOptions,
};

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::search::{SearchQuery, SearchResults};

/// Unified document API. Implemented by storage backends.
///
/// JACS core provides a default filesystem + sqlite implementation.
/// All methods enforce append-only provenance semantics: "update" creates
/// a successor version, "remove" tombstones — nothing is ever destroyed.
///
/// # Object Safety
///
/// This trait is object-safe: `Box<dyn DocumentService>` is valid.
/// All methods take `&self` and use owned types or references — no
/// associated types or generic parameters.
///
/// # Thread Safety
///
/// Implementors must be `Send + Sync` so the trait object can be shared
/// across threads (e.g., in an async runtime or MCP server).
pub trait DocumentService: Send + Sync {
    // === CRUD ===

    /// Create a new document, sign it, return the signed document.
    ///
    /// The `json` parameter is the raw JSON payload to sign.
    /// The `options` parameter controls the `jacsType`, visibility, and
    /// optional custom schema for validation.
    fn create(&self, json: &str, options: CreateOptions) -> Result<JACSDocument, JacsError>;

    /// Read a document by its key (`id:version`).
    fn get(&self, key: &str) -> Result<JACSDocument, JacsError>;

    /// Get the latest version of a document by its original ID.
    fn get_latest(&self, document_id: &str) -> Result<JACSDocument, JacsError>;

    /// Update a document, creating a new signed version.
    ///
    /// This creates a successor version linked to the prior version
    /// (new signature, new version ID). The original is never mutated.
    fn update(
        &self,
        document_id: &str,
        new_json: &str,
        options: UpdateOptions,
    ) -> Result<JACSDocument, JacsError>;

    /// Remove a document from storage.
    ///
    /// This does NOT delete the document — it marks it as removed
    /// (tombstoned). Signed provenance is never destroyed.
    fn remove(&self, key: &str) -> Result<JACSDocument, JacsError>;

    /// List document keys, optionally filtered.
    ///
    /// Returns lightweight summaries suitable for display or pagination.
    fn list(&self, filter: ListFilter) -> Result<Vec<DocumentSummary>, JacsError>;

    // === VERSIONS ===

    /// Get all versions of a document, ordered by creation date.
    fn versions(&self, document_id: &str) -> Result<Vec<JACSDocument>, JacsError>;

    /// Diff two versions of a document.
    ///
    /// Both `key_a` and `key_b` are full document keys (`id:version`).
    fn diff(&self, key_a: &str, key_b: &str) -> Result<DocumentDiff, JacsError>;

    // === SEARCH ===

    /// Search documents. The backend decides whether to use fulltext,
    /// vector similarity, or hybrid. The caller doesn't know or care.
    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError>;

    // === BATCH ===

    /// Create multiple documents in a single operation.
    ///
    /// Returns either all successfully created documents or a list of
    /// errors for each failed creation.
    fn create_batch(
        &self,
        documents: &[&str],
        options: CreateOptions,
    ) -> Result<Vec<JACSDocument>, Vec<JacsError>>;

    // === VISIBILITY ===

    /// Get the visibility level of a document.
    fn visibility(&self, key: &str) -> Result<DocumentVisibility, JacsError>;

    /// Set the visibility level of a document.
    ///
    /// Visibility is storage-level metadata (a separate database column),
    /// not part of the signed document payload. Changing visibility updates
    /// the metadata in place without creating a new document version.
    /// This is intentional: visibility is an access-control hint that can
    /// be changed without re-signing, which would require the agent's
    /// private key.
    fn set_visibility(
        &self,
        key: &str,
        visibility: DocumentVisibility,
    ) -> Result<(), JacsError>;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `DocumentService` is object-safe by constructing a
    /// `Box<dyn DocumentService>`. This test is a compile-time check —
    /// if it compiles, the trait is object-safe.
    #[test]
    fn document_service_is_object_safe() {
        // This function signature proves object safety at compile time.
        // If DocumentService were not object-safe, this would fail to compile.
        fn _assert_object_safe(_: &dyn DocumentService) {}
    }

    /// Verify that `DocumentService` requires `Send + Sync`.
    #[test]
    fn document_service_is_send_sync() {
        fn _assert_send_sync<T: Send + Sync + ?Sized>() {}
        _assert_send_sync::<dyn DocumentService>();
    }
}
