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
//!
//! # Usage
//!
//! ```rust,ignore
//! use jacs::document::{DocumentService, CreateOptions, DocumentVisibility, ListFilter};
//! use jacs::search::SearchQuery;
//!
//! // Obtain a DocumentService from your storage backend
//! let service: Box<dyn DocumentService> = /* backend-specific constructor */;
//!
//! // Create a document with default options (type="artifact", visibility=private)
//! let doc = service.create(r#"{"hello": "world"}"#, CreateOptions::default())?;
//!
//! // Create a public document with a specific type
//! let opts = CreateOptions {
//!     jacs_type: "agentstate".to_string(),
//!     visibility: DocumentVisibility::Public,
//!     custom_schema: None,
//! };
//! let state_doc = service.create(r#"{"memory": "important"}"#, opts)?;
//!
//! // Read by key (id:version)
//! let fetched = service.get(&format!("{}:{}", doc.id, doc.version))?;
//!
//! // Search documents (backend chooses fulltext, vector, or hybrid)
//! let results = service.search(SearchQuery {
//!     query: "hello".to_string(),
//!     ..SearchQuery::default()
//! })?;
//!
//! // List documents with filtering
//! let summaries = service.list(ListFilter {
//!     jacs_type: Some("artifact".to_string()),
//!     ..ListFilter::default()
//! })?;
//!
//! // Change visibility without re-signing
//! let key = format!("{}:{}", doc.id, doc.version);
//! service.set_visibility(&key, DocumentVisibility::Public)?;
//! ```
//!
//! # Implementing a Storage Backend
//!
//! To create a new storage backend, implement [`DocumentService`] and
//! optionally [`SearchProvider`](crate::search::SearchProvider):
//!
//! ```rust,ignore
//! use jacs::document::{DocumentService, CreateOptions, UpdateOptions, ListFilter,
//!     DocumentSummary, DocumentDiff, DocumentVisibility};
//! use jacs::agent::document::JACSDocument;
//! use jacs::search::{SearchQuery, SearchResults};
//! use jacs::error::JacsError;
//!
//! struct MyBackend { /* ... */ }
//!
//! impl DocumentService for MyBackend {
//!     fn create(&self, json: &str, options: CreateOptions) -> Result<JACSDocument, JacsError> {
//!         // Sign the document and persist to your storage
//!         todo!()
//!     }
//!     // ... implement remaining methods
//! }
//! ```

pub mod filesystem;
pub mod types;

pub use filesystem::FilesystemDocumentService;
pub use types::{
    CreateOptions, DocumentDiff, DocumentSummary, DocumentVisibility, ListFilter, UpdateOptions,
};

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::agent::loaders::{FileLoader, fetch_remote_public_key};
use crate::agent::{DOCUMENT_AGENT_SIGNATURE_FIELDNAME, SHA256_FIELDNAME};
use crate::config::{KeyResolutionSource, get_key_resolution_order};
use crate::error::JacsError;
use crate::search::{SearchQuery, SearchResults};
use crate::storage::MultiStorage;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

#[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
use crate::storage::SqliteDocumentService;

const SQLITE_DOCUMENT_DB_FILENAME: &str = "jacs_documents.sqlite3";

fn same_signer(current_agent_id: Option<&str>, signer_id: &str) -> bool {
    fn normalize(value: &str) -> &str {
        value.split(':').next().unwrap_or(value)
    }
    match current_agent_id {
        Some(agent_id) if !agent_id.is_empty() && !signer_id.is_empty() => {
            normalize(agent_id) == normalize(signer_id)
        }
        _ => false,
    }
}

fn document_signer_id(value: &serde_json::Value) -> Option<&str> {
    value
        .get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .and_then(|sig| sig.get("agentID"))
        .and_then(|id| id.as_str())
}

fn resolve_document_verification_key(
    agent: &mut Agent,
    value: &serde_json::Value,
) -> Result<(Vec<u8>, Option<String>), JacsError> {
    let signer_id = document_signer_id(value).unwrap_or_default();
    let current_agent_id = agent
        .get_value()
        .and_then(|agent_value| agent_value.get("jacsId"))
        .and_then(|id| id.as_str());

    if same_signer(current_agent_id, signer_id) {
        return Ok((agent.get_public_key()?, None));
    }

    let public_key_hash = value
        .get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .and_then(|sig| sig.get("publicKeyHash"))
        .and_then(|hash| hash.as_str())
        .unwrap_or_default()
        .to_string();
    let signer_version = value
        .get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .and_then(|sig| sig.get("agentVersion"))
        .and_then(|version| version.as_str())
        .unwrap_or_default()
        .to_string();

    let resolution_order = get_key_resolution_order();
    let mut last_error: Option<JacsError> = None;

    for source in &resolution_order {
        debug!("Resolving document verification key via {:?}", source);
        match source {
            KeyResolutionSource::Local => match agent.fs_load_public_key(&public_key_hash) {
                Ok(key) => {
                    let enc_type = agent.fs_load_public_key_type(&public_key_hash).ok();
                    return Ok((key, enc_type));
                }
                Err(err) => last_error = Some(err),
            },
            KeyResolutionSource::Dns => {
                // DNS validates key identity during signature verification.
                continue;
            }
            KeyResolutionSource::Registry => {
                if signer_id.is_empty() {
                    continue;
                }

                let requested_version = if signer_version.is_empty() {
                    "latest".to_string()
                } else {
                    signer_version.clone()
                };

                match fetch_remote_public_key(signer_id, &requested_version) {
                    Ok(key_info) => {
                        if !public_key_hash.is_empty()
                            && !key_info.hash.is_empty()
                            && key_info.hash != public_key_hash
                        {
                            warn!(
                                "Registry key hash mismatch for signer {}: expected {}..., got {}...",
                                signer_id,
                                &public_key_hash[..public_key_hash.len().min(16)],
                                &key_info.hash[..key_info.hash.len().min(16)]
                            );
                            last_error = Some(JacsError::VerificationClaimFailed {
                                claim: "registry".to_string(),
                                reason: format!(
                                    "Registry key hash mismatch for signer '{}'",
                                    signer_id
                                ),
                            });
                            continue;
                        }

                        return Ok((key_info.public_key, Some(key_info.algorithm)));
                    }
                    Err(err) => last_error = Some(err),
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        JacsError::DocumentError(format!(
            "Failed to resolve verification key for signer '{}'",
            signer_id
        ))
    }))
}

pub(crate) fn verify_document_with_agent(
    agent: &mut Agent,
    doc: &JACSDocument,
) -> Result<(), JacsError> {
    verify_document_value_with_agent(agent, &doc.value)
}

pub(crate) fn verify_document_value_with_agent(
    agent: &mut Agent,
    value: &serde_json::Value,
) -> Result<(), JacsError> {
    let _ = agent.verify_hash(value)?;
    agent.verify_document_files(value)?;
    let (public_key, public_key_enc_type) = resolve_document_verification_key(agent, value)?;
    agent.signature_verification_procedure(
        value,
        None,
        DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
        public_key,
        public_key_enc_type,
        None,
        None,
    )?;
    Ok(())
}

pub(crate) fn has_signed_document_headers(value: &serde_json::Value) -> bool {
    value.get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME).is_some() || value.get(SHA256_FIELDNAME).is_some()
}

pub fn sqlite_database_path(base_dir: &Path) -> PathBuf {
    base_dir.join(SQLITE_DOCUMENT_DB_FILENAME)
}

pub fn service_from_agent(agent: Arc<Mutex<Agent>>) -> Result<Arc<dyn DocumentService>, JacsError> {
    let (storage_type, base_dir) = {
        let agent_guard = agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let config = agent_guard
            .config
            .as_ref()
            .ok_or_else(|| JacsError::Internal {
                message: "Agent has no config; load an agent first".to_string(),
            })?;

        let data_dir = config
            .jacs_data_directory()
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "./jacs_data".to_string());
        let storage = config
            .jacs_default_storage()
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "fs".to_string());

        (storage, PathBuf::from(data_dir))
    };

    match storage_type.as_str() {
        "fs" => {
            let storage = MultiStorage::_new(storage_type, base_dir.clone())
                .map_err(|e| JacsError::StorageError(e.to_string()))?;
            Ok(Arc::new(FilesystemDocumentService::new(
                Arc::new(storage),
                agent,
                base_dir,
            )))
        }
        #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
        "rusqlite" | "sqlite" => {
            if let Some(parent) = base_dir.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|e| {
                    JacsError::StorageError(format!(
                        "Failed to create sqlite parent directory '{}': {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            std::fs::create_dir_all(&base_dir).map_err(|e| {
                JacsError::StorageError(format!(
                    "Failed to create data directory '{}': {}",
                    base_dir.display(),
                    e
                ))
            })?;
            let db_path = sqlite_database_path(&base_dir);
            let service = SqliteDocumentService::with_agent(&db_path.to_string_lossy(), agent)?;
            Ok(Arc::new(service))
        }
        unsupported => Err(JacsError::StorageError(format!(
            "DocumentService is not yet wired for storage backend '{}'",
            unsupported
        ))),
    }
}

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
    ///
    /// **Note:** This operation is NOT atomic. On partial failure, some
    /// documents may have been successfully persisted to storage before
    /// the error occurred. Those documents exist on disk but their handles
    /// are not returned. Implementations should log which documents
    /// succeeded to aid recovery.
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
    fn set_visibility(&self, key: &str, visibility: DocumentVisibility) -> Result<(), JacsError>;
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
