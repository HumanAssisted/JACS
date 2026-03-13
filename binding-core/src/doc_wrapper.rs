//! `DocumentServiceWrapper` — JSON-in/JSON-out adapter for the unified Document API.
//!
//! This module wraps `dyn DocumentService` with FFI-safe methods that
//! accept and return JSON strings.  Zero business logic — pure marshaling.

use std::sync::Arc;

use crate::{BindingCoreError, BindingResult};
use jacs::document::DocumentService;
use jacs::document::types::{CreateOptions, ListFilter, UpdateOptions};

/// Thread-safe, Clone-able FFI wrapper for the unified Document API.
///
/// All methods accept JSON strings and return JSON strings, making them
/// suitable for consumption from Python, Node.js, Go, and other FFI callers.
#[derive(Clone)]
pub struct DocumentServiceWrapper {
    inner: Arc<dyn DocumentService>,
}

// Compile-time proof of thread safety.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<DocumentServiceWrapper>();
    }
};

impl DocumentServiceWrapper {
    /// Create a wrapper from a boxed `DocumentService`.
    pub fn new(service: Box<dyn DocumentService>) -> Self {
        Self {
            inner: Arc::from(service),
        }
    }

    /// Create a wrapper from an `Arc<dyn DocumentService>`.
    pub fn from_arc(service: Arc<dyn DocumentService>) -> Self {
        Self { inner: service }
    }

    /// Create a wrapper from an `AgentWrapper` using the filesystem backend.
    ///
    /// This is the typical construction path for language bindings:
    /// load an agent, then create a document service from it.
    pub fn from_agent_wrapper(wrapper: &crate::AgentWrapper) -> BindingResult<Self> {
        let agent_arc = wrapper.inner_arc();

        // Extract storage and data directory from the agent's config.
        let (storage, base_dir) = {
            let agent = agent_arc.lock().map_err(|e| {
                BindingCoreError::lock_failed(format!("Failed to lock agent: {}", e))
            })?;

            let config = agent.config.as_ref().ok_or_else(|| {
                BindingCoreError::agent_load(
                    "Agent has no config — load an agent first".to_string(),
                )
            })?;

            let data_dir = config
                .jacs_data_directory()
                .as_ref()
                .cloned()
                .unwrap_or_else(|| "./jacs_data".to_string());

            let storage_type = config
                .jacs_default_storage()
                .as_ref()
                .cloned()
                .unwrap_or_else(|| "fs".to_string());

            let storage = jacs::storage::MultiStorage::new(storage_type).map_err(|e| {
                BindingCoreError::generic(format!("Failed to create storage: {}", e))
            })?;

            (storage, std::path::PathBuf::from(data_dir))
        };

        let fs_service =
            jacs::document::FilesystemDocumentService::new(Arc::new(storage), agent_arc, base_dir);

        Ok(Self::new(Box::new(fs_service)))
    }

    // =========================================================================
    // CRUD — JSON-in/JSON-out
    // =========================================================================

    /// Create a new document. Returns the signed document as JSON.
    ///
    /// `options_json` is an optional JSON string of `CreateOptions`.
    /// If `None`, defaults are used.
    pub fn create_json(&self, json: &str, options_json: Option<&str>) -> BindingResult<String> {
        let options: CreateOptions = match options_json {
            Some(opts) => serde_json::from_str(opts).map_err(|e| {
                BindingCoreError::invalid_argument(format!("Invalid CreateOptions JSON: {}", e))
            })?,
            None => CreateOptions::default(),
        };

        let doc = self.inner.create(json, options).map_err(|e| {
            BindingCoreError::document_failed(format!("Document create failed: {}", e))
        })?;

        serde_json::to_string(&doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize created document: {}",
                e
            ))
        })
    }

    /// Get a document by key (`id:version`). Returns the document JSON.
    pub fn get_json(&self, key: &str) -> BindingResult<String> {
        let doc = self.inner.get(key).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to get document '{}': {}", key, e))
        })?;

        serde_json::to_string(&doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize document '{}': {}",
                key, e
            ))
        })
    }

    /// Get the latest version of a document. Returns the document JSON.
    pub fn get_latest_json(&self, document_id: &str) -> BindingResult<String> {
        let doc = self.inner.get_latest(document_id).map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to get latest version of '{}': {}",
                document_id, e
            ))
        })?;

        serde_json::to_string(&doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize document '{}': {}",
                document_id, e
            ))
        })
    }

    /// Update a document, creating a new signed version. Returns the new version JSON.
    ///
    /// `options_json` is an optional JSON string of `UpdateOptions`.
    pub fn update_json(
        &self,
        document_id: &str,
        new_json: &str,
        options_json: Option<&str>,
    ) -> BindingResult<String> {
        let options: UpdateOptions = match options_json {
            Some(opts) => serde_json::from_str(opts).map_err(|e| {
                BindingCoreError::invalid_argument(format!("Invalid UpdateOptions JSON: {}", e))
            })?,
            None => UpdateOptions::default(),
        };

        let doc = self
            .inner
            .update(document_id, new_json, options)
            .map_err(|e| {
                BindingCoreError::document_failed(format!(
                    "Failed to update document '{}': {}",
                    document_id, e
                ))
            })?;

        serde_json::to_string(&doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize updated document: {}",
                e
            ))
        })
    }

    /// Remove (tombstone) a document. Returns the tombstoned document JSON.
    pub fn remove_json(&self, key: &str) -> BindingResult<String> {
        let doc = self.inner.remove(key).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to remove document '{}': {}", key, e))
        })?;

        serde_json::to_string(&doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize removed document: {}",
                e
            ))
        })
    }

    /// List documents with optional filter. Returns JSON array of `DocumentSummary`.
    ///
    /// `filter_json` is an optional JSON string of `ListFilter`.
    pub fn list_json(&self, filter_json: Option<&str>) -> BindingResult<String> {
        let filter: ListFilter = match filter_json {
            Some(f) => serde_json::from_str(f).map_err(|e| {
                BindingCoreError::invalid_argument(format!("Invalid ListFilter JSON: {}", e))
            })?,
            None => ListFilter::default(),
        };

        let summaries = self.inner.list(filter).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to list documents: {}", e))
        })?;

        serde_json::to_string(&summaries).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize document list: {}",
                e
            ))
        })
    }

    // =========================================================================
    // Search
    // =========================================================================

    /// Search documents. Returns JSON `SearchResults`.
    ///
    /// `query_json` is a JSON string of `SearchQuery`.
    pub fn search_json(&self, query_json: &str) -> BindingResult<String> {
        let query: jacs::search::SearchQuery = serde_json::from_str(query_json).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid SearchQuery JSON: {}", e))
        })?;

        let results = self.inner.search(query).map_err(|e| {
            BindingCoreError::document_failed(format!("Document search failed: {}", e))
        })?;

        serde_json::to_string(&results).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize search results: {}",
                e
            ))
        })
    }

    // =========================================================================
    // Versions
    // =========================================================================

    /// Get all versions of a document. Returns JSON array of documents.
    pub fn versions_json(&self, document_id: &str) -> BindingResult<String> {
        let docs = self.inner.versions(document_id).map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to get versions of '{}': {}",
                document_id, e
            ))
        })?;

        let values: Vec<_> = docs.iter().map(|d| &d.value).collect();
        serde_json::to_string(&values).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize document versions: {}",
                e
            ))
        })
    }

    /// Diff two document versions. Returns JSON `DocumentDiff`.
    pub fn diff_json(&self, key_a: &str, key_b: &str) -> BindingResult<String> {
        let diff = self.inner.diff(key_a, key_b).map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to diff '{}' and '{}': {}",
                key_a, key_b, e
            ))
        })?;

        serde_json::to_string(&diff).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize diff: {}", e))
        })
    }

    // =========================================================================
    // Visibility
    // =========================================================================

    /// Get the visibility of a document. Returns JSON string (`"public"`, `"private"`, etc.).
    pub fn visibility_json(&self, key: &str) -> BindingResult<String> {
        let vis = self.inner.visibility(key).map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to get visibility of '{}': {}",
                key, e
            ))
        })?;

        serde_json::to_string(&vis).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize visibility: {}", e))
        })
    }

    /// Set the visibility of a document.
    ///
    /// `visibility_json` is a JSON string (e.g., `"public"`, `"private"`,
    /// `{"restricted":["agent-a"]}`).
    pub fn set_visibility_json(&self, key: &str, visibility_json: &str) -> BindingResult<()> {
        let vis: jacs::document::DocumentVisibility = serde_json::from_str(visibility_json)
            .map_err(|e| {
                BindingCoreError::invalid_argument(format!(
                    "Invalid DocumentVisibility JSON: {}",
                    e
                ))
            })?;

        self.inner.set_visibility(key, vis).map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to set visibility on '{}': {}",
                key, e
            ))
        })
    }
}
