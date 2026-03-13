//! Filesystem-backed implementation of [`DocumentService`].
//!
//! Wraps the existing [`MultiStorage`](crate::storage::MultiStorage) (filesystem mode)
//! and an [`Agent`](crate::agent::Agent) for signing, providing the unified Document
//! API over the always-available filesystem backend.
//!
//! # Search
//!
//! The filesystem backend supports only exact key and prefix-based lookups.
//! [`search()`](DocumentService::search) scans document metadata for field matches
//! and returns [`SearchMethod::FieldMatch`](crate::search::SearchMethod::FieldMatch).
//!
//! # Visibility
//!
//! Visibility is read from and written to the `jacsVisibility` field in the
//! document JSON payload. Changing visibility creates a new signed version
//! to maintain provenance integrity.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing::warn;

use crate::agent::Agent;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::document::types::{
    CreateOptions, DocumentDiff, DocumentSummary, DocumentVisibility, ListFilter, UpdateOptions,
};
use crate::document::{
    DocumentService, has_signed_document_headers, verify_document_value_with_agent,
    verify_document_with_agent,
};
use crate::error::JacsError;
use crate::search::{
    SearchCapabilities, SearchHit, SearchMethod, SearchProvider, SearchQuery, SearchResults,
};
use crate::storage::{MultiStorage, StorageDocumentTraits};

/// Filesystem-backed [`DocumentService`] implementation.
///
/// This is the default document service for JACS — always available,
/// no feature flags required.  It delegates storage to [`MultiStorage`]
/// (configured for filesystem) and signing to an [`Agent`].
///
/// # Construction
///
/// ```rust,ignore
/// use jacs::document::filesystem::FilesystemDocumentService;
/// use jacs::storage::MultiStorage;
/// use std::sync::{Arc, Mutex};
///
/// let storage = MultiStorage::new("fs".to_string())?;
/// let agent: Agent = /* ... */;
/// let svc = FilesystemDocumentService::new(
///     Arc::new(storage),
///     Arc::new(Mutex::new(agent)),
///     PathBuf::from("./jacs_data"),
/// );
/// ```
pub struct FilesystemDocumentService {
    storage: Arc<MultiStorage>,
    agent: Arc<Mutex<Agent>>,
    /// Base directory for document storage. Documents are stored under
    /// `{base_dir}/documents/{id}:{version}.json`.
    base_dir: PathBuf,
}

// Send+Sync are derived automatically: Arc<MultiStorage>, Arc<Mutex<Agent>>,
// and PathBuf are all Send+Sync. No manual unsafe impl needed.

impl FilesystemDocumentService {
    /// Create a new filesystem document service.
    ///
    /// # Arguments
    ///
    /// * `storage` — A [`MultiStorage`] configured for filesystem mode.
    /// * `agent` — The JACS agent used for signing new document versions.
    /// * `base_dir` — The base directory for document storage (e.g., `./jacs_data`).
    pub fn new(storage: Arc<MultiStorage>, agent: Arc<Mutex<Agent>>, base_dir: PathBuf) -> Self {
        Self {
            storage,
            agent,
            base_dir,
        }
    }

    /// Helper: extract the document ID (without version) from a key.
    fn document_id_from_key(key: &str) -> &str {
        key.split(':').next().unwrap_or(key)
    }

    /// Helper: build a `DocumentSummary` from a `JACSDocument`.
    fn summarize(doc: &JACSDocument) -> DocumentSummary {
        let visibility = doc
            .value
            .get("jacsVisibility")
            .and_then(|v| serde_json::from_value::<DocumentVisibility>(v.clone()).ok())
            .unwrap_or_default();

        let created_at = doc
            .value
            .get("jacsVersionDate")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let agent_id = doc
            .value
            .pointer("/jacsSignature/agentID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        DocumentSummary {
            key: doc.getkey(),
            document_id: doc.id.clone(),
            version: doc.version.clone(),
            jacs_type: doc.jacs_type.clone(),
            visibility,
            created_at,
            agent_id,
        }
    }

    /// List all document keys from the filesystem `documents/` directory.
    ///
    /// This reads the directory directly rather than using ObjectStore's `list()`
    /// because ObjectStore returns absolute paths that don't match the relative
    /// prefix expected by `StorageDocumentTraits::list_documents()`.
    fn list_document_keys(&self) -> Result<Vec<String>, JacsError> {
        let docs_dir = self.base_dir.join("documents");
        if !docs_dir.exists() {
            return Ok(Vec::new());
        }

        let mut keys = Vec::new();
        let entries = std::fs::read_dir(&docs_dir).map_err(|e| {
            JacsError::StorageError(format!("Failed to read documents directory: {}", e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                JacsError::StorageError(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                // Skip archived documents
                if path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    == Some("archive")
                {
                    continue;
                }

                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    keys.push(stem.to_string());
                }
            }
        }

        Ok(keys)
    }

    /// List all document keys that belong to a specific document ID.
    ///
    /// A document key is `{id}:{version}`. This returns all keys where
    /// the ID portion matches `document_id`.
    fn version_keys_for(&self, document_id: &str) -> Result<Vec<String>, JacsError> {
        let all_keys = self.list_document_keys()?;
        let prefix = format!("{}:", document_id);
        Ok(all_keys
            .into_iter()
            .filter(|k| k.starts_with(&prefix))
            .collect())
    }
}

impl DocumentService for FilesystemDocumentService {
    fn create(&self, json: &str, options: CreateOptions) -> Result<JACSDocument, JacsError> {
        // Merge options into the JSON payload
        let mut value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| JacsError::DocumentError(e.to_string()))?;

        if let Some(obj) = value.as_object_mut() {
            obj.insert("jacsType".to_string(), serde_json::json!(options.jacs_type));
            // Set jacsLevel to "artifact" so documents are updatable via update_document().
            // The JACS schema requires jacsLevel to be one of EDITABLE_JACS_DOCS for updates.
            obj.insert("jacsLevel".to_string(), serde_json::json!("artifact"));
            let vis_value = serde_json::to_value(&options.visibility)
                .map_err(|e| JacsError::DocumentError(e.to_string()))?;
            obj.insert("jacsVisibility".to_string(), vis_value);
        }

        let doc_string =
            serde_json::to_string(&value).map_err(|e| JacsError::DocumentError(e.to_string()))?;

        // Sign the document via the Agent
        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let jacs_doc = agent
            .create_document_and_load(&doc_string, None, None)
            .map_err(|e| JacsError::DocumentError(format!("Failed to create document: {}", e)))?;

        verify_document_with_agent(&mut agent, &jacs_doc)?;

        // Store in filesystem
        self.storage
            .store_document(&jacs_doc)
            .map_err(|e| JacsError::StorageError(format!("Failed to store document: {}", e)))?;

        Ok(jacs_doc)
    }

    fn get(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let doc = self.storage.get_document(key).map_err(|e| {
            JacsError::StorageError(format!("Failed to get document '{}': {}", key, e))
        })?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        verify_document_with_agent(&mut agent, &doc)?;
        Ok(doc)
    }

    fn get_latest(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let version_keys = self.version_keys_for(document_id)?;

        if version_keys.is_empty() {
            return Err(JacsError::DocumentError(format!(
                "No documents found with ID: {}",
                document_id
            )));
        }

        // Find the version with the latest jacsVersionDate
        let mut latest_doc: Option<JACSDocument> = None;
        let mut latest_date = String::new();
        let mut latest_key = String::new();

        for key in version_keys {
            let doc = self.get(&key)?;
            let date = doc
                .value
                .get("jacsVersionDate")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if latest_doc.is_none()
                || date > latest_date
                || (date == latest_date && key > latest_key)
            {
                latest_date = date;
                latest_key = key;
                latest_doc = Some(doc);
            }
        }

        latest_doc.ok_or_else(|| {
            JacsError::DocumentError(format!("No documents found with ID: {}", document_id))
        })
    }

    fn update(
        &self,
        document_id: &str,
        new_json: &str,
        options: UpdateOptions,
    ) -> Result<JACSDocument, JacsError> {
        // Get the latest version to link to
        let current = self.get_latest(document_id)?;
        let current_key = current.getkey();

        // Build the updated document payload.
        // Agent::update_document() requires the new document to have the SAME
        // jacsId and jacsVersion as the old one — it then assigns a new version.
        let mut value: serde_json::Value =
            serde_json::from_str(new_json).map_err(|e| JacsError::DocumentError(e.to_string()))?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        if has_signed_document_headers(&value) {
            verify_document_value_with_agent(&mut agent, &value)?;
        }

        if let Some(obj) = value.as_object_mut() {
            // Must match the current document's ID and version for update_document
            obj.insert(
                "jacsId".to_string(),
                current
                    .value
                    .get("jacsId")
                    .cloned()
                    .unwrap_or(serde_json::json!(document_id)),
            );
            obj.insert(
                "jacsVersion".to_string(),
                current
                    .value
                    .get("jacsVersion")
                    .cloned()
                    .unwrap_or(serde_json::json!(current.version)),
            );

            // Preserve jacsType
            obj.insert("jacsType".to_string(), serde_json::json!(current.jacs_type));

            // Set jacsLevel to "artifact" for editability
            obj.insert("jacsLevel".to_string(), serde_json::json!("artifact"));

            // Apply visibility
            if let Some(ref vis) = options.visibility {
                let vis_value = serde_json::to_value(vis)
                    .map_err(|e| JacsError::DocumentError(e.to_string()))?;
                obj.insert("jacsVisibility".to_string(), vis_value);
            } else if let Some(existing_vis) = current.value.get("jacsVisibility") {
                obj.insert("jacsVisibility".to_string(), existing_vis.clone());
            }

            // Preserve other JACS header fields from the original
            for field in &[
                "$schema",
                "jacsOriginalVersion",
                "jacsOriginalDate",
                "jacsSha256",
                "jacsSignature",
                "jacsVersionDate",
            ] {
                if let Some(val) = current.value.get(*field) {
                    obj.entry(field.to_string()).or_insert(val.clone());
                }
            }
        }

        let doc_string =
            serde_json::to_string(&value).map_err(|e| JacsError::DocumentError(e.to_string()))?;

        // Use Agent::update_document to create a new version with the same ID
        // First, load the current document into the Agent's in-memory store
        // so update_document can find it
        let _ = agent.load_document(
            &serde_json::to_string(&current.value)
                .map_err(|e| JacsError::DocumentError(e.to_string()))?,
        );

        let new_doc = agent
            .update_document(&current_key, &doc_string, None, None)
            .map_err(|e| JacsError::DocumentError(format!("Failed to update document: {}", e)))?;

        verify_document_with_agent(&mut agent, &new_doc)?;

        // Store the new version on the filesystem
        self.storage.store_document(&new_doc).map_err(|e| {
            JacsError::StorageError(format!("Failed to store updated document: {}", e))
        })?;

        Ok(new_doc)
    }

    fn remove(&self, key: &str) -> Result<JACSDocument, JacsError> {
        self.storage.remove_document(key).map_err(|e| {
            JacsError::StorageError(format!("Failed to remove document '{}': {}", key, e))
        })
    }

    fn list(&self, filter: ListFilter) -> Result<Vec<DocumentSummary>, JacsError> {
        let keys = self.list_document_keys()?;

        let mut summaries = Vec::new();
        for key in &keys {
            if let Ok(doc) = self.get(key) {
                let summary = Self::summarize(&doc);

                // Apply filters
                if let Some(ref jacs_type) = filter.jacs_type {
                    if &summary.jacs_type != jacs_type {
                        continue;
                    }
                }
                if let Some(ref agent_id) = filter.agent_id {
                    if &summary.agent_id != agent_id {
                        continue;
                    }
                }
                if let Some(ref visibility) = filter.visibility {
                    if &summary.visibility != visibility {
                        continue;
                    }
                }

                summaries.push(summary);
            }
        }

        // Apply pagination
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(summaries.len());
        let paginated: Vec<DocumentSummary> =
            summaries.into_iter().skip(offset).take(limit).collect();

        Ok(paginated)
    }

    fn versions(&self, document_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let version_keys = self.version_keys_for(document_id)?;

        let mut docs = Vec::new();
        for key in version_keys {
            let doc = self.get(&key)?;
            docs.push(doc);
        }

        // Sort by creation date
        docs.sort_by(|a, b| {
            let date_a = a
                .value
                .get("jacsVersionDate")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let date_b = b
                .value
                .get("jacsVersionDate")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            date_a.cmp(date_b)
        });

        Ok(docs)
    }

    fn diff(&self, key_a: &str, key_b: &str) -> Result<DocumentDiff, JacsError> {
        let doc_a = self.get(key_a)?;
        let doc_b = self.get(key_b)?;

        let json_a = serde_json::to_string_pretty(&doc_a.value)
            .map_err(|e| JacsError::DocumentError(e.to_string()))?;
        let json_b = serde_json::to_string_pretty(&doc_b.value)
            .map_err(|e| JacsError::DocumentError(e.to_string()))?;

        // Simple line-by-line diff
        let lines_a: Vec<&str> = json_a.lines().collect();
        let lines_b: Vec<&str> = json_b.lines().collect();

        let mut diff_text = String::new();
        let mut additions = 0usize;
        let mut deletions = 0usize;

        for line in &lines_a {
            if !lines_b.contains(line) {
                diff_text.push_str(&format!("- {}\n", line));
                deletions += 1;
            }
        }
        for line in &lines_b {
            if !lines_a.contains(line) {
                diff_text.push_str(&format!("+ {}\n", line));
                additions += 1;
            }
        }

        Ok(DocumentDiff {
            key_a: key_a.to_string(),
            key_b: key_b.to_string(),
            diff_text,
            additions,
            deletions,
        })
    }

    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError> {
        // NOTE: `query.min_score` is intentionally ignored by this backend.
        // The filesystem backend assigns `score: 1.0` to all matches (FieldMatch),
        // so filtering by min_score would never exclude results. Backends with
        // ranked scoring (FullText, Vector, Hybrid) should respect min_score.
        let all_keys = self.list_document_keys()?;

        let mut hits = Vec::new();

        for key in &all_keys {
            if let Ok(doc) = self.get(key) {
                let mut matched = false;
                let mut matched_fields = Vec::new();

                // Filter by jacs_type if specified
                if let Some(ref jacs_type) = query.jacs_type {
                    if &doc.jacs_type != jacs_type {
                        continue;
                    }
                }

                // Filter by agent_id if specified
                if let Some(ref agent_id) = query.agent_id {
                    let doc_agent = doc
                        .value
                        .pointer("/jacsSignature/agentID")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if doc_agent != agent_id {
                        continue;
                    }
                }

                // Field filter: exact match on a specific field path
                if let Some(ref field_filter) = query.field_filter {
                    let field_value = doc
                        .value
                        .pointer(&format!("/{}", field_filter.field_path.replace('.', "/")))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if field_value == field_filter.value {
                        matched = true;
                        matched_fields.push(field_filter.field_path.clone());
                    } else {
                        continue;
                    }
                }

                // Query string: match against document content
                if !query.query.is_empty() {
                    let doc_str = doc.value.to_string().to_lowercase();
                    let query_lower = query.query.to_lowercase();
                    if doc_str.contains(&query_lower) || key.contains(&query.query) {
                        matched = true;
                        matched_fields.push("content".to_string());
                    } else if !matched {
                        continue;
                    }
                } else if !matched {
                    // No query string and no field filter = include all
                    matched = true;
                }

                if matched {
                    hits.push(SearchHit {
                        document: doc,
                        score: 1.0,
                        matched_fields,
                    });
                }
            }
        }

        let total_count = hits.len();

        let paginated: Vec<SearchHit> = hits
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();

        Ok(SearchResults {
            results: paginated,
            total_count,
            method: SearchMethod::FieldMatch,
        })
    }

    fn create_batch(
        &self,
        documents: &[&str],
        options: CreateOptions,
    ) -> Result<Vec<JACSDocument>, Vec<JacsError>> {
        let mut created = Vec::new();
        let mut errors = Vec::new();

        for (idx, json) in documents.iter().enumerate() {
            match self.create(json, options.clone()) {
                Ok(doc) => created.push(doc),
                Err(e) => {
                    warn!(
                        "create_batch: document at index {} failed: {}. \
                         {} document(s) already created and stored on disk.",
                        idx,
                        e,
                        created.len()
                    );
                    errors.push(e);
                }
            }
        }

        if errors.is_empty() {
            Ok(created)
        } else {
            // NOTE: This is NOT atomic. On partial failure, `created.len()` documents
            // have already been persisted to disk but their handles are not returned
            // to the caller. The successfully created document IDs are logged above
            // at WARN level for recovery. The trait signature
            // `Result<Vec<JACSDocument>, Vec<JacsError>>` cannot represent partial
            // success — a `BatchResult { created, errors }` return type would be
            // needed for that (tracked as a future improvement).
            warn!(
                "create_batch: returning {} error(s); {} document(s) were successfully \
                 created and persisted but their handles are being dropped. \
                 Created IDs: {:?}",
                errors.len(),
                created.len(),
                created.iter().map(|d| d.getkey()).collect::<Vec<_>>()
            );
            Err(errors)
        }
    }

    fn visibility(&self, key: &str) -> Result<DocumentVisibility, JacsError> {
        let doc = self.get(key)?;
        let vis = doc
            .value
            .get("jacsVisibility")
            .and_then(|v| serde_json::from_value::<DocumentVisibility>(v.clone()).ok())
            .unwrap_or_default();
        Ok(vis)
    }

    fn set_visibility(&self, key: &str, visibility: DocumentVisibility) -> Result<(), JacsError> {
        let doc = self.get(key)?;
        let document_id = Self::document_id_from_key(key);

        // Create a new version with updated visibility
        let mut new_value = doc.value.clone();
        if let Some(obj) = new_value.as_object_mut() {
            let vis_value = serde_json::to_value(&visibility)
                .map_err(|e| JacsError::DocumentError(e.to_string()))?;
            obj.insert("jacsVisibility".to_string(), vis_value);
        }

        let new_json = serde_json::to_string(&new_value)
            .map_err(|e| JacsError::DocumentError(e.to_string()))?;

        self.update(
            document_id,
            &new_json,
            UpdateOptions {
                visibility: Some(visibility),
                ..Default::default()
            },
        )?;

        Ok(())
    }
}

// =============================================================================
// SearchProvider implementation
// =============================================================================

impl SearchProvider for FilesystemDocumentService {
    /// Delegates to [`DocumentService::search()`] — the filesystem backend
    /// uses the same field-match scan for both traits.
    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError> {
        DocumentService::search(self, query)
    }

    /// Reports filesystem search capabilities: only field-level filtering.
    fn capabilities(&self) -> SearchCapabilities {
        SearchCapabilities {
            fulltext: false,
            vector: false,
            hybrid: false,
            field_filter: true,
        }
    }
}
