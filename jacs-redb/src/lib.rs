//! Redb embedded key-value storage backend for JACS documents.
//!
//! This crate provides a pure-Rust embedded KV storage backend for JACS
//! documents using [redb](https://docs.rs/redb). No C bindings, no external
//! services required.
//!
//! Uses manual secondary index tables:
//! - `documents`: primary store, `"id:version"` -> JSON bytes
//! - `type_index`: `"type\0id:version"` -> `[]`
//! - `agent_index`: `"agent_id\0id:version"` -> `[]`
//! - `version_index`: `"id\0created_at\0version"` -> `[]`
//! - `tombstone_index`: `"id:version"` -> `[]` (soft-delete markers)
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new entries
//! keyed by `(id, version)`. Idempotent inserts skip if key exists.
//!
//! # Search
//!
//! Redb has no native fulltext or vector search. The [`SearchProvider`]
//! implementation reports all capabilities as `false` and returns
//! `Err(JacsError::StorageError(...))` from `search()`.
//!
//! # Example
//!
//! ```rust,no_run
//! use jacs_redb::RedbStorage;
//! use jacs::storage::StorageDocumentTraits;
//! use jacs::storage::database_traits::DatabaseDocumentTraits;
//!
//! let storage = RedbStorage::in_memory().expect("create in-memory redb");
//! storage.run_migrations().expect("run migrations");
//! ```

use jacs::agent::document::JACSDocument;
use jacs::error::JacsError;
use jacs::search::{SearchCapabilities, SearchProvider, SearchQuery, SearchResults};
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::Value;
use std::error::Error;

/// Primary table: `"id:version"` -> serialized JACSDocument JSON bytes.
const DOCUMENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("documents");

/// Secondary index: `"type\0id:version"` -> empty bytes (for query_by_type).
const TYPE_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("type_index");

/// Secondary index: `"agent_id\0id:version"` -> empty bytes (for query_by_agent).
const AGENT_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("agent_index");

/// Ordering index: `"id\0created_at\0version"` -> empty bytes (for get_versions, get_latest).
const VERSION_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("version_index");

/// Tombstone index: `"id:version"` -> empty bytes (marks soft-deleted documents).
const TOMBSTONE_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("tombstone_index");

/// Redb storage backend for JACS documents.
pub struct RedbStorage {
    db: Database,
}

impl RedbStorage {
    /// Create a new RedbStorage connected to the given file path.
    pub fn new(path: &str) -> Result<Self, JacsError> {
        let db = Database::create(path).map_err(|e| JacsError::DatabaseError {
            operation: "create".to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self { db })
    }

    /// Create an in-memory Redb database (useful for tests).
    pub fn in_memory() -> Result<Self, JacsError> {
        let backend = redb::backends::InMemoryBackend::new();
        let db = Database::builder()
            .create_with_backend(backend)
            .map_err(|e| JacsError::DatabaseError {
                operation: "create_in_memory".to_string(),
                reason: e.to_string(),
            })?;
        Ok(Self { db })
    }

    /// Parse a document key in format `"id:version"` into `(id, version)`.
    fn parse_key(key: &str) -> Result<(&str, &str), JacsError> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid document key '{}': expected 'id:version'", key).into());
        }
        Ok((parts[0], parts[1]))
    }

    /// Deserialize JSON bytes into a JACSDocument.
    fn bytes_to_document(bytes: &[u8]) -> Result<JACSDocument, JacsError> {
        let value: Value = serde_json::from_slice(bytes)?;

        let id = value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .ok_or("Document missing required field: jacsId")?
            .to_string();
        let version = value
            .get("jacsVersion")
            .and_then(|v| v.as_str())
            .ok_or("Document missing required field: jacsVersion")?
            .to_string();
        let jacs_type = value
            .get("jacsType")
            .and_then(|v| v.as_str())
            .ok_or("Document missing required field: jacsType")?
            .to_string();

        Ok(JACSDocument {
            id,
            version,
            value,
            jacs_type,
        })
    }

    /// Extract agent_id from a document's JSON value, if present.
    fn extract_agent_id(value: &Value) -> Option<String> {
        value
            .get("jacsSignature")
            .and_then(|s| s.get("jacsSignatureAgentId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Collect all document keys matching a prefix in an index table.
    /// Index keys are formatted as `"prefix\0id:version"`.
    fn collect_keys_from_index(
        &self,
        table_def: TableDefinition<&str, &[u8]>,
        prefix: &str,
    ) -> Result<Vec<String>, JacsError> {
        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;

        let table = read_txn.open_table(table_def);
        let table = match table {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(db_err_box("open_table", e)),
        };

        let range_start = format!("{}\0", prefix);
        let range_end = format!("{}\x01", prefix);

        let mut keys = Vec::new();
        let iter = table
            .range(range_start.as_str()..range_end.as_str())
            .map_err(db_err("range_scan"))?;

        for entry in iter {
            let (key_guard, _) = entry.map_err(db_err("iterate"))?;
            let index_key = key_guard.value();
            if let Some(pos) = index_key.find('\0') {
                keys.push(index_key[pos + 1..].to_string());
            }
        }

        Ok(keys)
    }

    /// Check whether a document key has been tombstoned (soft-deleted).
    fn is_tombstoned(&self, key: &str) -> Result<bool, JacsError> {
        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;
        let table = read_txn.open_table(TOMBSTONE_INDEX);
        let table = match table {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(db_err_box("open_table", e)),
        };
        Ok(table.get(key).map_err(db_err("check_tombstone"))?.is_some())
    }

    /// Filter out any tombstoned keys from a list.
    fn filter_tombstoned(&self, keys: Vec<String>) -> Result<Vec<String>, JacsError> {
        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;
        let table = read_txn.open_table(TOMBSTONE_INDEX);
        let table = match table {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(keys),
            Err(e) => return Err(db_err_box("open_table", e)),
        };

        Ok(keys
            .into_iter()
            .filter(|k| !table.get(k.as_str()).ok().flatten().is_some())
            .collect())
    }
}

impl StorageDocumentTraits for RedbStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
        let key = doc.getkey();
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let json_bytes = raw_json.as_bytes();
        let agent_id = Self::extract_agent_id(&doc.value);
        let created_at = chrono::Utc::now().to_rfc3339();

        let write_txn = self.db.begin_write().map_err(db_err("begin_write"))?;

        {
            let mut doc_table = write_txn
                .open_table(DOCUMENTS)
                .map_err(db_err("open_table"))?;

            // Idempotent: skip if already exists
            if doc_table
                .get(key.as_str())
                .map_err(db_err("check_exists"))?
                .is_some()
            {
                return Ok(());
            }

            doc_table
                .insert(key.as_str(), json_bytes)
                .map_err(db_err("insert_document"))?;

            // Type index
            let mut type_table = write_txn
                .open_table(TYPE_INDEX)
                .map_err(db_err("open_type_index"))?;
            let type_key = format!("{}\0{}", doc.jacs_type, key);
            type_table
                .insert(type_key.as_str(), &[] as &[u8])
                .map_err(db_err("insert_type_index"))?;

            // Agent index
            if let Some(ref aid) = agent_id {
                let mut agent_table = write_txn
                    .open_table(AGENT_INDEX)
                    .map_err(db_err("open_agent_index"))?;
                let agent_key = format!("{}\0{}", aid, key);
                agent_table
                    .insert(agent_key.as_str(), &[] as &[u8])
                    .map_err(db_err("insert_agent_index"))?;
            }

            // Version index: "id\0created_at\0version"
            let mut version_table = write_txn
                .open_table(VERSION_INDEX)
                .map_err(db_err("open_version_index"))?;
            let version_key = format!("{}\0{}\0{}", doc.id, created_at, doc.version);
            version_table
                .insert(version_key.as_str(), &[] as &[u8])
                .map_err(db_err("insert_version_index"))?;
        }

        write_txn.commit().map_err(db_err("commit"))?;
        Ok(())
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let (_id, _version) = Self::parse_key(key)?;

        // Check tombstone first — soft-deleted documents appear as "not found"
        if self.is_tombstoned(key)? {
            return Err(db_err_box(
                "get_document",
                format!("Document not found: {}", key),
            ));
        }

        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;
        let table = read_txn
            .open_table(DOCUMENTS)
            .map_err(db_err("open_table"))?;

        let guard =
            table
                .get(key)
                .map_err(db_err("get_document"))?
                .ok_or_else(|| {
                    db_err_box("get_document", format!("Document not found: {}", key))
                })?;

        Self::bytes_to_document(guard.value())
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        // Fetch the document first (this also checks it exists and is not already tombstoned)
        let doc = self.get_document(key)?;

        // Soft-delete: add the key to the tombstone index, leave document and indexes intact
        let write_txn = self.db.begin_write().map_err(db_err("begin_write"))?;
        {
            let mut tombstone_table = write_txn
                .open_table(TOMBSTONE_INDEX)
                .map_err(db_err("open_tombstone_index"))?;
            tombstone_table
                .insert(key, &[] as &[u8])
                .map_err(db_err("insert_tombstone"))?;
        }
        write_txn.commit().map_err(db_err("commit"))?;

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, JacsError> {
        let keys = self.collect_keys_from_index(TYPE_INDEX, prefix)?;
        self.filter_tombstoned(keys)
    }

    fn document_exists(&self, key: &str) -> Result<bool, JacsError> {
        let (_id, _version) = Self::parse_key(key)?;

        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;

        let table = read_txn.open_table(DOCUMENTS);
        let table = match table {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(db_err_box("open_table", e)),
        };

        let exists = table.get(key).map_err(db_err("document_exists"))?.is_some();
        if exists && self.is_tombstoned(key)? {
            return Ok(false);
        }
        Ok(exists)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError> {
        let keys = self.collect_keys_from_index(AGENT_INDEX, agent_id)?;
        self.filter_tombstoned(keys)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, JacsError> {
        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;

        let table = read_txn.open_table(VERSION_INDEX);
        let table = match table {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(db_err_box("open_table", e)),
        };

        let prefix = format!("{}\0", document_id);
        let range_end = format!("{}\x01", document_id);

        let mut keys = Vec::new();
        let iter = table
            .range(prefix.as_str()..range_end.as_str())
            .map_err(db_err("range_scan"))?;

        for entry in iter {
            let (key_guard, _) = entry.map_err(db_err("iterate"))?;
            let index_key = key_guard.value();
            // Key format: "id\0created_at\0version"
            let parts: Vec<&str> = index_key.splitn(3, '\0').collect();
            if parts.len() == 3 {
                keys.push(format!("{}:{}", parts[0], parts[2]));
            }
        }

        self.filter_tombstoned(keys)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let versions = self.get_document_versions(document_id)?;

        if versions.is_empty() {
            return Err(db_err_box(
                "get_latest_document",
                format!("No documents found with ID: {}", document_id),
            ));
        }

        // Versions are ordered by created_at ASC. The last one is the latest.
        let latest_key = versions.last().unwrap();
        self.get_document(latest_key)
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, JacsError> {
        Err(db_err_box(
            "merge_documents",
            "Not implemented for Redb backend",
        ))
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<JacsError>> {
        let mut errors = Vec::new();
        let mut keys = Vec::new();
        for doc in &docs {
            let key = doc.getkey();
            match self.store_document(doc) {
                Ok(_) => keys.push(key),
                Err(e) => errors.push(e),
            }
        }
        if errors.is_empty() {
            Ok(keys)
        } else {
            Err(errors)
        }
    }

    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<JacsError>> {
        let mut docs = Vec::new();
        let mut errors = Vec::new();
        for key in &keys {
            match self.get_document(key) {
                Ok(doc) => docs.push(doc),
                Err(e) => errors.push(e),
            }
        }
        if errors.is_empty() {
            Ok(docs)
        } else {
            Err(errors)
        }
    }
}

impl DatabaseDocumentTraits for RedbStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
        let keys = self.collect_keys_from_index(TYPE_INDEX, jacs_type)?;
        let keys = self.filter_tombstoned(keys)?;
        let mut docs = Vec::new();
        for key in keys.into_iter().skip(offset).take(limit) {
            docs.push(self.get_document(&key)?);
        }
        Ok(docs)
    }

    fn query_by_field(
        &self,
        field_path: &str,
        value: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;

        let doc_table = read_txn
            .open_table(DOCUMENTS)
            .map_err(db_err("open_table"))?;

        let mut results = Vec::new();
        let mut skipped = 0usize;

        let iter = doc_table.iter().map_err(db_err("iter"))?;

        for entry in iter {
            let (key_guard, value_guard) = entry.map_err(db_err("iterate"))?;

            // Skip tombstoned documents
            if self.is_tombstoned(key_guard.value())? {
                continue;
            }

            let doc = Self::bytes_to_document(value_guard.value())?;

            if let Some(t) = jacs_type {
                if doc.jacs_type != t {
                    continue;
                }
            }

            if let Some(fv) = get_nested_field(&doc.value, field_path) {
                let matches = match fv {
                    Value::String(s) => s == value,
                    other => other.to_string().trim_matches('"') == value,
                };
                if matches {
                    if skipped < offset {
                        skipped += 1;
                        continue;
                    }
                    results.push(doc);
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(results)
    }

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, JacsError> {
        let keys = self.collect_keys_from_index(TYPE_INDEX, jacs_type)?;
        let keys = self.filter_tombstoned(keys)?;
        Ok(keys.len())
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let keys = self.get_document_versions(jacs_id)?;
        let mut docs = Vec::new();
        for key in keys {
            docs.push(self.get_document(&key)?);
        }
        Ok(docs)
    }

    fn get_latest(&self, jacs_id: &str) -> Result<JACSDocument, JacsError> {
        self.get_latest_document(jacs_id)
    }

    fn query_by_agent(
        &self,
        agent_id: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
        let keys = self.collect_keys_from_index(AGENT_INDEX, agent_id)?;
        let keys = self.filter_tombstoned(keys)?;
        let mut results = Vec::new();
        let mut skipped = 0usize;

        for key in keys {
            let doc = self.get_document(&key)?;

            if let Some(t) = jacs_type {
                if doc.jacs_type != t {
                    continue;
                }
            }

            if skipped < offset {
                skipped += 1;
                continue;
            }

            results.push(doc);
            if results.len() >= limit {
                break;
            }
        }

        Ok(results)
    }

    fn run_migrations(&self) -> Result<(), JacsError> {
        let write_txn = self.db.begin_write().map_err(db_err("begin_write"))?;

        {
            let _t = write_txn
                .open_table(DOCUMENTS)
                .map_err(db_err("create_documents_table"))?;
            let _t = write_txn
                .open_table(TYPE_INDEX)
                .map_err(db_err("create_type_index"))?;
            let _t = write_txn
                .open_table(AGENT_INDEX)
                .map_err(db_err("create_agent_index"))?;
            let _t = write_txn
                .open_table(VERSION_INDEX)
                .map_err(db_err("create_version_index"))?;
            let _t = write_txn
                .open_table(TOMBSTONE_INDEX)
                .map_err(db_err("create_tombstone_index"))?;
        }

        write_txn.commit().map_err(db_err("commit_migrations"))?;

        Ok(())
    }
}

// =============================================================================
// SearchProvider implementation (no-op — Redb has no native search)
// =============================================================================

impl SearchProvider for RedbStorage {
    /// Redb does not support search. Returns an error indicating search is not supported.
    fn search(&self, _query: SearchQuery) -> Result<SearchResults, JacsError> {
        Err(JacsError::StorageError(
            "search not supported by redb backend".to_string(),
        ))
    }

    /// Reports that no search capabilities are available.
    fn capabilities(&self) -> SearchCapabilities {
        SearchCapabilities::none()
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Traverse a JSON value by a dot-separated field path.
fn get_nested_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Helper to create a closure that maps any Display error to a DatabaseError.
fn db_err<E: std::fmt::Display>(operation: &'static str) -> impl FnOnce(E) -> JacsError {
    move |e: E| -> JacsError {
        JacsError::DatabaseError {
            operation: operation.to_string(),
            reason: e.to_string(),
        }
    }
}

/// Helper to create a DatabaseError directly from an operation and reason.
fn db_err_box(operation: &str, reason: impl std::fmt::Display) -> JacsError {
    JacsError::DatabaseError {
        operation: operation.to_string(),
        reason: reason.to_string(),
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use jacs::testing::make_test_doc;

    #[test]
    fn test_create_in_memory() {
        let storage = RedbStorage::in_memory().expect("create in-memory redb");
        storage.run_migrations().expect("run migrations");
    }

    #[test]
    fn test_crud_roundtrip() {
        let storage = RedbStorage::in_memory().expect("create in-memory redb");
        storage.run_migrations().expect("run migrations");

        let doc = make_test_doc("crud-1", "v1", "agent", Some("alice"));
        storage.store_document(&doc).expect("store failed");

        // Read
        let retrieved = storage.get_document("crud-1:v1").expect("get failed");
        assert_eq!(retrieved.id, "crud-1");
        assert_eq!(retrieved.version, "v1");
        assert_eq!(retrieved.jacs_type, "agent");
        assert_eq!(retrieved.value["data"], "test content");

        // Exists
        assert!(storage.document_exists("crud-1:v1").expect("exists check"));
        assert!(!storage.document_exists("nonexistent:v1").expect("exists check"));

        // Remove
        let removed = storage.remove_document("crud-1:v1").expect("remove failed");
        assert_eq!(removed.id, "crud-1");
        assert!(!storage.document_exists("crud-1:v1").expect("exists after remove"));
    }

    #[test]
    fn test_database_document_traits_queries() {
        let storage = RedbStorage::in_memory().expect("create in-memory redb");
        storage.run_migrations().expect("run migrations");

        storage
            .store_document(&make_test_doc("dbt-1", "v1", "agent", Some("alice")))
            .unwrap();
        storage
            .store_document(&make_test_doc("dbt-2", "v1", "config", Some("alice")))
            .unwrap();
        storage
            .store_document(&make_test_doc("dbt-3", "v1", "agent", Some("bob")))
            .unwrap();

        // query_by_type
        let agents = storage.query_by_type("agent", 100, 0).unwrap();
        assert_eq!(agents.len(), 2);

        // count_by_type
        assert_eq!(storage.count_by_type("agent").unwrap(), 2);
        assert_eq!(storage.count_by_type("config").unwrap(), 1);

        // query_by_agent
        let alice_docs = storage.query_by_agent("alice", None, 100, 0).unwrap();
        assert_eq!(alice_docs.len(), 2);

        let bob_docs = storage.query_by_agent("bob", None, 100, 0).unwrap();
        assert_eq!(bob_docs.len(), 1);

        // query_by_agent with type filter
        let alice_agents = storage.query_by_agent("alice", Some("agent"), 100, 0).unwrap();
        assert_eq!(alice_agents.len(), 1);
    }

    #[test]
    fn test_search_provider_capabilities_all_false() {
        let storage = RedbStorage::in_memory().expect("create in-memory redb");
        let caps = storage.capabilities();
        assert!(!caps.fulltext);
        assert!(!caps.vector);
        assert!(!caps.hybrid);
        assert!(!caps.field_filter);
    }

    #[test]
    fn test_search_provider_search_returns_error() {
        let storage = RedbStorage::in_memory().expect("create in-memory redb");
        let query = SearchQuery::default();
        let result = storage.search(query);
        assert!(result.is_err(), "search() should return an error for redb");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("not supported"),
            "Error should mention 'not supported', got: {}",
            err_msg
        );
    }
}
