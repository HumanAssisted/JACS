//! Redb embedded key-value storage backend for JACS documents.
//!
//! Uses pure-Rust redb with manual secondary index tables:
//! - `documents`: primary store, `"id:version"` → JSON bytes
//! - `type_index`: `"type\0id:version"` → `[]`
//! - `agent_index`: `"agent_id\0id:version"` → `[]`
//! - `version_index`: `"id\0created_at\0version"` → `[]`
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new entries
//! keyed by `(id, version)`. Idempotent inserts skip if key exists.
//!
//! # Feature Gate
//!
//! This module requires the `redb-storage` feature flag and is excluded from WASM.

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::storage::StorageDocumentTraits;
use crate::storage::database_traits::DatabaseDocumentTraits;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::Value;
use std::error::Error;

/// Primary table: `"id:version"` → serialized JACSDocument JSON bytes.
const DOCUMENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("documents");

/// Secondary index: `"type\0id:version"` → empty bytes (for query_by_type).
const TYPE_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("type_index");

/// Secondary index: `"agent_id\0id:version"` → empty bytes (for query_by_agent).
const AGENT_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("agent_index");

/// Ordering index: `"id\0created_at\0version"` → empty bytes (for get_versions, get_latest).
const VERSION_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("version_index");

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
    fn parse_key(key: &str) -> Result<(&str, &str), Box<dyn Error>> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid document key '{}': expected 'id:version'", key).into());
        }
        Ok((parts[0], parts[1]))
    }

    /// Deserialize JSON bytes into a JACSDocument.
    fn bytes_to_document(bytes: &[u8]) -> Result<JACSDocument, Box<dyn Error>> {
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
    ) -> Result<Vec<String>, Box<dyn Error>> {
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
}

impl StorageDocumentTraits for RedbStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>> {
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

    fn get_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let (_id, _version) = Self::parse_key(key)?;

        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;
        let table = read_txn
            .open_table(DOCUMENTS)
            .map_err(db_err("open_table"))?;

        let guard = table
            .get(key)
            .map_err(db_err("get_document"))?
            .ok_or_else(|| -> Box<dyn Error> {
                db_err_box(
                    "get_document",
                    format!("Document not found: {}", key),
                )
            })?;

        Self::bytes_to_document(guard.value())
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let doc = self.get_document(key)?;

        let write_txn = self.db.begin_write().map_err(db_err("begin_write"))?;

        {
            // Remove from primary table
            let mut doc_table = write_txn
                .open_table(DOCUMENTS)
                .map_err(db_err("open_table"))?;
            doc_table.remove(key).map_err(db_err("remove_document"))?;

            // Remove from type index
            let mut type_table = write_txn
                .open_table(TYPE_INDEX)
                .map_err(db_err("open_type_index"))?;
            let type_key = format!("{}\0{}", doc.jacs_type, key);
            let _ = type_table.remove(type_key.as_str());

            // Remove from agent index
            if let Some(ref aid) = Self::extract_agent_id(&doc.value) {
                let mut agent_table = write_txn
                    .open_table(AGENT_INDEX)
                    .map_err(db_err("open_agent_index"))?;
                let agent_key = format!("{}\0{}", aid, key);
                let _ = agent_table.remove(agent_key.as_str());
            }

            // Remove from version index
            let mut version_table = write_txn
                .open_table(VERSION_INDEX)
                .map_err(db_err("open_version_index"))?;

            let prefix = format!("{}\0", doc.id);
            let range_end = format!("{}\x01", doc.id);
            let suffix = format!("\0{}", doc.version);

            let keys_to_remove: Vec<String> = {
                let iter = version_table
                    .range(prefix.as_str()..range_end.as_str())
                    .map_err(db_err("range_scan"))?;

                let mut to_remove = Vec::new();
                for entry in iter {
                    let (key_guard, _) = entry.map_err(db_err("iterate"))?;
                    let vk = key_guard.value().to_string();
                    if vk.ends_with(&suffix) {
                        to_remove.push(vk);
                    }
                }
                to_remove
            };

            for vk in &keys_to_remove {
                let _ = version_table.remove(vk.as_str());
            }
        }

        write_txn.commit().map_err(db_err("commit"))?;
        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>> {
        self.collect_keys_from_index(TYPE_INDEX, prefix)
    }

    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        let (_id, _version) = Self::parse_key(key)?;

        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;

        let table = read_txn.open_table(DOCUMENTS);
        let table = match table {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(db_err_box("open_table", e)),
        };

        let exists = table.get(key).map_err(db_err("document_exists"))?;
        Ok(exists.is_some())
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        self.collect_keys_from_index(AGENT_INDEX, agent_id)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
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

        Ok(keys)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
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
    ) -> Result<JACSDocument, Box<dyn Error>> {
        Err(db_err_box(
            "merge_documents",
            "Not implemented for Redb backend",
        ))
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
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

    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<Box<dyn Error>>> {
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
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let keys = self.collect_keys_from_index(TYPE_INDEX, jacs_type)?;
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
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let read_txn = self.db.begin_read().map_err(db_err("begin_read"))?;

        let doc_table = read_txn
            .open_table(DOCUMENTS)
            .map_err(db_err("open_table"))?;

        let mut results = Vec::new();
        let mut skipped = 0usize;

        let iter = doc_table.iter().map_err(db_err("iter"))?;

        for entry in iter {
            let (_, value_guard) = entry.map_err(db_err("iterate"))?;
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

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, Box<dyn Error>> {
        let keys = self.collect_keys_from_index(TYPE_INDEX, jacs_type)?;
        Ok(keys.len())
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let keys = self.get_document_versions(jacs_id)?;
        let mut docs = Vec::new();
        for key in keys {
            docs.push(self.get_document(&key)?);
        }
        Ok(docs)
    }

    fn get_latest(&self, jacs_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
        self.get_latest_document(jacs_id)
    }

    fn query_by_agent(
        &self,
        agent_id: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let keys = self.collect_keys_from_index(AGENT_INDEX, agent_id)?;
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

    fn run_migrations(&self) -> Result<(), Box<dyn Error>> {
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
        }

        write_txn
            .commit()
            .map_err(db_err("commit_migrations"))?;

        Ok(())
    }
}

/// Traverse a JSON value by a dot-separated field path.
fn get_nested_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Helper to create a closure that maps any Display error to a DatabaseError Box.
fn db_err<E: std::fmt::Display>(operation: &'static str) -> impl FnOnce(E) -> Box<dyn Error> {
    move |e: E| -> Box<dyn Error> {
        Box::new(JacsError::DatabaseError {
            operation: operation.to_string(),
            reason: e.to_string(),
        })
    }
}

/// Helper to create a DatabaseError Box directly from an operation and reason.
fn db_err_box(operation: &str, reason: impl std::fmt::Display) -> Box<dyn Error> {
    Box::new(JacsError::DatabaseError {
        operation: operation.to_string(),
        reason: reason.to_string(),
    })
}
