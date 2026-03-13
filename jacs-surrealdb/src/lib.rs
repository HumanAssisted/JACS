//! SurrealDB storage backend for JACS documents.
//!
//! Provides a standalone `SurrealDbStorage` type that implements JACS core's
//! `StorageDocumentTraits` and `DatabaseDocumentTraits`.
//!
//! Uses SurrealDB's native JSON support with SCHEMAFULL tables.
//! - `raw_contents` (string): Preserves exact JSON bytes for signature verification
//! - `file_contents` (object): Native JSON stored as SurrealDB object, queried via field paths
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new rows
//! keyed by compound record ID `jacs_document:[jacs_id, jacs_version]`.
//! Compound IDs give natural idempotency — repeated inserts are no-ops.
//!
//! # Example
//!
//! ```rust,ignore
//! use jacs_surrealdb::SurrealDbStorage;
//! use jacs::storage::database_traits::DatabaseDocumentTraits;
//!
//! let storage = SurrealDbStorage::in_memory_async().await?;
//! storage.run_migrations()?;
//! ```

use jacs::agent::document::JACSDocument;
use jacs::error::JacsError;
use jacs::search::{
    FieldFilter, SearchCapabilities, SearchHit, SearchMethod, SearchProvider, SearchQuery,
    SearchResults,
};
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use surrealdb::types::SurrealValue;
use tokio::runtime::Handle;

/// SurrealDB storage backend for JACS documents.
pub struct SurrealDbStorage {
    db: Surreal<surrealdb::engine::local::Db>,
    handle: Handle,
}

/// Internal record type for SurrealDB serialization/deserialization.
#[derive(Debug, Serialize, Deserialize, SurrealValue)]
struct JacsRecord {
    jacs_id: String,
    jacs_version: String,
    agent_id: Option<String>,
    jacs_type: String,
    raw_contents: String,
    file_contents: Value,
    created_at: String,
    tombstoned: bool,
}

/// Helper for deserializing COUNT ... GROUP ALL results.
#[derive(Debug, Deserialize, SurrealValue)]
struct CountResult {
    count: usize,
}

impl SurrealDbStorage {
    /// Async in-memory constructor — safe to call from `#[tokio::test]` or any async context.
    pub async fn in_memory_async() -> Result<Self, JacsError> {
        let handle = Handle::try_current().map_err(|e| JacsError::DatabaseError {
            operation: "init".to_string(),
            reason: format!("No tokio runtime available: {}", e),
        })?;

        let db = Surreal::new::<Mem>(())
            .await
            .map_err(|e| JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })?;

        db.use_ns("jacs")
            .use_db("documents")
            .await
            .map_err(|e| JacsError::DatabaseError {
                operation: "use_ns_db".to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self { db, handle })
    }

    /// Synchronous in-memory constructor. Requires an active tokio runtime.
    pub fn in_memory() -> Result<Self, JacsError> {
        let handle = Handle::try_current().map_err(|e| JacsError::DatabaseError {
            operation: "init".to_string(),
            reason: format!(
                "No tokio runtime available. SurrealDB storage requires a tokio runtime: {}",
                e
            ),
        })?;

        let db = tokio::task::block_in_place(|| {
            handle.block_on(async {
                let db = Surreal::new::<Mem>(()).await?;
                db.use_ns("jacs").use_db("documents").await?;
                Ok::<_, surrealdb::Error>(db)
            })
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self { db, handle })
    }

    /// Helper to run async SurrealDB operations synchronously.
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        tokio::task::block_in_place(|| self.handle.block_on(f))
    }

    /// Parse a document key in format "id:version" into (id, version).
    fn parse_key(key: &str) -> Result<(String, String), Box<dyn Error>> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid document key '{}': expected 'id:version'", key).into());
        }
        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Convert a JacsRecord to a JACSDocument.
    fn record_to_document(record: &JacsRecord) -> Result<JACSDocument, JacsError> {
        let value: Value = serde_json::from_str(&record.raw_contents)?;
        Ok(JACSDocument {
            id: record.jacs_id.clone(),
            version: record.jacs_version.clone(),
            value,
            jacs_type: record.jacs_type.clone(),
        })
    }

    /// SurrealQL schema definition for the jacs_document table.
    const SCHEMA_SQL: &str = r#"
        DEFINE TABLE IF NOT EXISTS jacs_document SCHEMAFULL;
        DEFINE FIELD IF NOT EXISTS jacs_id ON TABLE jacs_document TYPE string;
        DEFINE FIELD IF NOT EXISTS jacs_version ON TABLE jacs_document TYPE string;
        DEFINE FIELD IF NOT EXISTS agent_id ON TABLE jacs_document TYPE option<string>;
        DEFINE FIELD IF NOT EXISTS jacs_type ON TABLE jacs_document TYPE string;
        DEFINE FIELD IF NOT EXISTS raw_contents ON TABLE jacs_document TYPE string;
        DEFINE FIELD IF NOT EXISTS file_contents ON TABLE jacs_document TYPE object FLEXIBLE;
        DEFINE FIELD IF NOT EXISTS created_at ON TABLE jacs_document TYPE string;
        DEFINE FIELD IF NOT EXISTS tombstoned ON TABLE jacs_document TYPE bool DEFAULT false;
        DEFINE INDEX IF NOT EXISTS idx_jacs_type ON TABLE jacs_document COLUMNS jacs_type;
        DEFINE INDEX IF NOT EXISTS idx_agent_id ON TABLE jacs_document COLUMNS agent_id;
        DEFINE INDEX IF NOT EXISTS idx_created_at ON TABLE jacs_document COLUMNS created_at;
    "#;
}

impl StorageDocumentTraits for SurrealDbStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let file_contents_json = doc.value.clone();
        let agent_id = doc
            .value
            .get("jacsSignature")
            .and_then(|s| s.get("jacsSignatureAgentId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let jacs_id = doc.id.clone();
        let jacs_version = doc.version.clone();
        let jacs_type = doc.jacs_type.clone();

        self.block_on(async {
            let sql = r#"
                INSERT INTO jacs_document {
                    id: type::record('jacs_document', [$jacs_id, $jacs_version]),
                    jacs_id: $jacs_id,
                    jacs_version: $jacs_version,
                    agent_id: $agent_id,
                    jacs_type: $jacs_type,
                    raw_contents: $raw_contents,
                    file_contents: $file_contents,
                    created_at: $created_at,
                    tombstoned: $tombstoned
                } ON DUPLICATE KEY UPDATE id = id
            "#;

            self.db
                .query(sql)
                .bind(("jacs_id", jacs_id))
                .bind(("jacs_version", jacs_version))
                .bind(("agent_id", agent_id))
                .bind(("jacs_type", jacs_type))
                .bind(("raw_contents", raw_json))
                .bind(("file_contents", file_contents_json))
                .bind(("created_at", created_at))
                .bind(("tombstoned", false))
                .await
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "store_document".to_string(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let (id, version) = Self::parse_key(key)?;

        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id AND jacs_version = $jacs_version AND tombstoned = false LIMIT 1")
                    .bind(("jacs_id", id))
                    .bind(("jacs_version", version))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_document".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let record = records
            .into_iter()
            .next()
            .ok_or_else(|| JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: format!("Document not found: {}", key),
            })?;

        Self::record_to_document(&record)
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let doc = self.get_document(key)?;
        let (id, version) = Self::parse_key(key)?;

        self.block_on(async {
            self.db
                .query("UPDATE jacs_document SET tombstoned = true WHERE jacs_id = $jacs_id AND jacs_version = $jacs_version")
                .bind(("jacs_id", id))
                .bind(("jacs_version", version))
                .await
        })
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "remove_document".to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, JacsError> {
        let jacs_type = prefix.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_type = $jacs_type AND tombstoned = false ORDER BY created_at DESC")
                    .bind(("jacs_type", jacs_type))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "list_documents".to_string(),
                    reason: e.to_string(),
                }
            })?;

        Ok(records
            .iter()
            .map(|r| format!("{}:{}", r.jacs_id, r.jacs_version))
            .collect())
    }

    fn document_exists(&self, key: &str) -> Result<bool, JacsError> {
        let (id, version) = Self::parse_key(key)?;

        let count: usize = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT count() AS count FROM jacs_document WHERE jacs_id = $jacs_id AND jacs_version = $jacs_version AND tombstoned = false GROUP ALL")
                    .bind(("jacs_id", id))
                    .bind(("jacs_version", version))
                    .await?;
                let row: Option<CountResult> = result.take(0)?;
                Ok::<_, surrealdb::Error>(row.map(|r| r.count).unwrap_or(0))
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "document_exists".to_string(),
                    reason: e.to_string(),
                }
            })?;

        Ok(count > 0)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError> {
        let agent_id_owned = agent_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE agent_id = $agent_id AND tombstoned = false ORDER BY created_at DESC")
                    .bind(("agent_id", agent_id_owned))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_documents_by_agent".to_string(),
                    reason: e.to_string(),
                }
            })?;

        Ok(records
            .iter()
            .map(|r| format!("{}:{}", r.jacs_id, r.jacs_version))
            .collect())
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, JacsError> {
        let jacs_id = document_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id AND tombstoned = false ORDER BY created_at ASC")
                    .bind(("jacs_id", jacs_id))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_document_versions".to_string(),
                    reason: e.to_string(),
                }
            })?;

        Ok(records
            .iter()
            .map(|r| format!("{}:{}", r.jacs_id, r.jacs_version))
            .collect())
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let jacs_id = document_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id AND tombstoned = false ORDER BY created_at DESC LIMIT 1")
                    .bind(("jacs_id", jacs_id))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_latest_document".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let record = records
            .into_iter()
            .next()
            .ok_or_else(|| JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: format!("No documents found with ID: {}", document_id),
            })?;

        Self::record_to_document(&record)
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, JacsError> {
        Err(JacsError::DatabaseError {
            operation: "merge_documents".to_string(),
            reason: "Not implemented for SurrealDB backend".to_string(),
        })
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<JacsError>> {
        let mut errors = Vec::new();
        let mut keys = Vec::new();
        for doc in &docs {
            match self.store_document(doc) {
                Ok(_) => keys.push(doc.getkey()),
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

impl DatabaseDocumentTraits for SurrealDbStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
        let jacs_type_owned = jacs_type.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_type = $jacs_type AND tombstoned = false ORDER BY created_at DESC LIMIT $limit START $offset")
                    .bind(("jacs_type", jacs_type_owned))
                    .bind(("limit", limit))
                    .bind(("offset", offset))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "query_by_type".to_string(),
                    reason: e.to_string(),
                }
            })?;

        records.iter().map(Self::record_to_document).collect()
    }

    fn query_by_field(
        &self,
        field_path: &str,
        value: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
        // Validate field_path to prevent SurrealQL injection.
        // Only allow alphanumeric characters, dots, and underscores.
        if !field_path
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
        {
            return Err(JacsError::DatabaseError {
                operation: "query_by_field".to_string(),
                reason: format!(
                    "Invalid field path: contains disallowed characters: {}",
                    field_path
                ),
            });
        }

        let value_owned = value.to_string();
        let jacs_type_owned = jacs_type.map(|s| s.to_string());
        let field_path_owned = field_path.to_string();

        let records: Vec<JacsRecord> = if let Some(doc_type) = jacs_type_owned {
            self.block_on(async {
                let query = format!(
                    "SELECT * FROM jacs_document WHERE file_contents.{} = $value AND jacs_type = $jacs_type AND tombstoned = false ORDER BY created_at DESC LIMIT $limit START $offset",
                    field_path_owned
                );
                let mut result = self
                    .db
                    .query(&query)
                    .bind(("value", value_owned))
                    .bind(("jacs_type", doc_type))
                    .bind(("limit", limit))
                    .bind(("offset", offset))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
        } else {
            self.block_on(async {
                let query = format!(
                    "SELECT * FROM jacs_document WHERE file_contents.{} = $value AND tombstoned = false ORDER BY created_at DESC LIMIT $limit START $offset",
                    field_path_owned
                );
                let mut result = self
                    .db
                    .query(&query)
                    .bind(("value", value_owned))
                    .bind(("limit", limit))
                    .bind(("offset", offset))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
        }
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "query_by_field".to_string(),
                reason: e.to_string(),
            }
        })?;

        records.iter().map(Self::record_to_document).collect()
    }

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, JacsError> {
        let jacs_type_owned = jacs_type.to_string();
        let count: usize = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT count() AS count FROM jacs_document WHERE jacs_type = $jacs_type AND tombstoned = false GROUP ALL")
                    .bind(("jacs_type", jacs_type_owned))
                    .await?;
                let row: Option<CountResult> = result.take(0)?;
                Ok::<_, surrealdb::Error>(row.map(|r| r.count).unwrap_or(0))
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "count_by_type".to_string(),
                    reason: e.to_string(),
                }
            })?;

        Ok(count)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let jacs_id_owned = jacs_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id AND tombstoned = false ORDER BY created_at ASC")
                    .bind(("jacs_id", jacs_id_owned))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_versions".to_string(),
                    reason: e.to_string(),
                }
            })?;

        records.iter().map(Self::record_to_document).collect()
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
        let agent_id_owned = agent_id.to_string();
        let jacs_type_owned = jacs_type.map(|s| s.to_string());

        let records: Vec<JacsRecord> = if let Some(doc_type) = jacs_type_owned {
            self.block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE agent_id = $agent_id AND jacs_type = $jacs_type AND tombstoned = false ORDER BY created_at DESC LIMIT $limit START $offset")
                    .bind(("agent_id", agent_id_owned))
                    .bind(("jacs_type", doc_type))
                    .bind(("limit", limit))
                    .bind(("offset", offset))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
        } else {
            self.block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE agent_id = $agent_id AND tombstoned = false ORDER BY created_at DESC LIMIT $limit START $offset")
                    .bind(("agent_id", agent_id_owned))
                    .bind(("limit", limit))
                    .bind(("offset", offset))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
        }
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "query_by_agent".to_string(),
                reason: e.to_string(),
            }
        })?;

        records.iter().map(Self::record_to_document).collect()
    }

    fn run_migrations(&self) -> Result<(), JacsError> {
        self.block_on(async { self.db.query(Self::SCHEMA_SQL).await })
            .map_err(|e| JacsError::DatabaseError {
                operation: "run_migrations".to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }
}

impl SearchProvider for SurrealDbStorage {
    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError> {
        // Handle field_filter queries via query_by_field (exact field match)
        if let Some(FieldFilter {
            ref field_path,
            ref value,
        }) = query.field_filter
        {
            let docs = self
                .query_by_field(
                    field_path,
                    value,
                    query.jacs_type.as_deref(),
                    query.limit,
                    query.offset,
                )
                .map_err(|e| {
                    JacsError::StorageError(format!("field_filter search failed: {}", e))
                })?;

            let total_count = docs.len();
            let results = docs
                .into_iter()
                .map(|doc| SearchHit {
                    document: doc,
                    score: 1.0,
                    matched_fields: vec![field_path.clone()],
                })
                .collect();

            return Ok(SearchResults {
                results,
                total_count,
                method: SearchMethod::FieldMatch,
            });
        }

        if query.query.is_empty() {
            return Ok(SearchResults {
                results: vec![],
                total_count: 0,
                method: SearchMethod::FieldMatch,
            });
        }

        // Build dynamic WHERE clause for CONTAINS search with optional filters
        let mut where_parts = vec![
            "raw_contents CONTAINS $query".to_string(),
            "tombstoned = false".to_string(),
        ];
        if query.jacs_type.is_some() {
            where_parts.push("jacs_type = $jacs_type".to_string());
        }
        if query.agent_id.is_some() {
            where_parts.push("agent_id = $agent_id".to_string());
        }
        let where_clause = where_parts.join(" AND ");

        // Count query (pre-pagination total)
        let count_sql = format!(
            "SELECT count() AS count FROM jacs_document WHERE {} GROUP ALL",
            where_clause
        );
        let total_count: usize = self
            .block_on(async {
                let mut q = self
                    .db
                    .query(&count_sql)
                    .bind(("query", query.query.clone()));
                if let Some(ref jacs_type) = query.jacs_type {
                    q = q.bind(("jacs_type", jacs_type.clone()));
                }
                if let Some(ref agent_id) = query.agent_id {
                    q = q.bind(("agent_id", agent_id.clone()));
                }
                let mut result = q.await?;
                let count: Option<CountResult> = result.take(0)?;
                Ok::<_, surrealdb::Error>(count.map(|c| c.count).unwrap_or(0))
            })
            .map_err(|e| JacsError::StorageError(format!("SurrealDB count query failed: {}", e)))?;

        // Results query (with pagination)
        let results_sql = format!(
            "SELECT * FROM jacs_document WHERE {} ORDER BY created_at DESC LIMIT $limit START $offset",
            where_clause
        );
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut q = self
                    .db
                    .query(&results_sql)
                    .bind(("query", query.query.clone()))
                    .bind(("limit", query.limit))
                    .bind(("offset", query.offset));
                if let Some(ref jacs_type) = query.jacs_type {
                    q = q.bind(("jacs_type", jacs_type.clone()));
                }
                if let Some(ref agent_id) = query.agent_id {
                    q = q.bind(("agent_id", agent_id.clone()));
                }
                let mut result = q.await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| JacsError::StorageError(format!("SurrealDB search failed: {}", e)))?;

        let mut results = Vec::new();
        for record in &records {
            let doc = Self::record_to_document(record)
                .map_err(|e| JacsError::StorageError(format!("Failed to parse record: {}", e)))?;

            let score = 1.0; // SurrealDB CONTAINS is boolean; no native ranking score

            if let Some(min_score) = query.min_score {
                if score < min_score {
                    continue;
                }
            }

            results.push(SearchHit {
                document: doc,
                score,
                matched_fields: vec!["raw_contents".to_string()],
            });
        }

        Ok(SearchResults {
            total_count,
            results,
            method: SearchMethod::FieldMatch,
        })
    }

    fn capabilities(&self) -> SearchCapabilities {
        SearchCapabilities {
            fulltext: false, // SurrealDB CONTAINS is substring, not true fulltext
            vector: false,
            hybrid: false,
            field_filter: true,
        }
    }
}
