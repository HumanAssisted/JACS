//! SurrealDB storage backend for JACS documents.
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
//! # Feature Gate
//!
//! This module requires the `surrealdb-storage` feature flag and is excluded from WASM.

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::storage::StorageDocumentTraits;
use crate::storage::database_traits::DatabaseDocumentTraits;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::runtime::Handle;

/// SurrealDB storage backend for JACS documents.
pub struct SurrealDbStorage {
    db: Surreal<surrealdb::engine::local::Db>,
    handle: Handle,
}

/// Internal record type for SurrealDB serialization/deserialization.
#[derive(Debug, Serialize, Deserialize)]
struct JacsRecord {
    jacs_id: String,
    jacs_version: String,
    agent_id: Option<String>,
    jacs_type: String,
    raw_contents: String,
    file_contents: Value,
    created_at: String,
}

/// Helper for deserializing COUNT ... GROUP ALL results.
#[derive(Debug, Deserialize)]
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
            return Err(
                format!("Invalid document key '{}': expected 'id:version'", key).into(),
            );
        }
        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Convert a JacsRecord to a JACSDocument.
    fn record_to_document(record: &JacsRecord) -> Result<JACSDocument, Box<dyn Error>> {
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
        DEFINE FIELD IF NOT EXISTS file_contents ON TABLE jacs_document FLEXIBLE TYPE object;
        DEFINE FIELD IF NOT EXISTS created_at ON TABLE jacs_document TYPE string;
        DEFINE INDEX IF NOT EXISTS idx_jacs_type ON TABLE jacs_document COLUMNS jacs_type;
        DEFINE INDEX IF NOT EXISTS idx_agent_id ON TABLE jacs_document COLUMNS agent_id;
        DEFINE INDEX IF NOT EXISTS idx_created_at ON TABLE jacs_document COLUMNS created_at;
    "#;
}

impl StorageDocumentTraits for SurrealDbStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>> {
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let file_contents_json = doc.value.clone();
        let agent_id = doc
            .value
            .get("jacsSignature")
            .and_then(|s| s.get("jacsSignatureAgentId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let created_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let jacs_id = doc.id.clone();
        let jacs_version = doc.version.clone();
        let jacs_type = doc.jacs_type.clone();

        self.block_on(async {
            let sql = r#"
                INSERT INTO jacs_document {
                    id: type::thing('jacs_document', [$jacs_id, $jacs_version]),
                    jacs_id: $jacs_id,
                    jacs_version: $jacs_version,
                    agent_id: $agent_id,
                    jacs_type: $jacs_type,
                    raw_contents: $raw_contents,
                    file_contents: $file_contents,
                    created_at: $created_at
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
                .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "store_document".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(())
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let (id, version) = Self::parse_key(key)?;

        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id AND jacs_version = $jacs_version LIMIT 1")
                    .bind(("jacs_id", id))
                    .bind(("jacs_version", version))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_document".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let record =
            records
                .into_iter()
                .next()
                .ok_or_else(|| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "get_document".to_string(),
                        reason: format!("Document not found: {}", key),
                    })
                })?;

        Self::record_to_document(&record)
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let doc = self.get_document(key)?;
        let (id, version) = Self::parse_key(key)?;

        self.block_on(async {
            self.db
                .query("DELETE FROM jacs_document WHERE jacs_id = $jacs_id AND jacs_version = $jacs_version")
                .bind(("jacs_id", id))
                .bind(("jacs_version", version))
                .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "remove_document".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let jacs_type = prefix.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_type = $jacs_type ORDER BY created_at DESC")
                    .bind(("jacs_type", jacs_type))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "list_documents".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(records
            .iter()
            .map(|r| format!("{}:{}", r.jacs_id, r.jacs_version))
            .collect())
    }

    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        let (id, version) = Self::parse_key(key)?;

        let count: usize = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT count() AS count FROM jacs_document WHERE jacs_id = $jacs_id AND jacs_version = $jacs_version GROUP ALL")
                    .bind(("jacs_id", id))
                    .bind(("jacs_version", version))
                    .await?;
                let row: Option<CountResult> = result.take(0)?;
                Ok::<_, surrealdb::Error>(row.map(|r| r.count).unwrap_or(0))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "document_exists".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(count > 0)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let agent_id_owned = agent_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE agent_id = $agent_id ORDER BY created_at DESC")
                    .bind(("agent_id", agent_id_owned))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_documents_by_agent".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(records
            .iter()
            .map(|r| format!("{}:{}", r.jacs_id, r.jacs_version))
            .collect())
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let jacs_id = document_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id ORDER BY created_at ASC")
                    .bind(("jacs_id", jacs_id))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_document_versions".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(records
            .iter()
            .map(|r| format!("{}:{}", r.jacs_id, r.jacs_version))
            .collect())
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let jacs_id = document_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id ORDER BY created_at DESC LIMIT 1")
                    .bind(("jacs_id", jacs_id))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_latest_document".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let record =
            records
                .into_iter()
                .next()
                .ok_or_else(|| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "get_latest_document".to_string(),
                        reason: format!("No documents found with ID: {}", document_id),
                    })
                })?;

        Self::record_to_document(&record)
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        Err(Box::new(JacsError::DatabaseError {
            operation: "merge_documents".to_string(),
            reason: "Not implemented for SurrealDB backend".to_string(),
        }))
    }

    fn store_documents(
        &self,
        docs: Vec<JACSDocument>,
    ) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
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

    fn get_documents(
        &self,
        keys: Vec<String>,
    ) -> Result<Vec<JACSDocument>, Vec<Box<dyn Error>>> {
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
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let jacs_type_owned = jacs_type.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_type = $jacs_type ORDER BY created_at DESC LIMIT $limit START $offset")
                    .bind(("jacs_type", jacs_type_owned))
                    .bind(("limit", limit))
                    .bind(("offset", offset))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "query_by_type".to_string(),
                    reason: e.to_string(),
                })
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
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let value_owned = value.to_string();
        let jacs_type_owned = jacs_type.map(|s| s.to_string());
        let field_path_owned = field_path.to_string();

        let records: Vec<JacsRecord> = if let Some(doc_type) = jacs_type_owned {
            self.block_on(async {
                let query = format!(
                    "SELECT * FROM jacs_document WHERE file_contents.{} = $value AND jacs_type = $jacs_type ORDER BY created_at DESC LIMIT $limit START $offset",
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
                    "SELECT * FROM jacs_document WHERE file_contents.{} = $value ORDER BY created_at DESC LIMIT $limit START $offset",
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
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_field".to_string(),
                reason: e.to_string(),
            })
        })?;

        records.iter().map(Self::record_to_document).collect()
    }

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, Box<dyn Error>> {
        let jacs_type_owned = jacs_type.to_string();
        let count: usize = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT count() AS count FROM jacs_document WHERE jacs_type = $jacs_type GROUP ALL")
                    .bind(("jacs_type", jacs_type_owned))
                    .await?;
                let row: Option<CountResult> = result.take(0)?;
                Ok::<_, surrealdb::Error>(row.map(|r| r.count).unwrap_or(0))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "count_by_type".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(count)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let jacs_id_owned = jacs_id.to_string();
        let records: Vec<JacsRecord> = self
            .block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE jacs_id = $jacs_id ORDER BY created_at ASC")
                    .bind(("jacs_id", jacs_id_owned))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_versions".to_string(),
                    reason: e.to_string(),
                })
            })?;

        records.iter().map(Self::record_to_document).collect()
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
        let agent_id_owned = agent_id.to_string();
        let jacs_type_owned = jacs_type.map(|s| s.to_string());

        let records: Vec<JacsRecord> = if let Some(doc_type) = jacs_type_owned {
            self.block_on(async {
                let mut result = self
                    .db
                    .query("SELECT * FROM jacs_document WHERE agent_id = $agent_id AND jacs_type = $jacs_type ORDER BY created_at DESC LIMIT $limit START $offset")
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
                    .query("SELECT * FROM jacs_document WHERE agent_id = $agent_id ORDER BY created_at DESC LIMIT $limit START $offset")
                    .bind(("agent_id", agent_id_owned))
                    .bind(("limit", limit))
                    .bind(("offset", offset))
                    .await?;
                let records: Vec<JacsRecord> = result.take(0)?;
                Ok::<_, surrealdb::Error>(records)
            })
        }
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_agent".to_string(),
                reason: e.to_string(),
            })
        })?;

        records.iter().map(Self::record_to_document).collect()
    }

    fn run_migrations(&self) -> Result<(), Box<dyn Error>> {
        self.block_on(async { self.db.query(Self::SCHEMA_SQL).await })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "run_migrations".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(())
    }
}
