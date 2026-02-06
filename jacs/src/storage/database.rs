//! PostgreSQL database storage backend for JACS documents.
//!
//! Uses TEXT + JSONB dual-column strategy:
//! - `raw_contents` (TEXT): Preserves exact JSON bytes for signature verification
//! - `file_contents` (JSONB): Enables efficient queries and indexing
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new rows
//! keyed by `(jacs_id, jacs_version)`. No UPDATE operations on existing rows.
//!
//! # Feature Gate
//!
//! This module requires the `database` feature flag and is excluded from WASM.

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::storage::database_traits::DatabaseDocumentTraits;
use crate::storage::StorageDocumentTraits;
use serde_json::Value;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use std::error::Error;
use std::time::Duration;
use tokio::runtime::Handle;

/// PostgreSQL storage backend for JACS documents.
pub struct DatabaseStorage {
    pool: PgPool,
    handle: Handle,
}

impl DatabaseStorage {
    /// Create a new DatabaseStorage connected to the given PostgreSQL URL.
    ///
    /// Pool settings:
    /// - `max_connections`: Maximum pool size (default 10)
    /// - `min_connections`: Minimum pool size (default 1)
    /// - `connect_timeout_secs`: Connection timeout (default 30)
    pub fn new(
        database_url: &str,
        max_connections: Option<u32>,
        min_connections: Option<u32>,
        connect_timeout_secs: Option<u64>,
    ) -> Result<Self, JacsError> {
        let handle = Handle::try_current().map_err(|e| JacsError::DatabaseError {
            operation: "init".to_string(),
            reason: format!(
                "No tokio runtime available. Database storage requires a tokio runtime: {}",
                e
            ),
        })?;

        let pool = handle.block_on(async {
            PgPoolOptions::new()
                .max_connections(max_connections.unwrap_or(10))
                .min_connections(min_connections.unwrap_or(1))
                .acquire_timeout(Duration::from_secs(connect_timeout_secs.unwrap_or(30)))
                .connect(database_url)
                .await
        }).map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self { pool, handle })
    }

    /// Create a DatabaseStorage from an existing pool and handle (for testing).
    pub fn with_pool(pool: PgPool, handle: Handle) -> Self {
        Self { pool, handle }
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Helper to run async sqlx operations synchronously.
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        self.handle.block_on(f)
    }

    /// Parse a document key in format "id:version" into (id, version).
    fn parse_key(key: &str) -> Result<(&str, &str), Box<dyn Error>> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid document key '{}': expected 'id:version'", key).into());
        }
        Ok((parts[0], parts[1]))
    }

    /// Build a JACSDocument from a database row.
    /// Uses raw_contents (TEXT) to preserve exact signed JSON bytes.
    fn row_to_document(row: &PgRow) -> Result<JACSDocument, Box<dyn Error>> {
        let raw: String = row.try_get("raw_contents")?;
        let value: Value = serde_json::from_str(&raw)?;

        let id: String = row.try_get("jacs_id")?;
        let version: String = row.try_get("jacs_version")?;
        let jacs_type: String = row.try_get("jacs_type")?;

        Ok(JACSDocument {
            id,
            version,
            value,
            jacs_type,
        })
    }

    /// SQL for the jacs_document table creation.
    const CREATE_TABLE_SQL: &str = r#"
        CREATE TABLE IF NOT EXISTS jacs_document (
            jacs_id TEXT NOT NULL,
            jacs_version TEXT NOT NULL,
            agent_id TEXT,
            jacs_type TEXT NOT NULL,
            raw_contents TEXT NOT NULL,
            file_contents JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (jacs_id, jacs_version)
        )
    "#;

    /// SQL for basic indexes.
    const CREATE_INDEXES_SQL: &[&str] = &[
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_type ON jacs_document (jacs_type)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_agent ON jacs_document (agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_created ON jacs_document (created_at DESC)",
    ];
}

impl StorageDocumentTraits for DatabaseStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>> {
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let jsonb_value = &doc.value;
        let agent_id = doc
            .value
            .get("jacsSignature")
            .and_then(|s| s.get("jacsSignatureAgentId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        self.block_on(async {
            sqlx::query(
                r#"INSERT INTO jacs_document (jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (jacs_id, jacs_version) DO NOTHING"#,
            )
            .bind(&doc.id)
            .bind(&doc.version)
            .bind(&agent_id)
            .bind(&doc.jacs_type)
            .bind(&raw_json)
            .bind(jsonb_value)
            .execute(&self.pool)
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

        let row = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = $1 AND jacs_version = $2",
            )
            .bind(id)
            .bind(version)
            .fetch_one(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: e.to_string(),
            })
        })?;

        Self::row_to_document(&row)
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let doc = self.get_document(key)?;
        let (id, version) = Self::parse_key(key)?;

        self.block_on(async {
            sqlx::query("DELETE FROM jacs_document WHERE jacs_id = $1 AND jacs_version = $2")
                .bind(id)
                .bind(version)
                .execute(&self.pool)
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
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_type = $1 ORDER BY created_at DESC",
            )
            .bind(prefix)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "list_documents".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(rows
            .iter()
            .map(|row| {
                let id: String = row.get("jacs_id");
                let version: String = row.get("jacs_version");
                format!("{}:{}", id, version)
            })
            .collect())
    }

    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        let (id, version) = Self::parse_key(key)?;

        let exists: bool = self.block_on(async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM jacs_document WHERE jacs_id = $1 AND jacs_version = $2)",
            )
            .bind(id)
            .bind(version)
            .fetch_one(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "document_exists".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(exists)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE agent_id = $1 ORDER BY created_at DESC",
            )
            .bind(agent_id)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_documents_by_agent".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(rows
            .iter()
            .map(|row| {
                let id: String = row.get("jacs_id");
                let version: String = row.get("jacs_version");
                format!("{}:{}", id, version)
            })
            .collect())
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_id = $1 ORDER BY created_at ASC",
            )
            .bind(document_id)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_document_versions".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(rows
            .iter()
            .map(|row| {
                let id: String = row.get("jacs_id");
                let version: String = row.get("jacs_version");
                format!("{}:{}", id, version)
            })
            .collect())
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let row = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = $1 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(document_id)
            .fetch_one(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: e.to_string(),
            })
        })?;

        Self::row_to_document(&row)
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        Err(Box::new(JacsError::DatabaseError {
            operation: "merge_documents".to_string(),
            reason: "Not implemented for database backend".to_string(),
        }))
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
        let mut errors = Vec::new();
        for doc in &docs {
            if let Err(e) = self.store_document(doc) {
                errors.push(e);
            }
        }
        if errors.is_empty() {
            Ok(Vec::new())
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

impl DatabaseDocumentTraits for DatabaseStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(jacs_type)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_type".to_string(),
                reason: e.to_string(),
            })
        })?;

        rows.iter().map(Self::row_to_document).collect()
    }

    fn query_by_field(
        &self,
        field_path: &str,
        value: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let rows = if let Some(doc_type) = jacs_type {
            self.block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE file_contents->>$1 = $2 AND jacs_type = $3 ORDER BY created_at DESC LIMIT $4 OFFSET $5",
                )
                .bind(field_path)
                .bind(value)
                .bind(doc_type)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
            })
        } else {
            self.block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE file_contents->>$1 = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(field_path)
                .bind(value)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
            })
        }
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_field".to_string(),
                reason: e.to_string(),
            })
        })?;

        rows.iter().map(Self::row_to_document).collect()
    }

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, Box<dyn Error>> {
        let count: i64 = self.block_on(async {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM jacs_document WHERE jacs_type = $1",
            )
            .bind(jacs_type)
            .fetch_one(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "count_by_type".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(count as usize)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = $1 ORDER BY created_at ASC",
            )
            .bind(jacs_id)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_versions".to_string(),
                reason: e.to_string(),
            })
        })?;

        rows.iter().map(Self::row_to_document).collect()
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
        let rows = if let Some(doc_type) = jacs_type {
            self.block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = $1 AND jacs_type = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(agent_id)
                .bind(doc_type)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
            })
        } else {
            self.block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(agent_id)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
            })
        }
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_agent".to_string(),
                reason: e.to_string(),
            })
        })?;

        rows.iter().map(Self::row_to_document).collect()
    }

    fn run_migrations(&self) -> Result<(), Box<dyn Error>> {
        self.block_on(async {
            sqlx::query(Self::CREATE_TABLE_SQL)
                .execute(&self.pool)
                .await
        })
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "run_migrations".to_string(),
                reason: e.to_string(),
            })
        })?;

        for index_sql in Self::CREATE_INDEXES_SQL {
            self.block_on(async { sqlx::query(index_sql).execute(&self.pool).await })
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "run_migrations".to_string(),
                        reason: format!("Failed to create index: {}", e),
                    })
                })?;
        }

        Ok(())
    }
}
