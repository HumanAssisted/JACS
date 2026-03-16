//! SQLite database storage backend for JACS documents.
//!
//! Uses TEXT columns for JSON storage with `json_extract()` for queries.
//! - `raw_contents` (TEXT): Preserves exact JSON bytes for signature verification
//! - `file_contents` (TEXT): JSON stored as text, queried via `json_extract()`
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new rows
//! keyed by `(jacs_id, jacs_version)`. No UPDATE operations on existing rows.
//!
//! # Feature Gate
//!
//! This module requires the `sqlite` feature flag and is excluded from WASM.

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::storage::StorageDocumentTraits;
use crate::storage::database_traits::DatabaseDocumentTraits;
use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow};
use std::time::Duration;
use tokio::runtime::Handle;

/// SQLite storage backend for JACS documents.
pub struct SqliteStorage {
    pool: SqlitePool,
    handle: Handle,
}

impl SqliteStorage {
    /// Create a new SqliteStorage connected to the given SQLite database file.
    ///
    /// This is a synchronous constructor. Use `new_async()` when calling
    /// from within a tokio async context (e.g., `#[tokio::test]`).
    ///
    /// # Arguments
    ///
    /// * `database_path` - Path to the SQLite database file (e.g., `"./jacs.db"`)
    /// * `max_connections` - Maximum pool size (default 5)
    pub fn new(database_path: &str, max_connections: Option<u32>) -> Result<Self, JacsError> {
        let handle = Handle::try_current().map_err(|e| JacsError::DatabaseError {
            operation: "init".to_string(),
            reason: format!(
                "No tokio runtime available. SQLite storage requires a tokio runtime: {}",
                e
            ),
        })?;

        let database_url = format!("sqlite:{}?mode=rwc", database_path);

        let pool = tokio::task::block_in_place(|| {
            handle.block_on(async {
                SqlitePoolOptions::new()
                    .max_connections(max_connections.unwrap_or(5))
                    .acquire_timeout(Duration::from_secs(30))
                    .connect(&database_url)
                    .await
            })
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self { pool, handle })
    }

    /// Async constructor — safe to call from within `#[tokio::test]` or any async context.
    pub async fn new_async(
        database_path: &str,
        max_connections: Option<u32>,
    ) -> Result<Self, JacsError> {
        let handle = Handle::try_current().map_err(|e| JacsError::DatabaseError {
            operation: "init".to_string(),
            reason: format!("No tokio runtime available: {}", e),
        })?;

        let database_url = format!("sqlite:{}?mode=rwc", database_path);

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections.unwrap_or(5))
            .acquire_timeout(Duration::from_secs(30))
            .connect(&database_url)
            .await
            .map_err(|e| JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self { pool, handle })
    }

    /// Create an in-memory SQLite database (useful for tests).
    ///
    /// This is a synchronous constructor. Use `in_memory_async()` when calling
    /// from within a tokio async context.
    pub fn in_memory() -> Result<Self, JacsError> {
        let handle = Handle::try_current().map_err(|e| JacsError::DatabaseError {
            operation: "init".to_string(),
            reason: format!(
                "No tokio runtime available. SQLite storage requires a tokio runtime: {}",
                e
            ),
        })?;

        let pool = tokio::task::block_in_place(|| {
            handle.block_on(async {
                SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect("sqlite::memory:")
                    .await
            })
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self { pool, handle })
    }

    /// Async in-memory constructor — safe to call from within `#[tokio::test]`.
    pub async fn in_memory_async() -> Result<Self, JacsError> {
        let handle = Handle::try_current().map_err(|e| JacsError::DatabaseError {
            operation: "init".to_string(),
            reason: format!("No tokio runtime available: {}", e),
        })?;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self { pool, handle })
    }

    /// Create a SqliteStorage from an existing pool and handle (for testing).
    pub fn with_pool(pool: SqlitePool, handle: Handle) -> Self {
        Self { pool, handle }
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Helper to run async sqlx operations synchronously.
    ///
    /// Uses `block_in_place` to avoid panicking when called from within
    /// a multi-thread tokio runtime.
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        tokio::task::block_in_place(|| self.handle.block_on(f))
    }

    /// Parse a document key in format "id:version" into (id, version).
    fn parse_key(key: &str) -> Result<(&str, &str), JacsError> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid document key '{}': expected 'id:version'", key).into());
        }
        Ok((parts[0], parts[1]))
    }

    /// Build a JACSDocument from a database row.
    /// Uses raw_contents (TEXT) to preserve exact signed JSON bytes.
    fn row_to_document(row: &SqliteRow) -> Result<JACSDocument, JacsError> {
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

    /// SQL for the jacs_document table creation (SQLite-compatible).
    const CREATE_TABLE_SQL: &str = r#"
        CREATE TABLE IF NOT EXISTS jacs_document (
            jacs_id TEXT NOT NULL,
            jacs_version TEXT NOT NULL,
            agent_id TEXT,
            jacs_type TEXT NOT NULL,
            raw_contents TEXT NOT NULL,
            file_contents TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
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

impl StorageDocumentTraits for SqliteStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let file_contents_json = serde_json::to_string(&doc.value)?;
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
            .bind(&file_contents_json)
            .execute(&self.pool)
            .await
        })
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "store_document".to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(())
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
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
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: e.to_string(),
            }
        })?;

        Self::row_to_document(&row)
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let doc = self.get_document(key)?;
        let (id, version) = Self::parse_key(key)?;

        self.block_on(async {
            sqlx::query("DELETE FROM jacs_document WHERE jacs_id = $1 AND jacs_version = $2")
                .bind(id)
                .bind(version)
                .execute(&self.pool)
                .await
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "remove_document".to_string(),
            reason: e.to_string(),
        })?;

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, JacsError> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_type = $1 ORDER BY created_at DESC",
            )
            .bind(prefix)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "list_documents".to_string(),
                reason: e.to_string(),
            }
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

    fn document_exists(&self, key: &str) -> Result<bool, JacsError> {
        let (id, version) = Self::parse_key(key)?;

        let count: i32 = self
            .block_on(async {
                sqlx::query_scalar::<_, i32>(
                    "SELECT COUNT(*) FROM jacs_document WHERE jacs_id = $1 AND jacs_version = $2",
                )
                .bind(id)
                .bind(version)
                .fetch_one(&self.pool)
                .await
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "document_exists".to_string(),
                reason: e.to_string(),
            })?;

        Ok(count > 0)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE agent_id = $1 ORDER BY created_at DESC",
            )
            .bind(agent_id)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "get_documents_by_agent".to_string(),
                reason: e.to_string(),
            }
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

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, JacsError> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_id = $1 ORDER BY created_at ASC",
            )
            .bind(document_id)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "get_document_versions".to_string(),
                reason: e.to_string(),
            }
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

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let row = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = $1 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(document_id)
            .fetch_one(&self.pool)
            .await
        })
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: e.to_string(),
            }
        })?;

        Self::row_to_document(&row)
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, JacsError> {
        Err(JacsError::DatabaseError {
            operation: "merge_documents".to_string(),
            reason: "Not implemented for SQLite backend".to_string(),
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

impl DatabaseDocumentTraits for SqliteStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
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
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "query_by_type".to_string(),
                reason: e.to_string(),
            }
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
    ) -> Result<Vec<JACSDocument>, JacsError> {
        // SQLite uses json_extract() instead of PostgreSQL's ->> operator.
        // We build the JSON path as $.field_path for json_extract().
        let json_path = format!("$.{}", field_path);

        let rows = if let Some(doc_type) = jacs_type {
            self.block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, $1) = $2 AND jacs_type = $3 ORDER BY created_at DESC LIMIT $4 OFFSET $5",
                )
                .bind(&json_path)
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, $1) = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(&json_path)
                .bind(value)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
            })
        }
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "query_by_field".to_string(),
                reason: e.to_string(),
            }
        })?;

        rows.iter().map(Self::row_to_document).collect()
    }

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, JacsError> {
        let count: i32 = self
            .block_on(async {
                sqlx::query_scalar::<_, i32>(
                    "SELECT COUNT(*) FROM jacs_document WHERE jacs_type = $1",
                )
                .bind(jacs_type)
                .fetch_one(&self.pool)
                .await
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "count_by_type".to_string(),
                reason: e.to_string(),
            })?;

        Ok(count as usize)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = $1 ORDER BY created_at ASC",
            )
            .bind(jacs_id)
            .fetch_all(&self.pool)
            .await
        })
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "get_versions".to_string(),
                reason: e.to_string(),
            }
        })?;

        rows.iter().map(Self::row_to_document).collect()
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
        .map_err(|e| {
            JacsError::DatabaseError {
                operation: "query_by_agent".to_string(),
                reason: e.to_string(),
            }
        })?;

        rows.iter().map(Self::row_to_document).collect()
    }

    fn run_migrations(&self) -> Result<(), JacsError> {
        self.block_on(async {
            sqlx::query(Self::CREATE_TABLE_SQL)
                .execute(&self.pool)
                .await
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "run_migrations".to_string(),
            reason: e.to_string(),
        })?;

        for index_sql in Self::CREATE_INDEXES_SQL {
            self.block_on(async { sqlx::query(index_sql).execute(&self.pool).await })
                .map_err(|e| JacsError::DatabaseError {
                    operation: "run_migrations".to_string(),
                    reason: format!("Failed to create index: {}", e),
                })?;
        }

        Ok(())
    }
}
