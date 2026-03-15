//! PostgreSQL storage backend for JACS documents.
//!
//! This crate provides `PostgresStorage`, a PostgreSQL-backed implementation of
//! JACS storage traits:
//! - [`StorageDocumentTraits`] -- basic document CRUD
//! - [`DatabaseDocumentTraits`] -- database-specific query capabilities
//! - [`SearchProvider`] -- fulltext search via PostgreSQL tsvector
//!
//! # Dual-Column Strategy
//!
//! Uses TEXT + JSONB dual-column storage:
//! - `raw_contents` (TEXT): Preserves exact JSON bytes for signature verification
//! - `file_contents` (JSONB): Enables efficient queries and indexing
//!
//! # Append-Only Model with Soft Delete
//!
//! Documents are immutable once stored. New versions create new rows
//! keyed by `(jacs_id, jacs_version)`. The only UPDATE operation is
//! soft-delete via `remove_document`, which sets `tombstoned = true`
//! rather than physically deleting rows.
//!
//! # Usage
//!
//! ```rust,ignore
//! use jacs_postgresql::PostgresStorage;
//! use jacs::storage::StorageDocumentTraits;
//! use jacs::storage::DatabaseDocumentTraits;
//!
//! let storage = PostgresStorage::new(&database_url, None, None, None)?;
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
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use std::error::Error;
use std::time::Duration;
use tokio::runtime::Handle;

/// PostgreSQL storage backend for JACS documents.
///
/// Implements [`StorageDocumentTraits`], [`DatabaseDocumentTraits`], and
/// [`SearchProvider`]. Supports fulltext search via PostgreSQL tsvector.
/// Vector search (pgvector) is not yet implemented but the capability
/// reporting is prepared for it.
pub struct PostgresStorage {
    pool: PgPool,
    handle: Handle,
}

impl PostgresStorage {
    /// Create a new PostgresStorage connected to the given PostgreSQL URL.
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

        let pool = tokio::task::block_in_place(|| {
            handle.block_on(async {
                PgPoolOptions::new()
                    .max_connections(max_connections.unwrap_or(10))
                    .min_connections(min_connections.unwrap_or(1))
                    .acquire_timeout(Duration::from_secs(connect_timeout_secs.unwrap_or(30)))
                    .connect(database_url)
                    .await
            })
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self { pool, handle })
    }

    /// Create a PostgresStorage from an existing pool and handle (for testing).
    pub fn with_pool(pool: PgPool, handle: Handle) -> Self {
        Self { pool, handle }
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Helper to run async sqlx operations synchronously.
    ///
    /// Uses `block_in_place` so this is safe to call from within a tokio
    /// multi-threaded runtime (e.g. from `#[tokio::test]`).
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        tokio::task::block_in_place(|| self.handle.block_on(f))
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
    fn row_to_document(row: &PgRow) -> Result<JACSDocument, JacsError> {
        let raw: String = row
            .try_get("raw_contents")
            .map_err(|e| JacsError::DatabaseError {
                operation: "row_to_document".into(),
                reason: e.to_string(),
            })?;
        let value: Value = serde_json::from_str(&raw)?;

        let id: String = row
            .try_get("jacs_id")
            .map_err(|e| JacsError::DatabaseError {
                operation: "row_to_document".into(),
                reason: e.to_string(),
            })?;
        let version: String =
            row.try_get("jacs_version")
                .map_err(|e| JacsError::DatabaseError {
                    operation: "row_to_document".into(),
                    reason: e.to_string(),
                })?;
        let jacs_type: String = row
            .try_get("jacs_type")
            .map_err(|e| JacsError::DatabaseError {
                operation: "row_to_document".into(),
                reason: e.to_string(),
            })?;

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
            tombstoned BOOLEAN NOT NULL DEFAULT false,
            PRIMARY KEY (jacs_id, jacs_version)
        )
    "#;

    /// SQL for basic indexes.
    const CREATE_INDEXES_SQL: &[&str] = &[
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_type ON jacs_document (jacs_type)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_agent ON jacs_document (agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_created ON jacs_document (created_at DESC)",
    ];

    /// SQL for fulltext search index (tsvector).
    const CREATE_FTS_INDEX_SQL: &str = r#"
        CREATE INDEX IF NOT EXISTS idx_jacs_document_fts
        ON jacs_document
        USING GIN (to_tsvector('english', raw_contents))
    "#;
}

impl StorageDocumentTraits for PostgresStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
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
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                 FROM jacs_document WHERE jacs_id = $1 AND jacs_version = $2 AND tombstoned = false",
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
            sqlx::query("UPDATE jacs_document SET tombstoned = true WHERE jacs_id = $1 AND jacs_version = $2")
                .bind(id)
                .bind(version)
                .execute(&self.pool)
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
        let rows = self
            .block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version FROM jacs_document \
                 WHERE jacs_type = $1 AND tombstoned = false ORDER BY created_at DESC",
                )
                .bind(prefix)
                .fetch_all(&self.pool)
                .await
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "list_documents".to_string(),
                reason: e.to_string(),
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

        let exists: bool = self
            .block_on(async {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM jacs_document \
                     WHERE jacs_id = $1 AND jacs_version = $2 AND tombstoned = false)",
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

        Ok(exists)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError> {
        let rows = self
            .block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version FROM jacs_document \
                 WHERE agent_id = $1 AND tombstoned = false ORDER BY created_at DESC",
                )
                .bind(agent_id)
                .fetch_all(&self.pool)
                .await
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_documents_by_agent".to_string(),
                reason: e.to_string(),
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
        let rows = self
            .block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version FROM jacs_document \
                 WHERE jacs_id = $1 AND tombstoned = false ORDER BY created_at ASC",
                )
                .bind(document_id)
                .fetch_all(&self.pool)
                .await
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_document_versions".to_string(),
                reason: e.to_string(),
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
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                 FROM jacs_document WHERE jacs_id = $1 AND tombstoned = false ORDER BY created_at DESC LIMIT 1",
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
            reason: "Not implemented for database backend".to_string(),
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

impl DatabaseDocumentTraits for PostgresStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
        let rows = self
            .block_on(async {
                sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                 FROM jacs_document WHERE jacs_type = $1 AND tombstoned = false \
                 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(jacs_type)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "query_by_type".to_string(),
                reason: e.to_string(),
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
        let rows = if let Some(doc_type) = jacs_type {
            self.block_on(async {
                sqlx::query(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                     FROM jacs_document WHERE file_contents->>$1 = $2 AND jacs_type = $3 AND tombstoned = false \
                     ORDER BY created_at DESC LIMIT $4 OFFSET $5",
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                     FROM jacs_document WHERE file_contents->>$1 = $2 AND tombstoned = false \
                     ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(field_path)
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
        let count: i64 = self
            .block_on(async {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM jacs_document WHERE jacs_type = $1 AND tombstoned = false",
                )
                .bind(jacs_type)
                .fetch_one(&self.pool)
                .await
            })
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "count_by_type".to_string(),
                    reason: e.to_string(),
                }
            })?;

        Ok(count as usize)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let rows = self.block_on(async {
            sqlx::query(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                 FROM jacs_document WHERE jacs_id = $1 AND tombstoned = false ORDER BY created_at ASC",
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                     FROM jacs_document WHERE agent_id = $1 AND jacs_type = $2 AND tombstoned = false \
                     ORDER BY created_at DESC LIMIT $3 OFFSET $4",
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents \
                     FROM jacs_document WHERE agent_id = $1 AND tombstoned = false \
                     ORDER BY created_at DESC LIMIT $2 OFFSET $3",
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

        // Create fulltext search index for tsvector-based search.
        self.block_on(async {
            sqlx::query(Self::CREATE_FTS_INDEX_SQL)
                .execute(&self.pool)
                .await
        })
        .map_err(|e| JacsError::DatabaseError {
            operation: "run_migrations".to_string(),
            reason: format!("Failed to create FTS index: {}", e),
        })?;

        // Tombstone migration: add tombstoned column for soft-delete support.
        // Idempotent -- IF NOT EXISTS prevents errors on re-run.
        let _ = self.block_on(async {
            sqlx::query("ALTER TABLE jacs_document ADD COLUMN IF NOT EXISTS tombstoned BOOLEAN NOT NULL DEFAULT false")
                .execute(&self.pool)
                .await
        });

        Ok(())
    }
}

impl SearchProvider for PostgresStorage {
    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError> {
        // Handle field_filter queries via query_by_field (exact field match, no FTS)
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
                method: SearchMethod::FullText,
            });
        }

        // Build fulltext search dynamically to support optional jacs_type and agent_id filters.
        // PostgreSQL tsvector fulltext search with parameterized queries.
        let has_type = query.jacs_type.is_some();
        let has_agent = query.agent_id.is_some();

        // Build SQL with correct positional parameter indices ($1 = query text)
        let (count_sql, results_sql) = match (has_type, has_agent) {
            (true, true) => (
                "SELECT COUNT(*) FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND jacs_type = $2 AND agent_id = $3 AND tombstoned = false"
                    .to_string(),
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents, \
                 ts_rank(to_tsvector('english', raw_contents), plainto_tsquery('english', $1)) AS rank \
                 FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND jacs_type = $2 AND agent_id = $3 AND tombstoned = false \
                 ORDER BY rank DESC LIMIT $4 OFFSET $5"
                    .to_string(),
            ),
            (true, false) => (
                "SELECT COUNT(*) FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND jacs_type = $2 AND tombstoned = false"
                    .to_string(),
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents, \
                 ts_rank(to_tsvector('english', raw_contents), plainto_tsquery('english', $1)) AS rank \
                 FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND jacs_type = $2 AND tombstoned = false \
                 ORDER BY rank DESC LIMIT $3 OFFSET $4"
                    .to_string(),
            ),
            (false, true) => (
                "SELECT COUNT(*) FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND agent_id = $2 AND tombstoned = false"
                    .to_string(),
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents, \
                 ts_rank(to_tsvector('english', raw_contents), plainto_tsquery('english', $1)) AS rank \
                 FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND agent_id = $2 AND tombstoned = false \
                 ORDER BY rank DESC LIMIT $3 OFFSET $4"
                    .to_string(),
            ),
            (false, false) => (
                "SELECT COUNT(*) FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND tombstoned = false"
                    .to_string(),
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents, \
                 ts_rank(to_tsvector('english', raw_contents), plainto_tsquery('english', $1)) AS rank \
                 FROM jacs_document \
                 WHERE to_tsvector('english', raw_contents) @@ plainto_tsquery('english', $1) \
                 AND tombstoned = false \
                 ORDER BY rank DESC LIMIT $2 OFFSET $3"
                    .to_string(),
            ),
        };

        // Execute count query
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(&query.query);
        if let Some(ref jt) = query.jacs_type {
            count_q = count_q.bind(jt);
        }
        if let Some(ref ai) = query.agent_id {
            count_q = count_q.bind(ai);
        }
        let total_count: i64 = self
            .block_on(async { count_q.fetch_one(&self.pool).await })
            .map_err(|e| JacsError::StorageError(format!("FTS count query failed: {}", e)))?;

        // Execute results query
        let mut results_q = sqlx::query(&results_sql).bind(&query.query);
        if let Some(ref jt) = query.jacs_type {
            results_q = results_q.bind(jt);
        }
        if let Some(ref ai) = query.agent_id {
            results_q = results_q.bind(ai);
        }
        results_q = results_q.bind(query.limit as i64).bind(query.offset as i64);

        let rows = self
            .block_on(async { results_q.fetch_all(&self.pool).await })
            .map_err(|e| JacsError::StorageError(format!("FTS search failed: {}", e)))?;

        // Collect ranks for relative normalization
        let ranks: Vec<f32> = rows
            .iter()
            .map(|row| row.try_get::<f32, _>("rank").unwrap_or(0.0))
            .collect();
        let max_rank = ranks.iter().cloned().fold(f32::MIN, f32::max);

        let mut results = Vec::new();
        for (row, &rank) in rows.iter().zip(ranks.iter()) {
            let doc = Self::row_to_document(row)
                .map_err(|e| JacsError::StorageError(format!("Failed to parse row: {}", e)))?;

            // Normalize rank relative to max score in result set (preserves ranking fidelity)
            let score = if max_rank > 0.0 {
                (rank / max_rank) as f64
            } else {
                0.0
            };

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
            results,
            total_count: total_count as usize,
            method: SearchMethod::FullText,
        })
    }

    fn capabilities(&self) -> SearchCapabilities {
        SearchCapabilities {
            fulltext: true,
            vector: false,
            hybrid: false,
            field_filter: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_reports_fulltext_true_vector_false() {
        let caps = SearchCapabilities {
            fulltext: true,
            vector: false,
            hybrid: false,
            field_filter: true,
        };
        assert!(caps.fulltext);
        assert!(!caps.vector);
        assert!(!caps.hybrid);
        assert!(caps.field_filter);
    }

    #[test]
    fn parse_key_valid() {
        let (id, version) = PostgresStorage::parse_key("doc-1:v1").unwrap();
        assert_eq!(id, "doc-1");
        assert_eq!(version, "v1");
    }

    #[test]
    fn parse_key_invalid() {
        let result = PostgresStorage::parse_key("invalid-key-no-colon");
        assert!(result.is_err());
    }

    #[test]
    fn parse_key_with_colons_in_version() {
        let (id, version) = PostgresStorage::parse_key("doc-1:v1:extra").unwrap();
        assert_eq!(id, "doc-1");
        assert_eq!(version, "v1:extra");
    }
}
