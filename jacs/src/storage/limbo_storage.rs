//! Limbo database storage backend for JACS documents.
//!
//! Uses the `limbo_core` crate (a pure-Rust SQLite rewrite) for embedded
//! storage with the same SQL schema as the SQLite backend.
//!
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
//! This module requires the `limbo-storage` feature flag and is excluded from WASM.

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::storage::StorageDocumentTraits;
use crate::storage::database_traits::DatabaseDocumentTraits;
use limbo_core::{Database, MemoryIO, StepResult, Value as LimboValue};
use serde_json::Value;
use std::error::Error;
use std::num::NonZero;
use std::sync::Arc;

/// Limbo storage backend for JACS documents.
///
/// Stores an `Arc<Database>` (which is `Send + Sync`) and creates
/// short-lived connections per operation, since `limbo_core::Connection`
/// is `!Send` (uses `Rc`/`RefCell` internally).
pub struct LimboStorage {
    db: Arc<Database>,
    /// Kept alive to ensure the IO backend outlives the database.
    _io: Arc<dyn limbo_core::IO>,
}

// SAFETY: Database has `unsafe impl Send + Sync`. The IO we use (MemoryIO or
// PlatformIO) is also Send+Sync. We never store a Connection across threads.
unsafe impl Send for LimboStorage {}
unsafe impl Sync for LimboStorage {}

impl LimboStorage {
    /// Create a new LimboStorage connected to the given database file.
    #[cfg(target_family = "unix")]
    pub fn new(database_path: &str) -> Result<Self, JacsError> {
        let io: Arc<dyn limbo_core::IO> = Arc::new(limbo_core::PlatformIO::new().map_err(
            |e| JacsError::DatabaseError {
                operation: "init_io".to_string(),
                reason: e.to_string(),
            },
        )?);

        let db = Database::open_file(io.clone(), database_path, false).map_err(|e| {
            JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(Self { db, _io: io })
    }

    /// Create an in-memory Limbo database (useful for tests).
    pub fn in_memory() -> Result<Self, JacsError> {
        let io: Arc<dyn limbo_core::IO> = Arc::new(MemoryIO::new());

        let db = Database::open_file(io.clone(), ":memory:", false).map_err(|e| {
            JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(Self { db, _io: io })
    }

    /// Execute a SQL statement that returns no rows (DDL, INSERT, DELETE, etc.).
    fn execute_sql(&self, sql: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.db.connect().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })
        })?;

        conn.execute(sql).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "execute".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(())
    }

    /// Execute a SQL statement with bound parameters that returns no rows.
    fn execute_with_params(
        &self,
        sql: &str,
        params: &[LimboParam],
    ) -> Result<(), Box<dyn Error>> {
        let conn = self.db.connect().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })
        })?;

        let mut stmt = conn.prepare(sql).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "prepare".to_string(),
                reason: e.to_string(),
            })
        })?;

        for (i, param) in params.iter().enumerate() {
            let idx = NonZero::new(i + 1).unwrap();
            stmt.bind_at(idx, param.to_limbo_value());
        }

        loop {
            match stmt.step().map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "step".to_string(),
                    reason: e.to_string(),
                })
            })? {
                StepResult::Done => break,
                StepResult::IO => {
                    stmt.run_once().map_err(|e| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "io".to_string(),
                            reason: e.to_string(),
                        })
                    })?;
                }
                StepResult::Row => {
                    // For non-SELECT statements, consume any result rows
                    continue;
                }
                StepResult::Interrupt => {
                    return Err(Box::new(JacsError::DatabaseError {
                        operation: "execute".to_string(),
                        reason: "Statement interrupted".to_string(),
                    }));
                }
                StepResult::Busy => {
                    return Err(Box::new(JacsError::DatabaseError {
                        operation: "execute".to_string(),
                        reason: "Database busy".to_string(),
                    }));
                }
            }
        }

        Ok(())
    }

    /// Execute a query and collect results as JACSDocuments.
    fn query_documents(
        &self,
        sql: &str,
        params: &[LimboParam],
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let conn = self.db.connect().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })
        })?;

        let mut stmt = conn.prepare(sql).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "prepare".to_string(),
                reason: e.to_string(),
            })
        })?;

        for (i, param) in params.iter().enumerate() {
            let idx = NonZero::new(i + 1).unwrap();
            stmt.bind_at(idx, param.to_limbo_value());
        }

        let mut docs = Vec::new();
        loop {
            match stmt.step().map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "step".to_string(),
                    reason: e.to_string(),
                })
            })? {
                StepResult::Row => {
                    let row = stmt.row().ok_or_else(|| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "row".to_string(),
                            reason: "Expected row but got None".to_string(),
                        })
                    })?;
                    let doc = Self::row_to_document(row)?;
                    docs.push(doc);
                }
                StepResult::Done => break,
                StepResult::IO => {
                    stmt.run_once().map_err(|e| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "io".to_string(),
                            reason: e.to_string(),
                        })
                    })?;
                }
                StepResult::Interrupt => {
                    return Err(Box::new(JacsError::DatabaseError {
                        operation: "query".to_string(),
                        reason: "Query interrupted".to_string(),
                    }));
                }
                StepResult::Busy => {
                    return Err(Box::new(JacsError::DatabaseError {
                        operation: "query".to_string(),
                        reason: "Database busy".to_string(),
                    }));
                }
            }
        }

        Ok(docs)
    }

    /// Execute a query and collect results as key strings ("id:version").
    fn query_keys(
        &self,
        sql: &str,
        params: &[LimboParam],
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let conn = self.db.connect().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })
        })?;

        let mut stmt = conn.prepare(sql).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "prepare".to_string(),
                reason: e.to_string(),
            })
        })?;

        for (i, param) in params.iter().enumerate() {
            let idx = NonZero::new(i + 1).unwrap();
            stmt.bind_at(idx, param.to_limbo_value());
        }

        let mut keys = Vec::new();
        loop {
            match stmt.step().map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "step".to_string(),
                    reason: e.to_string(),
                })
            })? {
                StepResult::Row => {
                    let row = stmt.row().ok_or_else(|| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "row".to_string(),
                            reason: "Expected row but got None".to_string(),
                        })
                    })?;
                    let id: String = row.get(0).map_err(|e| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "get_column".to_string(),
                            reason: e.to_string(),
                        })
                    })?;
                    let version: String = row.get(1).map_err(|e| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "get_column".to_string(),
                            reason: e.to_string(),
                        })
                    })?;
                    keys.push(format!("{}:{}", id, version));
                }
                StepResult::Done => break,
                StepResult::IO => {
                    stmt.run_once().map_err(|e| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "io".to_string(),
                            reason: e.to_string(),
                        })
                    })?;
                }
                StepResult::Interrupt | StepResult::Busy => {
                    return Err(Box::new(JacsError::DatabaseError {
                        operation: "query".to_string(),
                        reason: "Query interrupted or busy".to_string(),
                    }));
                }
            }
        }

        Ok(keys)
    }

    /// Execute a COUNT(*) query and return the count.
    fn query_count(
        &self,
        sql: &str,
        params: &[LimboParam],
    ) -> Result<i64, Box<dyn Error>> {
        let conn = self.db.connect().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: e.to_string(),
            })
        })?;

        let mut stmt = conn.prepare(sql).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "prepare".to_string(),
                reason: e.to_string(),
            })
        })?;

        for (i, param) in params.iter().enumerate() {
            let idx = NonZero::new(i + 1).unwrap();
            stmt.bind_at(idx, param.to_limbo_value());
        }

        let mut count: i64 = 0;
        loop {
            match stmt.step().map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "step".to_string(),
                    reason: e.to_string(),
                })
            })? {
                StepResult::Row => {
                    let row = stmt.row().ok_or_else(|| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "row".to_string(),
                            reason: "Expected row but got None".to_string(),
                        })
                    })?;
                    count = row.get(0).map_err(|e| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "get_column".to_string(),
                            reason: e.to_string(),
                        })
                    })?;
                }
                StepResult::Done => break,
                StepResult::IO => {
                    stmt.run_once().map_err(|e| -> Box<dyn Error> {
                        Box::new(JacsError::DatabaseError {
                            operation: "io".to_string(),
                            reason: e.to_string(),
                        })
                    })?;
                }
                StepResult::Interrupt | StepResult::Busy => {
                    return Err(Box::new(JacsError::DatabaseError {
                        operation: "query".to_string(),
                        reason: "Query interrupted or busy".to_string(),
                    }));
                }
            }
        }

        Ok(count)
    }

    /// Parse a document key in format "id:version" into (id, version).
    fn parse_key(key: &str) -> Result<(&str, &str), Box<dyn Error>> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid document key '{}': expected 'id:version'", key).into());
        }
        Ok((parts[0], parts[1]))
    }

    /// Build a JACSDocument from a Limbo row.
    /// Expects columns: 0=jacs_id, 1=jacs_version, 2=agent_id, 3=jacs_type, 4=raw_contents, 5=file_contents
    fn row_to_document(row: &limbo_core::Row) -> Result<JACSDocument, Box<dyn Error>> {
        let id: String = row.get(0).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "row_get".to_string(),
                reason: format!("Failed to get jacs_id: {}", e),
            })
        })?;
        let version: String = row.get(1).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "row_get".to_string(),
                reason: format!("Failed to get jacs_version: {}", e),
            })
        })?;
        // column 2 is agent_id (skip)
        let jacs_type: String = row.get(3).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "row_get".to_string(),
                reason: format!("Failed to get jacs_type: {}", e),
            })
        })?;
        let raw: String = row.get(4).map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "row_get".to_string(),
                reason: format!("Failed to get raw_contents: {}", e),
            })
        })?;

        let value: Value = serde_json::from_str(&raw)?;

        Ok(JACSDocument {
            id,
            version,
            value,
            jacs_type,
        })
    }

    /// SQL for the jacs_document table creation.
    /// Limbo v0.0.22 does not support composite PRIMARY KEY constraints in
    /// CREATE TABLE, so we use a UNIQUE INDEX instead.
    const CREATE_TABLE_SQL: &str = r#"
        CREATE TABLE IF NOT EXISTS jacs_document (
            jacs_id TEXT NOT NULL,
            jacs_version TEXT NOT NULL,
            agent_id TEXT,
            jacs_type TEXT NOT NULL,
            raw_contents TEXT NOT NULL,
            file_contents TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
        )
    "#;

    /// SQL for indexes. The first index enforces the composite unique key.
    const CREATE_INDEXES_SQL: &[&str] = &[
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_jacs_document_pk ON jacs_document (jacs_id, jacs_version)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_type ON jacs_document (jacs_type)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_agent ON jacs_document (agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_created ON jacs_document (created_at DESC)",
    ];
}

/// Helper enum for parameter binding.
///
/// Limbo v0.0.22 does not support parameterized LIMIT/OFFSET, so integer
/// parameters are only needed if future versions add support. For now,
/// LIMIT values are inlined into the SQL string.
enum LimboParam {
    Text(String),
}

impl LimboParam {
    fn text(s: &str) -> Self {
        LimboParam::Text(s.to_string())
    }

    fn to_limbo_value(&self) -> LimboValue {
        match self {
            LimboParam::Text(s) => LimboValue::Text(limbo_core::types::Text::from_str(s.as_str())),
        }
    }

    fn text_opt(s: &Option<String>) -> Self {
        match s {
            Some(s) => LimboParam::Text(s.clone()),
            None => LimboParam::Text(String::new()),
        }
    }
}

impl StorageDocumentTraits for LimboStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>> {
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let file_contents_json = serde_json::to_string(&doc.value)?;
        let agent_id = doc
            .value
            .get("jacsSignature")
            .and_then(|s| s.get("jacsSignatureAgentId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Limbo v0.0.22 does not support INSERT OR IGNORE / ON CONFLICT,
        // so we check for existence first for idempotent behavior.
        let key = format!("{}:{}", doc.id, doc.version);
        if self.document_exists(&key)? {
            return Ok(());
        }

        let sql = r#"INSERT INTO jacs_document (jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#;

        let params = vec![
            LimboParam::text(&doc.id),
            LimboParam::text(&doc.version),
            LimboParam::text_opt(&agent_id),
            LimboParam::text(&doc.jacs_type),
            LimboParam::text(&raw_json),
            LimboParam::text(&file_contents_json),
        ];

        self.execute_with_params(sql, &params)
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let (id, version) = Self::parse_key(key)?;

        let sql = "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2";
        let params = vec![LimboParam::text(id), LimboParam::text(version)];

        let docs = self.query_documents(sql, &params)?;
        docs.into_iter().next().ok_or_else(|| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: format!("Document not found: {}", key),
            })
        })
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let doc = self.get_document(key)?;
        let (id, version) = Self::parse_key(key)?;

        // Limbo v0.0.22 has a bug where DELETE panics with an arithmetic
        // overflow. We catch the panic so the caller gets a proper error
        // instead of a process abort.
        let id_owned = id.to_string();
        let version_owned = version.to_string();

        // Build the connection and run delete inside catch_unwind
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let sql = "DELETE FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2";
            let params = vec![
                LimboParam::text(&id_owned),
                LimboParam::text(&version_owned),
            ];
            self.execute_with_params(sql, &params)
        }));

        match result {
            Ok(Ok(())) => Ok(doc),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // DELETE panicked (limbo_core v0.0.22 bug). Return the document
                // but note the data may not actually be removed.
                Err(Box::new(JacsError::DatabaseError {
                    operation: "remove_document".to_string(),
                    reason: "DELETE operation failed due to limbo_core v0.0.22 bug (arithmetic overflow). Document data may not be removed.".to_string(),
                }))
            }
        }
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let sql = "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_type = ?1 ORDER BY created_at DESC";
        let params = vec![LimboParam::text(prefix)];
        self.query_keys(sql, &params)
    }

    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        let (id, version) = Self::parse_key(key)?;

        let sql = "SELECT COUNT(*) FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2";
        let params = vec![LimboParam::text(id), LimboParam::text(version)];
        let count = self.query_count(sql, &params)?;

        Ok(count > 0)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let sql = "SELECT jacs_id, jacs_version FROM jacs_document WHERE agent_id = ?1 ORDER BY created_at DESC";
        let params = vec![LimboParam::text(agent_id)];
        self.query_keys(sql, &params)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let sql = "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at ASC";
        let params = vec![LimboParam::text(document_id)];
        self.query_keys(sql, &params)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let sql = "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at DESC LIMIT 1";
        let params = vec![LimboParam::text(document_id)];

        let docs = self.query_documents(sql, &params)?;
        docs.into_iter().next().ok_or_else(|| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: format!("No documents found with ID: {}", document_id),
            })
        })
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        Err(Box::new(JacsError::DatabaseError {
            operation: "merge_documents".to_string(),
            reason: "Not implemented for Limbo backend".to_string(),
        }))
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
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

impl DatabaseDocumentTraits for LimboStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        // Limbo v0.0.22 does not support OFFSET or parameterized LIMIT,
        // so we inline the LIMIT value and skip rows in Rust.
        let fetch_count = limit + offset;
        let sql = format!(
            "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_type = ?1 ORDER BY created_at DESC LIMIT {}",
            fetch_count
        );
        let params = vec![LimboParam::text(jacs_type)];
        let docs = self.query_documents(&sql, &params)?;
        Ok(docs.into_iter().skip(offset).collect())
    }

    fn query_by_field(
        &self,
        field_path: &str,
        value: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let json_path = format!("$.{}", field_path);
        let fetch_count = limit + offset;

        let docs = if let Some(doc_type) = jacs_type {
            let sql = format!(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, ?1) = ?2 AND jacs_type = ?3 ORDER BY created_at DESC LIMIT {}",
                fetch_count
            );
            let params = vec![
                LimboParam::text(&json_path),
                LimboParam::text(value),
                LimboParam::text(doc_type),
            ];
            self.query_documents(&sql, &params)?
        } else {
            let sql = format!(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, ?1) = ?2 ORDER BY created_at DESC LIMIT {}",
                fetch_count
            );
            let params = vec![
                LimboParam::text(&json_path),
                LimboParam::text(value),
            ];
            self.query_documents(&sql, &params)?
        };
        Ok(docs.into_iter().skip(offset).collect())
    }

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, Box<dyn Error>> {
        let sql = "SELECT COUNT(*) FROM jacs_document WHERE jacs_type = ?1";
        let params = vec![LimboParam::text(jacs_type)];
        let count = self.query_count(sql, &params)?;
        Ok(count as usize)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let sql = "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at ASC";
        let params = vec![LimboParam::text(jacs_id)];
        self.query_documents(sql, &params)
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
        let fetch_count = limit + offset;

        let docs = if let Some(doc_type) = jacs_type {
            let sql = format!(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ?1 AND jacs_type = ?2 ORDER BY created_at DESC LIMIT {}",
                fetch_count
            );
            let params = vec![
                LimboParam::text(agent_id),
                LimboParam::text(doc_type),
            ];
            self.query_documents(&sql, &params)?
        } else {
            let sql = format!(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ?1 ORDER BY created_at DESC LIMIT {}",
                fetch_count
            );
            let params = vec![LimboParam::text(agent_id)];
            self.query_documents(&sql, &params)?
        };
        Ok(docs.into_iter().skip(offset).collect())
    }

    fn run_migrations(&self) -> Result<(), Box<dyn Error>> {
        self.execute_sql(Self::CREATE_TABLE_SQL)?;

        for index_sql in Self::CREATE_INDEXES_SQL {
            // Limbo v0.0.22 has a bug where `IF NOT EXISTS` on indexes
            // still errors if the index already exists. We ignore that
            // specific error to make migrations idempotent.
            if let Err(e) = self.execute_sql(index_sql) {
                let msg = e.to_string();
                if !msg.contains("already exists") {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
