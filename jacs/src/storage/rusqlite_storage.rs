//! Rusqlite storage backend for JACS documents.
//!
//! Lightweight sync SQLite backend using `rusqlite` (no tokio/async required).
//! Uses TEXT columns for JSON storage with `json_extract()` for queries.
//! - `raw_contents` (TEXT): Preserves exact JSON bytes for signature verification
//! - `file_contents` (TEXT): JSON stored as text, queried via `json_extract()`
//!
//! # Append-Only Model
//!
//! Document content is immutable once stored. New versions create new rows
//! keyed by `(jacs_id, jacs_version)`. No UPDATE operations on signed content.
//!
//! # Visibility
//!
//! There are two code paths:
//! - **`DocumentService` path** (via `SqliteDocumentService` with an agent):
//!   `set_visibility()` routes through `update()`, creating a **successor version**
//!   with a new signature. This is the normal usage path.
//! - **`StorageDocumentTraits` path** (raw storage, no agent):
//!   `set_visibility()` updates only the `visibility` column in-place without
//!   creating a new version. This path is used internally and does not re-sign.
//!
//! # Feature Gate
//!
//! This module requires the `sqlite` feature flag and is excluded from WASM.

use crate::agent::Agent;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::document::{
    has_signed_document_headers, verify_document_value_with_agent, verify_document_with_agent,
};
use crate::error::JacsError;
use crate::storage::StorageDocumentTraits;
use crate::storage::database_traits::DatabaseDocumentTraits;
use rusqlite::{Connection, params};
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// Rusqlite storage backend for JACS documents.
///
/// Wraps a `rusqlite::Connection` in a `Mutex` for thread safety (`Send + Sync`).
/// All operations are synchronous — no tokio runtime required.
pub struct RusqliteStorage {
    conn: Mutex<Connection>,
}

impl RusqliteStorage {
    /// Create a new RusqliteStorage connected to the given SQLite database file.
    ///
    /// # Arguments
    ///
    /// * `database_path` - Path to the SQLite database file (e.g., `"./jacs.db"`)
    pub fn new(database_path: &str) -> Result<Self, JacsError> {
        let conn = Connection::open(database_path).map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;
        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: format!("Failed to enable WAL mode: {}", e),
            })?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory SQLite database (useful for tests).
    pub fn in_memory() -> Result<Self, JacsError> {
        let conn = Connection::open_in_memory().map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Parse a document key in format "id:version" into (id, version).
    fn parse_key(key: &str) -> Result<(&str, &str), JacsError> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid document key '{}': expected 'id:version'", key).into());
        }
        Ok((parts[0], parts[1]))
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

impl StorageDocumentTraits for RusqliteStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let file_contents_json = serde_json::to_string(&doc.value)?;
        let agent_id = doc
            .value
            .get("jacsSignature")
            .and_then(|s| s.get("jacsSignatureAgentId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "store_document".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        conn.execute(
            r#"INSERT OR IGNORE INTO jacs_document (jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![doc.id, doc.version, agent_id, doc.jacs_type, raw_json, file_contents_json],
        )
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

        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "get_document".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2",
            )
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_document".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let mut rows = stmt
            .query_map(params![id, version], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: e.to_string(),
            })?;

        match rows.next() {
            Some(Ok((jacs_id, jacs_version, jacs_type, raw))) => {
                let value: Value = serde_json::from_str(&raw)?;
                Ok(JACSDocument {
                    id: jacs_id,
                    version: jacs_version,
                    value,
                    jacs_type,
                })
            }
            Some(Err(e)) => Err(JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: e.to_string(),
            }),
            None => Err(JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: format!("Document not found: {}", key),
            }),
        }
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let doc = self.get_document(key)?;
        let (id, version) = Self::parse_key(key)?;

        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "remove_document".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        conn.execute(
            "DELETE FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2",
            params![id, version],
        )
        .map_err(|e| JacsError::DatabaseError {
            operation: "remove_document".to_string(),
            reason: e.to_string(),
        })?;

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "list_documents".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_type = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "list_documents".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let rows = stmt
            .query_map(params![prefix], |row| {
                let id: String = row.get(0)?;
                let version: String = row.get(1)?;
                Ok(format!("{}:{}", id, version))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "list_documents".to_string(),
                reason: e.to_string(),
            })?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| JacsError::DatabaseError {
                operation: "list_documents".to_string(),
                reason: e.to_string(),
            })?);
        }
        Ok(keys)
    }

    fn document_exists(&self, key: &str) -> Result<bool, JacsError> {
        let (id, version) = Self::parse_key(key)?;

        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "document_exists".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2",
                params![id, version],
                |row| row.get(0),
            )
            .map_err(|e| JacsError::DatabaseError {
                operation: "document_exists".to_string(),
                reason: e.to_string(),
            })?;

        Ok(count > 0)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "get_documents_by_agent".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE agent_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_documents_by_agent".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let rows = stmt
            .query_map(params![agent_id], |row| {
                let id: String = row.get(0)?;
                let version: String = row.get(1)?;
                Ok(format!("{}:{}", id, version))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_documents_by_agent".to_string(),
                reason: e.to_string(),
            })?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| JacsError::DatabaseError {
                operation: "get_documents_by_agent".to_string(),
                reason: e.to_string(),
            })?);
        }
        Ok(keys)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "get_document_versions".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_document_versions".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let rows = stmt
            .query_map(params![document_id], |row| {
                let id: String = row.get(0)?;
                let version: String = row.get(1)?;
                Ok(format!("{}:{}", id, version))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_document_versions".to_string(),
                reason: e.to_string(),
            })?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| JacsError::DatabaseError {
                operation: "get_document_versions".to_string(),
                reason: e.to_string(),
            })?);
        }
        Ok(keys)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "get_latest_document".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at DESC LIMIT 1",
            )
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_latest_document".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let mut rows = stmt
            .query_map(params![document_id], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: e.to_string(),
            })?;

        match rows.next() {
            Some(Ok((jacs_id, jacs_version, jacs_type, raw))) => {
                let value: Value = serde_json::from_str(&raw)?;
                Ok(JACSDocument {
                    id: jacs_id,
                    version: jacs_version,
                    value,
                    jacs_type,
                })
            }
            Some(Err(e)) => Err(JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: e.to_string(),
            }),
            None => Err(JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: format!("Document not found: {}", document_id),
            }),
        }
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, JacsError> {
        Err(JacsError::DatabaseError {
            operation: "merge_documents".to_string(),
            reason: "Not implemented for rusqlite backend".to_string(),
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

impl DatabaseDocumentTraits for RusqliteStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "query_by_type".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_type = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "query_by_type".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let rows = stmt
            .query_map(params![jacs_type, limit as i64, offset as i64], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "query_by_type".to_string(),
                reason: e.to_string(),
            })?;

        let mut docs = Vec::new();
        for row in rows {
            let (jacs_id, jacs_version, jacs_type, raw) =
                row.map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_type".to_string(),
                    reason: e.to_string(),
                })?;
            let value: Value = serde_json::from_str(&raw)?;
            docs.push(JACSDocument {
                id: jacs_id,
                version: jacs_version,
                value,
                jacs_type,
            });
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
        let json_path = format!("$.{}", field_path);

        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "query_by_field".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let rows_result: Vec<(String, String, String, String)> = if let Some(doc_type) = jacs_type {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, ?1) = ?2 AND jacs_type = ?3 ORDER BY created_at DESC LIMIT ?4 OFFSET ?5",
                )
                .map_err(|e| {
                    JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    }
                })?;

            let rows = stmt
                .query_map(
                    params![json_path, value, doc_type, limit as i64, offset as i64],
                    |row| {
                        let raw: String = row.get(4)?;
                        let jacs_id: String = row.get(0)?;
                        let jacs_version: String = row.get(1)?;
                        let jacs_type: String = row.get(3)?;
                        Ok((jacs_id, jacs_version, jacs_type, raw))
                    },
                )
                .map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_field".to_string(),
                    reason: e.to_string(),
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_field".to_string(),
                    reason: e.to_string(),
                })?);
            }
            collected
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, ?1) = ?2 ORDER BY created_at DESC LIMIT ?3 OFFSET ?4",
                )
                .map_err(|e| {
                    JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    }
                })?;

            let rows = stmt
                .query_map(
                    params![json_path, value, limit as i64, offset as i64],
                    |row| {
                        let raw: String = row.get(4)?;
                        let jacs_id: String = row.get(0)?;
                        let jacs_version: String = row.get(1)?;
                        let jacs_type: String = row.get(3)?;
                        Ok((jacs_id, jacs_version, jacs_type, raw))
                    },
                )
                .map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_field".to_string(),
                    reason: e.to_string(),
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_field".to_string(),
                    reason: e.to_string(),
                })?);
            }
            collected
        };

        let mut docs = Vec::new();
        for (jacs_id, jacs_version, jacs_type, raw) in rows_result {
            let value: Value = serde_json::from_str(&raw)?;
            docs.push(JACSDocument {
                id: jacs_id,
                version: jacs_version,
                value,
                jacs_type,
            });
        }
        Ok(docs)
    }

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "count_by_type".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM jacs_document WHERE jacs_type = ?1",
                params![jacs_type],
                |row| row.get(0),
            )
            .map_err(|e| JacsError::DatabaseError {
                operation: "count_by_type".to_string(),
                reason: e.to_string(),
            })?;

        Ok(count as usize)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "get_versions".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(|e| {
                JacsError::DatabaseError {
                    operation: "get_versions".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let rows = stmt
            .query_map(params![jacs_id], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_versions".to_string(),
                reason: e.to_string(),
            })?;

        let mut docs = Vec::new();
        for row in rows {
            let (jacs_id, jacs_version, jacs_type, raw) =
                row.map_err(|e| JacsError::DatabaseError {
                    operation: "get_versions".to_string(),
                    reason: e.to_string(),
                })?;
            let value: Value = serde_json::from_str(&raw)?;
            docs.push(JACSDocument {
                id: jacs_id,
                version: jacs_version,
                value,
                jacs_type,
            });
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
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "query_by_agent".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let rows_result: Vec<(String, String, String, String)> = if let Some(doc_type) = jacs_type {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ?1 AND jacs_type = ?2 ORDER BY created_at DESC LIMIT ?3 OFFSET ?4",
                )
                .map_err(|e| {
                    JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    }
                })?;

            let rows = stmt
                .query_map(
                    params![agent_id, doc_type, limit as i64, offset as i64],
                    |row| {
                        let raw: String = row.get(4)?;
                        let jacs_id: String = row.get(0)?;
                        let jacs_version: String = row.get(1)?;
                        let jacs_type: String = row.get(3)?;
                        Ok((jacs_id, jacs_version, jacs_type, raw))
                    },
                )
                .map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_agent".to_string(),
                    reason: e.to_string(),
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_agent".to_string(),
                    reason: e.to_string(),
                })?);
            }
            collected
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
                )
                .map_err(|e| {
                    JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    }
                })?;

            let rows = stmt
                .query_map(params![agent_id, limit as i64, offset as i64], |row| {
                    let raw: String = row.get(4)?;
                    let jacs_id: String = row.get(0)?;
                    let jacs_version: String = row.get(1)?;
                    let jacs_type: String = row.get(3)?;
                    Ok((jacs_id, jacs_version, jacs_type, raw))
                })
                .map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_agent".to_string(),
                    reason: e.to_string(),
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| JacsError::DatabaseError {
                    operation: "query_by_agent".to_string(),
                    reason: e.to_string(),
                })?);
            }
            collected
        };

        let mut docs = Vec::new();
        for (jacs_id, jacs_version, jacs_type, raw) in rows_result {
            let value: Value = serde_json::from_str(&raw)?;
            docs.push(JACSDocument {
                id: jacs_id,
                version: jacs_version,
                value,
                jacs_type,
            });
        }
        Ok(docs)
    }

    fn run_migrations(&self) -> Result<(), JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "run_migrations".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        conn.execute_batch(Self::CREATE_TABLE_SQL)
            .map_err(|e| JacsError::DatabaseError {
                operation: "run_migrations".to_string(),
                reason: e.to_string(),
            })?;

        for index_sql in Self::CREATE_INDEXES_SQL {
            conn.execute_batch(index_sql)
                .map_err(|e| JacsError::DatabaseError {
                    operation: "run_migrations".to_string(),
                    reason: format!("Failed to create index: {}", e),
                })?;
        }

        Ok(())
    }
}

// =============================================================================
// SqliteDocumentService — implements DocumentService + SearchProvider with FTS5
// =============================================================================

use crate::document::DocumentService;
use crate::document::types::{
    CreateOptions, DocumentDiff, DocumentSummary, DocumentVisibility, ListFilter, UpdateOptions,
};
use crate::search::{
    SearchCapabilities, SearchHit, SearchMethod, SearchProvider, SearchQuery, SearchResults,
};

/// SQLite-backed implementation of [`DocumentService`] with FTS5 fulltext search.
///
/// Wraps a `rusqlite::Connection` in a `Mutex` for thread safety.
/// All operations are synchronous — no tokio runtime required.
///
/// # FTS5 Search
///
/// On migration, a virtual FTS5 table `documents_fts` is created that indexes
/// `raw_contents` (document JSON), `jacs_type`, and `agent_id`. The `search()`
/// method uses `MATCH` queries against this table and returns
/// [`SearchMethod::FullText`].
///
/// # Visibility & Tombstoning
///
/// The extended schema adds `visibility` (TEXT, default `"private"`) and
/// `removed` (INTEGER, default 0) columns. `remove()` sets `removed = 1`
/// (tombstone) — it never deletes rows. `list()` excludes removed documents.
pub struct SqliteDocumentService {
    conn: Mutex<Connection>,
    agent: Arc<Mutex<Agent>>,
}

impl SqliteDocumentService {
    /// Create a new SqliteDocumentService connected to the given SQLite database file.
    pub fn new(database_path: &str) -> Result<Self, JacsError> {
        Self::with_agent(
            database_path,
            Arc::new(Mutex::new(crate::get_empty_agent())),
        )
    }

    /// Create a new SqliteDocumentService with an explicit signing/verifying agent.
    pub fn with_agent(database_path: &str, agent: Arc<Mutex<Agent>>) -> Result<Self, JacsError> {
        let conn = Connection::open(database_path).map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| JacsError::DatabaseError {
                operation: "connect".to_string(),
                reason: format!("Failed to enable WAL mode: {}", e),
            })?;
        let svc = Self {
            conn: Mutex::new(conn),
            agent,
        };
        svc.run_migrations()?;
        Ok(svc)
    }

    /// Create an in-memory SQLite database (useful for tests).
    pub fn in_memory() -> Result<Self, JacsError> {
        Self::in_memory_with_agent(Arc::new(Mutex::new(crate::get_empty_agent())))
    }

    /// Create an in-memory SQLite database with an explicit signing/verifying agent.
    pub fn in_memory_with_agent(agent: Arc<Mutex<Agent>>) -> Result<Self, JacsError> {
        let conn = Connection::open_in_memory().map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;
        let svc = Self {
            conn: Mutex::new(conn),
            agent,
        };
        svc.run_migrations()?;
        Ok(svc)
    }

    /// Run migrations: create jacs_document table (extended with visibility/removed),
    /// indexes, and FTS5 virtual table.
    fn run_migrations(&self) -> Result<(), JacsError> {
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "run_migrations".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        conn.execute_batch(Self::CREATE_TABLE_SQL)
            .map_err(|e| JacsError::DatabaseError {
                operation: "run_migrations".to_string(),
                reason: e.to_string(),
            })?;

        for index_sql in Self::CREATE_INDEXES_SQL {
            conn.execute_batch(index_sql)
                .map_err(|e| JacsError::DatabaseError {
                    operation: "run_migrations".to_string(),
                    reason: format!("Failed to create index: {}", e),
                })?;
        }

        conn.execute_batch(Self::CREATE_FTS_TABLE_SQL)
            .map_err(|e| JacsError::DatabaseError {
                operation: "run_migrations".to_string(),
                reason: format!("Failed to create FTS5 table: {}", e),
            })?;

        Ok(())
    }

    /// Parse a document key in format "id:version" into (id, version).
    fn parse_key(key: &str) -> Result<(&str, &str), JacsError> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(JacsError::DocumentError(format!(
                "Invalid document key '{}': expected 'id:version'",
                key
            )));
        }
        Ok((parts[0], parts[1]))
    }

    /// Extended schema with visibility and removed columns.
    const CREATE_TABLE_SQL: &str = r#"
        CREATE TABLE IF NOT EXISTS jacs_document (
            jacs_id TEXT NOT NULL,
            jacs_version TEXT NOT NULL,
            agent_id TEXT,
            jacs_type TEXT NOT NULL,
            raw_contents TEXT NOT NULL,
            file_contents TEXT NOT NULL,
            visibility TEXT NOT NULL DEFAULT 'private',
            removed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
            PRIMARY KEY (jacs_id, jacs_version)
        )
    "#;

    const CREATE_INDEXES_SQL: &[&str] = &[
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_type ON jacs_document (jacs_type)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_agent ON jacs_document (agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_created ON jacs_document (created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_removed ON jacs_document (removed)",
    ];

    /// FTS5 virtual table for fulltext search on document content.
    /// Uses content sync so we can manage the content table ourselves.
    const CREATE_FTS_TABLE_SQL: &str = r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
            raw_contents,
            jacs_type,
            agent_id,
            content='jacs_document',
            content_rowid='rowid'
        )
    "#;

    /// Helper: lock the connection and return a guard.
    fn lock_conn(
        &self,
        operation: &str,
    ) -> Result<std::sync::MutexGuard<'_, Connection>, JacsError> {
        self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: operation.to_string(),
            reason: format!("Lock poisoned: {}", e),
        })
    }

    /// Store a document and update the FTS5 index.
    fn store_and_index(
        &self,
        doc: &JACSDocument,
        visibility: &DocumentVisibility,
    ) -> Result<(), JacsError> {
        let raw_json = serde_json::to_string_pretty(&doc.value).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize document: {}", e))
        })?;
        let file_contents_json = serde_json::to_string(&doc.value).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize document: {}", e))
        })?;
        let agent_id = doc
            .value
            .get("jacsSignature")
            .and_then(|s| s.get("agentID").or_else(|| s.get("jacsSignatureAgentId")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let visibility_str = serde_json::to_string(visibility).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize visibility: {}", e))
        })?;

        let conn = self.lock_conn("store_and_index")?;

        conn.execute(
            r#"INSERT INTO jacs_document
               (jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents, visibility)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![
                doc.id,
                doc.version,
                agent_id,
                doc.jacs_type,
                raw_json,
                file_contents_json,
                visibility_str,
            ],
        )
        .map_err(|e| {
            let reason = e.to_string();
            if reason.contains("UNIQUE constraint") {
                JacsError::DocumentError(format!(
                    "Document already exists: {}:{}",
                    doc.id, doc.version
                ))
            } else {
                JacsError::DatabaseError {
                    operation: "store_and_index".to_string(),
                    reason,
                }
            }
        })?;

        // Update FTS5 index
        conn.execute(
            r#"INSERT INTO documents_fts(rowid, raw_contents, jacs_type, agent_id)
               SELECT rowid, raw_contents, jacs_type, COALESCE(agent_id, '')
               FROM jacs_document
               WHERE jacs_id = ?1 AND jacs_version = ?2"#,
            params![doc.id, doc.version],
        )
        .map_err(|e| JacsError::DatabaseError {
            operation: "store_and_index_fts".to_string(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Reconstruct a JACSDocument from a database row.
    fn doc_from_row(
        jacs_id: String,
        jacs_version: String,
        jacs_type: String,
        raw: String,
    ) -> Result<JACSDocument, JacsError> {
        let value: Value = serde_json::from_str(&raw).map_err(|e| {
            JacsError::DocumentError(format!("Failed to parse stored document JSON: {}", e))
        })?;
        Ok(JACSDocument {
            id: jacs_id,
            version: jacs_version,
            value,
            jacs_type,
        })
    }

    fn lock_agent(&self, operation: &str) -> Result<std::sync::MutexGuard<'_, Agent>, JacsError> {
        self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to lock agent for {}: {}", operation, e),
        })
    }
}

impl DocumentService for SqliteDocumentService {
    fn create(&self, json: &str, options: CreateOptions) -> Result<JACSDocument, JacsError> {
        let mut value: Value = serde_json::from_str(json)
            .map_err(|e| JacsError::DocumentError(format!("Invalid JSON: {}", e)))?;

        if let Some(obj) = value.as_object_mut() {
            obj.insert("jacsType".to_string(), serde_json::json!(options.jacs_type));
            obj.insert("jacsLevel".to_string(), serde_json::json!("artifact"));
            let vis_value = serde_json::to_value(&options.visibility).map_err(|e| {
                JacsError::DocumentError(format!("Failed to serialize visibility: {}", e))
            })?;
            obj.insert("jacsVisibility".to_string(), vis_value);
        }

        let doc_string = serde_json::to_string(&value).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize document payload: {}", e))
        })?;

        let mut agent = self.lock_agent("create")?;
        let doc = agent
            .create_document_and_load(&doc_string, None, None)
            .map_err(|e| JacsError::DocumentError(format!("Failed to create document: {}", e)))?;

        verify_document_with_agent(&mut agent, &doc)?;
        self.store_and_index(&doc, &options.visibility)?;
        Ok(doc)
    }

    fn get(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let (id, version) = Self::parse_key(key)?;
        let conn = self.lock_conn("get")?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, jacs_type, raw_contents FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2",
            )
            .map_err(|e| JacsError::DatabaseError {
                operation: "get".to_string(),
                reason: e.to_string(),
            })?;

        let mut rows = stmt
            .query_map(params![id, version], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get".to_string(),
                reason: e.to_string(),
            })?;

        match rows.next() {
            Some(Ok((jacs_id, jacs_version, jacs_type, raw))) => {
                let doc = Self::doc_from_row(jacs_id, jacs_version, jacs_type, raw)?;
                let mut agent = self.lock_agent("get")?;
                verify_document_with_agent(&mut agent, &doc)?;
                Ok(doc)
            }
            Some(Err(e)) => Err(JacsError::DatabaseError {
                operation: "get".to_string(),
                reason: e.to_string(),
            }),
            None => Err(JacsError::DocumentError(format!(
                "Document not found: {}",
                key
            ))),
        }
    }

    fn get_latest(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let conn = self.lock_conn("get_latest")?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, jacs_type, raw_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at DESC LIMIT 1",
            )
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_latest".to_string(),
                reason: e.to_string(),
            })?;

        let mut rows = stmt
            .query_map(params![document_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "get_latest".to_string(),
                reason: e.to_string(),
            })?;

        match rows.next() {
            Some(Ok((jacs_id, jacs_version, jacs_type, raw))) => {
                let doc = Self::doc_from_row(jacs_id, jacs_version, jacs_type, raw)?;
                let mut agent = self.lock_agent("get_latest")?;
                verify_document_with_agent(&mut agent, &doc)?;
                Ok(doc)
            }
            Some(Err(e)) => Err(JacsError::DatabaseError {
                operation: "get_latest".to_string(),
                reason: e.to_string(),
            }),
            None => Err(JacsError::DocumentError(format!(
                "Document not found: {}",
                document_id
            ))),
        }
    }

    fn update(
        &self,
        document_id: &str,
        new_json: &str,
        options: UpdateOptions,
    ) -> Result<JACSDocument, JacsError> {
        let current = self.get_latest(document_id)?;
        let current_key = current.getkey();

        let mut value: Value = serde_json::from_str(new_json)
            .map_err(|e| JacsError::DocumentError(format!("Invalid JSON: {}", e)))?;

        let mut agent = self.lock_agent("update")?;
        if has_signed_document_headers(&value) {
            verify_document_value_with_agent(&mut agent, &value)?;
        }

        let visibility = match options.visibility {
            Some(vis) => vis,
            None => current
                .value
                .get("jacsVisibility")
                .cloned()
                .and_then(|raw| serde_json::from_value(raw).ok())
                .unwrap_or(DocumentVisibility::Private),
        };

        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "jacsId".to_string(),
                current
                    .value
                    .get("jacsId")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(document_id)),
            );
            obj.insert(
                "jacsVersion".to_string(),
                current
                    .value
                    .get("jacsVersion")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(current.version)),
            );
            obj.insert("jacsType".to_string(), serde_json::json!(current.jacs_type));
            obj.insert("jacsLevel".to_string(), serde_json::json!("artifact"));
            let vis_value = serde_json::to_value(&visibility).map_err(|e| {
                JacsError::DocumentError(format!("Failed to serialize visibility: {}", e))
            })?;
            obj.insert("jacsVisibility".to_string(), vis_value);

            for field in &[
                "$schema",
                "jacsOriginalVersion",
                "jacsOriginalDate",
                "jacsSha256",
                "jacsSignature",
                "jacsVersionDate",
            ] {
                if let Some(existing) = current.value.get(*field) {
                    obj.entry((*field).to_string()).or_insert(existing.clone());
                }
            }
        }

        let new_doc_string = serde_json::to_string(&value).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize updated document: {}", e))
        })?;

        let _ = agent.load_document(
            &serde_json::to_string(&current.value)
                .map_err(|e| JacsError::DocumentError(e.to_string()))?,
        );

        let doc = agent
            .update_document(&current_key, &new_doc_string, None, None)
            .map_err(|e| JacsError::DocumentError(format!("Failed to update document: {}", e)))?;

        verify_document_with_agent(&mut agent, &doc)?;
        self.store_and_index(&doc, &visibility)?;
        Ok(doc)
    }

    fn remove(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let doc = self.get(key)?;
        let (id, version) = Self::parse_key(key)?;

        let conn = self.lock_conn("remove")?;
        conn.execute(
            "UPDATE jacs_document SET removed = 1 WHERE jacs_id = ?1 AND jacs_version = ?2",
            params![id, version],
        )
        .map_err(|e| JacsError::DatabaseError {
            operation: "remove".to_string(),
            reason: e.to_string(),
        })?;

        Ok(doc)
    }

    fn list(&self, filter: ListFilter) -> Result<Vec<DocumentSummary>, JacsError> {
        let conn = self.lock_conn("list")?;

        let mut sql = String::from(
            "SELECT jacs_id, jacs_version, jacs_type, agent_id, visibility, created_at FROM jacs_document WHERE removed = 0",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(ref jt) = filter.jacs_type {
            sql.push_str(&format!(" AND jacs_type = ?{}", param_idx));
            param_values.push(Box::new(jt.clone()));
            param_idx += 1;
        }
        if let Some(ref aid) = filter.agent_id {
            sql.push_str(&format!(" AND agent_id = ?{}", param_idx));
            param_values.push(Box::new(aid.clone()));
            param_idx += 1;
        }
        if let Some(ref vis) = filter.visibility {
            let vis_str = serde_json::to_string(vis).map_err(|e| {
                JacsError::DocumentError(format!("Failed to serialize visibility: {}", e))
            })?;
            sql.push_str(&format!(" AND visibility = ?{}", param_idx));
            param_values.push(Box::new(vis_str));
            param_idx += 1;
        }

        sql.push_str(" ORDER BY created_at DESC");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT ?{}", param_idx));
            param_values.push(Box::new(limit as i64));
            param_idx += 1;
        }
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET ?{}", param_idx));
            param_values.push(Box::new(offset as i64));
            // param_idx += 1; // not needed further
        }

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn.prepare(&sql).map_err(|e| JacsError::DatabaseError {
            operation: "list".to_string(),
            reason: e.to_string(),
        })?;

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "list".to_string(),
                reason: e.to_string(),
            })?;

        let mut row_data = Vec::new();
        for row in rows {
            let (jacs_id, jacs_version, jacs_type, agent_id, visibility_str, created_at) = row
                .map_err(|e| JacsError::DatabaseError {
                    operation: "list".to_string(),
                    reason: e.to_string(),
                })?;

            let visibility: DocumentVisibility =
                serde_json::from_str(&visibility_str).unwrap_or(DocumentVisibility::Private);
            row_data.push((
                format!("{}:{}", jacs_id, jacs_version),
                jacs_id,
                jacs_version,
                jacs_type,
                visibility,
                created_at,
                agent_id.unwrap_or_default(),
            ));
        }
        drop(stmt);
        drop(conn);

        let mut summaries = Vec::new();
        for (key, jacs_id, jacs_version, jacs_type, visibility, created_at, agent_id) in row_data {
            let _ = self.get(&key)?;
            summaries.push(DocumentSummary {
                key,
                document_id: jacs_id,
                version: jacs_version,
                jacs_type,
                visibility,
                created_at,
                agent_id,
            });
        }

        Ok(summaries)
    }

    fn versions(&self, document_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let conn = self.lock_conn("versions")?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, jacs_type, raw_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(|e| JacsError::DatabaseError {
                operation: "versions".to_string(),
                reason: e.to_string(),
            })?;

        let rows = stmt
            .query_map(params![document_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "versions".to_string(),
                reason: e.to_string(),
            })?;

        let mut docs = Vec::new();
        let mut agent = self.lock_agent("versions")?;
        for row in rows {
            let (jacs_id, jacs_version, jacs_type, raw) =
                row.map_err(|e| JacsError::DatabaseError {
                    operation: "versions".to_string(),
                    reason: e.to_string(),
                })?;
            let doc = Self::doc_from_row(jacs_id, jacs_version, jacs_type, raw)?;
            verify_document_with_agent(&mut agent, &doc)?;
            docs.push(doc);
        }
        Ok(docs)
    }

    fn diff(&self, key_a: &str, key_b: &str) -> Result<DocumentDiff, JacsError> {
        let doc_a = self.get(key_a)?;
        let doc_b = self.get(key_b)?;

        let json_a = serde_json::to_string_pretty(&doc_a.value).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize document: {}", e))
        })?;
        let json_b = serde_json::to_string_pretty(&doc_b.value).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize document: {}", e))
        })?;

        let changeset = difference::Changeset::new(&json_a, &json_b, "\n");
        let mut additions = 0usize;
        let mut deletions = 0usize;
        let mut diff_lines = Vec::new();

        for diff in &changeset.diffs {
            match diff {
                difference::Difference::Add(x) => {
                    additions += 1;
                    diff_lines.push(format!("+ {}", x));
                }
                difference::Difference::Rem(x) => {
                    deletions += 1;
                    diff_lines.push(format!("- {}", x));
                }
                difference::Difference::Same(x) => {
                    diff_lines.push(format!("  {}", x));
                }
            }
        }

        Ok(DocumentDiff {
            key_a: key_a.to_string(),
            key_b: key_b.to_string(),
            diff_text: diff_lines.join("\n"),
            additions,
            deletions,
        })
    }

    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError> {
        // Delegate to SearchProvider::search
        SearchProvider::search(self, query)
    }

    fn create_batch(
        &self,
        documents: &[&str],
        options: CreateOptions,
    ) -> Result<Vec<JACSDocument>, Vec<JacsError>> {
        let mut created = Vec::new();
        let mut errors = Vec::new();
        for json_str in documents {
            match self.create(json_str, options.clone()) {
                Ok(doc) => created.push(doc),
                Err(err) => errors.push(err),
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(created)
    }

    fn visibility(&self, key: &str) -> Result<DocumentVisibility, JacsError> {
        let doc = self.get(key)?;
        Ok(doc
            .value
            .get("jacsVisibility")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| JacsError::DocumentError(format!("Failed to parse visibility: {}", e)))?
            .unwrap_or(DocumentVisibility::Private))
    }

    fn set_visibility(&self, key: &str, visibility: DocumentVisibility) -> Result<(), JacsError> {
        let doc = self.get(key)?;

        // Strip signed headers so update() won't try to verify the old
        // signature against modified content. update() will re-add all
        // JACS headers and re-sign the document.
        let mut new_value = doc.value.clone();
        if let Some(obj) = new_value.as_object_mut() {
            obj.remove("jacsSignature");
            obj.remove("jacsSha256");
        }

        let new_json = serde_json::to_string(&new_value).map_err(|e| {
            JacsError::DocumentError(format!("Failed to serialize updated visibility: {}", e))
        })?;
        self.update(
            &doc.id,
            &new_json,
            UpdateOptions {
                visibility: Some(visibility),
                ..UpdateOptions::default()
            },
        )?;
        Ok(())
    }
}

impl SearchProvider for SqliteDocumentService {
    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError> {
        let conn = self.lock_conn("search")?;

        // If query is completely empty (no text, no filters), return empty results
        if query.query.trim().is_empty()
            && query.jacs_type.is_none()
            && query.agent_id.is_none()
            && query.field_filter.is_none()
        {
            return Ok(SearchResults {
                results: vec![],
                total_count: 0,
                method: SearchMethod::FullText,
            });
        }

        let has_fts_query = !query.query.trim().is_empty();

        // Build SQL using FTS5 MATCH when there's a query string
        let mut sql: String;
        let mut count_sql: String;
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut count_param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if has_fts_query {
            // Escape FTS5 special characters and add wildcard for prefix matching
            let fts_query = query.query.trim().to_string();

            sql = format!(
                "SELECT d.jacs_id, d.jacs_version, d.jacs_type, d.raw_contents, \
                 rank \
                 FROM documents_fts f \
                 JOIN jacs_document d ON f.rowid = d.rowid \
                 WHERE documents_fts MATCH ?{} AND d.removed = 0",
                param_idx
            );
            count_sql = format!(
                "SELECT COUNT(*) FROM documents_fts f \
                 JOIN jacs_document d ON f.rowid = d.rowid \
                 WHERE documents_fts MATCH ?{} AND d.removed = 0",
                param_idx
            );
            param_values.push(Box::new(fts_query.clone()));
            count_param_values.push(Box::new(fts_query));
            param_idx += 1;
        } else {
            sql = "SELECT d.jacs_id, d.jacs_version, d.jacs_type, d.raw_contents, \
                   0.5 as rank \
                   FROM jacs_document d \
                   WHERE d.removed = 0"
                .to_string();
            count_sql = "SELECT COUNT(*) FROM jacs_document d WHERE d.removed = 0".to_string();
        }

        if let Some(ref jt) = query.jacs_type {
            sql.push_str(&format!(" AND d.jacs_type = ?{}", param_idx));
            count_sql.push_str(&format!(" AND d.jacs_type = ?{}", param_idx));
            param_values.push(Box::new(jt.clone()));
            count_param_values.push(Box::new(jt.clone()));
            param_idx += 1;
        }

        if let Some(ref aid) = query.agent_id {
            sql.push_str(&format!(" AND d.agent_id = ?{}", param_idx));
            count_sql.push_str(&format!(" AND d.agent_id = ?{}", param_idx));
            param_values.push(Box::new(aid.clone()));
            count_param_values.push(Box::new(aid.clone()));
            param_idx += 1;
        }

        if let Some(ref ff) = query.field_filter {
            let json_path = format!("$.{}", ff.field_path);
            sql.push_str(&format!(
                " AND json_extract(d.file_contents, ?{}) = ?{}",
                param_idx,
                param_idx + 1
            ));
            count_sql.push_str(&format!(
                " AND json_extract(d.file_contents, ?{}) = ?{}",
                param_idx,
                param_idx + 1
            ));
            param_values.push(Box::new(json_path.clone()));
            param_values.push(Box::new(ff.value.clone()));
            count_param_values.push(Box::new(json_path));
            count_param_values.push(Box::new(ff.value.clone()));
            param_idx += 2;
        }

        if has_fts_query {
            sql.push_str(" ORDER BY rank");
        } else {
            sql.push_str(" ORDER BY d.created_at DESC");
        }

        sql.push_str(&format!(" LIMIT ?{}", param_idx));
        param_values.push(Box::new(query.limit as i64));
        param_idx += 1;

        sql.push_str(&format!(" OFFSET ?{}", param_idx));
        param_values.push(Box::new(query.offset as i64));

        // Get total count
        let count_refs: Vec<&dyn rusqlite::types::ToSql> =
            count_param_values.iter().map(|b| b.as_ref()).collect();
        let total_count: i64 = conn
            .query_row(&count_sql, count_refs.as_slice(), |row| row.get(0))
            .map_err(|e| JacsError::DatabaseError {
                operation: "search_count".to_string(),
                reason: e.to_string(),
            })?;

        // Get results
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn.prepare(&sql).map_err(|e| JacsError::DatabaseError {
            operation: "search".to_string(),
            reason: e.to_string(),
        })?;

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, f64>(4)?,
                ))
            })
            .map_err(|e| JacsError::DatabaseError {
                operation: "search".to_string(),
                reason: e.to_string(),
            })?;

        let mut hits = Vec::new();
        let mut agent = self.lock_agent("search")?;
        for row in rows {
            let (jacs_id, jacs_version, jacs_type, raw, rank) =
                row.map_err(|e| JacsError::DatabaseError {
                    operation: "search".to_string(),
                    reason: e.to_string(),
                })?;

            let doc = Self::doc_from_row(jacs_id, jacs_version, jacs_type, raw)?;
            verify_document_with_agent(&mut agent, &doc)?;
            // FTS5 rank is negative (lower = better). Normalize to 0.0-1.0 scale.
            let score = if has_fts_query {
                1.0 / (1.0 + rank.abs())
            } else {
                0.5
            };

            if let Some(min_score) = query.min_score {
                if score < min_score {
                    continue;
                }
            }

            hits.push(SearchHit {
                document: doc,
                score,
                matched_fields: if has_fts_query {
                    vec!["raw_contents".to_string()]
                } else {
                    vec![]
                },
            });
        }

        Ok(SearchResults {
            results: hits,
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
