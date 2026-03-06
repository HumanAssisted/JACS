//! Rusqlite storage backend for JACS documents.
//!
//! Lightweight sync SQLite backend using `rusqlite` (no tokio/async required).
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
//! This module requires the `rusqlite-storage` feature flag and is excluded from WASM.

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::storage::StorageDocumentTraits;
use crate::storage::database_traits::DatabaseDocumentTraits;
use rusqlite::{Connection, params};
use serde_json::Value;
use std::error::Error;
use std::sync::Mutex;

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
    fn parse_key(key: &str) -> Result<(&str, &str), Box<dyn Error>> {
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
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>> {
        let raw_json = serde_json::to_string_pretty(&doc.value)?;
        let file_contents_json = serde_json::to_string(&doc.value)?;
        let agent_id = doc
            .value
            .get("jacsSignature")
            .and_then(|s| s.get("jacsSignatureAgentId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "store_document".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        conn.execute(
            r#"INSERT OR IGNORE INTO jacs_document (jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![doc.id, doc.version, agent_id, doc.jacs_type, raw_json, file_contents_json],
        )
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

        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2",
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_document".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut rows = stmt
            .query_map(params![id, version], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_document".to_string(),
                    reason: e.to_string(),
                })
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
            Some(Err(e)) => Err(Box::new(JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: e.to_string(),
            })),
            None => Err(Box::new(JacsError::DatabaseError {
                operation: "get_document".to_string(),
                reason: format!("Document not found: {}", key),
            })),
        }
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let doc = self.get_document(key)?;
        let (id, version) = Self::parse_key(key)?;

        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "remove_document".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        conn.execute(
            "DELETE FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2",
            params![id, version],
        )
        .map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "remove_document".to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "list_documents".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_type = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "list_documents".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let rows = stmt
            .query_map(params![prefix], |row| {
                let id: String = row.get(0)?;
                let version: String = row.get(1)?;
                Ok(format!("{}:{}", id, version))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "list_documents".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "list_documents".to_string(),
                    reason: e.to_string(),
                })
            })?);
        }
        Ok(keys)
    }

    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        let (id, version) = Self::parse_key(key)?;

        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "document_exists".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM jacs_document WHERE jacs_id = ?1 AND jacs_version = ?2",
                params![id, version],
                |row| row.get(0),
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "document_exists".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(count > 0)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_documents_by_agent".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE agent_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_documents_by_agent".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let rows = stmt
            .query_map(params![agent_id], |row| {
                let id: String = row.get(0)?;
                let version: String = row.get(1)?;
                Ok(format!("{}:{}", id, version))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_documents_by_agent".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_documents_by_agent".to_string(),
                    reason: e.to_string(),
                })
            })?);
        }
        Ok(keys)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_document_versions".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_document_versions".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let rows = stmt
            .query_map(params![document_id], |row| {
                let id: String = row.get(0)?;
                let version: String = row.get(1)?;
                Ok(format!("{}:{}", id, version))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_document_versions".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_document_versions".to_string(),
                    reason: e.to_string(),
                })
            })?);
        }
        Ok(keys)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at DESC LIMIT 1",
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_latest_document".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut rows = stmt
            .query_map(params![document_id], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_latest_document".to_string(),
                    reason: e.to_string(),
                })
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
            Some(Err(e)) => Err(Box::new(JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: e.to_string(),
            })),
            None => Err(Box::new(JacsError::DatabaseError {
                operation: "get_latest_document".to_string(),
                reason: format!("Document not found: {}", document_id),
            })),
        }
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        Err(Box::new(JacsError::DatabaseError {
            operation: "merge_documents".to_string(),
            reason: "Not implemented for rusqlite backend".to_string(),
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

impl DatabaseDocumentTraits for RusqliteStorage {
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_type".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_type = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "query_by_type".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let rows = stmt
            .query_map(params![jacs_type, limit as i64, offset as i64], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "query_by_type".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut docs = Vec::new();
        for row in rows {
            let (jacs_id, jacs_version, jacs_type, raw) = row.map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "query_by_type".to_string(),
                    reason: e.to_string(),
                })
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
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let json_path = format!("$.{}", field_path);

        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_field".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let rows_result: Vec<(String, String, String, String)> = if let Some(doc_type) = jacs_type {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, ?1) = ?2 AND jacs_type = ?3 ORDER BY created_at DESC LIMIT ?4 OFFSET ?5",
                )
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    })
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
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    })
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    })
                })?);
            }
            collected
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract(file_contents, ?1) = ?2 ORDER BY created_at DESC LIMIT ?3 OFFSET ?4",
                )
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    })
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
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    })
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_field".to_string(),
                        reason: e.to_string(),
                    })
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

    fn count_by_type(&self, jacs_type: &str) -> Result<usize, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "count_by_type".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM jacs_document WHERE jacs_type = ?1",
                params![jacs_type],
                |row| row.get(0),
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "count_by_type".to_string(),
                    reason: e.to_string(),
                })
            })?;

        Ok(count as usize)
    }

    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "get_versions".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_versions".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let rows = stmt
            .query_map(params![jacs_id], |row| {
                let raw: String = row.get(4)?;
                let jacs_id: String = row.get(0)?;
                let jacs_version: String = row.get(1)?;
                let jacs_type: String = row.get(3)?;
                Ok((jacs_id, jacs_version, jacs_type, raw))
            })
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_versions".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut docs = Vec::new();
        for row in rows {
            let (jacs_id, jacs_version, jacs_type, raw) = row.map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "get_versions".to_string(),
                    reason: e.to_string(),
                })
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
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "query_by_agent".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let rows_result: Vec<(String, String, String, String)> = if let Some(doc_type) = jacs_type {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ?1 AND jacs_type = ?2 ORDER BY created_at DESC LIMIT ?3 OFFSET ?4",
                )
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    })
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
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    })
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    })
                })?);
            }
            collected
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
                )
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    })
                })?;

            let rows = stmt
                .query_map(params![agent_id, limit as i64, offset as i64], |row| {
                    let raw: String = row.get(4)?;
                    let jacs_id: String = row.get(0)?;
                    let jacs_version: String = row.get(1)?;
                    let jacs_type: String = row.get(3)?;
                    Ok((jacs_id, jacs_version, jacs_type, raw))
                })
                .map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    })
                })?;

            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(|e| -> Box<dyn Error> {
                    Box::new(JacsError::DatabaseError {
                        operation: "query_by_agent".to_string(),
                        reason: e.to_string(),
                    })
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

    fn run_migrations(&self) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "run_migrations".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        conn.execute_batch(Self::CREATE_TABLE_SQL)
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "run_migrations".to_string(),
                    reason: e.to_string(),
                })
            })?;

        for index_sql in Self::CREATE_INDEXES_SQL {
            conn.execute_batch(index_sql)
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
