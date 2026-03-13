//! DuckDB storage backend for JACS documents.
//!
//! This crate provides an in-process DuckDB storage implementation for the
//! JACS document system. It implements [`StorageDocumentTraits`],
//! [`DatabaseDocumentTraits`], and [`SearchProvider`] from the `jacs` crate.
//!
//! # Table Schema
//!
//! Documents are stored in a single `jacs_document` table with columns:
//! - `jacs_id` (VARCHAR, PK part 1) — stable document identifier
//! - `jacs_version` (VARCHAR, PK part 2) — version identifier
//! - `agent_id` (VARCHAR, nullable) — signing agent, extracted from `jacsSignature`
//! - `jacs_type` (VARCHAR) — document type (e.g., "agent", "config", "artifact")
//! - `raw_contents` (VARCHAR) — pretty-printed JSON for signature verification
//! - `file_contents` (VARCHAR) — compact JSON for `json_extract_string()` queries
//! - `created_at` (TIMESTAMP) — insertion timestamp
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new rows
//! keyed by `(jacs_id, jacs_version)`. No UPDATE operations on existing rows.
//! `INSERT OR IGNORE` provides idempotent writes.
//!
//! # Search Capabilities
//!
//! This backend supports fulltext search via DuckDB's `json_extract_string()`
//! for field-based queries, and `LIKE` for keyword search across JSON content.
//! Vector search is not supported.
//!
//! # Examples
//!
//! ```rust,no_run
//! use jacs_duckdb::DuckDbStorage;
//! use jacs::storage::database_traits::DatabaseDocumentTraits;
//!
//! let storage = DuckDbStorage::in_memory().expect("create in-memory DuckDB");
//! storage.run_migrations().expect("create tables");
//! ```

use jacs::agent::document::JACSDocument;
use jacs::error::JacsError;
use jacs::search::{
    FieldFilter, SearchCapabilities, SearchHit, SearchMethod, SearchProvider, SearchQuery,
    SearchResults,
};
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;

use duckdb::{Connection, params};
use serde_json::Value;
use std::error::Error;
use std::sync::Mutex;

/// DuckDB storage backend for JACS documents.
///
/// Wraps a `duckdb::Connection` in a `Mutex` for thread safety (`Send + Sync`).
/// All operations are synchronous — no tokio runtime required.
///
/// DuckDB runs fully in-process. No external server or Docker is needed.
pub struct DuckDbStorage {
    conn: Mutex<Connection>,
}

impl DuckDbStorage {
    /// Create a new DuckDbStorage connected to the given DuckDB database file.
    ///
    /// # Arguments
    ///
    /// * `database_path` - Path to the DuckDB database file (e.g., `"./jacs.duckdb"`)
    pub fn new(database_path: &str) -> Result<Self, JacsError> {
        let conn = Connection::open(database_path).map_err(|e| JacsError::DatabaseError {
            operation: "connect".to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory DuckDB database (useful for tests).
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

    /// SQL for the jacs_document table creation (DuckDB-compatible).
    const CREATE_TABLE_SQL: &str = r#"
        CREATE TABLE IF NOT EXISTS jacs_document (
            jacs_id VARCHAR NOT NULL,
            jacs_version VARCHAR NOT NULL,
            agent_id VARCHAR,
            jacs_type VARCHAR NOT NULL,
            raw_contents VARCHAR NOT NULL,
            file_contents VARCHAR NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (jacs_id, jacs_version)
        )
    "#;

    /// SQL for basic indexes.
    const CREATE_INDEXES_SQL: &[&str] = &[
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_type ON jacs_document (jacs_type)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_agent ON jacs_document (agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_jacs_document_created ON jacs_document (created_at DESC)",
    ];

    /// Return aggregate statistics: count of documents grouped by `jacs_type`.
    ///
    /// Inspired by the `db_stats()` pattern from `libhai/src/io/quack.rs`.
    pub fn db_stats(&self) -> Result<Vec<(i64, String)>, Box<dyn Error>> {
        let conn = self.conn.lock().map_err(|e| -> Box<dyn Error> {
            Box::new(JacsError::DatabaseError {
                operation: "db_stats".to_string(),
                reason: format!("Lock poisoned: {}", e),
            })
        })?;

        let mut stmt = conn
            .prepare("SELECT count(*) as count, jacs_type FROM jacs_document GROUP BY jacs_type")
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "db_stats".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "db_stats".to_string(),
                    reason: e.to_string(),
                })
            })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| -> Box<dyn Error> {
                Box::new(JacsError::DatabaseError {
                    operation: "db_stats".to_string(),
                    reason: e.to_string(),
                })
            })?);
        }
        Ok(results)
    }
}

// =============================================================================
// StorageDocumentTraits
// =============================================================================

impl StorageDocumentTraits for DuckDbStorage {
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
               VALUES (?, ?, ?, ?, ?, ?)"#,
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
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ? AND jacs_version = ?",
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
            "DELETE FROM jacs_document WHERE jacs_id = ? AND jacs_version = ?",
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
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_type = ? ORDER BY created_at DESC",
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
                "SELECT COUNT(*) FROM jacs_document WHERE jacs_id = ? AND jacs_version = ?",
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
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE agent_id = ? ORDER BY created_at DESC",
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
                "SELECT jacs_id, jacs_version FROM jacs_document WHERE jacs_id = ? ORDER BY created_at ASC",
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
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ? ORDER BY created_at DESC LIMIT 1",
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
            reason: "Not implemented for DuckDB backend".to_string(),
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

// =============================================================================
// DatabaseDocumentTraits
// =============================================================================

impl DatabaseDocumentTraits for DuckDbStorage {
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
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract_string(file_contents, ?) = ? AND jacs_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE json_extract_string(file_contents, ?) = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
                "SELECT COUNT(*) FROM jacs_document WHERE jacs_type = ?",
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
                "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE jacs_id = ? ORDER BY created_at ASC",
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ? AND jacs_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
                    "SELECT jacs_id, jacs_version, agent_id, jacs_type, raw_contents, file_contents FROM jacs_document WHERE agent_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
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

// =============================================================================
// SearchProvider
// =============================================================================

impl SearchProvider for DuckDbStorage {
    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError> {
        // If a field filter is provided, use json_extract_string for exact match
        if let Some(FieldFilter { field_path, value }) = &query.field_filter {
            let docs = self
                .query_by_field(
                    field_path,
                    value,
                    query.jacs_type.as_deref(),
                    query.limit,
                    query.offset,
                )
                .map_err(|e| JacsError::DatabaseError {
                    operation: "search".to_string(),
                    reason: e.to_string(),
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

        // For keyword queries, use LIKE on file_contents
        let conn = self.conn.lock().map_err(|e| JacsError::DatabaseError {
            operation: "search".to_string(),
            reason: format!("Lock poisoned: {}", e),
        })?;

        let like_pattern = format!("%{}%", query.query);

        let (sql, param_count) = match (&query.jacs_type, &query.agent_id) {
            (Some(_), Some(_)) => (
                "SELECT jacs_id, jacs_version, jacs_type, raw_contents FROM jacs_document WHERE file_contents LIKE ? AND jacs_type = ? AND agent_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                5,
            ),
            (Some(_), None) => (
                "SELECT jacs_id, jacs_version, jacs_type, raw_contents FROM jacs_document WHERE file_contents LIKE ? AND jacs_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                4,
            ),
            (None, Some(_)) => (
                "SELECT jacs_id, jacs_version, jacs_type, raw_contents FROM jacs_document WHERE file_contents LIKE ? AND agent_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                4,
            ),
            (None, None) => (
                "SELECT jacs_id, jacs_version, jacs_type, raw_contents FROM jacs_document WHERE file_contents LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                3,
            ),
        };

        let mut stmt = conn.prepare(sql).map_err(|e| JacsError::DatabaseError {
            operation: "search".to_string(),
            reason: e.to_string(),
        })?;

        // Build dynamic parameter list based on which filters are active
        let limit_i64 = query.limit as i64;
        let offset_i64 = query.offset as i64;

        let rows_result: Result<Vec<(String, String, String, String)>, _> = match param_count {
            5 => {
                let jt = query.jacs_type.as_deref().unwrap();
                let ai = query.agent_id.as_deref().unwrap();
                stmt.query_map(
                    params![like_pattern, jt, ai, limit_i64, offset_i64],
                    |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    },
                )
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            }
            4 if query.jacs_type.is_some() => {
                let jt = query.jacs_type.as_deref().unwrap();
                stmt.query_map(
                    params![like_pattern, jt, limit_i64, offset_i64],
                    |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    },
                )
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            }
            4 => {
                let ai = query.agent_id.as_deref().unwrap();
                stmt.query_map(
                    params![like_pattern, ai, limit_i64, offset_i64],
                    |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    },
                )
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            }
            _ => {
                stmt.query_map(
                    params![like_pattern, limit_i64, offset_i64],
                    |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    },
                )
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            }
        };

        let rows = rows_result.map_err(|e| JacsError::DatabaseError {
            operation: "search".to_string(),
            reason: e.to_string(),
        })?;

        // Pre-pagination total: run a separate COUNT query
        let count_where = match (&query.jacs_type, &query.agent_id) {
            (Some(_), Some(_)) => "WHERE file_contents LIKE ? AND jacs_type = ? AND agent_id = ?",
            (Some(_), None) => "WHERE file_contents LIKE ? AND jacs_type = ?",
            (None, Some(_)) => "WHERE file_contents LIKE ? AND agent_id = ?",
            (None, None) => "WHERE file_contents LIKE ?",
        };
        let count_sql = format!("SELECT COUNT(*) FROM jacs_document {}", count_where);
        let mut count_stmt = conn.prepare(&count_sql).map_err(|e| JacsError::DatabaseError {
            operation: "search_count".to_string(),
            reason: e.to_string(),
        })?;
        let total_count: i64 = match (&query.jacs_type, &query.agent_id) {
            (Some(jt), Some(ai)) => count_stmt.query_row(params![like_pattern, jt, ai], |row| row.get(0)),
            (Some(jt), None) => count_stmt.query_row(params![like_pattern, jt], |row| row.get(0)),
            (None, Some(ai)) => count_stmt.query_row(params![like_pattern, ai], |row| row.get(0)),
            (None, None) => count_stmt.query_row(params![like_pattern], |row| row.get(0)),
        }
        .map_err(|e| JacsError::DatabaseError {
            operation: "search_count".to_string(),
            reason: e.to_string(),
        })?;

        let mut results = Vec::new();
        for (jacs_id, jacs_version, jacs_type, raw) in rows {
            let value: Value = serde_json::from_str(&raw).map_err(|e| {
                JacsError::DatabaseError {
                    operation: "search".to_string(),
                    reason: format!("JSON parse error: {}", e),
                }
            })?;

            let score = if query.query.is_empty() {
                1.0
            } else {
                // Simple relevance: count occurrences of query in raw content
                let count = raw.matches(&query.query).count();
                (count as f64 / (count as f64 + 1.0)).min(1.0)
            };

            if let Some(min_score) = query.min_score {
                if score < min_score {
                    continue;
                }
            }

            results.push(SearchHit {
                document: JACSDocument {
                    id: jacs_id,
                    version: jacs_version,
                    value,
                    jacs_type,
                },
                score,
                matched_fields: vec!["file_contents".to_string()],
            });
        }

        Ok(SearchResults {
            results,
            total_count: total_count as usize,
            method: SearchMethod::FieldMatch, // LIKE is substring matching, not true fulltext
        })
    }

    fn capabilities(&self) -> SearchCapabilities {
        SearchCapabilities {
            fulltext: false, // DuckDB uses LIKE substring matching, not true fulltext search
            vector: false,
            hybrid: false,
            field_filter: true,
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use jacs::testing::make_test_doc as make_doc;

    fn setup() -> DuckDbStorage {
        let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
        storage.run_migrations().expect("migrations");
        storage
    }

    #[test]
    fn store_and_retrieve() {
        let storage = setup();
        let doc = make_doc("doc-1", "v1", "agent", Some("agent-1"));
        storage.store_document(&doc).expect("store");
        let got = storage.get_document("doc-1:v1").expect("get");
        assert_eq!(got.id, "doc-1");
        assert_eq!(got.version, "v1");
        assert_eq!(got.jacs_type, "agent");
        assert_eq!(got.value["data"], "test content");
    }

    #[test]
    fn document_not_found() {
        let storage = setup();
        assert!(storage.get_document("missing:v1").is_err());
    }

    #[test]
    fn document_exists_check() {
        let storage = setup();
        let doc = make_doc("exists-1", "v1", "config", None);
        storage.store_document(&doc).unwrap();
        assert!(storage.document_exists("exists-1:v1").unwrap());
        assert!(!storage.document_exists("nope:v1").unwrap());
    }

    #[test]
    fn remove_document_returns_doc() {
        let storage = setup();
        let doc = make_doc("rm-1", "v1", "config", None);
        storage.store_document(&doc).unwrap();
        let removed = storage.remove_document("rm-1:v1").unwrap();
        assert_eq!(removed.id, "rm-1");
        assert!(!storage.document_exists("rm-1:v1").unwrap());
    }

    #[test]
    fn list_documents_by_type() {
        let storage = setup();
        storage.store_document(&make_doc("ls-1", "v1", "agent", None)).unwrap();
        storage.store_document(&make_doc("ls-2", "v1", "agent", None)).unwrap();
        storage.store_document(&make_doc("ls-3", "v1", "config", None)).unwrap();

        let agents = storage.list_documents("agent").unwrap();
        assert_eq!(agents.len(), 2);
    }

    #[test]
    fn version_tracking() {
        let storage = setup();
        storage.store_document(&make_doc("ver-1", "alpha", "agent", None)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        storage.store_document(&make_doc("ver-1", "beta", "agent", None)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        storage.store_document(&make_doc("ver-1", "gamma", "agent", None)).unwrap();

        let versions = storage.get_document_versions("ver-1").unwrap();
        assert_eq!(versions.len(), 3);

        let db_versions = storage.get_versions("ver-1").unwrap();
        assert_eq!(db_versions.len(), 3);
        assert_eq!(db_versions[0].version, "alpha");
        assert_eq!(db_versions[2].version, "gamma");

        let latest = storage.get_latest_document("ver-1").unwrap();
        assert_eq!(latest.version, "gamma");
    }

    #[test]
    fn search_capabilities_reports_correctly() {
        let storage = setup();
        let caps = storage.capabilities();
        assert!(caps.fulltext);
        assert!(!caps.vector);
        assert!(!caps.hybrid);
        assert!(caps.field_filter);
    }

    #[test]
    fn search_by_field_filter() {
        let storage = setup();
        let mut doc = make_doc("sf-1", "v1", "config", None);
        doc.value["status"] = json!("active");
        storage.store_document(&doc).unwrap();

        let mut doc2 = make_doc("sf-2", "v1", "config", None);
        doc2.value["status"] = json!("inactive");
        storage.store_document(&doc2).unwrap();

        let results = storage
            .search(SearchQuery {
                query: String::new(),
                field_filter: Some(FieldFilter {
                    field_path: "status".to_string(),
                    value: "active".to_string(),
                }),
                limit: 10,
                offset: 0,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(results.results.len(), 1);
        assert_eq!(results.results[0].document.id, "sf-1");
        assert_eq!(results.method, SearchMethod::FieldMatch);
    }

    #[test]
    fn search_by_keyword() {
        let storage = setup();
        let mut doc = make_doc("kw-1", "v1", "artifact", None);
        doc.value["description"] = json!("authentication middleware implementation");
        storage.store_document(&doc).unwrap();

        let mut doc2 = make_doc("kw-2", "v1", "artifact", None);
        doc2.value["description"] = json!("database migration script");
        storage.store_document(&doc2).unwrap();

        let results = storage
            .search(SearchQuery {
                query: "authentication".to_string(),
                limit: 10,
                offset: 0,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(results.results.len(), 1);
        assert_eq!(results.results[0].document.id, "kw-1");
        assert_eq!(results.method, SearchMethod::FieldMatch);
    }

    #[test]
    fn db_stats_returns_type_counts() {
        let storage = setup();
        storage.store_document(&make_doc("st-1", "v1", "agent", None)).unwrap();
        storage.store_document(&make_doc("st-2", "v1", "agent", None)).unwrap();
        storage.store_document(&make_doc("st-3", "v1", "config", None)).unwrap();

        let stats = storage.db_stats().unwrap();
        assert_eq!(stats.len(), 2);
        // Find agent count
        let agent_stat = stats.iter().find(|(_, t)| t == "agent").unwrap();
        assert_eq!(agent_stat.0, 2);
    }

    #[test]
    fn idempotent_store() {
        let storage = setup();
        let doc = make_doc("idem-1", "v1", "agent", None);
        storage.store_document(&doc).unwrap();
        storage.store_document(&doc).unwrap(); // INSERT OR IGNORE
        let versions = storage.get_document_versions("idem-1").unwrap();
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn invalid_key_format() {
        let storage = setup();
        assert!(storage.get_document("no-colon-here").is_err());
    }

    #[test]
    fn merge_returns_error() {
        let storage = setup();
        assert!(storage.merge_documents("x", "v1", "v2").is_err());
    }

    #[test]
    fn bulk_store_and_get() {
        let storage = setup();
        let docs = vec![
            make_doc("bulk-1", "v1", "agent", None),
            make_doc("bulk-2", "v1", "config", None),
        ];
        let keys = storage.store_documents(docs).unwrap();
        assert_eq!(keys.len(), 2);

        let retrieved = storage.get_documents(keys).unwrap();
        assert_eq!(retrieved.len(), 2);
    }

    #[test]
    fn query_by_agent() {
        let storage = setup();
        storage.store_document(&make_doc("qa-1", "v1", "agent", Some("alice"))).unwrap();
        storage.store_document(&make_doc("qa-2", "v1", "config", Some("alice"))).unwrap();
        storage.store_document(&make_doc("qa-3", "v1", "agent", Some("bob"))).unwrap();

        let alice_all = storage.query_by_agent("alice", None, 100, 0).unwrap();
        assert_eq!(alice_all.len(), 2);

        let alice_agents = storage.query_by_agent("alice", Some("agent"), 100, 0).unwrap();
        assert_eq!(alice_agents.len(), 1);

        let agent_keys = storage.get_documents_by_agent("alice").unwrap();
        assert_eq!(agent_keys.len(), 2);
    }

    #[test]
    fn count_by_type_accuracy() {
        let storage = setup();
        assert_eq!(storage.count_by_type("widget").unwrap(), 0);
        for i in 0..5 {
            storage.store_document(&make_doc(&format!("cnt-{}", i), "v1", "widget", None)).unwrap();
        }
        assert_eq!(storage.count_by_type("widget").unwrap(), 5);
        storage.remove_document("cnt-2:v1").unwrap();
        assert_eq!(storage.count_by_type("widget").unwrap(), 4);
    }

    #[test]
    fn special_characters_roundtrip() {
        let storage = setup();
        let mut doc = make_doc("special-1", "v1", "agent", None);
        doc.value["data"] =
            json!("Hello 'world' with \"quotes\" and \nnewlines\tand\ttabs and unicode: \u{1F600}");
        storage.store_document(&doc).unwrap();
        let got = storage.get_document("special-1:v1").unwrap();
        assert_eq!(got.value["data"], doc.value["data"]);
    }

    #[test]
    fn large_document_handling() {
        let storage = setup();
        let large_data = "x".repeat(100_000);
        let mut doc = make_doc("large-1", "v1", "artifact", None);
        doc.value["largeField"] = json!(large_data);
        storage.store_document(&doc).unwrap();
        let got = storage.get_document("large-1:v1").unwrap();
        assert_eq!(got.value["largeField"].as_str().unwrap().len(), 100_000);
    }

    #[test]
    fn query_by_type_with_pagination() {
        let storage = setup();
        for i in 0..5 {
            storage
                .store_document(&make_doc(&format!("pag-{}", i), "v1", "task", None))
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let page1 = storage.query_by_type("task", 3, 0).unwrap();
        assert_eq!(page1.len(), 3);
        let page2 = storage.query_by_type("task", 3, 3).unwrap();
        assert_eq!(page2.len(), 2);
    }

    #[test]
    fn migrations_are_idempotent() {
        let storage = setup();
        // Already ran in setup; run again
        storage.run_migrations().expect("second run_migrations should not error");
    }
}
