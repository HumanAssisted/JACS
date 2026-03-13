//! Database storage traits for JACS documents (Level 2 in the trait hierarchy).
//!
//! This module defines [`DatabaseDocumentTraits`] which extends
//! [`StorageDocumentTraits`](super::StorageDocumentTraits) with indexed query
//! capabilities that only a database backend can provide.
//!
//! # Trait Hierarchy
//!
//! ```text
//! StorageDocumentTraits        (base -- CRUD, list, versions, bulk)
//!     └── DatabaseDocumentTraits   (indexed queries -- type, field, agent, pagination)
//!         └── SearchProvider       (fulltext/vector/hybrid search -- defined in search/)
//! ```
//!
//! # Implementations
//!
//! - **Built-in:** `SqliteStorage` (sqlx), `RusqliteStorage` (rusqlite)
//! - **Extracted crates:** `jacs-postgresql`, `jacs-surrealdb`, `jacs-duckdb`, `jacs-redb`
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new rows
//! keyed by `(jacs_id, jacs_version)`. No UPDATE operations on existing rows.

use crate::agent::document::JACSDocument;
use std::error::Error;

/// Extended storage trait for database backends (Level 2).
///
/// Builds on [`StorageDocumentTraits`](super::StorageDocumentTraits) by adding
/// indexed query capabilities:
/// - Type-based queries with pagination
/// - Field-based JSON/JSONB queries
/// - Aggregation counts
/// - Version history ordered by creation date
/// - Agent-scoped queries
///
/// All methods are synchronous. Async implementations bridge internally
/// (e.g., `tokio::runtime::Handle::block_on`).
pub trait DatabaseDocumentTraits: Send + Sync {
    /// Query documents by their `jacsType` field with pagination.
    fn query_by_type(
        &self,
        jacs_type: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>>;

    /// Query documents where a JSONB field matches a value.
    /// `field_path` is a top-level field name (e.g., "jacsCommitmentStatus").
    fn query_by_field(
        &self,
        field_path: &str,
        value: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>>;

    /// Count documents by type.
    fn count_by_type(&self, jacs_type: &str) -> Result<usize, Box<dyn Error>>;

    /// Get all versions of a document ordered by creation date.
    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, Box<dyn Error>>;

    /// Get the most recent version of a document.
    fn get_latest(&self, jacs_id: &str) -> Result<JACSDocument, Box<dyn Error>>;

    /// Query documents by the agent that signed them.
    fn query_by_agent(
        &self,
        agent_id: &str,
        jacs_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JACSDocument>, Box<dyn Error>>;

    /// Run database migrations to create/update the schema.
    fn run_migrations(&self) -> Result<(), Box<dyn Error>>;
}

/// Placeholder for future vector search capabilities.
/// No methods yet — exists so downstream code can use `T: VectorSearchTraits` bounds.
pub trait VectorSearchTraits: DatabaseDocumentTraits {}
