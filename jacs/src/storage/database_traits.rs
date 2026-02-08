//! Generic database storage traits for JACS documents.
//!
//! This module defines the `DatabaseDocumentTraits` trait which extends
//! `StorageDocumentTraits` with query capabilities that only a database
//! can provide. The trait is backend-agnostic -- implementations exist
//! for PostgreSQL (reference) with SQLite, DuckDB, and LanceDB planned.
//!
//! # Append-Only Model
//!
//! Documents are immutable once stored. New versions create new rows
//! keyed by `(jacs_id, jacs_version)`. No UPDATE operations on existing rows.

use crate::agent::document::JACSDocument;
use std::error::Error;

/// Extended storage trait for database backends.
///
/// Provides query capabilities beyond basic CRUD:
/// - Type-based queries with pagination
/// - Field-based JSONB queries
/// - Aggregation counts
/// - Version history
///
/// All methods are synchronous. Implementations bridge async internally.
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
