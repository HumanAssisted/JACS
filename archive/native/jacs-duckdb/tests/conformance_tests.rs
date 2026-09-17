//! Conformance tests for the DuckDB backend using JACS conformance macros.
//!
//! These tests run against an in-memory DuckDB instance — no external
//! services required.
//!
//! ```sh
//! cargo test -p jacs-duckdb -- conformance
//! ```

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs_duckdb::DuckDbStorage;
use serial_test::serial;

async fn create_duckdb_storage() -> DuckDbStorage {
    let storage = DuckDbStorage::in_memory().expect("Failed to create in-memory DuckDB");
    storage
        .run_migrations()
        .expect("Failed to run DuckDB migrations");
    storage
}

// Use the JACS conformance test macros.
// These macros bring in `make_test_doc` from `jacs::testing`.
jacs::storage_conformance_tests!(create_duckdb_storage);
jacs::database_conformance_tests!(create_duckdb_storage);
