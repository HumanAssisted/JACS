#![cfg(all(not(target_arch = "wasm32"), feature = "duckdb-tests"))]

//! Conformance tests for the DuckDB backend.
//!
//! These tests run without Docker using an in-memory DuckDB database.
//!
//! ```sh
//! cargo test --features duckdb-tests -- conformance_duckdb
//! ```

mod conformance;

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::duckdb_storage::DuckDbStorage;
use serial_test::serial;

async fn create_duckdb_storage() -> DuckDbStorage {
    let db = DuckDbStorage::in_memory().expect("Failed to create in-memory DuckDB");
    db.run_migrations()
        .expect("Failed to run DuckDB migrations");
    db
}

storage_conformance_tests!(create_duckdb_storage);
database_conformance_tests!(create_duckdb_storage);
