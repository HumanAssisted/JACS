#![cfg(all(not(target_arch = "wasm32"), feature = "sqlite-tests"))]

//! Conformance tests for the SQLite backend.
//!
//! These tests run without Docker using an in-memory SQLite database.
//!
//! ```sh
//! cargo test --features sqlite-tests -- conformance_sqlite
//! ```

mod conformance;

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::sqlite::SqliteStorage;
use serial_test::serial;

async fn create_sqlite_storage() -> SqliteStorage {
    let db = SqliteStorage::in_memory_async()
        .await
        .expect("Failed to create in-memory SQLite");
    db.run_migrations()
        .expect("Failed to run SQLite migrations");
    db
}

storage_conformance_tests!(create_sqlite_storage);
database_conformance_tests!(create_sqlite_storage);
