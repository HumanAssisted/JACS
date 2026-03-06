#![cfg(all(not(target_arch = "wasm32"), feature = "rusqlite-tests"))]

//! Conformance tests for the rusqlite backend.
//!
//! These tests run without Docker using an in-memory SQLite database.
//!
//! ```sh
//! cargo test --features rusqlite-tests -- conformance_rusqlite
//! ```

mod conformance;

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::rusqlite_storage::RusqliteStorage;
use serial_test::serial;

async fn create_rusqlite_storage() -> RusqliteStorage {
    let db = RusqliteStorage::in_memory().expect("Failed to create in-memory rusqlite");
    db.run_migrations()
        .expect("Failed to run rusqlite migrations");
    db
}

storage_conformance_tests!(create_rusqlite_storage);
database_conformance_tests!(create_rusqlite_storage);
