#![cfg(all(not(target_arch = "wasm32"), feature = "redb-tests"))]

//! Conformance tests for the Redb backend.
//!
//! These tests run using an in-memory Redb database (via `InMemoryBackend`).
//!
//! ```sh
//! cargo test --features redb-tests -- conformance_redb
//! ```

mod conformance;

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::redb_storage::RedbStorage;
use serial_test::serial;

async fn create_redb_storage() -> RedbStorage {
    let db = RedbStorage::in_memory().expect("Failed to create in-memory Redb");
    db.run_migrations().expect("Failed to run Redb migrations");
    db
}

storage_conformance_tests!(create_redb_storage);
database_conformance_tests!(create_redb_storage);
