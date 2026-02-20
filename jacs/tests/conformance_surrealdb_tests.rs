#![cfg(all(not(target_arch = "wasm32"), feature = "surrealdb-tests"))]

//! Conformance tests for the SurrealDB backend.
//!
//! These tests run without external dependencies using an in-memory SurrealDB.
//!
//! ```sh
//! cargo test --features surrealdb-tests -- conformance_surrealdb
//! ```

mod conformance;

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::surrealdb_storage::SurrealDbStorage;
use serial_test::serial;

async fn create_surrealdb_storage() -> SurrealDbStorage {
    let db = SurrealDbStorage::in_memory_async()
        .await
        .expect("Failed to create in-memory SurrealDB");
    db.run_migrations()
        .expect("Failed to run SurrealDB migrations");
    db
}

storage_conformance_tests!(create_surrealdb_storage);
database_conformance_tests!(create_surrealdb_storage);
