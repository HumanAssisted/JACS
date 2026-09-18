//! Conformance tests for the SurrealDB backend using JACS conformance macros.
//!
//! These tests run against an in-memory SurrealDB instance — no external
//! services required.
//!
//! ```sh
//! cargo test -p jacs-surrealdb -- conformance
//! ```

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs_surrealdb::SurrealDbStorage;
use serial_test::serial;

async fn create_surrealdb_storage() -> SurrealDbStorage {
    let db = SurrealDbStorage::in_memory_async()
        .await
        .expect("Failed to create in-memory SurrealDB");
    db.run_migrations()
        .expect("Failed to run SurrealDB migrations");
    db
}

// Use the JACS conformance test macros.
// These macros bring in `make_test_doc` from `jacs::testing`.
jacs::storage_conformance_tests!(create_surrealdb_storage);
jacs::database_conformance_tests!(create_surrealdb_storage);
