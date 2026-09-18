//! Conformance tests for the Redb backend using JACS conformance macros.
//!
//! These tests run against an in-memory Redb instance — no external
//! services required.
//!
//! ```sh
//! cargo test -p jacs-redb -- conformance
//! ```

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs_redb::RedbStorage;
use serial_test::serial;

async fn create_redb_storage() -> RedbStorage {
    let storage = RedbStorage::in_memory().expect("Failed to create in-memory Redb");
    storage
        .run_migrations()
        .expect("Failed to run Redb migrations");
    storage
}

// Use the JACS conformance test macros.
// These macros bring in `make_test_doc` from `jacs::testing`.
jacs::storage_conformance_tests!(create_redb_storage);
jacs::database_conformance_tests!(create_redb_storage);
