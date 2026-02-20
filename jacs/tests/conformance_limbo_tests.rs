#![cfg(all(not(target_arch = "wasm32"), feature = "limbo-tests"))]

//! Conformance tests for the Limbo backend.
//!
//! These tests run using an in-memory Limbo database (pure Rust, no external deps).
//!
//! ```sh
//! cargo test --features limbo-tests -- conformance_limbo
//! ```

mod conformance;

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::limbo_storage::LimboStorage;
use serial_test::serial;

async fn create_limbo_storage() -> LimboStorage {
    let db = LimboStorage::in_memory().expect("Failed to create in-memory Limbo");
    db.run_migrations().expect("Failed to run Limbo migrations");
    db
}

storage_conformance_tests!(create_limbo_storage);
database_conformance_tests!(create_limbo_storage);
