//! Conformance tests for the in-memory (`MultiStorage`) backend.
//!
//! These tests run without Docker and validate that the memory-backed
//! `StorageDocumentTraits` implementation passes all conformance checks.
//!
//! ```sh
//! cargo test -- conformance_memory
//! ```

mod conformance;

use jacs::storage::MultiStorage;
use serial_test::serial;

async fn create_memory_storage() -> MultiStorage {
    MultiStorage::new("memory".to_string()).expect("memory storage")
}

storage_conformance_tests!(create_memory_storage);
