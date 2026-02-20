#![cfg(all(not(target_arch = "wasm32"), feature = "limbo-tests"))]

//! Limbo-specific integration tests beyond the conformance suite.
//!
//! Tests cover:
//! - File-based Limbo storage
//! - File persistence across connections
//! - JSON round-trip fidelity
//! - Large document handling
//! - Special characters in data
//! - json_extract query
//! - Version ordering
//!
//! ```sh
//! cargo test --features limbo-tests -- limbo_tests
//! ```

use jacs::agent::document::JACSDocument;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::limbo_storage::LimboStorage;
use serde_json::json;
use serial_test::serial;

/// Create a test document with the given fields.
fn make_test_doc(
    id: &str,
    version: &str,
    jacs_type: &str,
    agent_id: Option<&str>,
) -> JACSDocument {
    let mut value = json!({
        "jacsId": id,
        "jacsVersion": version,
        "jacsType": jacs_type,
        "jacsLevel": "raw",
        "data": "test content"
    });
    if let Some(aid) = agent_id {
        value["jacsSignature"] = json!({
            "jacsSignatureAgentId": aid
        });
    }
    JACSDocument {
        id: id.to_string(),
        version: version.to_string(),
        value,
        jacs_type: jacs_type.to_string(),
    }
}

#[cfg(target_family = "unix")]
mod file_tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a file-based Limbo storage in a temp directory.
    fn create_file_limbo(tmpdir: &TempDir) -> LimboStorage {
        let db_path = tmpdir.path().join("test.db");
        let db_path_str = db_path.to_str().expect("valid path");
        let storage = LimboStorage::new(db_path_str).expect("Failed to create file-based Limbo");
        storage.run_migrations().expect("Failed to run migrations");
        storage
    }

    #[test]
    #[serial]
    fn test_limbo_file_based_storage() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let storage = create_file_limbo(&tmpdir);

        let doc = make_test_doc("file-1", "v1", "agent", None);
        storage.store_document(&doc).expect("store failed");

        let retrieved = storage.get_document("file-1:v1").expect("get failed");
        assert_eq!(retrieved.id, "file-1");
        assert_eq!(retrieved.value["data"], "test content");
    }

    #[test]
    #[serial]
    fn test_limbo_file_persistence() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let db_path = tmpdir.path().join("persist.db");
        let db_path_str = db_path.to_str().expect("valid path").to_string();

        // Write with one connection
        {
            let storage =
                LimboStorage::new(&db_path_str).expect("Failed to create Limbo");
            storage.run_migrations().expect("migrations failed");
            storage
                .store_document(&make_test_doc("persist-1", "v1", "agent", None))
                .expect("store failed");
        }

        // Read with a fresh connection
        {
            let storage =
                LimboStorage::new(&db_path_str).expect("Failed to reopen Limbo");
            let doc = storage.get_document("persist-1:v1").expect("get failed");
            assert_eq!(doc.id, "persist-1");
        }
    }
}

#[test]
#[serial]
fn test_limbo_raw_contents_preserves_json() {
    let storage = LimboStorage::in_memory().expect("in-memory Limbo");
    storage.run_migrations().expect("migrations failed");

    let doc = make_test_doc("preserve-1", "v1", "artifact", None);
    let expected_value = doc.value.clone();

    storage.store_document(&doc).expect("store failed");
    let retrieved = storage.get_document("preserve-1:v1").expect("get failed");

    assert_eq!(
        retrieved.value, expected_value,
        "Round-tripped value must match the original exactly"
    );
}

#[test]
#[serial]
fn test_limbo_large_document() {
    let storage = LimboStorage::in_memory().expect("in-memory Limbo");
    storage.run_migrations().expect("migrations failed");

    // Create a document with a large data payload (~100KB)
    let large_data = "x".repeat(100_000);
    let mut doc = make_test_doc("large-1", "v1", "artifact", None);
    doc.value["largeField"] = json!(large_data);

    storage
        .store_document(&doc)
        .expect("store large doc failed");

    let retrieved = storage
        .get_document("large-1:v1")
        .expect("get large doc failed");
    assert_eq!(
        retrieved.value["largeField"].as_str().unwrap().len(),
        100_000,
        "Large field should be preserved"
    );
}

#[test]
#[serial]
fn test_limbo_special_characters_in_data() {
    let storage = LimboStorage::in_memory().expect("in-memory Limbo");
    storage.run_migrations().expect("migrations failed");

    let mut doc = make_test_doc("special-1", "v1", "agent", None);
    doc.value["data"] = json!("Hello 'world' with \"quotes\" and \nnewlines\tand\ttabs and unicode: \u{1F600}");

    storage
        .store_document(&doc)
        .expect("store special chars failed");
    let retrieved = storage
        .get_document("special-1:v1")
        .expect("get special chars failed");

    assert_eq!(retrieved.value["data"], doc.value["data"]);
}

#[test]
#[serial]
fn test_limbo_query_by_field_with_json_extract() {
    let storage = LimboStorage::in_memory().expect("in-memory Limbo");
    storage.run_migrations().expect("migrations failed");

    let mut doc_a = make_test_doc("jqf-a", "v1", "config", None);
    doc_a.value["status"] = json!("active");
    storage.store_document(&doc_a).unwrap();

    let mut doc_b = make_test_doc("jqf-b", "v1", "config", None);
    doc_b.value["status"] = json!("inactive");
    storage.store_document(&doc_b).unwrap();

    let active = storage
        .query_by_field("status", "active", Some("config"), 100, 0)
        .expect("query_by_field failed");
    assert_eq!(active.len(), 1, "Should find 1 active config document");
    assert_eq!(active[0].id, "jqf-a");
}

#[test]
#[serial]
fn test_limbo_multiple_versions_ordering() {
    let storage = LimboStorage::in_memory().expect("in-memory Limbo");
    storage.run_migrations().expect("migrations failed");

    // Insert versions with small delays for distinct timestamps
    storage
        .store_document(&make_test_doc("mvo-1", "alpha", "agent", None))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    storage
        .store_document(&make_test_doc("mvo-1", "beta", "agent", None))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    storage
        .store_document(&make_test_doc("mvo-1", "gamma", "agent", None))
        .unwrap();

    let versions = storage.get_versions("mvo-1").expect("get_versions failed");
    assert_eq!(versions.len(), 3);
    // Should be ordered by created_at ASC
    assert_eq!(versions[0].version, "alpha");
    assert_eq!(versions[1].version, "beta");
    assert_eq!(versions[2].version, "gamma");

    let latest = storage.get_latest("mvo-1").expect("get_latest failed");
    assert_eq!(latest.version, "gamma");
}
