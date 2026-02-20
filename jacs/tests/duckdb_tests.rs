#![cfg(all(not(target_arch = "wasm32"), feature = "duckdb-tests"))]

//! DuckDB-specific integration tests beyond the conformance suite.
//!
//! Tests cover:
//! - File-based DuckDB (not just in-memory)
//! - File persistence across connections
//! - JSON round-trip preservation
//! - Large document handling
//! - Special characters in data
//! - json_extract_string queries
//! - Version ordering
//!
//! ```sh
//! cargo test --features duckdb-tests -- duckdb_tests
//! ```

use jacs::agent::document::JACSDocument;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::duckdb_storage::DuckDbStorage;
use serde_json::json;
use serial_test::serial;
use tempfile::TempDir;

/// Create a test document with the given fields.
fn make_test_doc(id: &str, version: &str, jacs_type: &str, agent_id: Option<&str>) -> JACSDocument {
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

/// Create a file-based DuckDB storage in a temp directory.
fn create_file_duckdb(tmpdir: &TempDir) -> DuckDbStorage {
    let db_path = tmpdir.path().join("test.duckdb");
    let db_path_str = db_path.to_str().expect("valid path");
    let storage = DuckDbStorage::new(db_path_str).expect("Failed to create file-based DuckDB");
    storage.run_migrations().expect("Failed to run migrations");
    storage
}

#[test]
#[serial]
fn test_duckdb_file_based_storage() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let storage = create_file_duckdb(&tmpdir);

    let doc = make_test_doc("file-1", "v1", "agent", None);
    storage.store_document(&doc).expect("store failed");

    let retrieved = storage.get_document("file-1:v1").expect("get failed");
    assert_eq!(retrieved.id, "file-1");
    assert_eq!(retrieved.value["data"], "test content");
}

#[test]
#[serial]
fn test_duckdb_file_persistence() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let db_path = tmpdir.path().join("persist.duckdb");
    let db_path_str = db_path.to_str().expect("valid path").to_string();

    // Write with one connection
    {
        let storage = DuckDbStorage::new(&db_path_str).expect("Failed to create DuckDB");
        storage.run_migrations().expect("migrations failed");
        storage
            .store_document(&make_test_doc("persist-1", "v1", "agent", None))
            .expect("store failed");
    }

    // Read with a fresh connection
    {
        let storage = DuckDbStorage::new(&db_path_str).expect("Failed to reopen DuckDB");
        let doc = storage.get_document("persist-1:v1").expect("get failed");
        assert_eq!(doc.id, "persist-1");
    }
}

#[test]
#[serial]
fn test_duckdb_raw_contents_preserves_json() {
    let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
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
fn test_duckdb_large_document() {
    let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
    storage.run_migrations().expect("migrations failed");

    // Create a document with a large data payload (~100KB)
    let large_data = "x".repeat(100_000);
    let mut doc = make_test_doc("large-1", "v1", "artifact", None);
    doc.value["largeField"] = json!(large_data);

    storage.store_document(&doc).expect("store large doc failed");

    let retrieved = storage.get_document("large-1:v1").expect("get large doc failed");
    assert_eq!(
        retrieved.value["largeField"].as_str().unwrap().len(),
        100_000,
        "Large field should be preserved"
    );
}

#[test]
#[serial]
fn test_duckdb_special_characters_in_data() {
    let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
    storage.run_migrations().expect("migrations failed");

    let mut doc = make_test_doc("special-1", "v1", "agent", None);
    doc.value["data"] = json!("Hello 'world' with \"quotes\" and \nnewlines\tand\ttabs and unicode: \u{1F600}");

    storage.store_document(&doc).expect("store special chars failed");
    let retrieved = storage.get_document("special-1:v1").expect("get special chars failed");

    assert_eq!(retrieved.value["data"], doc.value["data"]);
}

#[test]
#[serial]
fn test_duckdb_query_by_field_with_json_extract() {
    let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
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
fn test_duckdb_multiple_versions_ordering() {
    let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
    storage.run_migrations().expect("migrations failed");

    // Insert versions with small delays to ensure different timestamps
    storage.store_document(&make_test_doc("mvo-1", "alpha", "agent", None)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    storage.store_document(&make_test_doc("mvo-1", "beta", "agent", None)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    storage.store_document(&make_test_doc("mvo-1", "gamma", "agent", None)).unwrap();

    let versions = storage.get_versions("mvo-1").expect("get_versions failed");
    assert_eq!(versions.len(), 3);
    // Should be ordered by created_at ASC
    assert_eq!(versions[0].version, "alpha");
    assert_eq!(versions[1].version, "beta");
    assert_eq!(versions[2].version, "gamma");

    let latest = storage.get_latest("mvo-1").expect("get_latest failed");
    assert_eq!(latest.version, "gamma");
}

#[test]
#[serial]
fn test_duckdb_count_accuracy() {
    let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
    storage.run_migrations().expect("migrations failed");

    // Start with zero
    assert_eq!(storage.count_by_type("widget").unwrap(), 0);

    // Add documents
    for i in 0..7 {
        storage.store_document(&make_test_doc(&format!("cnt-{}", i), "v1", "widget", None)).unwrap();
    }
    assert_eq!(storage.count_by_type("widget").unwrap(), 7);

    // Remove one
    storage.remove_document("cnt-3:v1").unwrap();
    assert_eq!(storage.count_by_type("widget").unwrap(), 6);
}
