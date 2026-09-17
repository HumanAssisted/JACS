#![cfg(all(not(target_arch = "wasm32"), feature = "sqlx-sqlite"))]

//! SQLite-specific integration tests beyond the conformance suite.
//!
//! Tests cover:
//! - File-based SQLite (not just in-memory)
//! - WAL mode
//! - Concurrent reads
//! - Large document handling
//! - Raw contents preservation
//!
//! ```sh
//! cargo test --features sqlite -- sqlite_tests
//! ```

use jacs::agent::document::JACSDocument;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::sqlite::SqliteStorage;
use serde_json::json;
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

/// Create a file-based SQLite storage in a temp directory.
async fn create_file_sqlite(tmpdir: &TempDir) -> SqliteStorage {
    let db_path = tmpdir.path().join("test.db");
    let db_path_str = db_path.to_str().expect("valid path");
    let storage = SqliteStorage::new_async(db_path_str, Some(5))
        .await
        .expect("Failed to create file-based SQLite");
    storage.run_migrations().expect("Failed to run migrations");
    storage
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_file_based_storage() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let storage = create_file_sqlite(&tmpdir).await;

    let doc = make_test_doc("file-1", "v1", "agent", None);
    storage.store_document(&doc).expect("store failed");

    let retrieved = storage.get_document("file-1:v1").expect("get failed");
    assert_eq!(retrieved.id, "file-1");
    assert_eq!(retrieved.value["data"], "test content");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_file_persistence() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let db_path = tmpdir.path().join("persist.db");
    let db_path_str = db_path.to_str().expect("valid path").to_string();

    // Write with one connection
    {
        let storage = SqliteStorage::new_async(&db_path_str, Some(1))
            .await
            .expect("Failed to create SQLite");
        storage.run_migrations().expect("migrations failed");
        storage
            .store_document(&make_test_doc("persist-1", "v1", "agent", None))
            .expect("store failed");
    }

    // Read with a fresh connection
    {
        let storage = SqliteStorage::new_async(&db_path_str, Some(1))
            .await
            .expect("Failed to reopen SQLite");
        let doc = storage.get_document("persist-1:v1").expect("get failed");
        assert_eq!(doc.id, "persist-1");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_raw_contents_preserves_json() {
    let storage = SqliteStorage::in_memory_async()
        .await
        .expect("in-memory SQLite");
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

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_large_document() {
    let storage = SqliteStorage::in_memory_async()
        .await
        .expect("in-memory SQLite");
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

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_concurrent_reads() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let db_path = tmpdir.path().join("concurrent.db");
    let db_path_str = db_path.to_str().expect("valid path").to_string();

    // Set up the database with some data
    let storage = SqliteStorage::new_async(&db_path_str, Some(5))
        .await
        .expect("Failed to create SQLite");
    storage.run_migrations().expect("migrations failed");

    for i in 0..10 {
        storage
            .store_document(&make_test_doc(&format!("conc-{}", i), "v1", "agent", None))
            .expect("store failed");
    }

    // Perform concurrent reads
    let mut handles = Vec::new();
    for i in 0..10 {
        let path = db_path_str.clone();
        let key = format!("conc-{}:v1", i);
        handles.push(tokio::spawn(async move {
            let s = SqliteStorage::new_async(&path, Some(1))
                .await
                .expect("Failed to open SQLite for read");
            s.get_document(&key).expect("concurrent read failed")
        }));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let doc = handle.await.expect("join failed");
        assert_eq!(doc.id, format!("conc-{}", i));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_query_by_field_with_json_extract() {
    let storage = SqliteStorage::in_memory_async()
        .await
        .expect("in-memory SQLite");
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

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_multiple_versions_ordering() {
    let storage = SqliteStorage::in_memory_async()
        .await
        .expect("in-memory SQLite");
    storage.run_migrations().expect("migrations failed");

    // Insert versions with delays to ensure different timestamps
    storage
        .store_document(&make_test_doc("mvo-1", "alpha", "agent", None))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    storage
        .store_document(&make_test_doc("mvo-1", "beta", "agent", None))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
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

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_count_accuracy() {
    let storage = SqliteStorage::in_memory_async()
        .await
        .expect("in-memory SQLite");
    storage.run_migrations().expect("migrations failed");

    // Start with zero
    assert_eq!(storage.count_by_type("widget").unwrap(), 0);

    // Add documents
    for i in 0..7 {
        storage
            .store_document(&make_test_doc(&format!("cnt-{}", i), "v1", "widget", None))
            .unwrap();
    }
    assert_eq!(storage.count_by_type("widget").unwrap(), 7);

    // Remove one
    storage.remove_document("cnt-3:v1").unwrap();
    assert_eq!(storage.count_by_type("widget").unwrap(), 6);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_special_characters_in_data() {
    let storage = SqliteStorage::in_memory_async()
        .await
        .expect("in-memory SQLite");
    storage.run_migrations().expect("migrations failed");

    let mut doc = make_test_doc("special-1", "v1", "agent", None);
    doc.value["data"] =
        json!("Hello 'world' with \"quotes\" and \nnewlines\tand\ttabs and unicode: \u{1F600}");

    storage
        .store_document(&doc)
        .expect("store special chars failed");
    let retrieved = storage
        .get_document("special-1:v1")
        .expect("get special chars failed");

    assert_eq!(retrieved.value["data"], doc.value["data"]);
}
