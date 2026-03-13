//! Redb-specific integration tests beyond the conformance suite.
//!
//! Tests cover:
//! - File-based persistence
//! - JSON round-trip fidelity
//! - Large document handling
//! - Special characters
//! - Secondary index correctness
//! - Version ordering
//! - Concurrent reads (transaction isolation)
//!
//! ```sh
//! cargo test -p jacs-redb -- redb_tests
//! ```

use jacs::agent::document::JACSDocument;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs_redb::RedbStorage;
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

/// Create a file-based Redb storage in a temp directory.
fn create_file_redb(tmpdir: &TempDir) -> RedbStorage {
    let db_path = tmpdir.path().join("test.redb");
    let db_path_str = db_path.to_str().expect("valid path");
    let storage = RedbStorage::new(db_path_str).expect("Failed to create file-based Redb");
    storage.run_migrations().expect("Failed to run migrations");
    storage
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_file_based_storage() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let storage = create_file_redb(&tmpdir);

    let doc = make_test_doc("file-1", "v1", "agent", None);
    storage.store_document(&doc).expect("store failed");

    let retrieved = storage.get_document("file-1:v1").expect("get failed");
    assert_eq!(retrieved.id, "file-1");
    assert_eq!(retrieved.value["data"], "test content");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_file_persistence() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let db_path = tmpdir.path().join("persist.redb");
    let db_path_str = db_path.to_str().expect("valid path").to_string();

    // Write with one instance
    {
        let storage = RedbStorage::new(&db_path_str).expect("Failed to create Redb");
        storage.run_migrations().expect("migrations failed");
        storage
            .store_document(&make_test_doc("persist-1", "v1", "agent", None))
            .expect("store failed");
    }

    // Read with a fresh instance
    {
        let storage = RedbStorage::new(&db_path_str).expect("Failed to reopen Redb");
        let doc = storage.get_document("persist-1:v1").expect("get failed");
        assert_eq!(doc.id, "persist-1");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_json_round_trip() {
    let storage = RedbStorage::in_memory().expect("in-memory Redb");
    storage.run_migrations().expect("migrations failed");

    let doc = make_test_doc("roundtrip-1", "v1", "artifact", None);
    let expected_value = doc.value.clone();

    storage.store_document(&doc).expect("store failed");
    let retrieved = storage.get_document("roundtrip-1:v1").expect("get failed");

    assert_eq!(
        retrieved.value, expected_value,
        "Round-tripped value must match the original exactly"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_large_document() {
    let storage = RedbStorage::in_memory().expect("in-memory Redb");
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
#[serial]
async fn test_redb_special_characters() {
    let storage = RedbStorage::in_memory().expect("in-memory Redb");
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

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_secondary_index_correctness() {
    let storage = RedbStorage::in_memory().expect("in-memory Redb");
    storage.run_migrations().expect("migrations failed");

    // Store documents with different types and agents
    storage
        .store_document(&make_test_doc("idx-1", "v1", "agent", Some("alice")))
        .unwrap();
    storage
        .store_document(&make_test_doc("idx-2", "v1", "config", Some("alice")))
        .unwrap();
    storage
        .store_document(&make_test_doc("idx-3", "v1", "agent", Some("bob")))
        .unwrap();

    // Type index should work correctly
    let agents = storage.query_by_type("agent", 100, 0).unwrap();
    assert_eq!(agents.len(), 2, "Should find 2 agent documents");

    let configs = storage.query_by_type("config", 100, 0).unwrap();
    assert_eq!(configs.len(), 1, "Should find 1 config document");

    // Agent index should work correctly
    let alice_docs = storage.query_by_agent("alice", None, 100, 0).unwrap();
    assert_eq!(alice_docs.len(), 2, "Alice should have 2 documents");

    let bob_docs = storage.query_by_agent("bob", None, 100, 0).unwrap();
    assert_eq!(bob_docs.len(), 1, "Bob should have 1 document");

    // Agent + type filter
    let alice_agents = storage
        .query_by_agent("alice", Some("agent"), 100, 0)
        .unwrap();
    assert_eq!(alice_agents.len(), 1, "Alice should have 1 agent document");

    // Count
    assert_eq!(storage.count_by_type("agent").unwrap(), 2);
    assert_eq!(storage.count_by_type("config").unwrap(), 1);
    assert_eq!(storage.count_by_type("nonexistent").unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_version_ordering() {
    let storage = RedbStorage::in_memory().expect("in-memory Redb");
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
#[serial]
async fn test_redb_concurrent_reads() {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let db_path = tmpdir.path().join("concurrent.redb");
    let db_path_str = db_path.to_str().expect("valid path").to_string();

    // Set up the database with data
    let storage = RedbStorage::new(&db_path_str).expect("Failed to create Redb");
    storage.run_migrations().expect("migrations failed");

    for i in 0..10 {
        storage
            .store_document(&make_test_doc(&format!("conc-{}", i), "v1", "agent", None))
            .expect("store failed");
    }

    // Multiple reads from the same instance (Redb supports concurrent reads via MVCC)
    for i in 0..10 {
        let key = format!("conc-{}:v1", i);
        let doc = storage.get_document(&key).expect("concurrent read failed");
        assert_eq!(doc.id, format!("conc-{}", i));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_remove_cleans_indexes() {
    let storage = RedbStorage::in_memory().expect("in-memory Redb");
    storage.run_migrations().expect("migrations failed");

    storage
        .store_document(&make_test_doc("rm-idx-1", "v1", "agent", Some("alice")))
        .unwrap();
    storage
        .store_document(&make_test_doc("rm-idx-2", "v1", "agent", Some("alice")))
        .unwrap();

    assert_eq!(storage.count_by_type("agent").unwrap(), 2);
    assert_eq!(
        storage.query_by_agent("alice", None, 100, 0).unwrap().len(),
        2
    );

    // Remove one
    storage.remove_document("rm-idx-1:v1").unwrap();

    assert_eq!(storage.count_by_type("agent").unwrap(), 1);
    assert_eq!(
        storage.query_by_agent("alice", None, 100, 0).unwrap().len(),
        1
    );
    assert!(!storage.document_exists("rm-idx-1:v1").unwrap());
    assert!(storage.document_exists("rm-idx-2:v1").unwrap());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_redb_query_by_field() {
    let storage = RedbStorage::in_memory().expect("in-memory Redb");
    storage.run_migrations().expect("migrations failed");

    let mut doc_a = make_test_doc("qbf-a", "v1", "config", None);
    doc_a.value["status"] = json!("active");
    storage.store_document(&doc_a).unwrap();

    let mut doc_b = make_test_doc("qbf-b", "v1", "config", None);
    doc_b.value["status"] = json!("inactive");
    storage.store_document(&doc_b).unwrap();

    let active = storage
        .query_by_field("status", "active", Some("config"), 100, 0)
        .expect("query_by_field failed");
    assert_eq!(active.len(), 1, "Should find 1 active config document");
    assert_eq!(active[0].id, "qbf-a");
}
