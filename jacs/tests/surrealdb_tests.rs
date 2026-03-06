#![cfg(all(not(target_arch = "wasm32"), feature = "surrealdb-tests"))]

//! SurrealDB-specific integration tests beyond the conformance suite.
//!
//! Tests cover:
//! - JSON round-trip preservation
//! - Large document handling
//! - Native JSON path queries
//! - Compound ID idempotency
//! - Version ordering
//! - Special characters in data
//! - Count accuracy after removals
//!
//! ```sh
//! cargo test --features surrealdb-tests -- surrealdb_tests
//! ```

use jacs::agent::document::JACSDocument;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::storage::surrealdb_storage::SurrealDbStorage;
use serde_json::json;
use serial_test::serial;

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

async fn create_storage() -> SurrealDbStorage {
    let db = SurrealDbStorage::in_memory_async()
        .await
        .expect("Failed to create in-memory SurrealDB");
    db.run_migrations()
        .expect("Failed to run SurrealDB migrations");
    db
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_surrealdb_json_round_trip() {
    let storage = create_storage().await;

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
async fn test_surrealdb_large_document() {
    let storage = create_storage().await;

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
async fn test_surrealdb_native_json_path_query() {
    let storage = create_storage().await;

    let mut doc_a = make_test_doc("jsonpath-a", "v1", "config", None);
    doc_a.value["status"] = json!("active");
    storage.store_document(&doc_a).unwrap();

    let mut doc_b = make_test_doc("jsonpath-b", "v1", "config", None);
    doc_b.value["status"] = json!("inactive");
    storage.store_document(&doc_b).unwrap();

    // SurrealDB uses native field paths: file_contents.status
    let active = storage
        .query_by_field("status", "active", Some("config"), 100, 0)
        .expect("query_by_field failed");
    assert_eq!(active.len(), 1, "Should find 1 active config document");
    assert_eq!(active[0].id, "jsonpath-a");

    // Query without type filter
    let all_active = storage
        .query_by_field("status", "active", None, 100, 0)
        .expect("query_by_field without type failed");
    assert_eq!(all_active.len(), 1, "Should find 1 active document total");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_surrealdb_compound_id_idempotency() {
    let storage = create_storage().await;

    let doc = make_test_doc("idem-1", "v1", "agent", None);

    // Store the same document multiple times
    storage
        .store_document(&doc)
        .expect("First store should succeed");
    storage
        .store_document(&doc)
        .expect("Second store should succeed (idempotent)");
    storage
        .store_document(&doc)
        .expect("Third store should succeed (idempotent)");

    // Should still have exactly one version
    let versions = storage
        .get_document_versions("idem-1")
        .expect("get_document_versions failed");
    assert_eq!(
        versions.len(),
        1,
        "Compound ID should prevent duplicate rows"
    );

    let count = storage
        .count_by_type("agent")
        .expect("count_by_type failed");
    assert_eq!(count, 1, "Count should reflect a single document");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_surrealdb_version_ordering() {
    let storage = create_storage().await;

    // Insert versions with delays to ensure different timestamps
    storage
        .store_document(&make_test_doc("order-1", "alpha", "agent", None))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    storage
        .store_document(&make_test_doc("order-1", "beta", "agent", None))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    storage
        .store_document(&make_test_doc("order-1", "gamma", "agent", None))
        .unwrap();

    let versions = storage
        .get_versions("order-1")
        .expect("get_versions failed");
    assert_eq!(versions.len(), 3);
    // Ordered by created_at ASC
    assert_eq!(versions[0].version, "alpha");
    assert_eq!(versions[1].version, "beta");
    assert_eq!(versions[2].version, "gamma");

    let latest = storage.get_latest("order-1").expect("get_latest failed");
    assert_eq!(latest.version, "gamma");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_surrealdb_special_characters() {
    let storage = create_storage().await;

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
async fn test_surrealdb_count_accuracy() {
    let storage = create_storage().await;

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
