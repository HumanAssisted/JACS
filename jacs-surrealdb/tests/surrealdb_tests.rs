//! SurrealDB-specific integration tests for the jacs-surrealdb crate.
//!
//! Tests cover:
//! - JSON round-trip preservation
//! - Large document handling
//! - Native JSON path queries
//! - Compound ID idempotency
//! - Version ordering
//! - Special characters in data
//! - Count accuracy after removals
//! - SearchProvider capabilities
//! - Search functionality
//!
//! ```sh
//! cargo test -p jacs-surrealdb
//! ```

use jacs::agent::document::JACSDocument;
use jacs::search::{SearchProvider, SearchQuery};
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs_surrealdb::SurrealDbStorage;
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

// =========================================================================
// Embedded mode creation
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_create_storage_in_embedded_mode() {
    let storage = create_storage().await;
    // Verify storage is operational by running a simple operation
    assert_eq!(storage.count_by_type("nonexistent").unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_migrations_are_idempotent() {
    let storage = create_storage().await;
    // Run migrations again -- should not error
    storage
        .run_migrations()
        .expect("Second run_migrations should not error");
}

// =========================================================================
// CRUD roundtrip
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_crud_roundtrip() {
    let storage = create_storage().await;

    let doc = make_test_doc("crud-1", "v1", "artifact", Some("agent-alpha"));
    let expected_value = doc.value.clone();

    // Create
    storage.store_document(&doc).expect("store failed");

    // Read
    let retrieved = storage.get_document("crud-1:v1").expect("get failed");
    assert_eq!(retrieved.id, "crud-1");
    assert_eq!(retrieved.version, "v1");
    assert_eq!(retrieved.jacs_type, "artifact");
    assert_eq!(retrieved.value, expected_value);

    // Exists
    assert!(storage.document_exists("crud-1:v1").unwrap());
    assert!(!storage.document_exists("nonexistent:v1").unwrap());

    // List
    let keys = storage.list_documents("artifact").unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].starts_with("crud-1:"));

    // Remove
    let removed = storage.remove_document("crud-1:v1").expect("remove failed");
    assert_eq!(removed.id, "crud-1");
    assert!(!storage.document_exists("crud-1:v1").unwrap());
}

// =========================================================================
// JSON round-trip preservation
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_json_round_trip() {
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

// =========================================================================
// Large document handling
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_large_document() {
    let storage = create_storage().await;

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

// =========================================================================
// Native JSON path queries
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_native_json_path_query() {
    let storage = create_storage().await;

    let mut doc_a = make_test_doc("jsonpath-a", "v1", "config", None);
    doc_a.value["status"] = json!("active");
    storage.store_document(&doc_a).unwrap();

    let mut doc_b = make_test_doc("jsonpath-b", "v1", "config", None);
    doc_b.value["status"] = json!("inactive");
    storage.store_document(&doc_b).unwrap();

    let active = storage
        .query_by_field("status", "active", Some("config"), 100, 0)
        .expect("query_by_field failed");
    assert_eq!(active.len(), 1, "Should find 1 active config document");
    assert_eq!(active[0].id, "jsonpath-a");

    let all_active = storage
        .query_by_field("status", "active", None, 100, 0)
        .expect("query_by_field without type failed");
    assert_eq!(all_active.len(), 1, "Should find 1 active document total");
}

// =========================================================================
// Compound ID idempotency
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_compound_id_idempotency() {
    let storage = create_storage().await;

    let doc = make_test_doc("idem-1", "v1", "agent", None);

    storage.store_document(&doc).expect("First store should succeed");
    storage.store_document(&doc).expect("Second store should succeed (idempotent)");
    storage.store_document(&doc).expect("Third store should succeed (idempotent)");

    let versions = storage
        .get_document_versions("idem-1")
        .expect("get_document_versions failed");
    assert_eq!(versions.len(), 1, "Compound ID should prevent duplicate rows");

    let count = storage.count_by_type("agent").expect("count_by_type failed");
    assert_eq!(count, 1, "Count should reflect a single document");
}

// =========================================================================
// Version ordering
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_version_ordering() {
    let storage = create_storage().await;

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

    let versions = storage.get_versions("order-1").expect("get_versions failed");
    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0].version, "alpha");
    assert_eq!(versions[1].version, "beta");
    assert_eq!(versions[2].version, "gamma");

    let latest = storage.get_latest("order-1").expect("get_latest failed");
    assert_eq!(latest.version, "gamma");
}

// =========================================================================
// Special characters
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_special_characters() {
    let storage = create_storage().await;

    let mut doc = make_test_doc("special-1", "v1", "agent", None);
    doc.value["data"] =
        json!("Hello 'world' with \"quotes\" and \nnewlines\tand\ttabs and unicode: \u{1F600}");

    storage.store_document(&doc).expect("store special chars failed");
    let retrieved = storage.get_document("special-1:v1").expect("get special chars failed");

    assert_eq!(retrieved.value["data"], doc.value["data"]);
}

// =========================================================================
// Count accuracy
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_count_accuracy() {
    let storage = create_storage().await;

    assert_eq!(storage.count_by_type("widget").unwrap(), 0);

    for i in 0..7 {
        storage
            .store_document(&make_test_doc(&format!("cnt-{}", i), "v1", "widget", None))
            .unwrap();
    }
    assert_eq!(storage.count_by_type("widget").unwrap(), 7);

    storage.remove_document("cnt-3:v1").unwrap();
    assert_eq!(storage.count_by_type("widget").unwrap(), 6);
}

// =========================================================================
// SearchCapabilities
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_search_capabilities() {
    let storage = create_storage().await;

    let caps = storage.capabilities();
    assert!(!caps.fulltext, "SurrealDB CONTAINS is not true fulltext search");
    assert!(!caps.vector, "Vector search not supported");
    assert!(!caps.hybrid, "Hybrid search not supported");
    assert!(caps.field_filter, "Field filtering is supported");
}

// =========================================================================
// Search functionality
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_search_empty_query_returns_empty() {
    let storage = create_storage().await;

    storage
        .store_document(&make_test_doc("search-1", "v1", "artifact", None))
        .unwrap();

    let results = storage
        .search(SearchQuery {
            query: "".to_string(),
            ..SearchQuery::default()
        })
        .expect("search should not error");

    assert_eq!(results.results.len(), 0);
    assert_eq!(results.total_count, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_search_finds_matching_documents() {
    let storage = create_storage().await;

    let mut doc = make_test_doc("search-match-1", "v1", "artifact", None);
    doc.value["data"] = json!("authentication middleware for security");
    storage.store_document(&doc).unwrap();

    let mut doc2 = make_test_doc("search-match-2", "v1", "artifact", None);
    doc2.value["data"] = json!("database connection pooling");
    storage.store_document(&doc2).unwrap();

    let results = storage
        .search(SearchQuery {
            query: "authentication".to_string(),
            ..SearchQuery::default()
        })
        .expect("search should succeed");

    assert!(results.results.len() >= 1, "Should find at least 1 matching document");
    assert_eq!(results.results[0].document.id, "search-match-1");
}

// =========================================================================
// Bulk operations
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bulk_store_and_retrieve() {
    let storage = create_storage().await;

    let docs = vec![
        make_test_doc("bulk-1", "v1", "agent", None),
        make_test_doc("bulk-2", "v1", "agent", None),
        make_test_doc("bulk-3", "v1", "config", None),
    ];

    let keys = storage.store_documents(docs).expect("store_documents failed");
    assert_eq!(keys.len(), 3);

    let retrieved = storage
        .get_documents(vec![
            "bulk-1:v1".to_string(),
            "bulk-2:v1".to_string(),
            "bulk-3:v1".to_string(),
        ])
        .expect("get_documents failed");
    assert_eq!(retrieved.len(), 3);
}

// =========================================================================
// Agent queries
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_query_by_agent() {
    let storage = create_storage().await;

    storage
        .store_document(&make_test_doc("agent-q-1", "v1", "agent", Some("alice")))
        .unwrap();
    storage
        .store_document(&make_test_doc("agent-q-2", "v1", "config", Some("alice")))
        .unwrap();
    storage
        .store_document(&make_test_doc("agent-q-3", "v1", "agent", Some("bob")))
        .unwrap();

    let alice_all = storage
        .query_by_agent("alice", None, 100, 0)
        .expect("query_by_agent failed");
    assert_eq!(alice_all.len(), 2, "Alice should have 2 documents");

    let alice_agents = storage
        .query_by_agent("alice", Some("agent"), 100, 0)
        .expect("query_by_agent with type failed");
    assert_eq!(alice_agents.len(), 1, "Alice should have 1 agent document");
}

// =========================================================================
// Invalid key format
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_invalid_key_format() {
    let storage = create_storage().await;
    let result = storage.get_document("invalid-key-no-colon");
    assert!(result.is_err(), "get_document with invalid key format should error");
}

// =========================================================================
// Not found
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_document_not_found() {
    let storage = create_storage().await;
    let result = storage.get_document("missing-doc:v1");
    assert!(result.is_err(), "get_document on missing key should error");
}
