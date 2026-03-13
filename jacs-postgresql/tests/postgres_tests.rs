//! Integration tests for the PostgreSQL storage backend.
//!
//! These tests use testcontainers to spin up an ephemeral PostgreSQL instance
//! per test. Run with:
//!
//! ```sh
//! cargo test -p jacs-postgresql
//! ```
//!
//! Requirements: Docker must be running on the host.

use jacs::search::{SearchMethod, SearchProvider, SearchQuery};
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::testing::make_test_doc;
use jacs_postgresql::PostgresStorage;
use serde_json::json;
use serial_test::serial;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

/// Spin up a fresh PostgreSQL container and return the `PostgresStorage`
/// connected to it (with migrations already applied) together with the
/// container handle. The container is kept alive as long as the returned
/// `ContainerAsync` is held.
async fn setup_db() -> (PostgresStorage, ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .start()
        .await
        .expect("Failed to start PostgreSQL container");

    let host_port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get host port");

    let database_url = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        host_port
    );

    let db = PostgresStorage::new(&database_url, Some(5), Some(1), Some(30))
        .expect("Failed to create PostgresStorage");

    db.run_migrations()
        .expect("Failed to run database migrations");

    (db, container)
}

// ---------------------------------------------------------------------------
// StorageDocumentTraits Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_connection_and_migration() {
    let (db, _container) = setup_db().await;

    // Verify the table exists by counting rows (should be zero in a fresh db).
    let count = db.count_by_type("agent").expect("count_by_type failed");
    assert_eq!(count, 0, "Fresh database should have zero documents");
}

#[tokio::test]
#[serial]
async fn test_store_and_retrieve_document() {
    let (db, _container) = setup_db().await;

    let doc = make_test_doc("doc-1", "v1", "agent", Some("agent-alpha"));
    db.store_document(&doc).expect("store_document failed");

    let key = "doc-1:v1";
    let retrieved = db.get_document(key).expect("get_document failed");

    assert_eq!(retrieved.id, "doc-1");
    assert_eq!(retrieved.version, "v1");
    assert_eq!(retrieved.jacs_type, "agent");
    assert_eq!(retrieved.value["jacsId"], "doc-1");
    assert_eq!(retrieved.value["jacsVersion"], "v1");
    assert_eq!(retrieved.value["data"], "test content");
    assert_eq!(
        retrieved.value["jacsSignature"]["jacsSignatureAgentId"],
        "agent-alpha"
    );
}

#[tokio::test]
#[serial]
async fn test_raw_contents_preserves_json() {
    let (db, _container) = setup_db().await;

    let doc = make_test_doc("preserve-1", "v1", "artifact", None);
    let expected_value = doc.value.clone();

    db.store_document(&doc).expect("store_document failed");

    let retrieved = db
        .get_document("preserve-1:v1")
        .expect("get_document failed");

    assert_eq!(
        retrieved.value, expected_value,
        "Round-tripped value must match the original exactly"
    );
}

#[tokio::test]
#[serial]
async fn test_document_exists() {
    let (db, _container) = setup_db().await;

    let doc = make_test_doc("exists-1", "v1", "agent", None);
    db.store_document(&doc).expect("store_document failed");

    assert!(
        db.document_exists("exists-1:v1")
            .expect("document_exists failed"),
        "Stored document should exist"
    );
    assert!(
        !db.document_exists("nonexistent:v1")
            .expect("document_exists failed"),
        "Non-existent document should not exist"
    );
}

#[tokio::test]
#[serial]
async fn test_remove_document() {
    let (db, _container) = setup_db().await;

    let doc = make_test_doc("remove-1", "v1", "config", None);
    db.store_document(&doc).expect("store_document failed");

    assert!(db.document_exists("remove-1:v1").unwrap());

    let removed = db
        .remove_document("remove-1:v1")
        .expect("remove_document failed");
    assert_eq!(removed.id, "remove-1");

    assert!(
        !db.document_exists("remove-1:v1").unwrap(),
        "Document should no longer exist after removal"
    );

    assert!(
        db.get_document("remove-1:v1").is_err(),
        "get_document on removed key should return Err"
    );
}

#[tokio::test]
#[serial]
async fn test_list_documents_by_type() {
    let (db, _container) = setup_db().await;

    db.store_document(&make_test_doc("list-a1", "v1", "agent", None))
        .unwrap();
    db.store_document(&make_test_doc("list-a2", "v1", "agent", None))
        .unwrap();
    db.store_document(&make_test_doc("list-c1", "v1", "config", None))
        .unwrap();

    let agent_docs = db.list_documents("agent").expect("list_documents failed");
    assert_eq!(agent_docs.len(), 2, "Should list exactly 2 agent documents");
    for key in &agent_docs {
        assert!(
            key.starts_with("list-a"),
            "Listed key '{}' should belong to agent type",
            key
        );
    }

    let config_docs = db.list_documents("config").expect("list_documents failed");
    assert_eq!(
        config_docs.len(),
        1,
        "Should list exactly 1 config document"
    );
}

#[tokio::test]
#[serial]
async fn test_append_only_same_key() {
    let (db, _container) = setup_db().await;

    let doc = make_test_doc("dup-1", "v1", "agent", None);
    db.store_document(&doc).expect("First store should succeed");

    db.store_document(&doc)
        .expect("Second store (DO NOTHING) should not error");

    let versions = db
        .get_document_versions("dup-1")
        .expect("get_document_versions failed");
    assert_eq!(
        versions.len(),
        1,
        "Append-only: duplicate insert should not create a second row"
    );
}

#[tokio::test]
#[serial]
async fn test_multiple_versions() {
    let (db, _container) = setup_db().await;

    db.store_document(&make_test_doc("mv-1", "v1", "agent", None))
        .unwrap();
    db.store_document(&make_test_doc("mv-1", "v2", "agent", None))
        .unwrap();
    db.store_document(&make_test_doc("mv-1", "v3", "agent", None))
        .unwrap();

    let versions = db
        .get_document_versions("mv-1")
        .expect("get_document_versions failed");
    assert_eq!(versions.len(), 3, "Should have 3 versions");

    for key in &versions {
        assert!(
            key.starts_with("mv-1:"),
            "Key '{}' should start with 'mv-1:'",
            key
        );
    }

    for v in ["v1", "v2", "v3"] {
        let key = format!("mv-1:{}", v);
        let doc = db.get_document(&key).unwrap();
        assert_eq!(doc.version, v);
    }
}

#[tokio::test]
#[serial]
async fn test_get_latest_document() {
    let (db, _container) = setup_db().await;

    db.store_document(&make_test_doc("lat-1", "v1", "agent", None))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    db.store_document(&make_test_doc("lat-1", "v2", "agent", None))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    db.store_document(&make_test_doc("lat-1", "v3", "agent", None))
        .unwrap();

    let latest = db
        .get_latest_document("lat-1")
        .expect("get_latest_document failed");
    assert_eq!(
        latest.version, "v3",
        "Latest document should be the one with the most recent created_at"
    );
}

// ---------------------------------------------------------------------------
// DatabaseDocumentTraits Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_query_by_type_with_pagination() {
    let (db, _container) = setup_db().await;

    for i in 0..7 {
        let id = format!("pag-{}", i);
        db.store_document(&make_test_doc(&id, "v1", "task", None))
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let page1 = db
        .query_by_type("task", 3, 0)
        .expect("query_by_type page1 failed");
    assert_eq!(page1.len(), 3, "Page 1 should have 3 results");

    let page2 = db
        .query_by_type("task", 3, 3)
        .expect("query_by_type page2 failed");
    assert_eq!(page2.len(), 3, "Page 2 should have 3 results");

    let page3 = db
        .query_by_type("task", 3, 6)
        .expect("query_by_type page3 failed");
    assert_eq!(page3.len(), 1, "Page 3 should have 1 result");

    let all_ids: Vec<String> = page1
        .iter()
        .chain(page2.iter())
        .chain(page3.iter())
        .map(|d| d.id.clone())
        .collect();
    let mut deduped = all_ids.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(
        all_ids.len(),
        deduped.len(),
        "Paginated results should not overlap"
    );
}

#[tokio::test]
#[serial]
async fn test_query_by_field() {
    let (db, _container) = setup_db().await;

    let mut doc_a = make_test_doc("field-a", "v1", "config", None);
    doc_a.value["status"] = json!("active");
    db.store_document(&doc_a).unwrap();

    let mut doc_b = make_test_doc("field-b", "v1", "config", None);
    doc_b.value["status"] = json!("inactive");
    db.store_document(&doc_b).unwrap();

    let mut doc_c = make_test_doc("field-c", "v1", "config", None);
    doc_c.value["status"] = json!("active");
    db.store_document(&doc_c).unwrap();

    let active_docs = db
        .query_by_field("status", "active", None, 100, 0)
        .expect("query_by_field failed");
    assert_eq!(active_docs.len(), 2, "Should find 2 active documents");

    let active_configs = db
        .query_by_field("status", "active", Some("config"), 100, 0)
        .expect("query_by_field with type failed");
    assert_eq!(
        active_configs.len(),
        2,
        "Should find 2 active config documents"
    );

    let missing = db
        .query_by_field("status", "archived", None, 100, 0)
        .expect("query_by_field for missing value failed");
    assert!(missing.is_empty(), "Should find no 'archived' documents");
}

#[tokio::test]
#[serial]
async fn test_count_by_type() {
    let (db, _container) = setup_db().await;

    for i in 0..4 {
        db.store_document(&make_test_doc(&format!("cnt-{}", i), "v1", "message", None))
            .unwrap();
    }
    db.store_document(&make_test_doc("cnt-other", "v1", "agent", None))
        .unwrap();

    let count = db.count_by_type("message").expect("count_by_type failed");
    assert_eq!(count, 4, "Should count exactly 4 message documents");

    let agent_count = db.count_by_type("agent").expect("count_by_type failed");
    assert_eq!(agent_count, 1, "Should count exactly 1 agent document");

    let zero_count = db
        .count_by_type("nonexistent")
        .expect("count_by_type failed");
    assert_eq!(zero_count, 0, "Non-existent type should have count 0");
}

#[tokio::test]
#[serial]
async fn test_query_by_agent() {
    let (db, _container) = setup_db().await;

    db.store_document(&make_test_doc("ag-1", "v1", "agent", Some("alice")))
        .unwrap();
    db.store_document(&make_test_doc("ag-2", "v1", "config", Some("alice")))
        .unwrap();
    db.store_document(&make_test_doc("ag-3", "v1", "agent", Some("bob")))
        .unwrap();

    let alice_all = db
        .query_by_agent("alice", None, 100, 0)
        .expect("query_by_agent failed");
    assert_eq!(alice_all.len(), 2, "Alice should have 2 documents total");

    let alice_agents = db
        .query_by_agent("alice", Some("agent"), 100, 0)
        .expect("query_by_agent with type failed");
    assert_eq!(alice_agents.len(), 1, "Alice should have 1 agent document");

    let bob_all = db
        .query_by_agent("bob", None, 100, 0)
        .expect("query_by_agent failed");
    assert_eq!(bob_all.len(), 1, "Bob should have 1 document");

    let alice_keys = db
        .get_documents_by_agent("alice")
        .expect("get_documents_by_agent failed");
    assert_eq!(alice_keys.len(), 2);
}

#[tokio::test]
#[serial]
async fn test_bulk_store_and_retrieve() {
    let (db, _container) = setup_db().await;

    let docs = vec![
        make_test_doc("bulk-1", "v1", "agent", None),
        make_test_doc("bulk-2", "v1", "agent", None),
        make_test_doc("bulk-3", "v1", "config", None),
    ];

    db.store_documents(docs).expect("store_documents failed");

    let keys = vec![
        "bulk-1:v1".to_string(),
        "bulk-2:v1".to_string(),
        "bulk-3:v1".to_string(),
    ];
    let retrieved = db.get_documents(keys).expect("get_documents failed");

    assert_eq!(retrieved.len(), 3, "Should retrieve all 3 documents");
    assert_eq!(retrieved[0].id, "bulk-1");
    assert_eq!(retrieved[1].id, "bulk-2");
    assert_eq!(retrieved[2].id, "bulk-3");
}

#[tokio::test]
#[serial]
async fn test_merge_documents_not_supported() {
    let (db, _container) = setup_db().await;

    let result = db.merge_documents("some-id", "v1", "v2");
    assert!(
        result.is_err(),
        "merge_documents should return an error for the database backend"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Not implemented") || err_msg.contains("not implemented"),
        "Error message should indicate merge is not implemented, got: {}",
        err_msg
    );
}

#[tokio::test]
#[serial]
async fn test_get_versions_returns_full_documents() {
    let (db, _container) = setup_db().await;

    db.store_document(&make_test_doc("gv-1", "v1", "agent", Some("agent-x")))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    db.store_document(&make_test_doc("gv-1", "v2", "agent", Some("agent-x")))
        .unwrap();

    let versions = db.get_versions("gv-1").expect("get_versions failed");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, "v1", "Ordered by created_at ASC");
    assert_eq!(versions[1].version, "v2");

    assert_eq!(versions[0].jacs_type, "agent");
    assert_eq!(
        versions[0].value["jacsSignature"]["jacsSignatureAgentId"],
        "agent-x"
    );
}

#[tokio::test]
#[serial]
async fn test_get_latest_trait_method() {
    let (db, _container) = setup_db().await;

    db.store_document(&make_test_doc("gl-1", "v1", "config", None))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    db.store_document(&make_test_doc("gl-1", "v2", "config", None))
        .unwrap();

    let latest = db.get_latest("gl-1").expect("get_latest failed");
    assert_eq!(latest.version, "v2");
}

#[tokio::test]
#[serial]
async fn test_get_document_invalid_key_format() {
    let (db, _container) = setup_db().await;

    let result = db.get_document("invalid-key-no-colon");
    assert!(
        result.is_err(),
        "get_document with invalid key format should error"
    );
}

#[tokio::test]
#[serial]
async fn test_store_documents_partial_idempotency() {
    let (db, _container) = setup_db().await;

    let first = make_test_doc("batch-dup", "v1", "agent", None);
    db.store_document(&first).unwrap();

    let batch = vec![
        make_test_doc("batch-dup", "v1", "agent", None), // duplicate
        make_test_doc("batch-new", "v1", "agent", None), // new
    ];

    db.store_documents(batch)
        .expect("store_documents with duplicate should not error");

    assert!(db.document_exists("batch-dup:v1").unwrap());
    assert!(db.document_exists("batch-new:v1").unwrap());

    let versions = db.get_document_versions("batch-dup").unwrap();
    assert_eq!(versions.len(), 1, "Duplicate should not create extra row");
}

#[tokio::test]
#[serial]
async fn test_migrations_idempotent() {
    let (db, _container) = setup_db().await;

    // run_migrations was already called by setup_db; calling again should not error.
    db.run_migrations()
        .expect("Second run_migrations should not error");
}

// ---------------------------------------------------------------------------
// SearchProvider Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_search_capabilities() {
    let (db, _container) = setup_db().await;

    let caps = db.capabilities();
    assert!(caps.fulltext, "PostgreSQL should support fulltext search");
    assert!(!caps.vector, "Vector search is not yet implemented");
    assert!(!caps.hybrid, "Hybrid search is not yet implemented");
    assert!(
        caps.field_filter,
        "PostgreSQL should support field filtering"
    );
}

#[tokio::test]
#[serial]
async fn test_search_empty_query_returns_empty() {
    let (db, _container) = setup_db().await;

    let query = SearchQuery {
        query: String::new(),
        ..SearchQuery::default()
    };

    let results = db.search(query).expect("search should not error");
    assert_eq!(results.results.len(), 0);
    assert_eq!(results.total_count, 0);
    assert_eq!(results.method, SearchMethod::FullText);
}

#[tokio::test]
#[serial]
async fn test_search_fulltext_returns_results() {
    let (db, _container) = setup_db().await;

    // Store documents with distinct content for fulltext search.
    let mut doc1 = make_test_doc("fts-1", "v1", "artifact", None);
    doc1.value["content"] = json!("authentication middleware security");
    db.store_document(&doc1).unwrap();

    let mut doc2 = make_test_doc("fts-2", "v1", "artifact", None);
    doc2.value["content"] = json!("database migration schema");
    db.store_document(&doc2).unwrap();

    let query = SearchQuery {
        query: "authentication".to_string(),
        ..SearchQuery::default()
    };

    let results = db.search(query).expect("search should not error");
    assert_eq!(results.method, SearchMethod::FullText);
    assert!(
        results.total_count >= 1,
        "Should find at least 1 document matching 'authentication'"
    );
}

#[tokio::test]
#[serial]
async fn test_search_with_type_filter() {
    let (db, _container) = setup_db().await;

    let mut doc1 = make_test_doc("fts-type-1", "v1", "artifact", None);
    doc1.value["content"] = json!("authentication security");
    db.store_document(&doc1).unwrap();

    let mut doc2 = make_test_doc("fts-type-2", "v1", "config", None);
    doc2.value["content"] = json!("authentication settings");
    db.store_document(&doc2).unwrap();

    let query = SearchQuery {
        query: "authentication".to_string(),
        jacs_type: Some("artifact".to_string()),
        ..SearchQuery::default()
    };

    let results = db.search(query).expect("search should not error");
    // All results should be of type "artifact".
    for hit in &results.results {
        assert_eq!(hit.document.jacs_type, "artifact");
    }
}
