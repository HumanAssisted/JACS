//! Integration tests for the jacs-duckdb crate.
//!
//! Tests run against an in-memory DuckDB database — no Docker or external
//! services required.

use jacs::search::{FieldFilter, SearchCapabilities, SearchMethod, SearchProvider, SearchQuery};
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs::testing::make_test_doc as make_doc;
use jacs_duckdb::DuckDbStorage;
use serde_json::json;

fn setup() -> DuckDbStorage {
    let storage = DuckDbStorage::in_memory().expect("in-memory DuckDB");
    storage.run_migrations().expect("run_migrations");
    storage
}

// =============================================================================
// CRUD Roundtrip
// =============================================================================

#[test]
fn crud_roundtrip() {
    let storage = setup();

    // Create
    let doc = make_doc("crud-1", "v1", "agent", Some("agent-alpha"));
    storage.store_document(&doc).expect("store");

    // Read
    let got = storage.get_document("crud-1:v1").expect("get");
    assert_eq!(got.id, "crud-1");
    assert_eq!(got.version, "v1");
    assert_eq!(got.jacs_type, "agent");
    assert_eq!(got.value["data"], "test content");

    // Exists
    assert!(storage.document_exists("crud-1:v1").unwrap());

    // Remove
    let removed = storage.remove_document("crud-1:v1").expect("remove");
    assert_eq!(removed.id, "crud-1");
    assert!(!storage.document_exists("crud-1:v1").unwrap());
}

// =============================================================================
// List Documents by Type
// =============================================================================

#[test]
fn list_documents_by_type() {
    let storage = setup();
    storage
        .store_document(&make_doc("lt-1", "v1", "agent", None))
        .unwrap();
    storage
        .store_document(&make_doc("lt-2", "v1", "agent", None))
        .unwrap();
    storage
        .store_document(&make_doc("lt-3", "v1", "config", None))
        .unwrap();

    let agents = storage.list_documents("agent").unwrap();
    assert_eq!(agents.len(), 2);

    let configs = storage.list_documents("config").unwrap();
    assert_eq!(configs.len(), 1);

    let empty = storage.list_documents("nonexistent").unwrap();
    assert!(empty.is_empty());
}

// =============================================================================
// Search Capabilities
// =============================================================================

#[test]
fn search_capabilities_report() {
    let storage = setup();
    let caps = storage.capabilities();
    assert_eq!(
        caps,
        SearchCapabilities {
            fulltext: false,
            vector: false,
            hybrid: false,
            field_filter: true,
        }
    );
}

// =============================================================================
// Fulltext Search (query_by_field)
// =============================================================================

#[test]
fn fulltext_search_via_query_by_field() {
    let storage = setup();

    let mut doc_a = make_doc("fts-a", "v1", "config", None);
    doc_a.value["status"] = json!("active");
    storage.store_document(&doc_a).unwrap();

    let mut doc_b = make_doc("fts-b", "v1", "config", None);
    doc_b.value["status"] = json!("inactive");
    storage.store_document(&doc_b).unwrap();

    // With type filter
    let active = storage
        .query_by_field("status", "active", Some("config"), 100, 0)
        .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "fts-a");

    // Without type filter
    let all_active = storage
        .query_by_field("status", "active", None, 100, 0)
        .unwrap();
    assert_eq!(all_active.len(), 1);

    // No matches
    let none = storage
        .query_by_field("status", "archived", None, 100, 0)
        .unwrap();
    assert!(none.is_empty());
}

// =============================================================================
// Version Tracking
// =============================================================================

#[test]
fn version_tracking() {
    let storage = setup();

    storage
        .store_document(&make_doc("vt-1", "alpha", "agent", None))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    storage
        .store_document(&make_doc("vt-1", "beta", "agent", None))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    storage
        .store_document(&make_doc("vt-1", "gamma", "agent", None))
        .unwrap();

    // get_document_versions (StorageDocumentTraits) returns keys
    let version_keys = storage.get_document_versions("vt-1").unwrap();
    assert_eq!(version_keys.len(), 3);

    // get_versions (DatabaseDocumentTraits) returns full documents, ordered ASC
    let versions = storage.get_versions("vt-1").unwrap();
    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0].version, "alpha");
    assert_eq!(versions[1].version, "beta");
    assert_eq!(versions[2].version, "gamma");

    // get_latest returns the most recent
    let latest = storage.get_latest("vt-1").unwrap();
    assert_eq!(latest.version, "gamma");

    let latest_via_storage = storage.get_latest_document("vt-1").unwrap();
    assert_eq!(latest_via_storage.version, "gamma");
}

// =============================================================================
// File-based Persistence
// =============================================================================

#[test]
fn file_based_persistence() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let db_path = tmpdir.path().join("test.duckdb");
    let db_path_str = db_path.to_str().expect("valid path").to_string();

    // Write with one connection
    {
        let storage = DuckDbStorage::new(&db_path_str).expect("create DuckDB");
        storage.run_migrations().unwrap();
        storage
            .store_document(&make_doc("persist-1", "v1", "agent", None))
            .unwrap();
    }

    // Read with a fresh connection
    {
        let storage = DuckDbStorage::new(&db_path_str).expect("reopen DuckDB");
        let doc = storage
            .get_document("persist-1:v1")
            .expect("get from reopened DB");
        assert_eq!(doc.id, "persist-1");
        assert_eq!(doc.value["data"], "test content");
    }
}

// =============================================================================
// SearchProvider Integration
// =============================================================================

#[test]
fn search_with_field_filter() {
    let storage = setup();

    let mut doc = make_doc("sf-1", "v1", "artifact", None);
    doc.value["category"] = json!("security");
    storage.store_document(&doc).unwrap();

    let mut doc2 = make_doc("sf-2", "v1", "artifact", None);
    doc2.value["category"] = json!("performance");
    storage.store_document(&doc2).unwrap();

    let results = storage
        .search(SearchQuery {
            query: String::new(),
            field_filter: Some(FieldFilter {
                field_path: "category".to_string(),
                value: "security".to_string(),
            }),
            limit: 10,
            offset: 0,
            ..Default::default()
        })
        .unwrap();

    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].document.id, "sf-1");
    assert_eq!(results.method, SearchMethod::FieldMatch);
}

#[test]
fn search_with_keyword() {
    let storage = setup();

    let mut doc = make_doc("kw-1", "v1", "artifact", None);
    doc.value["description"] = json!("authentication middleware for API gateway");
    storage.store_document(&doc).unwrap();

    let mut doc2 = make_doc("kw-2", "v1", "artifact", None);
    doc2.value["description"] = json!("database migration utility");
    storage.store_document(&doc2).unwrap();

    let results = storage
        .search(SearchQuery {
            query: "authentication".to_string(),
            limit: 10,
            offset: 0,
            ..Default::default()
        })
        .unwrap();

    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].document.id, "kw-1");
    assert_eq!(results.method, SearchMethod::FieldMatch);
    assert!(results.results[0].score > 0.0);
}

#[test]
fn search_empty_query_returns_all() {
    let storage = setup();
    storage
        .store_document(&make_doc("all-1", "v1", "agent", None))
        .unwrap();
    storage
        .store_document(&make_doc("all-2", "v1", "config", None))
        .unwrap();

    let results = storage
        .search(SearchQuery {
            query: String::new(),
            limit: 100,
            offset: 0,
            ..Default::default()
        })
        .unwrap();

    // Empty LIKE pattern "%%" matches everything
    assert_eq!(results.results.len(), 2);
}

// =============================================================================
// db_stats
// =============================================================================

#[test]
fn db_stats_returns_correct_counts() {
    let storage = setup();
    storage
        .store_document(&make_doc("ds-1", "v1", "agent", None))
        .unwrap();
    storage
        .store_document(&make_doc("ds-2", "v1", "agent", None))
        .unwrap();
    storage
        .store_document(&make_doc("ds-3", "v1", "config", None))
        .unwrap();

    let stats = storage.db_stats().unwrap();
    assert_eq!(stats.len(), 2);

    let agent_count = stats.iter().find(|(_, t)| t == "agent").unwrap().0;
    assert_eq!(agent_count, 2);

    let config_count = stats.iter().find(|(_, t)| t == "config").unwrap().0;
    assert_eq!(config_count, 1);
}
