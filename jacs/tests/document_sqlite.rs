#![cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]

//! Integration tests for `SqliteDocumentService` — the `DocumentService` + `SearchProvider`
//! implementation for rusqlite with FTS5 fulltext search.
//!
//! Tests cover:
//! - CRUD roundtrip (create, get, update, get_latest, versions)
//! - FTS5 search finds document by content match
//! - FTS5 search returns `SearchMethod::FullText`
//! - Search with `jacs_type` filter restricts results
//! - Search with `agent_id` filter restricts results
//! - `list()` with visibility filter works
//! - `remove()` tombstones document (still findable by direct get, not by list)
//! - `create_batch()` creates multiple documents atomically
//! - SearchProvider capabilities
//! - diff() between two versions
//! - visibility get/set
//!
//! ```sh
//! cargo test --features rusqlite-storage -- document_sqlite
//! ```

use jacs::document::DocumentService;
use jacs::document::types::{CreateOptions, DocumentVisibility, ListFilter, UpdateOptions};
use jacs::search::{FieldFilter, SearchCapabilities, SearchMethod, SearchProvider, SearchQuery};
use jacs::simple::{CreateAgentParams, SimpleAgent};

/// Helper: call search() via SearchProvider to avoid ambiguity with DocumentService::search.
fn do_search(
    svc: &SqliteDocumentService,
    query: SearchQuery,
) -> Result<jacs::search::SearchResults, jacs::error::JacsError> {
    SearchProvider::search(svc, query)
}
use jacs::storage::SqliteDocumentService;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// Helper: create test JSON with the given fields.
fn test_json(
    id: &str,
    version: &str,
    jacs_type: &str,
    content: &str,
    agent_id: Option<&str>,
) -> String {
    let mut value = json!({
        "jacsId": id,
        "jacsVersion": version,
        "jacsType": jacs_type,
        "jacsLevel": "raw",
        "data": content
    });
    if let Some(aid) = agent_id {
        value["jacsSignature"] = json!({
            "jacsSignatureAgentId": aid
        });
    }
    value.to_string()
}

/// Helper: create an in-memory SqliteDocumentService.
fn create_service() -> SqliteDocumentService {
    SqliteDocumentService::in_memory().expect("Failed to create in-memory SqliteDocumentService")
}

fn create_service_with_loaded_agent(
    database_path: &str,
) -> (SqliteDocumentService, tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("sqlite-read-verify")
        .password("TestP@ss123!#")
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .build();

    let (_agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#");
    }

    let mut agent = jacs::get_empty_agent();
    agent
        .load_by_config(config_path.to_string_lossy().into_owned())
        .expect("load agent should succeed");

    (
        SqliteDocumentService::with_agent(database_path, Arc::new(Mutex::new(agent)))
            .expect("sqlite service with agent should succeed"),
        tmp,
        config_path,
    )
}

// =============================================================================
// CRUD Roundtrip
// =============================================================================

#[test]
fn crud_roundtrip_create_get_update_get_latest_versions() {
    let svc = create_service();

    // Create
    let json_v1 = test_json("doc-1", "v1", "artifact", "initial content", None);
    let doc_v1 = svc
        .create(&json_v1, CreateOptions::default())
        .expect("create v1 failed");
    assert_eq!(doc_v1.id, "doc-1");
    assert_eq!(doc_v1.version, "v1");
    assert_eq!(doc_v1.jacs_type, "artifact");

    // Get by key
    let retrieved = svc.get("doc-1:v1").expect("get failed");
    assert_eq!(retrieved.id, "doc-1");
    assert_eq!(retrieved.value["data"], "initial content");

    // Update (creates a new version)
    let json_v2 = json!({
        "jacsId": "doc-1",
        "jacsVersion": "v2",
        "jacsType": "artifact",
        "jacsLevel": "raw",
        "data": "updated content"
    })
    .to_string();

    // Small delay so created_at differs
    std::thread::sleep(std::time::Duration::from_millis(20));

    let doc_v2 = svc
        .update("doc-1", &json_v2, UpdateOptions::default())
        .expect("update failed");
    assert_eq!(doc_v2.version, "v2");

    // Get latest
    let latest = svc.get_latest("doc-1").expect("get_latest failed");
    assert_eq!(latest.version, "v2");
    assert_eq!(latest.value["data"], "updated content");

    // Versions
    let versions = svc.versions("doc-1").expect("versions failed");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, "v1"); // ordered by created_at ASC
    assert_eq!(versions[1].version, "v2");
}

#[test]
fn get_rejects_tampered_stored_document_on_read() {
    let tmp_db = tempfile::TempDir::new().expect("create db tempdir");
    let db_path = tmp_db.path().join("documents.sqlite3");
    let (svc, _agent_tmp, _config_path) =
        create_service_with_loaded_agent(db_path.to_str().unwrap());

    let doc = svc
        .create(
            r#"{"content":"sqlite read verification"}"#,
            CreateOptions::default(),
        )
        .expect("create should succeed");

    let mut tampered = doc.value.clone();
    tampered["content"] = json!("tampered on disk");

    let tampered_pretty =
        serde_json::to_string_pretty(&tampered).expect("serialize tampered document");
    let tampered_compact = serde_json::to_string(&tampered).expect("serialize tampered document");

    let conn = rusqlite::Connection::open(&db_path).expect("open sqlite db");
    conn.execute(
        "UPDATE jacs_document SET raw_contents = ?1, file_contents = ?2 WHERE jacs_id = ?3 AND jacs_version = ?4",
        rusqlite::params![tampered_pretty, tampered_compact, doc.id, doc.version],
    )
    .expect("tamper stored row");

    let result = svc.get(&doc.getkey());
    assert!(
        result.is_err(),
        "read should fail verification for tampered data"
    );
}

// =============================================================================
// FTS5 Search
// =============================================================================

#[test]
fn fts5_search_finds_document_by_content_match() {
    let svc = create_service();

    let json1 = test_json(
        "fts-1",
        "v1",
        "artifact",
        "authentication middleware for security",
        None,
    );
    let json2 = test_json("fts-2", "v1", "artifact", "database migration helper", None);
    let json3 = test_json(
        "fts-3",
        "v1",
        "artifact",
        "user authentication service",
        None,
    );

    svc.create(&json1, CreateOptions::default()).unwrap();
    svc.create(&json2, CreateOptions::default()).unwrap();
    svc.create(&json3, CreateOptions::default()).unwrap();

    let results = do_search(
        &svc,
        SearchQuery {
            query: "authentication".to_string(),
            ..SearchQuery::default()
        },
    )
    .expect("search failed");

    assert!(
        results.results.len() >= 2,
        "Should find at least 2 documents with 'authentication', found {}",
        results.results.len()
    );
    assert_eq!(results.method, SearchMethod::FullText);
}

#[test]
fn fts5_search_returns_fulltext_method() {
    let svc = create_service();

    let json1 = test_json("method-1", "v1", "artifact", "test content", None);
    svc.create(&json1, CreateOptions::default()).unwrap();

    let results = do_search(
        &svc,
        SearchQuery {
            query: "test".to_string(),
            ..SearchQuery::default()
        },
    )
    .expect("search failed");

    assert_eq!(
        results.method,
        SearchMethod::FullText,
        "Search method should be FullText"
    );
}

// =============================================================================
// Search with Filters
// =============================================================================

#[test]
fn search_with_jacs_type_filter_restricts_results() {
    let svc = create_service();

    let json1 = test_json("tf-1", "v1", "artifact", "common search term", None);
    let json2 = test_json("tf-2", "v1", "message", "common search term", None);
    let json3 = test_json("tf-3", "v1", "artifact", "common search term", None);

    svc.create(
        &json1,
        CreateOptions {
            jacs_type: "artifact".to_string(),
            ..CreateOptions::default()
        },
    )
    .unwrap();
    svc.create(
        &json2,
        CreateOptions {
            jacs_type: "message".to_string(),
            ..CreateOptions::default()
        },
    )
    .unwrap();
    svc.create(
        &json3,
        CreateOptions {
            jacs_type: "artifact".to_string(),
            ..CreateOptions::default()
        },
    )
    .unwrap();

    let results = do_search(
        &svc,
        SearchQuery {
            query: "common".to_string(),
            jacs_type: Some("artifact".to_string()),
            ..SearchQuery::default()
        },
    )
    .expect("search failed");

    assert_eq!(
        results.results.len(),
        2,
        "Should find 2 artifacts, found {}",
        results.results.len()
    );
    for hit in &results.results {
        assert_eq!(hit.document.jacs_type, "artifact");
    }
}

#[test]
fn search_with_agent_id_filter_restricts_results() {
    let svc = create_service();

    let json1 = test_json(
        "af-1",
        "v1",
        "artifact",
        "shared content data",
        Some("alice"),
    );
    let json2 = test_json("af-2", "v1", "artifact", "shared content data", Some("bob"));
    let json3 = test_json(
        "af-3",
        "v1",
        "artifact",
        "shared content data",
        Some("alice"),
    );

    svc.create(&json1, CreateOptions::default()).unwrap();
    svc.create(&json2, CreateOptions::default()).unwrap();
    svc.create(&json3, CreateOptions::default()).unwrap();

    let results = do_search(
        &svc,
        SearchQuery {
            query: "shared".to_string(),
            agent_id: Some("alice".to_string()),
            ..SearchQuery::default()
        },
    )
    .expect("search failed");

    assert_eq!(
        results.results.len(),
        2,
        "Should find 2 documents by alice, found {}",
        results.results.len()
    );
}

#[test]
fn search_with_field_filter_restricts_results() {
    let svc = create_service();

    // Create documents with a "category" field set to different values
    let json1 = json!({
        "jacsId": "ff-1", "jacsVersion": "v1", "jacsType": "artifact",
        "jacsLevel": "raw", "data": "searchable content", "category": "security"
    })
    .to_string();
    let json2 = json!({
        "jacsId": "ff-2", "jacsVersion": "v1", "jacsType": "artifact",
        "jacsLevel": "raw", "data": "searchable content", "category": "networking"
    })
    .to_string();
    let json3 = json!({
        "jacsId": "ff-3", "jacsVersion": "v1", "jacsType": "artifact",
        "jacsLevel": "raw", "data": "searchable content", "category": "security"
    })
    .to_string();

    svc.create(&json1, CreateOptions::default()).unwrap();
    svc.create(&json2, CreateOptions::default()).unwrap();
    svc.create(&json3, CreateOptions::default()).unwrap();

    let results = do_search(
        &svc,
        SearchQuery {
            query: "searchable".to_string(),
            field_filter: Some(FieldFilter {
                field_path: "category".to_string(),
                value: "security".to_string(),
            }),
            ..SearchQuery::default()
        },
    )
    .expect("search failed");

    assert_eq!(
        results.results.len(),
        2,
        "Should find 2 documents with category=security, found {}",
        results.results.len()
    );
}

#[test]
fn search_with_field_filter_only_no_text_query() {
    let svc = create_service();

    let json1 = json!({
        "jacsId": "ffo-1", "jacsVersion": "v1", "jacsType": "artifact",
        "jacsLevel": "raw", "data": "content", "status": "active"
    })
    .to_string();
    let json2 = json!({
        "jacsId": "ffo-2", "jacsVersion": "v1", "jacsType": "artifact",
        "jacsLevel": "raw", "data": "content", "status": "archived"
    })
    .to_string();

    svc.create(&json1, CreateOptions::default()).unwrap();
    svc.create(&json2, CreateOptions::default()).unwrap();

    // Search with field_filter only (no text query)
    let results = do_search(
        &svc,
        SearchQuery {
            query: String::new(),
            field_filter: Some(FieldFilter {
                field_path: "status".to_string(),
                value: "active".to_string(),
            }),
            ..SearchQuery::default()
        },
    )
    .expect("search failed");

    assert_eq!(
        results.results.len(),
        1,
        "Should find 1 document with status=active, found {}",
        results.results.len()
    );
    assert_eq!(results.results[0].document.id, "ffo-1");
}

// =============================================================================
// List with Visibility Filter
// =============================================================================

#[test]
fn list_with_visibility_filter_works() {
    let svc = create_service();

    let json1 = test_json("vis-1", "v1", "artifact", "public doc", None);
    let json2 = test_json("vis-2", "v1", "artifact", "private doc", None);
    let json3 = test_json("vis-3", "v1", "artifact", "public doc 2", None);

    svc.create(
        &json1,
        CreateOptions {
            visibility: DocumentVisibility::Public,
            ..CreateOptions::default()
        },
    )
    .unwrap();
    svc.create(
        &json2,
        CreateOptions {
            visibility: DocumentVisibility::Private,
            ..CreateOptions::default()
        },
    )
    .unwrap();
    svc.create(
        &json3,
        CreateOptions {
            visibility: DocumentVisibility::Public,
            ..CreateOptions::default()
        },
    )
    .unwrap();

    let public_list = svc
        .list(ListFilter {
            visibility: Some(DocumentVisibility::Public),
            ..ListFilter::default()
        })
        .expect("list failed");

    assert_eq!(
        public_list.len(),
        2,
        "Should list 2 public documents, got {}",
        public_list.len()
    );
    for summary in &public_list {
        assert_eq!(summary.visibility, DocumentVisibility::Public);
    }
}

// =============================================================================
// Remove / Tombstone
// =============================================================================

#[test]
fn remove_tombstones_document_still_findable_by_get_but_not_by_list() {
    let svc = create_service();

    let json1 = test_json("rm-1", "v1", "artifact", "to be removed", None);
    let json2 = test_json("rm-2", "v1", "artifact", "to keep", None);

    svc.create(&json1, CreateOptions::default()).unwrap();
    svc.create(&json2, CreateOptions::default()).unwrap();

    // Remove doc rm-1
    let removed = svc.remove("rm-1:v1").expect("remove failed");
    assert_eq!(removed.id, "rm-1");

    // Still findable by direct get
    let got = svc
        .get("rm-1:v1")
        .expect("get should still work after tombstone");
    assert_eq!(got.id, "rm-1");

    // Not in list()
    let list = svc.list(ListFilter::default()).expect("list failed");
    assert_eq!(
        list.len(),
        1,
        "Only the non-removed document should be listed"
    );
    assert_eq!(list[0].document_id, "rm-2");
}

// =============================================================================
// Create Batch
// =============================================================================

#[test]
fn create_batch_creates_multiple_documents_atomically() {
    let svc = create_service();

    let json1 = json!({
        "jacsId": "batch-1",
        "jacsVersion": "v1",
        "jacsType": "artifact",
        "jacsLevel": "raw",
        "data": "batch item 1"
    })
    .to_string();
    let json2 = json!({
        "jacsId": "batch-2",
        "jacsVersion": "v1",
        "jacsType": "artifact",
        "jacsLevel": "raw",
        "data": "batch item 2"
    })
    .to_string();
    let json3 = json!({
        "jacsId": "batch-3",
        "jacsVersion": "v1",
        "jacsType": "artifact",
        "jacsLevel": "raw",
        "data": "batch item 3"
    })
    .to_string();

    let docs_str: Vec<&str> = vec![&json1, &json2, &json3];
    let created = svc
        .create_batch(&docs_str, CreateOptions::default())
        .expect("create_batch failed");

    assert_eq!(created.len(), 3, "Should create 3 documents");

    // Verify all exist
    svc.get("batch-1:v1").expect("batch-1 should exist");
    svc.get("batch-2:v1").expect("batch-2 should exist");
    svc.get("batch-3:v1").expect("batch-3 should exist");
}

// =============================================================================
// SearchProvider Capabilities
// =============================================================================

#[test]
fn search_provider_capabilities_reports_fulltext() {
    let svc = create_service();
    let caps = svc.capabilities();
    assert_eq!(
        caps,
        SearchCapabilities {
            fulltext: true,
            vector: false,
            hybrid: false,
            field_filter: true,
        }
    );
}

// =============================================================================
// Diff
// =============================================================================

#[test]
fn diff_between_two_versions_shows_changes() {
    let svc = create_service();

    let json_v1 = test_json("diff-1", "v1", "artifact", "original content", None);
    svc.create(&json_v1, CreateOptions::default()).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(20));

    let json_v2 = json!({
        "jacsId": "diff-1",
        "jacsVersion": "v2",
        "jacsType": "artifact",
        "jacsLevel": "raw",
        "data": "modified content"
    })
    .to_string();
    svc.update("diff-1", &json_v2, UpdateOptions::default())
        .unwrap();

    let diff = svc.diff("diff-1:v1", "diff-1:v2").expect("diff failed");
    assert_eq!(diff.key_a, "diff-1:v1");
    assert_eq!(diff.key_b, "diff-1:v2");
    assert!(
        diff.additions > 0 || diff.deletions > 0,
        "Should detect changes"
    );
    assert!(
        diff.diff_text.contains("original") || diff.diff_text.contains("modified"),
        "Diff text should contain changed content"
    );
}

// =============================================================================
// Visibility
// =============================================================================

#[test]
fn visibility_get_and_set() {
    let svc = create_service();

    let json1 = test_json("vgs-1", "v1", "artifact", "visibility test", None);
    svc.create(
        &json1,
        CreateOptions {
            visibility: DocumentVisibility::Private,
            ..CreateOptions::default()
        },
    )
    .unwrap();

    // Default visibility
    let vis = svc.visibility("vgs-1:v1").expect("visibility failed");
    assert_eq!(vis, DocumentVisibility::Private);

    // Update visibility
    svc.set_visibility("vgs-1:v1", DocumentVisibility::Public)
        .expect("set_visibility failed");

    let vis2 = svc.visibility("vgs-1:v1").expect("visibility failed");
    assert_eq!(vis2, DocumentVisibility::Public);
}

#[test]
fn set_visibility_is_in_place_update_no_new_version() {
    let svc = create_service();

    let json1 = test_json("vip-1", "v1", "artifact", "visibility in-place test", None);
    svc.create(
        &json1,
        CreateOptions {
            visibility: DocumentVisibility::Private,
            ..CreateOptions::default()
        },
    )
    .unwrap();

    // Change visibility
    svc.set_visibility("vip-1:v1", DocumentVisibility::Public)
        .expect("set_visibility failed");

    // Only one version should exist (no new version created)
    let versions = svc.versions("vip-1").expect("versions failed");
    assert_eq!(
        versions.len(),
        1,
        "set_visibility should NOT create a new version; visibility is storage-level metadata"
    );

    // The original version should have updated visibility
    let vis = svc.visibility("vip-1:v1").expect("visibility failed");
    assert_eq!(vis, DocumentVisibility::Public);
}

// =============================================================================
// Duplicate Create Semantics
// =============================================================================

#[test]
fn create_duplicate_document_returns_error() {
    let svc = create_service();

    let json1 = test_json("dup-1", "v1", "artifact", "original content", None);
    svc.create(&json1, CreateOptions::default())
        .expect("first create should succeed");

    // Second create with the same id:version should fail
    let result = svc.create(&json1, CreateOptions::default());
    assert!(
        result.is_err(),
        "Duplicate create should return an error, not silently succeed"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("already exists") || err_msg.contains("UNIQUE"),
        "Error should mention duplicate/already exists, got: {}",
        err_msg
    );
}

#[test]
fn create_batch_with_duplicate_in_batch_returns_error() {
    let svc = create_service();

    // First, create a document normally
    let json1 = test_json("bdup-1", "v1", "artifact", "content", None);
    svc.create(&json1, CreateOptions::default()).unwrap();

    // Now try a batch that includes the same id:version
    let json2 = test_json("bdup-1", "v1", "artifact", "content again", None);
    let json3 = test_json("bdup-2", "v1", "artifact", "new content", None);
    let docs: Vec<&str> = vec![&json2, &json3];

    let result = svc.create_batch(&docs, CreateOptions::default());
    assert!(result.is_err(), "Batch with duplicate should return errors");
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn get_nonexistent_document_returns_error() {
    let svc = create_service();
    let result = svc.get("nonexistent:v1");
    assert!(result.is_err(), "Should error on nonexistent document");
}

#[test]
fn update_nonexistent_document_returns_error() {
    let svc = create_service();
    let json = test_json("nope", "v1", "artifact", "content", None);
    let result = svc.update("nope", &json, UpdateOptions::default());
    assert!(
        result.is_err(),
        "Should error on update of nonexistent document"
    );
}

#[test]
fn search_empty_query_returns_empty_results() {
    let svc = create_service();

    let json1 = test_json("eq-1", "v1", "artifact", "some content", None);
    svc.create(&json1, CreateOptions::default()).unwrap();

    let results = do_search(&svc, SearchQuery::default()).expect("search failed");
    assert_eq!(
        results.results.len(),
        0,
        "Empty query should return empty results"
    );
}

#[test]
fn search_without_fts_query_but_with_type_filter() {
    let svc = create_service();

    let json1 = test_json("nfq-1", "v1", "artifact", "content a", None);
    let json2 = test_json("nfq-2", "v1", "message", "content b", None);

    svc.create(&json1, CreateOptions::default()).unwrap();
    svc.create(
        &json2,
        CreateOptions {
            jacs_type: "message".to_string(),
            ..CreateOptions::default()
        },
    )
    .unwrap();

    let results = do_search(
        &svc,
        SearchQuery {
            query: String::new(),
            jacs_type: Some("artifact".to_string()),
            ..SearchQuery::default()
        },
    )
    .expect("search failed");

    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].document.jacs_type, "artifact");
}

#[test]
fn list_excludes_removed_documents() {
    let svc = create_service();

    let json1 = test_json("le-1", "v1", "artifact", "keep", None);
    let json2 = test_json("le-2", "v1", "artifact", "remove", None);

    svc.create(&json1, CreateOptions::default()).unwrap();
    svc.create(&json2, CreateOptions::default()).unwrap();

    svc.remove("le-2:v1").unwrap();

    let list = svc.list(ListFilter::default()).expect("list failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].document_id, "le-1");
}

#[test]
fn each_test_gets_own_database() {
    // Two independent services should not share data
    let svc1 = create_service();
    let svc2 = create_service();

    let json1 = test_json("iso-1", "v1", "artifact", "svc1 data", None);
    svc1.create(&json1, CreateOptions::default()).unwrap();

    let result = svc2.get("iso-1:v1");
    assert!(
        result.is_err(),
        "svc2 should not see svc1's documents (in-memory isolation)"
    );
}
