//! Integration tests for `FilesystemDocumentService`.
//!
//! Tests the unified Document API backed by the filesystem storage backend.
//! Each test uses an isolated tempdir and a freshly created agent.

use jacs::document::DocumentService;
use jacs::document::filesystem::FilesystemDocumentService;
use jacs::document::types::{CreateOptions, DocumentVisibility, ListFilter, UpdateOptions};
use jacs::search::{SearchMethod, SearchQuery};
use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs::storage::MultiStorage;
use serial_test::serial;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestP@ss123!#";

/// Helper: create a `FilesystemDocumentService` in an isolated temp directory.
///
/// Returns the service, the temp directory (kept alive for test lifetime),
/// and the SimpleAgent (in case tests need to inspect agent state).
fn create_test_service() -> (FilesystemDocumentService, TempDir, SimpleAgent) {
    let tmp = TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("docservice-test-agent")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .description("Test agent for DocumentService filesystem tests")
        .build();

    let (agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    // Re-set env vars so the agent can find its files for signing
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
        std::env::set_var("JACS_DATA_DIRECTORY", data_dir.to_str().unwrap());
        std::env::set_var("JACS_KEY_DIRECTORY", key_dir.to_str().unwrap());
    }

    // Create MultiStorage pointing to the temp data directory
    let storage =
        MultiStorage::_new("fs".to_string(), data_dir.clone()).expect("create MultiStorage");

    // Extract the Agent from SimpleAgent to share with DocumentService.
    // We need to access the agent field. Since SimpleAgent has pub(crate) agent,
    // we'll create a new Agent by loading the config.
    let mut fs_agent = jacs::get_empty_agent();
    fs_agent
        .load_by_config(config_path.to_str().unwrap().to_string())
        .expect("load agent by config");

    let service =
        FilesystemDocumentService::new(Arc::new(storage), Arc::new(Mutex::new(fs_agent)), data_dir);

    (service, tmp, agent)
}

// =============================================================================
// CRUD Tests
// =============================================================================

#[test]
#[serial]
fn create_stores_document_and_returns_it_signed() {
    let (svc, _tmp, _agent) = create_test_service();

    let doc = svc
        .create(r#"{"content": "hello world"}"#, CreateOptions::default())
        .expect("create should succeed");

    // Document should have an ID and version
    assert!(!doc.id.is_empty(), "document ID should be set");
    assert!(!doc.version.is_empty(), "document version should be set");

    // Document should have a signature
    assert!(
        doc.value.get("jacsSignature").is_some(),
        "created document should be signed"
    );

    // Document should have jacsType from options
    assert_eq!(
        doc.value.get("jacsType").and_then(|v| v.as_str()),
        Some("artifact"),
        "default jacsType should be 'artifact'"
    );
}

#[test]
#[serial]
fn get_retrieves_a_created_document_by_key() {
    let (svc, _tmp, _agent) = create_test_service();

    let created = svc
        .create(r#"{"content": "test get"}"#, CreateOptions::default())
        .expect("create should succeed");

    let key = created.getkey();
    let retrieved = svc.get(&key).expect("get should succeed");

    assert_eq!(retrieved.id, created.id);
    assert_eq!(retrieved.version, created.version);
}

#[test]
#[serial]
fn get_latest_returns_the_most_recent_version() {
    let (svc, _tmp, _agent) = create_test_service();

    let v1 = svc
        .create(r#"{"content": "version 1"}"#, CreateOptions::default())
        .expect("create v1");

    let v2 = svc
        .update(
            &v1.id,
            r#"{"content": "version 2"}"#,
            UpdateOptions::default(),
        )
        .expect("update to v2");

    let latest = svc.get_latest(&v1.id).expect("get_latest should succeed");

    // The latest should be v2, not v1
    assert_ne!(
        latest.version, v1.version,
        "latest version should differ from v1"
    );
    // Check it matches v2's version
    assert_eq!(latest.version, v2.version, "latest should be v2");
}

#[test]
#[serial]
fn update_creates_a_new_version_linked_to_prior() {
    let (svc, _tmp, _agent) = create_test_service();

    let v1 = svc
        .create(r#"{"content": "original"}"#, CreateOptions::default())
        .expect("create v1");

    let v2 = svc
        .update(
            &v1.id,
            r#"{"content": "updated"}"#,
            UpdateOptions::default(),
        )
        .expect("update to v2");

    // v2 should have a different version
    assert_ne!(v1.version, v2.version, "update should create a new version");

    // v2 should reference v1 as previous version.
    // JACS stores the previous *version UUID* (not the full key) in jacsPreviousVersion.
    let prev = v2.value.get("jacsPreviousVersion").and_then(|v| v.as_str());
    assert_eq!(
        prev,
        Some(v1.version.as_str()),
        "v2 should link to v1's version as previous version"
    );
}

#[test]
#[serial]
fn remove_archives_document_and_get_returns_error() {
    let (svc, _tmp, _agent) = create_test_service();

    let doc = svc
        .create(r#"{"content": "to be removed"}"#, CreateOptions::default())
        .expect("create");

    let key = doc.getkey();
    let removed = svc.remove(&key).expect("remove should succeed");

    // remove() should return the document that was removed
    assert_eq!(removed.id, doc.id);

    // After removal, get() on the original key should fail
    // (document moved to archive)
    let get_result = svc.get(&key);
    assert!(
        get_result.is_err(),
        "get() should fail for removed document"
    );
}

#[test]
#[serial]
fn list_returns_created_documents() {
    let (svc, tmp, _agent) = create_test_service();

    svc.create(r#"{"content": "doc1"}"#, CreateOptions::default())
        .expect("create doc1");

    svc.create(r#"{"content": "doc2"}"#, CreateOptions::default())
        .expect("create doc2");

    let summaries = svc
        .list(ListFilter::default())
        .expect("list should succeed");

    assert!(
        summaries.len() >= 2,
        "should list at least 2 documents, got {}",
        summaries.len()
    );
}

#[test]
#[serial]
fn versions_returns_version_history() {
    let (svc, _tmp, _agent) = create_test_service();

    let v1 = svc
        .create(r#"{"content": "v1"}"#, CreateOptions::default())
        .expect("create v1");

    let v2 = svc
        .update(&v1.id, r#"{"content": "v2"}"#, UpdateOptions::default())
        .expect("update to v2");

    let versions = svc.versions(&v1.id).expect("versions should succeed");

    // After create + update we should have at least 2 versions for this document ID.
    // The filesystem backend stores versions as separate keys keyed by document ID prefix.
    assert!(
        versions.len() >= 2,
        "should have at least 2 versions after create + update, got {}",
        versions.len()
    );

    // v1 should appear in the list
    assert!(
        versions.iter().any(|v| v.version == v1.version),
        "versions should contain v1 (version {})",
        v1.version
    );
    // v2 should appear in the list
    assert!(
        versions.iter().any(|v| v.version == v2.version),
        "versions should contain v2 (version {})",
        v2.version
    );
}

// =============================================================================
// Search Tests
// =============================================================================

#[test]
#[serial]
fn search_with_query_returns_field_match_method() {
    let (svc, _tmp, _agent) = create_test_service();

    svc.create(
        r#"{"content": "searchable content here"}"#,
        CreateOptions::default(),
    )
    .expect("create searchable doc");

    let results = svc
        .search(SearchQuery {
            query: "searchable".to_string(),
            ..SearchQuery::default()
        })
        .expect("search should succeed");

    assert_eq!(
        results.method,
        SearchMethod::FieldMatch,
        "filesystem search should report FieldMatch method"
    );

    assert!(
        !results.results.is_empty(),
        "search should find the document containing 'searchable'"
    );
}

#[test]
#[serial]
fn search_empty_query_returns_all_documents() {
    let (svc, _tmp, _agent) = create_test_service();

    svc.create(r#"{"content": "alpha"}"#, CreateOptions::default())
        .expect("create alpha");

    svc.create(r#"{"content": "beta"}"#, CreateOptions::default())
        .expect("create beta");

    let results = svc
        .search(SearchQuery::default())
        .expect("search should succeed");

    assert!(
        results.results.len() >= 2,
        "empty query should return all documents, got {}",
        results.results.len()
    );
}

#[test]
#[serial]
fn search_pagination_returns_subset_with_correct_total_count() {
    let (svc, _tmp, _agent) = create_test_service();

    // Create 5 documents
    for i in 0..5 {
        svc.create(
            &format!(r#"{{"content": "pagination doc {}"}}"#, i),
            CreateOptions::default(),
        )
        .expect(&format!("create doc {}", i));
    }

    // Search with limit=2, offset=0
    let results = svc
        .search(SearchQuery {
            query: String::new(),
            limit: 2,
            offset: 0,
            ..SearchQuery::default()
        })
        .expect("search should succeed");

    assert_eq!(
        results.results.len(),
        2,
        "should return exactly 2 results when limit=2"
    );
    assert!(
        results.total_count >= 5,
        "total_count should reflect all matching documents (>= 5), got {}",
        results.total_count
    );
    assert_ne!(
        results.total_count,
        results.results.len(),
        "total_count should differ from results.len() when paginating"
    );

    // Search with offset=3 to verify offset works
    let page2 = svc
        .search(SearchQuery {
            query: String::new(),
            limit: 2,
            offset: 3,
            ..SearchQuery::default()
        })
        .expect("search page 2 should succeed");

    assert!(
        page2.results.len() <= 2,
        "offset=3 with limit=2 should return at most 2 results"
    );
}

// =============================================================================
// Visibility Tests
// =============================================================================

#[test]
#[serial]
fn visibility_returns_private_by_default() {
    let (svc, _tmp, _agent) = create_test_service();

    let doc = svc
        .create(r#"{"content": "private doc"}"#, CreateOptions::default())
        .expect("create");

    let vis = svc.visibility(&doc.getkey()).expect("visibility");

    assert_eq!(
        vis,
        DocumentVisibility::Private,
        "default visibility should be Private"
    );
}

#[test]
#[serial]
fn create_with_public_visibility() {
    let (svc, _tmp, _agent) = create_test_service();

    let doc = svc
        .create(
            r#"{"content": "public doc"}"#,
            CreateOptions {
                jacs_type: "artifact".to_string(),
                visibility: DocumentVisibility::Public,
                custom_schema: None,
            },
        )
        .expect("create with public visibility");

    let vis = svc.visibility(&doc.getkey()).expect("visibility");

    assert_eq!(
        vis,
        DocumentVisibility::Public,
        "visibility should be Public when explicitly set"
    );
}

// =============================================================================
// Batch Tests
// =============================================================================

#[test]
#[serial]
fn create_batch_creates_multiple_documents() {
    let (svc, _tmp, _agent) = create_test_service();

    let docs = &[
        r#"{"content": "batch1"}"#,
        r#"{"content": "batch2"}"#,
        r#"{"content": "batch3"}"#,
    ];

    let created = svc
        .create_batch(docs, CreateOptions::default())
        .expect("create_batch should succeed");

    assert_eq!(created.len(), 3, "should create 3 documents");

    for doc in &created {
        assert!(!doc.id.is_empty());
        assert!(doc.value.get("jacsSignature").is_some());
    }
}

// =============================================================================
// Diff Tests
// =============================================================================

#[test]
#[serial]
fn diff_shows_changes_between_versions() {
    let (svc, _tmp, _agent) = create_test_service();

    // Create v1, then update to v2 — diffs two versions of the *same* document.
    let v1 = svc
        .create(
            r#"{"content": "original content"}"#,
            CreateOptions::default(),
        )
        .expect("create v1");

    let v2 = svc
        .update(
            &v1.id,
            r#"{"content": "modified content"}"#,
            UpdateOptions::default(),
        )
        .expect("update to v2");

    let diff = svc
        .diff(&v1.getkey(), &v2.getkey())
        .expect("diff should succeed");

    assert_eq!(diff.key_a, v1.getkey());
    assert_eq!(diff.key_b, v2.getkey());
    // The diff should show changes between the two versions of the same document.
    // "original content" -> "modified content" must produce additions or deletions.
    assert!(
        diff.additions > 0 || diff.deletions > 0,
        "diff should detect changes between v1 and v2 of the same document"
    );
    // The diff text should contain the actual content that changed
    assert!(
        diff.diff_text.contains("original") || diff.diff_text.contains("modified"),
        "diff text should reference the changed content"
    );
}

// =============================================================================
// Object Safety Test
// =============================================================================

#[test]
#[serial]
fn filesystem_document_service_is_usable_as_trait_object() {
    let (svc, _tmp, _agent) = create_test_service();

    // Verify it can be used as Box<dyn DocumentService>
    let boxed: Box<dyn DocumentService> = Box::new(svc);

    let doc = boxed
        .create(
            r#"{"content": "trait object test"}"#,
            CreateOptions::default(),
        )
        .expect("create via trait object should succeed");

    assert!(!doc.id.is_empty());
}
