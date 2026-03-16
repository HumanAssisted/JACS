//! Test utilities for JACS storage backend conformance testing.
//!
//! This module provides:
//! - [`make_test_doc`] — helper to create test documents
//! - [`storage_conformance_tests!`] — macro generating 11 `StorageDocumentTraits` tests
//! - [`database_conformance_tests!`] — macro generating 9 `DatabaseDocumentTraits` tests
//!
//! These are intended for use by storage backend crates (jacs-postgresql,
//! jacs-surrealdb, etc.) to verify trait implementation correctness.
//!
//! # Usage from an external crate
//!
//! ```rust,ignore
//! use jacs::testing::make_test_doc;
//! use serial_test::serial;
//!
//! async fn create_my_storage() -> MyStorage { /* ... */ }
//!
//! jacs::storage_conformance_tests!(create_my_storage);
//! jacs::database_conformance_tests!(create_my_storage);
//! ```

use crate::agent::document::JACSDocument;
use serde_json::json;

/// Create a test document with the given fields.
///
/// If `agent_id` is provided, a `jacsSignature` block is attached so that
/// `store_document` can extract the agent ID column.
pub fn make_test_doc(
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

/// Generates 11 conformance tests for `StorageDocumentTraits`.
///
/// Tests cover: store/retrieve, exists, not found, remove, versions,
/// latest document, merge (error), bulk store/retrieve, idempotent store,
/// invalid key format.
///
/// Note: `list_documents` and `get_documents_by_agent` are excluded because
/// their semantics differ between file-based and database backends. They are
/// tested in [`database_conformance_tests!`] instead.
///
/// # Arguments
///
/// `$factory` — an async function that returns an instance implementing
/// `StorageDocumentTraits`. Each test calls it to get a fresh storage backend.
#[macro_export]
macro_rules! storage_conformance_tests {
    ($factory:expr) => {
        use jacs::storage::StorageDocumentTraits;
        use jacs::testing::make_test_doc;

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_store_and_retrieve() {
            let storage = $factory().await;
            let doc = make_test_doc("conf-sr-1", "v1", "agent", Some("agent-alpha"));
            storage.store_document(&doc).expect("store_document failed");

            let retrieved = storage
                .get_document("conf-sr-1:v1")
                .expect("get_document failed");
            assert_eq!(retrieved.id, "conf-sr-1");
            assert_eq!(retrieved.version, "v1");
            assert_eq!(retrieved.jacs_type, "agent");
            assert_eq!(retrieved.value["jacsId"], "conf-sr-1");
            assert_eq!(retrieved.value["data"], "test content");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_document_exists() {
            let storage = $factory().await;
            let doc = make_test_doc("conf-de-1", "v1", "agent", None);
            storage.store_document(&doc).expect("store_document failed");

            assert!(
                storage
                    .document_exists("conf-de-1:v1")
                    .expect("document_exists failed"),
                "Stored document should exist"
            );
            assert!(
                !storage
                    .document_exists("nonexistent:v1")
                    .expect("document_exists failed"),
                "Non-existent document should not exist"
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_document_not_found() {
            let storage = $factory().await;
            let result = storage.get_document("missing-doc:v1");
            assert!(result.is_err(), "get_document on missing key should error");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_remove_document() {
            let storage = $factory().await;
            let doc = make_test_doc("conf-rm-1", "v1", "config", None);
            storage.store_document(&doc).expect("store_document failed");

            assert!(storage.document_exists("conf-rm-1:v1").unwrap());

            let removed = storage
                .remove_document("conf-rm-1:v1")
                .expect("remove_document failed");
            assert_eq!(removed.id, "conf-rm-1");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_get_document_versions() {
            let storage = $factory().await;
            storage
                .store_document(&make_test_doc("conf-dv-1", "v1", "agent", None))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-dv-1", "v2", "agent", None))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-dv-1", "v3", "agent", None))
                .unwrap();

            let versions = storage
                .get_document_versions("conf-dv-1")
                .expect("get_document_versions failed");
            assert_eq!(versions.len(), 3, "Should have 3 versions");
            for key in &versions {
                assert!(
                    key.starts_with("conf-dv-1:"),
                    "Key '{}' should start with 'conf-dv-1:'",
                    key
                );
            }
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_get_latest_document() {
            let storage = $factory().await;
            storage
                .store_document(&make_test_doc("conf-gl-1", "v1", "agent", None))
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            storage
                .store_document(&make_test_doc("conf-gl-1", "v2", "agent", None))
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            storage
                .store_document(&make_test_doc("conf-gl-1", "v3", "agent", None))
                .unwrap();

            let latest = storage
                .get_latest_document("conf-gl-1")
                .expect("get_latest_document failed");
            assert_eq!(latest.version, "v3", "Latest should be v3");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_merge_documents() {
            let storage = $factory().await;
            let result = storage.merge_documents("some-id", "v1", "v2");
            assert!(result.is_err(), "merge_documents should return an error");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_store_documents_bulk() {
            let storage = $factory().await;
            let docs = vec![
                make_test_doc("conf-bulk-1", "v1", "agent", None),
                make_test_doc("conf-bulk-2", "v1", "agent", None),
                make_test_doc("conf-bulk-3", "v1", "config", None),
            ];

            storage
                .store_documents(docs)
                .expect("store_documents failed");

            assert!(storage.document_exists("conf-bulk-1:v1").unwrap());
            assert!(storage.document_exists("conf-bulk-2:v1").unwrap());
            assert!(storage.document_exists("conf-bulk-3:v1").unwrap());
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_get_documents_bulk() {
            let storage = $factory().await;
            let docs = vec![
                make_test_doc("conf-gbulk-1", "v1", "agent", None),
                make_test_doc("conf-gbulk-2", "v1", "config", None),
            ];
            storage
                .store_documents(docs)
                .expect("store_documents failed");

            let keys = vec!["conf-gbulk-1:v1".to_string(), "conf-gbulk-2:v1".to_string()];
            let retrieved = storage.get_documents(keys).expect("get_documents failed");
            assert_eq!(retrieved.len(), 2, "Should retrieve 2 documents");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_idempotent_store() {
            let storage = $factory().await;
            let doc = make_test_doc("conf-idem-1", "v1", "agent", None);
            storage
                .store_document(&doc)
                .expect("First store should succeed");
            storage
                .store_document(&doc)
                .expect("Second store (idempotent) should not error");

            let versions = storage
                .get_document_versions("conf-idem-1")
                .expect("get_document_versions failed");
            assert_eq!(
                versions.len(),
                1,
                "Duplicate insert should not create a second row"
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_invalid_key_format() {
            let storage = $factory().await;
            let result = storage.get_document("invalid-key-no-colon");
            assert!(
                result.is_err(),
                "get_document with invalid key format should error"
            );
        }
    };
}

/// Generates 9 conformance tests for `DatabaseDocumentTraits`.
///
/// Includes both `DatabaseDocumentTraits` methods and the database-specific
/// `StorageDocumentTraits` methods (`list_documents`, `get_documents_by_agent`)
/// which have different semantics in file-based backends.
///
/// # Arguments
///
/// `$factory` — an async function that returns an instance implementing
/// `DatabaseDocumentTraits + StorageDocumentTraits`. Each test calls it to
/// get a fresh storage backend.
#[macro_export]
macro_rules! database_conformance_tests {
    ($factory:expr) => {
        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_list_documents() {
            let storage = $factory().await;
            storage
                .store_document(&make_test_doc("conf-ls-a1", "v1", "agent", None))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-ls-a2", "v1", "agent", None))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-ls-c1", "v1", "config", None))
                .unwrap();

            let agent_docs = storage
                .list_documents("agent")
                .expect("list_documents failed");
            assert_eq!(agent_docs.len(), 2, "Should list exactly 2 agent documents");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_get_documents_by_agent() {
            let storage = $factory().await;
            storage
                .store_document(&make_test_doc("conf-ba-1", "v1", "agent", Some("alice")))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-ba-2", "v1", "config", Some("alice")))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-ba-3", "v1", "agent", Some("bob")))
                .unwrap();

            let alice_docs = storage
                .get_documents_by_agent("alice")
                .expect("get_documents_by_agent failed");
            assert_eq!(alice_docs.len(), 2, "Alice should have 2 documents");

            let bob_docs = storage
                .get_documents_by_agent("bob")
                .expect("get_documents_by_agent failed");
            assert_eq!(bob_docs.len(), 1, "Bob should have 1 document");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_query_by_type() {
            let storage = $factory().await;
            for i in 0..5 {
                let id = format!("conf-qbt-{}", i);
                storage
                    .store_document(&make_test_doc(&id, "v1", "task", None))
                    .unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }

            let page1 = storage
                .query_by_type("task", 3, 0)
                .expect("query_by_type page1 failed");
            assert_eq!(page1.len(), 3, "Page 1 should have 3 results");

            let page2 = storage
                .query_by_type("task", 3, 3)
                .expect("query_by_type page2 failed");
            assert_eq!(page2.len(), 2, "Page 2 should have 2 results");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_query_by_field() {
            let storage = $factory().await;

            let mut doc_a = make_test_doc("conf-qbf-a", "v1", "config", None);
            doc_a.value["status"] = serde_json::json!("active");
            storage.store_document(&doc_a).unwrap();

            let mut doc_b = make_test_doc("conf-qbf-b", "v1", "config", None);
            doc_b.value["status"] = serde_json::json!("inactive");
            storage.store_document(&doc_b).unwrap();

            let active = storage
                .query_by_field("status", "active", None, 100, 0)
                .expect("query_by_field failed");
            assert_eq!(active.len(), 1, "Should find 1 active document");

            let missing = storage
                .query_by_field("status", "archived", None, 100, 0)
                .expect("query_by_field for missing value failed");
            assert!(missing.is_empty(), "Should find no 'archived' documents");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_count_by_type() {
            let storage = $factory().await;
            for i in 0..4 {
                storage
                    .store_document(&make_test_doc(
                        &format!("conf-cnt-{}", i),
                        "v1",
                        "message",
                        None,
                    ))
                    .unwrap();
            }
            storage
                .store_document(&make_test_doc("conf-cnt-other", "v1", "agent", None))
                .unwrap();

            let count = storage
                .count_by_type("message")
                .expect("count_by_type failed");
            assert_eq!(count, 4, "Should count exactly 4 message documents");

            let zero = storage
                .count_by_type("nonexistent")
                .expect("count_by_type failed");
            assert_eq!(zero, 0, "Non-existent type should have count 0");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_get_versions() {
            let storage = $factory().await;
            storage
                .store_document(&make_test_doc("conf-gv-1", "v1", "agent", Some("agent-x")))
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            storage
                .store_document(&make_test_doc("conf-gv-1", "v2", "agent", Some("agent-x")))
                .unwrap();

            let versions = storage
                .get_versions("conf-gv-1")
                .expect("get_versions failed");
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0].version, "v1", "Ordered by created_at ASC");
            assert_eq!(versions[1].version, "v2");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_get_latest() {
            let storage = $factory().await;
            storage
                .store_document(&make_test_doc("conf-lt-1", "v1", "config", None))
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            storage
                .store_document(&make_test_doc("conf-lt-1", "v2", "config", None))
                .unwrap();

            let latest = storage.get_latest("conf-lt-1").expect("get_latest failed");
            assert_eq!(latest.version, "v2");
        }

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_query_by_agent() {
            let storage = $factory().await;
            storage
                .store_document(&make_test_doc("conf-qba-1", "v1", "agent", Some("alice")))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-qba-2", "v1", "config", Some("alice")))
                .unwrap();
            storage
                .store_document(&make_test_doc("conf-qba-3", "v1", "agent", Some("bob")))
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

        #[tokio::test(flavor = "multi_thread")]
        #[serial]
        async fn conformance_db_migrations_idempotent() {
            let storage = $factory().await;
            storage
                .run_migrations()
                .expect("Second run_migrations should not error");
        }
    };
}
