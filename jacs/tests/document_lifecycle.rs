//! Cross-backend integration tests for `DocumentService` CRUD lifecycle and search.
//!
//! These tests exercise the full document lifecycle (create -> update -> versions -> diff)
//! and search behavior across both the filesystem and SQLite backends. The tests
//! validate CRUD-as-versioning semantics (Section 3.0.1), canonical document kinds
//! (Section 3.0.2), and the state-tool-to-Document-API mapping (Section 3.2.3).
//!
//! # Running
//!
//! ```sh
//! # Filesystem tests only (always available)
//! cargo test --test document_lifecycle -- lifecycle_fs
//!
//! # SQLite tests only (requires rusqlite-tests feature)
//! cargo test --features rusqlite-tests --test document_lifecycle -- lifecycle_sqlite
//!
//! # Both backends
//! cargo test --features rusqlite-tests --test document_lifecycle
//! ```

use jacs::document::DocumentService;
use jacs::document::types::{CreateOptions, DocumentVisibility, ListFilter, UpdateOptions};
use jacs::search::{SearchMethod, SearchQuery};
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Shared test helpers
// ============================================================================

/// Atomic counter for generating unique document IDs across tests.
static DOC_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a unique document ID for test isolation.
fn next_id(prefix: &str) -> String {
    let n = DOC_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}-{}", prefix, n)
}

/// A factory trait for creating `Box<dyn DocumentService>` in tests.
///
/// Each backend provides its own implementation. This trait also controls
/// whether the JSON payload needs `jacsId`/`jacsVersion` fields:
/// - **SQLite**: requires `jacsId` and `jacsVersion` in the JSON.
/// - **Filesystem**: the Agent generates these; raw JSON content is sufficient.
#[allow(dead_code)]
trait TestBackend {
    /// Create a fresh service instance for one test.
    fn create_service(&self) -> Box<dyn DocumentService>;

    /// Whether this backend requires JACS header fields in the JSON input.
    fn needs_jacs_headers(&self) -> bool;

    /// The expected search method for this backend.
    fn expected_search_method(&self) -> SearchMethod;

    /// Build a JSON payload suitable for this backend's `create()`.
    fn make_json(&self, content_fields: &str) -> String {
        if self.needs_jacs_headers() {
            let id = next_id("lc");
            format!(
                r#"{{"jacsId":"{}","jacsVersion":"v1","jacsType":"artifact","jacsLevel":"raw",{}}}"#,
                id, content_fields
            )
        } else {
            format!(r#"{{{}}}"#, content_fields)
        }
    }

    /// Build JSON for an update. SQLite needs jacsId+jacsVersion matching the original.
    fn make_update_json(&self, doc_id: &str, _doc_version: &str, content_fields: &str) -> String {
        if self.needs_jacs_headers() {
            let new_version = next_id("v");
            format!(
                r#"{{"jacsId":"{}","jacsVersion":"{}","jacsType":"artifact","jacsLevel":"raw",{}}}"#,
                doc_id, new_version, content_fields
            )
        } else {
            format!(r#"{{{}}}"#, content_fields)
        }
    }
}

// ============================================================================
// Macro: generates a test suite using a TestBackend instance.
// ============================================================================

#[allow(unused_macros)]
macro_rules! lifecycle_test_suite {
    // Non-serial variant (used by SQLite)
    ($backend:expr) => {
        lifecycle_test_suite!(@impl $backend,);
    };
    // Serial variant (used by filesystem — needs #[serial] for env var mutation)
    ($backend:expr, serial) => {
        lifecycle_test_suite!(@impl $backend, #[serial]);
    };
    // Internal implementation rule — $($serial_attr)* is either empty or #[serial]
    (@impl $backend:expr, $(#[$serial_attr:meta])*) => {
        fn backend() -> &'static dyn TestBackend {
            // Leak a static reference so tests can reference it.
            // This is fine for tests — the process exits after tests complete.
            static BACKEND: std::sync::OnceLock<Box<dyn TestBackend + Send + Sync>> =
                std::sync::OnceLock::new();
            BACKEND.get_or_init(|| Box::new($backend)).as_ref()
        }

        $(#[$serial_attr])*
        #[test]
        fn full_lifecycle_create_update_versions_diff() {
            let b = backend();
            let svc = b.create_service();

            // 1. Create
            let v1 = svc
                .create(
                    &b.make_json(r#""content":"initial lifecycle content""#),
                    CreateOptions {
                        jacs_type: "artifact".to_string(),
                        ..CreateOptions::default()
                    },
                )
                .expect("create v1");

            assert!(!v1.id.is_empty(), "v1 should have an ID");
            assert!(!v1.version.is_empty(), "v1 should have a version");

            // Small delay so created_at differs (SQLite sorts by created_at DESC)
            std::thread::sleep(std::time::Duration::from_millis(20));

            // 2. First update
            let v2 = svc
                .update(
                    &v1.id,
                    &b.make_update_json(&v1.id, &v1.version, r#""content":"first update content""#),
                    UpdateOptions::default(),
                )
                .expect("update to v2");

            assert_eq!(v2.id, v1.id);
            assert_ne!(v2.version, v1.version);

            // Small delay so created_at differs
            std::thread::sleep(std::time::Duration::from_millis(20));

            // 3. Second update
            let v3 = svc
                .update(
                    &v1.id,
                    &b.make_update_json(&v1.id, &v2.version, r#""content":"second update content""#),
                    UpdateOptions::default(),
                )
                .expect("update to v3");

            assert_eq!(v3.id, v1.id);
            assert_ne!(v3.version, v2.version);

            // 4. Versions
            let versions = svc.versions(&v1.id).expect("versions");
            assert!(
                versions.len() >= 3,
                "should have >= 3 versions, got {}",
                versions.len()
            );
            for v in &versions {
                assert_eq!(v.id, v1.id);
            }

            // 5. get_latest
            let latest = svc.get_latest(&v1.id).expect("get_latest");
            assert_eq!(latest.version, v3.version);

            // 6. Diff
            let diff = svc.diff(&v1.getkey(), &v3.getkey()).expect("diff");
            assert_eq!(diff.key_a, v1.getkey());
            assert_eq!(diff.key_b, v3.getkey());
            assert!(diff.additions > 0 || diff.deletions > 0);
        }

        $(#[$serial_attr])*
        #[test]
        fn create_document_with_each_canonical_kind() {
            let b = backend();
            let svc = b.create_service();

            for kind in &["agent", "artifact", "agentstate", "message", "task", "commitment", "todo"] {
                let json = if b.needs_jacs_headers() {
                    let id = next_id("kind");
                    format!(
                        r#"{{"jacsId":"{}","jacsVersion":"v1","jacsType":"{}","jacsLevel":"raw","content":"doc of kind {}"}}"#,
                        id, kind, kind
                    )
                } else {
                    format!(r#"{{"content":"doc of kind {}"}}"#, kind)
                };

                let doc = svc
                    .create(
                        &json,
                        CreateOptions {
                            jacs_type: kind.to_string(),
                            ..CreateOptions::default()
                        },
                    )
                    .unwrap_or_else(|e| panic!("create {} failed: {}", kind, e));

                assert_eq!(doc.jacs_type, *kind);
                let retrieved = svc.get(&doc.getkey()).expect("get");
                assert_eq!(retrieved.jacs_type, *kind);
            }
        }

        $(#[$serial_attr])*
        #[test]
        fn visibility_model_private_to_public() {
            let b = backend();
            let svc = b.create_service();

            let doc = svc
                .create(
                    &b.make_json(r#""content":"visibility test""#),
                    CreateOptions {
                        visibility: DocumentVisibility::Private,
                        ..CreateOptions::default()
                    },
                )
                .expect("create");

            assert_eq!(svc.visibility(&doc.getkey()).unwrap(), DocumentVisibility::Private);

            svc.set_visibility(&doc.getkey(), DocumentVisibility::Public)
                .expect("set_visibility");

            // Filesystem creates a new version; SQLite updates in-place.
            // Test latest version for backend-agnostic verification.
            let latest = svc.get_latest(&doc.id).expect("get_latest");
            assert_eq!(
                svc.visibility(&latest.getkey()).unwrap(),
                DocumentVisibility::Public
            );
        }

        $(#[$serial_attr])*
        #[test]
        fn batch_create_multiple_documents() {
            let b = backend();
            let svc = b.create_service();

            let j1 = b.make_json(r#""content":"batch 1""#);
            let j2 = b.make_json(r#""content":"batch 2""#);
            let j3 = b.make_json(r#""content":"batch 3""#);
            let docs: Vec<&str> = vec![&j1, &j2, &j3];

            let created = svc
                .create_batch(&docs, CreateOptions::default())
                .expect("create_batch");

            assert_eq!(created.len(), 3);
            for doc in &created {
                svc.get(&doc.getkey()).expect("get batch doc");
            }
        }

        $(#[$serial_attr])*
        #[test]
        fn remove_tombstones_document_excluded_from_list() {
            let b = backend();
            let svc = b.create_service();

            let v1 = svc
                .create(&b.make_json(r#""content":"to remove""#), CreateOptions::default())
                .expect("create");

            let other = svc
                .create(&b.make_json(r#""content":"keep me""#), CreateOptions::default())
                .expect("create other");

            svc.remove(&v1.getkey()).expect("remove");

            let list = svc.list(ListFilter::default()).expect("list");
            let other_found = list.iter().any(|s| s.document_id == other.id);
            assert!(other_found, "other document should still be in list");
            let removed_found = list.iter().any(|s| s.document_id == v1.id);
            assert!(!removed_found, "removed document should NOT be in list");
        }

        $(#[$serial_attr])*
        #[test]
        fn search_finds_document_by_content() {
            let b = backend();
            let svc = b.create_service();

            svc.create(
                &b.make_json(r#""content":"quantum entanglement theory""#),
                CreateOptions::default(),
            )
            .unwrap();
            svc.create(
                &b.make_json(r#""content":"classical mechanics overview""#),
                CreateOptions::default(),
            )
            .unwrap();

            let results = svc
                .search(SearchQuery {
                    query: "quantum".to_string(),
                    ..SearchQuery::default()
                })
                .expect("search");

            assert!(!results.results.is_empty(), "should find 'quantum'");
            assert_eq!(results.method, b.expected_search_method());
        }

        $(#[$serial_attr])*
        #[test]
        fn search_by_jacs_type_filter() {
            let b = backend();
            let svc = b.create_service();

            for jt in &["artifact", "message", "artifact"] {
                let json = if b.needs_jacs_headers() {
                    let id = next_id("tf");
                    format!(
                        r#"{{"jacsId":"{}","jacsVersion":"v1","jacsType":"{}","jacsLevel":"raw","content":"type filter test"}}"#,
                        id, jt
                    )
                } else {
                    r#"{"content":"type filter test"}"#.to_string()
                };

                svc.create(
                    &json,
                    CreateOptions {
                        jacs_type: jt.to_string(),
                        ..CreateOptions::default()
                    },
                )
                .unwrap();
            }

            let results = svc
                .search(SearchQuery {
                    query: "filter".to_string(),
                    jacs_type: Some("artifact".to_string()),
                    ..SearchQuery::default()
                })
                .unwrap();

            assert_eq!(results.results.len(), 2, "should find 2 artifacts, found {}", results.results.len());
            for hit in &results.results {
                assert_eq!(hit.document.jacs_type, "artifact");
            }
        }

        $(#[$serial_attr])*
        #[test]
        fn search_by_agent_id_filter() {
            let b = backend();
            let svc = b.create_service();

            svc.create(
                &b.make_json(r#""content":"agent filter test doc""#),
                CreateOptions::default(),
            )
            .unwrap();

            let list = svc.list(ListFilter::default()).expect("list");
            assert!(!list.is_empty(), "list should not be empty after creating a document");

            let agent_id = &list[0].agent_id;
            assert!(!agent_id.is_empty(), "agent_id should not be empty — backend must populate agent_id");

            let results = svc
                .search(SearchQuery {
                    query: "agent filter".to_string(),
                    agent_id: Some(agent_id.clone()),
                    ..SearchQuery::default()
                })
                .unwrap();

            assert!(!results.results.is_empty());
        }

        $(#[$serial_attr])*
        #[test]
        fn search_pagination_offset_and_limit() {
            let b = backend();
            let svc = b.create_service();

            for i in 0..5 {
                svc.create(
                    &b.make_json(&format!(r#""content":"pagination test item {}""#, i)),
                    CreateOptions::default(),
                )
                .unwrap();
            }

            let page1 = svc
                .search(SearchQuery {
                    query: "pagination".to_string(),
                    limit: 2,
                    offset: 0,
                    ..SearchQuery::default()
                })
                .unwrap();
            assert_eq!(page1.results.len(), 2);
            assert!(page1.total_count >= 5, "total_count >= 5, got {}", page1.total_count);

            let page2 = svc
                .search(SearchQuery {
                    query: "pagination".to_string(),
                    limit: 2,
                    offset: 2,
                    ..SearchQuery::default()
                })
                .unwrap();
            assert_eq!(page2.results.len(), 2);

            let page3 = svc
                .search(SearchQuery {
                    query: "pagination".to_string(),
                    limit: 2,
                    offset: 4,
                    ..SearchQuery::default()
                })
                .unwrap();
            assert!(page3.results.len() <= 2);
        }

        $(#[$serial_attr])*
        #[test]
        fn search_with_min_score_filter() {
            let b = backend();
            let svc = b.create_service();

            svc.create(
                &b.make_json(r#""content":"min score relevance test""#),
                CreateOptions::default(),
            )
            .unwrap();

            let results = svc
                .search(SearchQuery {
                    query: "relevance".to_string(),
                    min_score: Some(0.5),
                    ..SearchQuery::default()
                })
                .unwrap();

            for hit in &results.results {
                assert!(
                    hit.score >= 0.5,
                    "score should be >= min_score 0.5, got {}",
                    hit.score
                );
            }
        }

        $(#[$serial_attr])*
        #[test]
        fn state_tools_map_to_document_api() {
            let b = backend();
            let svc = b.create_service();

            // jacs_sign_state -> create(kind="agentstate", visibility=Private)
            let state_json = if b.needs_jacs_headers() {
                let id = next_id("st");
                format!(
                    r#"{{"jacsId":"{}","jacsVersion":"v1","jacsType":"agentstate","jacsLevel":"raw","memory":"agent state data","plan":"step 1"}}"#,
                    id
                )
            } else {
                r#"{"memory":"agent state data","plan":"step 1"}"#.to_string()
            };

            let state_doc = svc
                .create(
                    &state_json,
                    CreateOptions {
                        jacs_type: "agentstate".to_string(),
                        visibility: DocumentVisibility::Private,
                        ..CreateOptions::default()
                    },
                )
                .expect("sign_state");
            assert_eq!(state_doc.jacs_type, "agentstate");

            // jacs_load_state -> get(key)
            let loaded = svc.get(&state_doc.getkey()).expect("load_state");
            assert_eq!(loaded.id, state_doc.id);

            // jacs_update_state -> update(id, new_content)
            std::thread::sleep(std::time::Duration::from_millis(20));
            let update_json = b.make_update_json(
                &state_doc.id,
                &state_doc.version,
                r#""memory":"updated state","plan":"step 2""#,
            );
            let updated = svc
                .update(&state_doc.id, &update_json, UpdateOptions::default())
                .expect("update_state");
            assert_eq!(updated.id, state_doc.id);
            assert_ne!(updated.version, state_doc.version);

            // jacs_list_state -> list(filter={kind: "agentstate"})
            svc.create(
                &b.make_json(r#""content":"not a state doc""#),
                CreateOptions {
                    jacs_type: "artifact".to_string(),
                    ..CreateOptions::default()
                },
            )
            .unwrap();

            let state_list = svc
                .list(ListFilter {
                    jacs_type: Some("agentstate".to_string()),
                    ..ListFilter::default()
                })
                .expect("list_state");
            for s in &state_list {
                assert_eq!(s.jacs_type, "agentstate");
            }
            assert!(!state_list.is_empty());

            // jacs_verify_state -> verify_document(key)
            // NOTE: DocumentService does not yet expose a verify() method.
            // The PRD Section 3.2.3 maps jacs_verify_state to verify_document(key),
            // but this has not been added to the trait. When it is, add:
            //   svc.verify(&state_doc.getkey()).expect("verify_state");
            // Tracked by ARCHITECTURE_UPGRADE_ISSUE_025.

            // jacs_adopt_state -> create(kind="agentstate", source=external)
            let adopt_json = if b.needs_jacs_headers() {
                let id = next_id("adopt");
                format!(
                    r#"{{"jacsId":"{}","jacsVersion":"v1","jacsType":"agentstate","jacsLevel":"raw","memory":"adopted from external","source":"agent-xyz"}}"#,
                    id
                )
            } else {
                r#"{"memory":"adopted from external","source":"agent-xyz"}"#.to_string()
            };

            let adopted = svc
                .create(
                    &adopt_json,
                    CreateOptions {
                        jacs_type: "agentstate".to_string(),
                        visibility: DocumentVisibility::Private,
                        ..CreateOptions::default()
                    },
                )
                .expect("adopt_state");
            assert_eq!(adopted.jacs_type, "agentstate");
        }

        $(#[$serial_attr])*
        #[test]
        fn append_only_old_version_still_accessible() {
            let b = backend();
            let svc = b.create_service();

            let v1 = svc
                .create(
                    &b.make_json(r#""content":"version one""#),
                    CreateOptions::default(),
                )
                .expect("v1");

            std::thread::sleep(std::time::Duration::from_millis(20));

            let v2 = svc
                .update(
                    &v1.id,
                    &b.make_update_json(&v1.id, &v1.version, r#""content":"version two""#),
                    UpdateOptions::default(),
                )
                .expect("v2");

            assert_eq!(svc.get(&v1.getkey()).unwrap().version, v1.version);
            assert_eq!(svc.get(&v2.getkey()).unwrap().version, v2.version);
        }

        $(#[$serial_attr])*
        #[test]
        fn list_with_type_and_visibility_filters() {
            let b = backend();
            let svc = b.create_service();

            let make_typed_json = |jt: &str, content: &str| -> String {
                if b.needs_jacs_headers() {
                    let id = next_id("flt");
                    format!(
                        r#"{{"jacsId":"{}","jacsVersion":"v1","jacsType":"{}","jacsLevel":"raw","content":"{}"}}"#,
                        id, jt, content
                    )
                } else {
                    format!(r#"{{"content":"{}"}}"#, content)
                }
            };

            svc.create(
                &make_typed_json("artifact", "public artifact"),
                CreateOptions {
                    jacs_type: "artifact".to_string(),
                    visibility: DocumentVisibility::Public,
                    ..CreateOptions::default()
                },
            )
            .unwrap();

            svc.create(
                &make_typed_json("artifact", "private artifact"),
                CreateOptions {
                    jacs_type: "artifact".to_string(),
                    visibility: DocumentVisibility::Private,
                    ..CreateOptions::default()
                },
            )
            .unwrap();

            svc.create(
                &make_typed_json("message", "public message"),
                CreateOptions {
                    jacs_type: "message".to_string(),
                    visibility: DocumentVisibility::Public,
                    ..CreateOptions::default()
                },
            )
            .unwrap();

            let filtered = svc
                .list(ListFilter {
                    jacs_type: Some("artifact".to_string()),
                    visibility: Some(DocumentVisibility::Public),
                    ..ListFilter::default()
                })
                .unwrap();

            for s in &filtered {
                assert_eq!(s.jacs_type, "artifact");
                assert_eq!(s.visibility, DocumentVisibility::Public);
            }
            assert!(!filtered.is_empty());
        }

        $(#[$serial_attr])*
        #[test]
        fn update_without_visibility_inherits_existing() {
            let b = backend();
            let svc = b.create_service();

            // Create a Public document
            let doc = svc
                .create(
                    &b.make_json(r#""content":"visibility inheritance test""#),
                    CreateOptions {
                        visibility: DocumentVisibility::Public,
                        ..CreateOptions::default()
                    },
                )
                .expect("create public doc");

            assert_eq!(
                svc.visibility(&doc.getkey()).unwrap(),
                DocumentVisibility::Public
            );

            // Update without specifying visibility — should inherit Public
            std::thread::sleep(std::time::Duration::from_millis(20));
            let updated = svc
                .update(
                    &doc.id,
                    &b.make_update_json(&doc.id, &doc.version, r#""content":"updated content""#),
                    UpdateOptions::default(), // visibility: None
                )
                .expect("update");

            let latest = svc.get_latest(&doc.id).expect("get_latest");
            assert_eq!(
                svc.visibility(&latest.getkey()).unwrap(),
                DocumentVisibility::Public,
                "visibility should be inherited as Public, not reset to Private"
            );
        }

        $(#[$serial_attr])*
        #[test]
        fn restricted_visibility_crud_lifecycle() {
            let b = backend();
            let svc = b.create_service();

            // 1. Create a document with Restricted visibility
            let principals = vec!["agent-a".to_string(), "agent-b".to_string()];
            let doc = svc
                .create(
                    &b.make_json(r#""content":"restricted visibility test""#),
                    CreateOptions {
                        visibility: DocumentVisibility::Restricted(principals.clone()),
                        ..CreateOptions::default()
                    },
                )
                .expect("create restricted doc");

            // 2. Read it back and verify visibility
            let vis = svc.visibility(&doc.getkey()).expect("get visibility");
            match vis {
                DocumentVisibility::Restricted(ref p) => {
                    assert_eq!(p, &principals, "principals should match");
                }
                other => panic!("Expected Restricted, got {:?}", other),
            }

            // 3. List with Restricted visibility filter
            let list = svc
                .list(ListFilter {
                    visibility: Some(DocumentVisibility::Restricted(principals.clone())),
                    ..ListFilter::default()
                })
                .expect("list restricted");
            let found = list.iter().any(|s| s.document_id == doc.id);
            assert!(found, "restricted document should appear in filtered list");

            // 4. Change visibility from Restricted to Public
            svc.set_visibility(&doc.getkey(), DocumentVisibility::Public)
                .expect("set_visibility to Public");
            let latest = svc.get_latest(&doc.id).expect("get_latest");
            assert_eq!(
                svc.visibility(&latest.getkey()).unwrap(),
                DocumentVisibility::Public,
                "visibility should be Public after change from Restricted"
            );
        }
    };
}

// ============================================================================
// Filesystem backend
// ============================================================================

mod fs_helpers {
    use super::*;
    use jacs::document::filesystem::FilesystemDocumentService;
    use jacs::simple::{CreateAgentParams, SimpleAgent};
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, OnceLock};
    use tempfile::TempDir;

    const TEST_PASSWORD: &str = "TestP@ss123!#";

    /// Cached agent artifacts: key directory and config path.
    /// Created once via OnceLock, reused across all FS tests to avoid
    /// re-generating Ed25519 keys (~35-40s) for every single test.
    struct CachedAgent {
        key_dir: PathBuf,
        config_path: PathBuf,
        _tempdir: TempDir, // held alive for the process lifetime
    }

    static CACHED_AGENT: OnceLock<CachedAgent> = OnceLock::new();

    fn get_or_create_cached_agent() -> &'static CachedAgent {
        CACHED_AGENT.get_or_init(|| {
            let tmp = TempDir::new().expect("create agent tempdir");
            let data_dir = tmp.path().join("jacs_data");
            let key_dir = tmp.path().join("jacs_keys");
            let config_path = tmp.path().join("jacs.config.json");

            let params = CreateAgentParams::builder()
                .name("lifecycle-test-agent")
                .password(TEST_PASSWORD)
                .algorithm("ring-Ed25519")
                .data_directory(data_dir.to_str().unwrap())
                .key_directory(key_dir.to_str().unwrap())
                .config_path(config_path.to_str().unwrap())
                .default_storage("fs")
                .description("Test agent for lifecycle integration tests")
                .build();

            let (_agent, _info) =
                SimpleAgent::create_with_params(params).expect("create_with_params");

            CachedAgent {
                key_dir,
                config_path,
                _tempdir: tmp,
            }
        })
    }

    // Thread-local to hold per-test TempDir alive during filesystem tests.
    thread_local! {
        pub static FS_TMP: RefCell<Option<TempDir>> = RefCell::new(None);
    }

    pub struct FsBackend;

    impl TestBackend for FsBackend {
        fn create_service(&self) -> Box<dyn DocumentService> {
            let cached = get_or_create_cached_agent();

            // Each test gets a fresh data directory for document isolation.
            let tmp = TempDir::new().expect("create test tempdir");
            let data_dir = tmp.path().join("jacs_data");

            unsafe {
                std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
                std::env::set_var("JACS_DATA_DIRECTORY", data_dir.to_str().unwrap());
                std::env::set_var("JACS_KEY_DIRECTORY", cached.key_dir.to_str().unwrap());
            }

            let storage = jacs::storage::MultiStorage::_new("fs".to_string(), data_dir.clone())
                .expect("create MultiStorage");

            let mut fs_agent = jacs::get_empty_agent();
            fs_agent
                .load_by_config(cached.config_path.to_str().unwrap().to_string())
                .expect("load agent by config");

            let service = FilesystemDocumentService::new(
                Arc::new(storage),
                Arc::new(Mutex::new(fs_agent)),
                data_dir,
            );

            // Keep TempDir alive
            FS_TMP.with(|cell| {
                *cell.borrow_mut() = Some(tmp);
            });

            Box::new(service)
        }

        fn needs_jacs_headers(&self) -> bool {
            false
        }

        fn expected_search_method(&self) -> SearchMethod {
            SearchMethod::FieldMatch
        }
    }
}

mod lifecycle_fs {
    use super::*;
    use serial_test::serial;

    lifecycle_test_suite!(fs_helpers::FsBackend, serial);
}

// ============================================================================
// SQLite backend (requires rusqlite-tests feature)
// ============================================================================

#[cfg(feature = "rusqlite-tests")]
mod sqlite_helpers {
    use super::*;

    pub struct SqliteBackend;

    impl TestBackend for SqliteBackend {
        fn create_service(&self) -> Box<dyn DocumentService> {
            use jacs::storage::SqliteDocumentService;
            Box::new(SqliteDocumentService::in_memory().expect("in-memory SQLite"))
        }

        fn needs_jacs_headers(&self) -> bool {
            true
        }

        fn expected_search_method(&self) -> SearchMethod {
            SearchMethod::FullText
        }
    }
}

#[cfg(feature = "rusqlite-tests")]
mod lifecycle_sqlite {
    use super::*;

    lifecycle_test_suite!(sqlite_helpers::SqliteBackend);
}
