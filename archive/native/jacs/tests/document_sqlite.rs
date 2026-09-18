#![cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]

//! Integration tests for `SqliteDocumentService` — SQLite-specific behavior
//! that is NOT covered by the cross-backend macro in `document_lifecycle.rs`.
//!
//! The 18 CRUD/search/visibility tests that previously lived here have been
//! removed: they all failed because `create()` now rejects pre-set
//! `jacsId`/`jacsVersion`, and the cross-backend macro in
//! `document_lifecycle.rs` already covers those operations for both backends.
//!
//! Remaining tests:
//! - Tamper detection on read (SQLite-specific: mutates rows directly)
//! - SearchProvider capabilities
//! - Error on nonexistent get/update
//!
//! ```sh
//! cargo test --features sqlite --test document_sqlite
//! ```

use jacs::document::DocumentService;
use jacs::document::types::{CreateOptions, UpdateOptions};
use jacs::search::{SearchCapabilities, SearchProvider};
use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs::storage::SqliteDocumentService;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// Helper: create test JSON with the given fields.
fn test_json(
    id: &str,
    version: &str,
    jacs_type: &str,
    content: &str,
    _agent_id: Option<&str>,
) -> String {
    let value = json!({
        "jacsId": id,
        "jacsVersion": version,
        "jacsType": jacs_type,
        "jacsLevel": "raw",
        "data": content
    });
    value.to_string()
}

/// Helper: create an in-memory SqliteDocumentService (no agent).
fn create_service() -> SqliteDocumentService {
    SqliteDocumentService::in_memory().expect("Failed to create in-memory SqliteDocumentService")
}

fn create_service_with_loaded_agent(
    database_path: &str,
) -> (SqliteDocumentService, tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("create tempdir");
    let root = tmp
        .path()
        .canonicalize()
        .unwrap_or_else(|_| tmp.path().to_path_buf());
    let data_dir = root.join("jacs_data");
    let key_dir = root.join("jacs_keys");
    let config_path = root.join("jacs.config.json");

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
// Tamper detection (SQLite-specific: directly mutates stored rows)
// =============================================================================

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

// NOTE: The previously-ignored `set_visibility_is_in_place_update_no_new_version`
// test was removed. It encoded outdated in-place semantics that no longer match
// the current implementation. The correct behavior (set_visibility creates a
// successor version) is tested in the cross-backend lifecycle suite:
//   document_lifecycle.rs::set_visibility_creates_successor_version
