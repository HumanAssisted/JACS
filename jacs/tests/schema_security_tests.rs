//! Security-focused tests for schema resolution path restrictions.

use jacs::schema::utils::resolve_schema;
use serial_test::serial;
use std::fs;
use std::path::Path;
use tempfile::Builder;

fn write_minimal_schema(path: &Path) {
    fs::write(
        path,
        r#"{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}"#,
    )
    .expect("failed to write test schema");
}

#[test]
#[serial]
fn resolve_schema_rejects_prefix_overlap_outside_allowed_directory() {
    let cwd = std::env::current_dir().expect("failed to get cwd");
    let temp = Builder::new()
        .prefix("jacs-schema-security-")
        .tempdir_in(&cwd)
        .expect("failed to create temp dir");

    let allowed_dir = temp.path().join("allowed");
    let outside_dir = temp.path().join("allowed_evil");
    fs::create_dir_all(&allowed_dir).expect("failed to create allowed dir");
    fs::create_dir_all(&outside_dir).expect("failed to create outside dir");

    let outside_schema = outside_dir.join("outside.schema.json");
    write_minimal_schema(&outside_schema);

    let allowed_rel = allowed_dir
        .strip_prefix(&cwd)
        .expect("allowed dir should be under cwd")
        .to_string_lossy()
        .to_string();
    let outside_rel = outside_schema
        .strip_prefix(&cwd)
        .expect("outside schema should be under cwd")
        .to_string_lossy()
        .to_string();

    // SAFETY: serial test; env var mutations are isolated to this test's process phase.
    unsafe {
        std::env::set_var("JACS_ALLOW_FILESYSTEM_SCHEMAS", "true");
        std::env::set_var("JACS_DATA_DIRECTORY", &allowed_rel);
        std::env::remove_var("JACS_SCHEMA_DIRECTORY");
    }

    let result = resolve_schema(&outside_rel);

    // SAFETY: serial test; cleanup mirrors setup above.
    unsafe {
        std::env::remove_var("JACS_ALLOW_FILESYSTEM_SCHEMAS");
        std::env::remove_var("JACS_DATA_DIRECTORY");
        std::env::remove_var("JACS_SCHEMA_DIRECTORY");
    }

    assert!(
        result.is_err(),
        "schema path with shared prefix should be rejected: {}",
        outside_rel
    );
    let err = result.err().expect("error expected").to_string();
    assert!(
        err.contains("outside allowed directories"),
        "unexpected error: {}",
        err
    );
}

#[test]
#[serial]
fn resolve_schema_allows_paths_within_allowed_directory() {
    let cwd = std::env::current_dir().expect("failed to get cwd");
    let temp = Builder::new()
        .prefix("jacs-schema-allowed-")
        .tempdir_in(&cwd)
        .expect("failed to create temp dir");

    let allowed_dir = temp.path().join("allowed");
    fs::create_dir_all(&allowed_dir).expect("failed to create allowed dir");

    let inside_schema = allowed_dir.join("inside.schema.json");
    write_minimal_schema(&inside_schema);

    let allowed_rel = allowed_dir
        .strip_prefix(&cwd)
        .expect("allowed dir should be under cwd")
        .to_string_lossy()
        .to_string();
    let inside_rel = inside_schema
        .strip_prefix(&cwd)
        .expect("inside schema should be under cwd")
        .to_string_lossy()
        .to_string();

    // SAFETY: serial test; env var mutations are isolated to this test's process phase.
    unsafe {
        std::env::set_var("JACS_ALLOW_FILESYSTEM_SCHEMAS", "true");
        std::env::set_var("JACS_DATA_DIRECTORY", &allowed_rel);
        std::env::remove_var("JACS_SCHEMA_DIRECTORY");
    }

    let result = resolve_schema(&inside_rel);

    // SAFETY: serial test; cleanup mirrors setup above.
    unsafe {
        std::env::remove_var("JACS_ALLOW_FILESYSTEM_SCHEMAS");
        std::env::remove_var("JACS_DATA_DIRECTORY");
        std::env::remove_var("JACS_SCHEMA_DIRECTORY");
    }

    assert!(
        result.is_ok(),
        "schema path within allowed directory should be permitted: {}",
        inside_rel
    );
}
