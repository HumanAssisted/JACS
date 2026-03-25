//! CLI integration tests for `jacs convert` subcommand.
//!
//! Uses `assert_cmd` to invoke the `jacs` binary and test format conversion.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn fixtures_raw_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("jacs")
        .join("tests")
        .join("fixtures")
        .join("raw")
}

fn cmd() -> Command {
    Command::cargo_bin("jacs").expect("jacs binary should exist")
}

#[test]
fn cli_convert_json_to_yaml() {
    let fixture = fixtures_raw_dir().join("favorite-fruit.json");

    cmd()
        .args(["convert", "--to", "yaml", "-f"])
        .arg(fixture.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("favorite-snack"));
}

#[test]
fn cli_convert_json_to_html() {
    let fixture = fixtures_raw_dir().join("favorite-fruit.json");

    cmd()
        .args(["convert", "--to", "html", "-f"])
        .arg(fixture.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::starts_with("<!DOCTYPE html>"));
}

#[test]
fn cli_convert_missing_file_returns_error() {
    cmd()
        .args(["convert", "--to", "yaml", "-f", "/nonexistent/file.json"])
        .assert()
        .failure();
}

#[test]
fn cli_convert_output_to_file() {
    let fixture = fixtures_raw_dir().join("favorite-fruit.json");
    let tmpdir = TempDir::new().unwrap();
    let output_path = tmpdir.path().join("output.yaml");

    cmd()
        .args(["convert", "--to", "yaml", "-f"])
        .arg(fixture.to_str().unwrap())
        .args(["-o"])
        .arg(output_path.to_str().unwrap())
        .assert()
        .success();

    // Verify the file was written and contains YAML content
    let content = std::fs::read_to_string(&output_path).expect("output file should exist");
    assert!(
        content.contains("favorite-snack"),
        "Output file should contain YAML content"
    );
}

#[test]
fn cli_convert_round_trip_json_yaml_json() {
    let fixture = fixtures_raw_dir().join("favorite-fruit.json");
    let original = std::fs::read_to_string(&fixture).unwrap();

    let tmpdir = TempDir::new().unwrap();
    let yaml_path = tmpdir.path().join("intermediate.yaml");
    let json_path = tmpdir.path().join("result.json");

    // JSON -> YAML
    cmd()
        .args(["convert", "--to", "yaml", "-f"])
        .arg(fixture.to_str().unwrap())
        .args(["-o"])
        .arg(yaml_path.to_str().unwrap())
        .assert()
        .success();

    // YAML -> JSON
    cmd()
        .args(["convert", "--to", "json", "-f"])
        .arg(yaml_path.to_str().unwrap())
        .args(["-o"])
        .arg(json_path.to_str().unwrap())
        .assert()
        .success();

    // Compare canonical JSON
    let result = std::fs::read_to_string(&json_path).unwrap();
    let original_value: serde_json::Value = serde_json::from_str(&original).unwrap();
    let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();
    let original_canonical = jacs::protocol::canonicalize_json(&original_value);
    let result_canonical = jacs::protocol::canonicalize_json(&result_value);
    assert_eq!(
        original_canonical, result_canonical,
        "Round-trip should preserve canonical JSON"
    );
}

#[test]
fn cli_convert_round_trip_json_html_json() {
    let fixture = fixtures_raw_dir().join("favorite-fruit.json");
    let original = std::fs::read_to_string(&fixture).unwrap();

    let tmpdir = TempDir::new().unwrap();
    let html_path = tmpdir.path().join("intermediate.html");
    let json_path = tmpdir.path().join("result.json");

    // JSON -> HTML
    cmd()
        .args(["convert", "--to", "html", "-f"])
        .arg(fixture.to_str().unwrap())
        .args(["-o"])
        .arg(html_path.to_str().unwrap())
        .assert()
        .success();

    // HTML -> JSON
    cmd()
        .args(["convert", "--to", "json", "-f"])
        .arg(html_path.to_str().unwrap())
        .args(["-o"])
        .arg(json_path.to_str().unwrap())
        .assert()
        .success();

    // Compare -- HTML embeds exact JSON, so string comparison works
    let result = std::fs::read_to_string(&json_path).unwrap();
    assert_eq!(
        original.trim(),
        result.trim(),
        "HTML round-trip should preserve exact JSON"
    );
}

#[test]
fn cli_convert_preserves_utf8() {
    let fixture = fixtures_raw_dir().join("json-ld.json");
    if !fixture.exists() {
        eprintln!("json-ld.json fixture not found; skipping UTF-8 test");
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let yaml_path = tmpdir.path().join("ld.yaml");
    let json_path = tmpdir.path().join("ld.json");

    // JSON -> YAML -> JSON
    cmd()
        .args(["convert", "--to", "yaml", "-f"])
        .arg(fixture.to_str().unwrap())
        .args(["-o"])
        .arg(yaml_path.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .args(["convert", "--to", "json", "-f"])
        .arg(yaml_path.to_str().unwrap())
        .args(["-o"])
        .arg(json_path.to_str().unwrap())
        .assert()
        .success();

    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fixture).unwrap()).unwrap();
    let result: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
    assert_eq!(
        jacs::protocol::canonicalize_json(&original),
        jacs::protocol::canonicalize_json(&result),
        "UTF-8 content should survive CLI round-trip"
    );
}
