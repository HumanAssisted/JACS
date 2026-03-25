//! Integration tests: YAML round-trip for all fixture documents.
//!
//! Verifies that JSON -> YAML -> JSON round-trip preserves the RFC 8785
//! canonical JSON for every fixture file in the test suite.

mod utils;

use jacs::convert::{jacs_to_yaml, yaml_to_jacs};
use jacs::protocol::canonicalize_json;
use jacs::simple::SimpleAgent;
use utils::collect_json_files;

/// Assert that a JSON string round-trips through YAML and the canonical form
/// is byte-identical. Returns the filename on failure for diagnostics.
fn assert_yaml_round_trip(json_str: &str, filename: &str) {
    let original: serde_json::Value = serde_json::from_str(json_str)
        .unwrap_or_else(|e| panic!("{}: invalid JSON: {}", filename, e));
    let original_canonical = canonicalize_json(&original);

    let yaml = jacs_to_yaml(json_str)
        .unwrap_or_else(|e| panic!("{}: jacs_to_yaml failed: {}", filename, e));
    let back_json =
        yaml_to_jacs(&yaml).unwrap_or_else(|e| panic!("{}: yaml_to_jacs failed: {}", filename, e));

    let reconstituted: serde_json::Value = serde_json::from_str(&back_json)
        .unwrap_or_else(|e| panic!("{}: reconstituted JSON invalid: {}", filename, e));
    let reconstituted_canonical = canonicalize_json(&reconstituted);

    assert_eq!(
        original_canonical,
        reconstituted_canonical,
        "Canonical JSON mismatch for '{}'\nOriginal length: {}\nReconstituted length: {}",
        filename,
        original_canonical.len(),
        reconstituted_canonical.len()
    );
}

#[test]
fn yaml_round_trip_all_signed_documents() {
    let dir = utils::fixtures_documents_dir();
    let files = collect_json_files(&dir);
    assert!(
        !files.is_empty(),
        "Expected at least one JSON file in fixtures/documents/"
    );

    let mut passed = 0;
    for path in &files {
        let json_str = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let filename = path.file_name().unwrap().to_string_lossy();
        assert_yaml_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "yaml_round_trip_all_signed_documents: {}/{} files passed",
        passed,
        files.len()
    );
}

#[test]
fn yaml_round_trip_raw_fixtures() {
    let dir = utils::fixtures_raw_dir();
    let files = collect_json_files(&dir);
    assert!(
        !files.is_empty(),
        "Expected at least one JSON file in fixtures/raw/"
    );

    let mut passed = 0;
    for path in &files {
        let json_str = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let filename = path.file_name().unwrap().to_string_lossy();
        assert_yaml_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "yaml_round_trip_raw_fixtures: {}/{} files passed",
        passed,
        files.len()
    );
}

#[test]
fn yaml_round_trip_agent_fixtures() {
    let dir = utils::find_fixtures_dir().join("agent");
    let files = collect_json_files(&dir);

    if files.is_empty() {
        eprintln!("No agent fixtures found; skipping");
        return;
    }

    let mut passed = 0;
    for path in &files {
        let json_str = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let filename = path.file_name().unwrap().to_string_lossy();
        assert_yaml_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "yaml_round_trip_agent_fixtures: {}/{} files passed",
        passed,
        files.len()
    );
}

#[test]
fn yaml_round_trip_cross_language_fixtures() {
    let dir = utils::find_fixtures_dir().join("cross-language");
    let files = collect_json_files(&dir);

    if files.is_empty() {
        eprintln!("No cross-language fixtures found; skipping");
        return;
    }

    let mut passed = 0;
    for path in &files {
        let json_str = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let filename = path.file_name().unwrap().to_string_lossy();
        assert_yaml_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "yaml_round_trip_cross_language_fixtures: {}/{} files passed",
        passed,
        files.len()
    );
}

#[test]
fn yaml_round_trip_golden_fixtures() {
    let dir = utils::fixtures_golden_dir();
    let files = collect_json_files(&dir);

    if files.is_empty() {
        eprintln!("No golden fixtures found; skipping");
        return;
    }

    let mut passed = 0;
    for path in &files {
        let json_str = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let filename = path.file_name().unwrap().to_string_lossy();
        assert_yaml_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "yaml_round_trip_golden_fixtures: {}/{} files passed",
        passed,
        files.len()
    );
}

/// Proves that YAML conversion does not break cryptographic verification.
/// Signs a document, converts to YAML, converts back to JSON, and verifies
/// the signature on the reconstituted document.
#[test]
fn yaml_round_trip_preserves_verification() {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("should create ephemeral agent");
    let signed = agent
        .sign_message(&serde_json::json!({"fixture_test": true, "round_trip": "yaml"}))
        .expect("sign should succeed");

    let yaml = jacs_to_yaml(&signed.raw).expect("jacs_to_yaml should succeed");
    let json_back = yaml_to_jacs(&yaml).expect("yaml_to_jacs should succeed");
    let result = agent.verify(&json_back).expect("verify should not error");
    assert!(
        result.valid,
        "Signed document should verify after YAML round-trip: {:?}",
        result.errors
    );
}
