//! Integration tests: HTML round-trip for all fixture documents.
//!
//! Verifies that JSON -> HTML -> JSON round-trip preserves the exact JSON
//! for every fixture file in the test suite.

mod utils;

use jacs::convert::{html_to_jacs, jacs_to_html};
use utils::collect_json_files;

/// Assert that a JSON string round-trips through HTML and is extracted identically.
fn assert_html_round_trip(json_str: &str, filename: &str) {
    let html = jacs_to_html(json_str)
        .unwrap_or_else(|e| panic!("{}: jacs_to_html failed: {}", filename, e));
    let extracted =
        html_to_jacs(&html).unwrap_or_else(|e| panic!("{}: html_to_jacs failed: {}", filename, e));

    assert_eq!(
        json_str,
        extracted,
        "Extracted JSON does not match original for '{}'.\nOriginal length: {}\nExtracted length: {}",
        filename,
        json_str.len(),
        extracted.len()
    );
}

#[test]
fn html_round_trip_all_signed_documents() {
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
        assert_html_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "html_round_trip_all_signed_documents: {}/{} files passed",
        passed,
        files.len()
    );
}

#[test]
fn html_round_trip_raw_fixtures() {
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
        assert_html_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "html_round_trip_raw_fixtures: {}/{} files passed",
        passed,
        files.len()
    );
}

#[test]
fn html_round_trip_agent_fixtures() {
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
        assert_html_round_trip(&json_str, &filename);
        passed += 1;
    }
    eprintln!(
        "html_round_trip_agent_fixtures: {}/{} files passed",
        passed,
        files.len()
    );
}

#[test]
fn html_metadata_extraction_from_signed_doc() {
    let dir = utils::fixtures_documents_dir();
    let files = collect_json_files(&dir);

    // Find a signed doc that has JACS metadata
    for path in &files {
        let json_str = std::fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Only test docs that have jacsId
        if let Some(jacs_id) = value.get("jacsId").and_then(|v| v.as_str()) {
            let html = jacs_to_html(&json_str).unwrap();

            // Verify metadata is visible in the HTML (not just in the script tag)
            // Find the content before the script tag
            let script_pos = html.find(r#"<script type="application/json""#).unwrap();
            let visible_html = &html[..script_pos];

            assert!(
                visible_html.contains(jacs_id),
                "jacsId '{}' should be visible in HTML body for {}",
                jacs_id,
                path.file_name().unwrap().to_string_lossy()
            );

            // Check for agent ID if signature exists
            if let Some(sigs) = value.get("jacsSignature").and_then(|v| v.as_array()) {
                if let Some(first_sig) = sigs.first() {
                    if let Some(agent_id) = first_sig.get("agentID").and_then(|v| v.as_str()) {
                        assert!(
                            visible_html.contains(agent_id),
                            "Agent ID '{}' should be visible in HTML for {}",
                            agent_id,
                            path.file_name().unwrap().to_string_lossy()
                        );
                    }
                }
            }

            // Check for timestamp if present
            if let Some(date) = value.get("jacsVersionDate").and_then(|v| v.as_str()) {
                assert!(
                    visible_html.contains(date),
                    "Timestamp '{}' should be visible in HTML for {}",
                    date,
                    path.file_name().unwrap().to_string_lossy()
                );
            }

            eprintln!(
                "html_metadata_extraction verified for {}",
                path.file_name().unwrap().to_string_lossy()
            );
            return; // One verified doc is sufficient
        }
    }
    panic!("No signed document with jacsId found in fixtures/documents/");
}
