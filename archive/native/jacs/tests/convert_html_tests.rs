//! Integration tests: HTML round-trip for all fixture documents.
//!
//! Verifies that JSON -> HTML -> JSON round-trip preserves the exact JSON
//! for every fixture file in the test suite.

mod utils;

use jacs::convert::{html_to_jacs, jacs_to_html};
use jacs::simple::SimpleAgent;
use utils::collect_json_files;

/// Produce a genuine signed document without relying on ignored local data.
fn fresh_signed_document() -> (SimpleAgent, String) {
    let (agent, _) = SimpleAgent::ephemeral_legacy_ed25519_for_fixtures()
        .expect("create disposable signing agent");
    let signed = agent
        .sign_message(&serde_json::json!({
            "title": "HTML parser compatibility",
            "content": "Unicode Ω <tags> & exact signed bytes"
        }))
        .expect("sign HTML fixture");
    (agent, signed.raw)
}

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
    let (agent, fresh) = fresh_signed_document();
    assert_html_round_trip(&fresh, "fresh signed document");
    let extracted = html_to_jacs(&jacs_to_html(&fresh).unwrap()).unwrap();
    assert!(
        agent
            .verify(&extracted)
            .expect("verify extracted document")
            .valid
    );

    // Retain coverage of any saved documents in addition to the fresh fixture.
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
    let (_agent, json_str) = fresh_signed_document();
    let value: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let jacs_id = value["jacsId"].as_str().expect("signed document ID");
    let date = value["jacsVersionDate"]
        .as_str()
        .expect("signed document timestamp");
    let html = jacs_to_html(&json_str).unwrap();
    let script_pos = html.find(r#"<script type="application/json""#).unwrap();
    let visible_html = &html[..script_pos];
    assert!(
        visible_html.contains(jacs_id),
        "document ID must be visible outside the JSON script"
    );
    assert!(
        visible_html.contains(date),
        "document timestamp must be visible outside the JSON script"
    );
}
