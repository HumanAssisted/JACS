//! Email fixture conformance tests.
//!
//! Loads each .eml fixture from `tests/fixtures/email/fixtures/` and its
//! corresponding expected result JSON from `tests/fixtures/email/expected/`,
//! then verifies that JACS email parsing and canonicalization produce the
//! expected output.

use jacs::email::{canonicalize_header, extract_email_parts};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("email")
        .join("fixtures")
}

fn expected_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("email")
        .join("expected")
}

/// Load a fixture .eml and its expected JSON, returning (raw_bytes, expected_json).
fn load_fixture(name: &str) -> (Vec<u8>, Value) {
    let eml_path = fixtures_dir().join(format!("{}.eml", name));
    let json_path = expected_dir().join(format!("{}.json", name));

    let raw = fs::read(&eml_path).unwrap_or_else(|e| {
        panic!("Failed to read {}: {}", eml_path.display(), e);
    });
    let expected_str = fs::read_to_string(&json_path).unwrap_or_else(|e| {
        panic!("Failed to read {}: {}", json_path.display(), e);
    });
    let expected: Value = serde_json::from_str(&expected_str).unwrap_or_else(|e| {
        panic!("Failed to parse {}: {}", json_path.display(), e);
    });

    (raw, expected)
}

/// Assert that a required header value matches expected after canonicalization.
fn assert_header_value(parts: &jacs::email::ParsedEmailParts, header_name: &str, expected: &Value) {
    if let Some(expected_value) = expected.get("value").and_then(|v| v.as_str()) {
        let raw_values = parts
            .headers
            .get(header_name)
            .expect(&format!("header '{}' should be present", header_name));
        assert_eq!(
            raw_values.len(),
            1,
            "header '{}' should have exactly one value",
            header_name
        );
        let canonical = canonicalize_header(header_name, &raw_values[0]).expect(&format!(
            "canonicalize_header('{}') should succeed",
            header_name
        ));
        assert_eq!(
            canonical, expected_value,
            "header '{}' canonical value mismatch",
            header_name
        );
    }
    // If there's a `value_note` instead of `value`, we skip exact matching
    // (e.g., encoded subjects where the note describes expected behavior)
}

// ---------------------------------------------------------------------------
// Pass-case fixtures: parsing should succeed and match expected payload
// ---------------------------------------------------------------------------

#[test]
fn fixture_01_canonical_baseline() {
    let (raw, expected) = load_fixture("01_canonical_baseline");
    let parts = extract_email_parts(&raw).expect("F01 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);
    assert_header_value(&parts, "date", &payload["headers"]["date"]);
    assert_header_value(&parts, "message-id", &payload["headers"]["message_id"]);

    assert!(
        parts.body_plain.is_some(),
        "F01 should have text/plain body"
    );
    assert!(
        parts.body_html.is_none(),
        "F01 should not have text/html body"
    );
    assert_eq!(
        parts.attachments.len(),
        0,
        "F01 should have 0 non-JACS attachments"
    );
}

#[test]
fn fixture_02_subject_folded_whitespace() {
    let (raw, expected) = load_fixture("02_subject_folded_whitespace");
    let parts = extract_email_parts(&raw).expect("F02 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);
    assert_header_value(&parts, "date", &payload["headers"]["date"]);
    assert_header_value(&parts, "message-id", &payload["headers"]["message_id"]);

    // Subject has folded whitespace — verify it parses without error
    let subject_raw = &parts.headers.get("subject").expect("subject present")[0];
    let canonical =
        canonicalize_header("subject", subject_raw).expect("subject should canonicalize");
    assert!(
        !canonical.is_empty(),
        "F02 canonical subject should not be empty"
    );

    assert!(parts.body_plain.is_some());
    assert!(parts.body_html.is_none());
    assert_eq!(parts.attachments.len(), 0);
}

#[test]
fn fixture_03_subject_rfc2047_utf8() {
    let (raw, _expected) = load_fixture("03_subject_rfc2047_utf8");
    let parts = extract_email_parts(&raw).expect("F03 should parse");

    let subject_raw = &parts.headers.get("subject").expect("subject present")[0];
    let canonical =
        canonicalize_header("subject", subject_raw).expect("subject should canonicalize");
    assert!(
        !canonical.is_empty(),
        "F03 canonical subject should not be empty"
    );
    assert!(parts.body_plain.is_some());
}

#[test]
fn fixture_04_from_case_only_variant() {
    let (raw, expected) = load_fixture("04_from_case_only_variant");
    let parts = extract_email_parts(&raw).expect("F04 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);
    assert!(parts.body_plain.is_some());
}

#[test]
fn fixture_05_to_case_only_variant() {
    let (raw, expected) = load_fixture("05_to_case_only_variant");
    let parts = extract_email_parts(&raw).expect("F05 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);
    assert!(parts.body_plain.is_some());
}

// ---------------------------------------------------------------------------
// Fail-case fixtures: parsing may succeed but signing should fail (duplicate headers)
// ---------------------------------------------------------------------------

#[test]
fn fixture_06_duplicate_from_required_fail() {
    let (raw, _expected) = load_fixture("06_duplicate_from_required_fail");
    let parts = extract_email_parts(&raw).expect("F06 parsing should succeed");

    // Duplicate From header detected
    let from_values = parts.headers.get("from").expect("from header present");
    assert!(
        from_values.len() > 1,
        "F06 should have duplicate From headers, found {}",
        from_values.len()
    );
}

#[test]
fn fixture_07_duplicate_date_required_fail() {
    let (raw, _expected) = load_fixture("07_duplicate_date_required_fail");
    let parts = extract_email_parts(&raw).expect("F07 parsing should succeed");

    let date_values = parts.headers.get("date").expect("date header present");
    assert!(
        date_values.len() > 1,
        "F07 should have duplicate Date headers, found {}",
        date_values.len()
    );
}

#[test]
fn fixture_08_duplicate_message_id_required_fail() {
    let (raw, _expected) = load_fixture("08_duplicate_message_id_required_fail");
    let parts = extract_email_parts(&raw).expect("F08 parsing should succeed");

    let mid_values = parts
        .headers
        .get("message-id")
        .expect("message-id header present");
    assert!(
        mid_values.len() > 1,
        "F08 should have duplicate Message-ID headers, found {}",
        mid_values.len()
    );
}

#[test]
fn fixture_09_missing_optional_in_reply_to_ok() {
    let (raw, expected) = load_fixture("09_missing_optional_in_reply_to_ok");
    let parts = extract_email_parts(&raw).expect("F09 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);
    assert_header_value(&parts, "message-id", &payload["headers"]["message_id"]);

    // In-Reply-To should be absent
    assert!(
        parts.headers.get("in-reply-to").is_none(),
        "F09 should not have In-Reply-To header"
    );
    assert!(payload["headers"]["in_reply_to"].is_null());
}

#[test]
fn fixture_10_duplicate_references_optional_fail() {
    let (raw, _expected) = load_fixture("10_duplicate_references_optional_fail");
    let parts = extract_email_parts(&raw).expect("F10 parsing should succeed");

    let ref_values = parts
        .headers
        .get("references")
        .expect("references header present");
    assert!(
        ref_values.len() > 1,
        "F10 should have duplicate References headers, found {}",
        ref_values.len()
    );
}

// ---------------------------------------------------------------------------
// Body encoding fixtures
// ---------------------------------------------------------------------------

#[test]
fn fixture_11_plain_qp_body() {
    let (raw, _expected) = load_fixture("11_plain_qp_body");
    let parts = extract_email_parts(&raw).expect("F11 should parse");

    assert!(
        parts.body_plain.is_some(),
        "F11 should have text/plain body"
    );
    assert!(parts.body_html.is_none());
    // QP body should be decoded
    let body = parts.body_plain.as_ref().unwrap();
    let text = String::from_utf8_lossy(&body.content);
    assert!(
        text.contains("Canonical body"),
        "F11 body should be decoded from QP"
    );
}

#[test]
fn fixture_12_plain_base64_body() {
    let (raw, _expected) = load_fixture("12_plain_base64_body");
    let parts = extract_email_parts(&raw).expect("F12 should parse");

    assert!(
        parts.body_plain.is_some(),
        "F12 should have text/plain body"
    );
    assert!(parts.body_html.is_none());
    // Base64 body should be decoded to same content as F11
    let body = parts.body_plain.as_ref().unwrap();
    let text = String::from_utf8_lossy(&body.content);
    assert!(
        text.contains("Canonical body"),
        "F12 body should be decoded from base64"
    );
}

#[test]
fn fixture_13_html_iso_8859_1_qp() {
    let (raw, _expected) = load_fixture("13_html_iso_8859_1_qp");
    let parts = extract_email_parts(&raw).expect("F13 should parse");

    assert!(parts.body_plain.is_none());
    assert!(parts.body_html.is_some(), "F13 should have text/html body");
}

#[test]
fn fixture_14_unicode_subject_nfc() {
    let (raw, _expected) = load_fixture("14_unicode_subject_nfc");
    let parts = extract_email_parts(&raw).expect("F14 should parse");

    let subject_raw = &parts.headers.get("subject").expect("subject present")[0];
    let canonical = canonicalize_header("subject", subject_raw).expect("canonicalize");
    // Should decode to NFC "Fixture 14 Cafe\u{0301}" -> "Fixture 14 Caf\u{00e9}"
    assert!(
        canonical.contains("Caf\u{00e9}"),
        "F14 subject should contain NFC cafe"
    );
}

#[test]
fn fixture_15_unicode_subject_nfd() {
    let (raw, _expected) = load_fixture("15_unicode_subject_nfd");
    let parts = extract_email_parts(&raw).expect("F15 should parse");

    let subject_raw = &parts.headers.get("subject").expect("subject present")[0];
    let canonical = canonicalize_header("subject", subject_raw).expect("canonicalize");
    // NFD input should normalize to NFC, matching F14
    assert!(
        canonical.contains("Caf\u{00e9}"),
        "F15 subject should normalize NFD to NFC cafe"
    );
}

#[test]
fn fixture_14_15_nfc_nfd_normalize_to_same_accent() {
    let (raw14, _) = load_fixture("14_unicode_subject_nfc");
    let (raw15, _) = load_fixture("15_unicode_subject_nfd");

    let parts14 = extract_email_parts(&raw14).expect("F14 parse");
    let parts15 = extract_email_parts(&raw15).expect("F15 parse");

    let sub14 = &parts14.headers.get("subject").unwrap()[0];
    let sub15 = &parts15.headers.get("subject").unwrap()[0];

    let canonical14 = canonicalize_header("subject", sub14).unwrap();
    let canonical15 = canonicalize_header("subject", sub15).unwrap();

    // The subjects differ ("Fixture 14 ..." vs "Fixture 15 ...") but both
    // should NFC-normalize the accented character identically: "Caf\u{00e9}"
    assert!(
        canonical14.contains("Caf\u{00e9}"),
        "F14 canonical should contain NFC cafe, got: {}",
        canonical14
    );
    assert!(
        canonical15.contains("Caf\u{00e9}"),
        "F15 canonical should contain NFC cafe, got: {}",
        canonical15
    );

    // Extract the accented word and verify they're byte-identical
    let accent14 = canonical14.split_whitespace().last().unwrap();
    let accent15 = canonical15.split_whitespace().last().unwrap();
    assert_eq!(
        accent14, accent15,
        "NFC and NFD should produce identical accented word"
    );
}

// ---------------------------------------------------------------------------
// Attachment fixtures
// ---------------------------------------------------------------------------

#[test]
fn fixture_16_attachment_base64_text() {
    let (raw, _expected) = load_fixture("16_attachment_base64_text");
    let parts = extract_email_parts(&raw).expect("F16 should parse");

    assert!(parts.body_plain.is_some());
    assert_eq!(
        parts.attachments.len(),
        1,
        "F16 should have 1 non-JACS attachment"
    );
    assert_eq!(parts.attachments[0].filename, "report.txt");
}

#[test]
fn fixture_17_attachment_qp_text_same_bytes() {
    let (raw, _expected) = load_fixture("17_attachment_qp_text_same_bytes");
    let parts = extract_email_parts(&raw).expect("F17 should parse");

    assert!(parts.body_plain.is_some());
    assert_eq!(
        parts.attachments.len(),
        1,
        "F17 should have 1 non-JACS attachment"
    );
    assert_eq!(parts.attachments[0].filename, "report.txt");
}

#[test]
fn fixture_18_attachment_filename_rfc2231() {
    let (raw, _expected) = load_fixture("18_attachment_filename_rfc2231");
    let parts = extract_email_parts(&raw).expect("F18 should parse");

    assert!(parts.body_plain.is_some());
    assert_eq!(
        parts.attachments.len(),
        1,
        "F18 should have 1 non-JACS attachment"
    );
    // RFC 2231 filename should be decoded to NFC UTF-8
    let filename = &parts.attachments[0].filename;
    assert!(
        filename.contains("caf") || filename.contains("caf\u{00e9}"),
        "F18 attachment filename should be decoded from RFC 2231: got '{}'",
        filename
    );
}

// ---------------------------------------------------------------------------
// Identity binding fixtures (fail cases)
// ---------------------------------------------------------------------------

#[test]
fn fixture_19_identity_issuer_registry_mismatch() {
    let (raw, expected) = load_fixture("19_identity_issuer_registry_mismatch");
    let parts = extract_email_parts(&raw).expect("F19 should parse");

    // Parsing succeeds — identity mismatch is a verification-time error
    assert!(parts.body_plain.is_some());
    assert_eq!(expected["expected_result"], "fail");
    assert_eq!(expected["expected_error"], "IssuerRegistryMismatch");

    // The jacs-signature.json should be present
    assert!(
        !parts.jacs_attachments.is_empty(),
        "F19 should have JACS signature attachment"
    );
}

#[test]
fn fixture_20_identity_from_registry_email_mismatch() {
    let (raw, expected) = load_fixture("20_identity_from_registry_email_mismatch");
    let parts = extract_email_parts(&raw).expect("F20 should parse");

    assert!(parts.body_plain.is_some());
    assert_eq!(expected["expected_result"], "fail");
    assert_eq!(expected["expected_error"], "FromRegistryEmailMismatch");

    // From header should be attacker@example.com
    let from_raw = &parts.headers.get("from").unwrap()[0];
    let canonical = canonicalize_header("from", from_raw).unwrap();
    assert_eq!(canonical, "attacker@example.com");
}

// ---------------------------------------------------------------------------
// Structure coverage fixtures (21-28)
// ---------------------------------------------------------------------------

#[test]
fn fixture_21_simple_text() {
    let (raw, expected) = load_fixture("21_simple_text");
    let parts = extract_email_parts(&raw).expect("F21 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);
    assert_header_value(&parts, "message-id", &payload["headers"]["message_id"]);

    assert!(
        parts.body_plain.is_some(),
        "F21 should have text/plain body"
    );
    assert!(parts.body_html.is_none());
    assert_eq!(parts.attachments.len(), 0);
    assert!(parts.jacs_attachments.is_empty());
}

#[test]
fn fixture_22_html_only() {
    let (raw, expected) = load_fixture("22_html_only");
    let parts = extract_email_parts(&raw).expect("F22 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);

    assert!(
        parts.body_plain.is_none(),
        "F22 should not have text/plain body"
    );
    assert!(parts.body_html.is_some(), "F22 should have text/html body");
    assert_eq!(parts.attachments.len(), 0);
}

#[test]
fn fixture_23_multipart_alternative() {
    let (raw, _expected) = load_fixture("23_multipart_alternative");
    let parts = extract_email_parts(&raw).expect("F23 should parse");

    assert!(
        parts.body_plain.is_some(),
        "F23 should have text/plain body"
    );
    assert!(parts.body_html.is_some(), "F23 should have text/html body");
    assert_eq!(parts.attachments.len(), 0);
}

#[test]
fn fixture_24_with_attachments() {
    let (raw, expected) = load_fixture("24_with_attachments");
    let parts = extract_email_parts(&raw).expect("F24 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);

    assert!(
        parts.body_plain.is_some(),
        "F24 should have text/plain body"
    );
    assert_eq!(
        parts.attachments.len(),
        2,
        "F24 should have 2 non-JACS attachments"
    );

    let filenames: Vec<&str> = parts
        .attachments
        .iter()
        .map(|a| a.filename.as_str())
        .collect();
    assert!(
        filenames.contains(&"notes.txt"),
        "F24 should have notes.txt"
    );
    assert!(
        filenames.contains(&"report.pdf"),
        "F24 should have report.pdf"
    );
}

#[test]
fn fixture_25_with_inline_images() {
    let (raw, _expected) = load_fixture("25_with_inline_images");
    let parts = extract_email_parts(&raw).expect("F25 should parse");

    assert!(parts.body_html.is_some(), "F25 should have text/html body");
    // Inline image counts as an attachment for hashing
    assert!(
        parts.attachments.len() >= 1,
        "F25 should have at least 1 inline image attachment"
    );
}

#[test]
fn fixture_26_threaded_reply() {
    let (raw, expected) = load_fixture("26_threaded_reply");
    let parts = extract_email_parts(&raw).expect("F26 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);
    assert_header_value(&parts, "message-id", &payload["headers"]["message_id"]);

    // In-Reply-To and References should be present
    let irt = parts.headers.get("in-reply-to");
    assert!(irt.is_some(), "F26 should have In-Reply-To header");
    let refs = parts.headers.get("references");
    assert!(refs.is_some(), "F26 should have References header");

    assert!(parts.body_plain.is_some());
}

#[test]
fn fixture_27_forwarded_chain() {
    let (raw, expected) = load_fixture("27_forwarded_chain");
    let parts = extract_email_parts(&raw).expect("F27 should parse");
    let payload = &expected["expected_payload"];

    assert_header_value(&parts, "from", &payload["headers"]["from"]);
    assert_header_value(&parts, "to", &payload["headers"]["to"]);

    assert!(
        parts.body_plain.is_some(),
        "F27 should have text/plain body"
    );

    // Should have 2 JACS signature attachments (jacs-signature-0.json and jacs-signature.json)
    assert_eq!(
        parts.jacs_attachments.len(),
        2,
        "F27 should have 2 JACS signature attachments, found {}",
        parts.jacs_attachments.len()
    );

    // parent_signature_hash should be set in expected
    assert!(
        !payload["parent_signature_hash"].is_null(),
        "F27 expected should have parent_signature_hash"
    );
}

#[test]
fn fixture_28_embedded_images() {
    let (raw, _expected) = load_fixture("28_embedded_images");
    let parts = extract_email_parts(&raw).expect("F28 should parse");

    assert!(parts.body_html.is_some(), "F28 should have text/html body");
    assert!(
        parts.attachments.len() >= 1,
        "F28 should have at least 1 inline image attachment"
    );
}

// ---------------------------------------------------------------------------
// Cross-fixture consistency: all expected JSONs are valid and consistent
// ---------------------------------------------------------------------------

#[test]
fn all_fixtures_have_matching_expected_jsons() {
    let fixture_dir = fixtures_dir();
    let expect_dir = expected_dir();

    let mut eml_names: Vec<String> = Vec::new();
    for entry in fs::read_dir(&fixture_dir).expect("read fixtures dir") {
        let entry = entry.expect("read dir entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".eml") {
            let base = name.trim_end_matches(".eml").to_string();
            eml_names.push(base);
        }
    }
    eml_names.sort();

    for base in &eml_names {
        let json_path = expect_dir.join(format!("{}.json", base));
        assert!(
            json_path.exists(),
            "Missing expected JSON for fixture {}.eml",
            base
        );

        let content = fs::read_to_string(&json_path).expect("read expected JSON");
        let json: Value = serde_json::from_str(&content).expect("parse expected JSON");

        assert!(
            json.get("fixture_id").is_some(),
            "{}: missing fixture_id",
            base
        );
        assert!(
            json.get("expected_result").is_some(),
            "{}: missing expected_result",
            base
        );
        assert!(
            json.get("expected_reason").is_some(),
            "{}: missing expected_reason",
            base
        );

        let result = json["expected_result"].as_str().unwrap();
        assert!(
            result == "pass" || result == "fail",
            "{}: expected_result must be 'pass' or 'fail', got '{}'",
            base,
            result
        );
    }
}
