//! Tests for `_jacs_meta` visibility metadata annotation.
//!
//! Verifies that the `common::inject_meta` and `common::annotate_response`
//! helpers produce the correct visibility levels and hints per
//! ARCHITECTURE_UPGRADE.md Section 3.1.5.

use serde_json::{json, Value};

// Re-use the helpers from the library crate.
use jacs_mcp::tools::common::{annotate_response, extract_visibility, inject_meta, Visibility};

// ============================================================================
// extract_visibility
// ============================================================================

#[test]
fn visibility_defaults_to_private_when_missing() {
    let doc = json!({"jacsType": "agentstate", "content": "secret"});
    assert_eq!(extract_visibility(&doc), Visibility::Private);
}

#[test]
fn visibility_public_from_string() {
    let doc = json!({"jacsVisibility": "public"});
    assert_eq!(extract_visibility(&doc), Visibility::Public);
}

#[test]
fn visibility_restricted_from_string() {
    let doc = json!({"jacsVisibility": "restricted"});
    assert_eq!(extract_visibility(&doc), Visibility::Restricted);
}

#[test]
fn visibility_private_from_string() {
    let doc = json!({"jacsVisibility": "private"});
    assert_eq!(extract_visibility(&doc), Visibility::Private);
}

#[test]
fn visibility_public_from_object_level() {
    let doc = json!({"jacsVisibility": {"level": "public"}});
    assert_eq!(extract_visibility(&doc), Visibility::Public);
}

#[test]
fn visibility_restricted_from_object_level() {
    let doc = json!({"jacsVisibility": {"level": "restricted"}});
    assert_eq!(extract_visibility(&doc), Visibility::Restricted);
}

#[test]
fn visibility_case_insensitive() {
    assert_eq!(
        extract_visibility(&json!({"jacsVisibility": "PUBLIC"})),
        Visibility::Public
    );
    assert_eq!(
        extract_visibility(&json!({"jacsVisibility": "Restricted"})),
        Visibility::Restricted
    );
    assert_eq!(
        extract_visibility(&json!({"jacsVisibility": "PRIVATE"})),
        Visibility::Private
    );
}

#[test]
fn visibility_unknown_value_defaults_private() {
    let doc = json!({"jacsVisibility": "top-secret"});
    assert_eq!(extract_visibility(&doc), Visibility::Private);
}

// ============================================================================
// Visibility hints
// ============================================================================

#[test]
fn public_hint_mentions_freely_shared() {
    let hint = Visibility::Public.hint();
    assert!(
        hint.contains("freely shared"),
        "expected 'freely shared' in hint: {hint}"
    );
}

#[test]
fn private_hint_mentions_do_not_share() {
    let hint = Visibility::Private.hint();
    assert!(
        hint.contains("Do not share"),
        "expected 'Do not share' in hint: {hint}"
    );
}

#[test]
fn restricted_hint_mentions_authorized_agents() {
    let hint = Visibility::Restricted.hint();
    assert!(
        hint.contains("authorized agents"),
        "expected 'authorized agents' in hint: {hint}"
    );
}

// ============================================================================
// annotate_response
// ============================================================================

#[test]
fn annotate_response_wraps_with_document_and_meta() {
    let doc = json!({"jacsVisibility": "public", "content": "hello"});
    let annotated = annotate_response(&doc);

    assert!(annotated.get("document").is_some(), "missing 'document' key");
    assert!(
        annotated.get("_jacs_meta").is_some(),
        "missing '_jacs_meta' key"
    );

    let meta = &annotated["_jacs_meta"];
    assert_eq!(meta["visibility"].as_str().unwrap(), "public");
    assert!(meta["hint"].as_str().unwrap().contains("freely shared"));
}

#[test]
fn annotate_response_defaults_to_private() {
    let doc = json!({"content": "data"});
    let annotated = annotate_response(&doc);
    assert_eq!(
        annotated["_jacs_meta"]["visibility"].as_str().unwrap(),
        "private"
    );
}

// ============================================================================
// inject_meta
// ============================================================================

#[test]
fn inject_meta_adds_jacs_meta_to_json() {
    let result = json!({"success": true, "message": "ok"});
    let result_str = serde_json::to_string_pretty(&result).unwrap();

    let injected_str = inject_meta(&result_str, None);
    let parsed: Value = serde_json::from_str(&injected_str).unwrap();

    // Original fields preserved
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["message"], "ok");

    // _jacs_meta added
    let meta = &parsed["_jacs_meta"];
    assert_eq!(meta["visibility"].as_str().unwrap(), "private");
    assert!(meta["hint"].as_str().unwrap().contains("Do not share"));
}

#[test]
fn inject_meta_uses_doc_visibility_when_provided() {
    let doc = json!({"jacsVisibility": "public"});
    let result = json!({"success": true, "signed_document": "..."});
    let result_str = serde_json::to_string_pretty(&result).unwrap();

    let injected_str = inject_meta(&result_str, Some(&doc));
    let parsed: Value = serde_json::from_str(&injected_str).unwrap();

    assert_eq!(
        parsed["_jacs_meta"]["visibility"].as_str().unwrap(),
        "public"
    );
}

#[test]
fn inject_meta_uses_restricted_when_doc_says_restricted() {
    let doc = json!({"jacsVisibility": {"level": "restricted"}});
    let result = json!({"success": true});
    let result_str = serde_json::to_string_pretty(&result).unwrap();

    let injected_str = inject_meta(&result_str, Some(&doc));
    let parsed: Value = serde_json::from_str(&injected_str).unwrap();

    assert_eq!(
        parsed["_jacs_meta"]["visibility"].as_str().unwrap(),
        "restricted"
    );
    assert!(parsed["_jacs_meta"]["hint"]
        .as_str()
        .unwrap()
        .contains("authorized agents"));
}

#[test]
fn inject_meta_preserves_all_original_fields() {
    let result = json!({
        "success": true,
        "jacs_document_id": "abc:1",
        "signed_document": "{...}",
        "content_hash": "deadbeef",
        "message": "Signed ok"
    });
    let result_str = serde_json::to_string_pretty(&result).unwrap();

    let injected_str = inject_meta(&result_str, None);
    let parsed: Value = serde_json::from_str(&injected_str).unwrap();

    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["jacs_document_id"], "abc:1");
    assert_eq!(parsed["signed_document"], "{...}");
    assert_eq!(parsed["content_hash"], "deadbeef");
    assert_eq!(parsed["message"], "Signed ok");
    assert!(parsed.get("_jacs_meta").is_some());
}

#[test]
fn inject_meta_returns_original_on_invalid_json() {
    let bad = "this is not json";
    let result = inject_meta(bad, None);
    assert_eq!(result, bad);
}

#[test]
fn inject_meta_handles_empty_json_object() {
    let result_str = "{}";
    let injected = inject_meta(result_str, None);
    let parsed: Value = serde_json::from_str(&injected).unwrap();
    assert!(parsed.get("_jacs_meta").is_some());
    assert_eq!(
        parsed["_jacs_meta"]["visibility"].as_str().unwrap(),
        "private"
    );
}

// ============================================================================
// Visibility as_str roundtrip
// ============================================================================

#[test]
fn visibility_as_str_roundtrip() {
    for vis in [Visibility::Public, Visibility::Private, Visibility::Restricted] {
        let s = vis.as_str();
        let parsed = Visibility::from_str_lossy(s);
        assert_eq!(vis, parsed, "roundtrip failed for {s}");
    }
}
