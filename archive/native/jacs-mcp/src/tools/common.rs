//! Shared helpers for MCP tool responses.
//!
//! Provides visibility metadata annotation for tool responses per
//! ARCHITECTURE_UPGRADE.md Section 3.1.5. When MCP tools return documents,
//! the response includes `_jacs_meta` with a visibility level and hint
//! that tells the LLM whether the content is safe to share.

use serde_json::{Value, json};

/// Visibility levels for JACS documents.
///
/// Default is "private" — safe by default. Documents must be explicitly
/// marked public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
    Restricted,
}

impl Visibility {
    /// Parse a visibility string, defaulting to `Private` for unknown values.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "public" => Self::Public,
            "restricted" => Self::Restricted,
            _ => Self::Private,
        }
    }

    /// Return the advisory hint for this visibility level.
    pub fn hint(self) -> &'static str {
        match self {
            Self::Public => "This document is public and can be freely shared.",
            Self::Restricted => {
                "This document is restricted to specific principals. \
                 Only share with authorized agents."
            }
            Self::Private => {
                "This document is private to the owning agent. \
                 Do not share or summarize its contents to other agents \
                 or users without explicit permission."
            }
        }
    }

    /// Return the canonical lowercase string for this visibility level.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Restricted => "restricted",
        }
    }
}

/// Extract the visibility level from a JACS document value.
///
/// Checks for `jacsVisibility` which can be:
/// - A simple string: `"public"`, `"private"`, `"restricted"`
/// - An object with a `"level"` field: `{"level": "public"}`
///
/// Returns `Private` if no visibility field is present (safe by default).
pub fn extract_visibility(doc: &Value) -> Visibility {
    doc.get("jacsVisibility")
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                Some(Visibility::from_str_lossy(s))
            } else if let Some(obj) = v.as_object() {
                obj.get("level")
                    .and_then(|l| l.as_str())
                    .map(Visibility::from_str_lossy)
            } else {
                None
            }
        })
        .unwrap_or(Visibility::Private)
}

/// Build the `_jacs_meta` JSON object for a given visibility level.
fn meta_value(visibility: Visibility) -> Value {
    json!({
        "visibility": visibility.as_str(),
        "hint": visibility.hint()
    })
}

/// Annotate a tool response value with `_jacs_meta` visibility metadata.
///
/// Wraps the document in a response envelope:
/// ```json
/// {
///   "document": <document>,
///   "_jacs_meta": { "visibility": "...", "hint": "..." }
/// }
/// ```
pub fn annotate_response(document: &Value) -> Value {
    let visibility = extract_visibility(document);
    json!({
        "document": document,
        "_jacs_meta": meta_value(visibility)
    })
}

/// Add `_jacs_meta` to an already-serialized tool response string.
///
/// Parses `result_json`, injects the `_jacs_meta` field at the top level,
/// and re-serializes. If `doc` is provided, its `jacsVisibility` field
/// determines the visibility level; otherwise defaults to "private".
///
/// On parse failure the original string is returned unchanged — this
/// ensures error responses that aren't valid JSON pass through safely.
pub fn inject_meta(result_json: &str, doc: Option<&Value>) -> String {
    let visibility = doc.map(extract_visibility).unwrap_or(Visibility::Private);

    if let Ok(mut val) = serde_json::from_str::<Value>(result_json) {
        if let Some(obj) = val.as_object_mut() {
            obj.insert("_jacs_meta".to_string(), meta_value(visibility));
        }
        serde_json::to_string_pretty(&val).unwrap_or_else(|_| result_json.to_string())
    } else {
        // Not valid JSON — return as-is.
        result_json.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_visibility_default_private() {
        let doc = json!({"jacsType": "document", "content": "hello"});
        assert_eq!(extract_visibility(&doc), Visibility::Private);
    }

    #[test]
    fn test_extract_visibility_public_string() {
        let doc = json!({"jacsVisibility": "public"});
        assert_eq!(extract_visibility(&doc), Visibility::Public);
    }

    #[test]
    fn test_extract_visibility_restricted_object() {
        let doc = json!({"jacsVisibility": {"level": "restricted"}});
        assert_eq!(extract_visibility(&doc), Visibility::Restricted);
    }

    #[test]
    fn test_extract_visibility_case_insensitive() {
        let doc = json!({"jacsVisibility": "PUBLIC"});
        assert_eq!(extract_visibility(&doc), Visibility::Public);
    }

    #[test]
    fn test_extract_visibility_unknown_defaults_private() {
        let doc = json!({"jacsVisibility": "secret"});
        assert_eq!(extract_visibility(&doc), Visibility::Private);
    }

    #[test]
    fn test_hint_for_public() {
        assert!(Visibility::Public.hint().contains("freely shared"));
    }

    #[test]
    fn test_hint_for_private() {
        assert!(Visibility::Private.hint().contains("Do not share"));
    }

    #[test]
    fn test_hint_for_restricted() {
        assert!(Visibility::Restricted.hint().contains("authorized agents"));
    }

    #[test]
    fn test_annotate_response_structure() {
        let doc = json!({"jacsVisibility": "public", "content": "data"});
        let annotated = annotate_response(&doc);
        assert!(annotated.get("document").is_some());
        assert!(annotated.get("_jacs_meta").is_some());
        assert_eq!(
            annotated["_jacs_meta"]["visibility"].as_str().unwrap(),
            "public"
        );
    }

    #[test]
    fn test_annotate_response_default_private() {
        let doc = json!({"content": "data"});
        let annotated = annotate_response(&doc);
        assert_eq!(
            annotated["_jacs_meta"]["visibility"].as_str().unwrap(),
            "private"
        );
    }

    #[test]
    fn test_inject_meta_adds_field() {
        let result = json!({"success": true, "message": "ok"});
        let result_str = serde_json::to_string_pretty(&result).unwrap();

        let injected = inject_meta(&result_str, None);
        let parsed: Value = serde_json::from_str(&injected).unwrap();

        assert!(parsed.get("_jacs_meta").is_some());
        assert_eq!(parsed["success"], true);
        assert_eq!(
            parsed["_jacs_meta"]["visibility"].as_str().unwrap(),
            "private"
        );
    }

    #[test]
    fn test_inject_meta_with_public_doc() {
        let doc = json!({"jacsVisibility": "public"});
        let result = json!({"success": true});
        let result_str = serde_json::to_string_pretty(&result).unwrap();

        let injected = inject_meta(&result_str, Some(&doc));
        let parsed: Value = serde_json::from_str(&injected).unwrap();

        assert_eq!(
            parsed["_jacs_meta"]["visibility"].as_str().unwrap(),
            "public"
        );
    }

    #[test]
    fn test_inject_meta_preserves_existing_fields() {
        let result = json!({
            "success": true,
            "jacs_document_id": "abc:1",
            "message": "Signed ok"
        });
        let result_str = serde_json::to_string_pretty(&result).unwrap();

        let injected = inject_meta(&result_str, None);
        let parsed: Value = serde_json::from_str(&injected).unwrap();

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["jacs_document_id"], "abc:1");
        assert_eq!(parsed["message"], "Signed ok");
        assert!(parsed.get("_jacs_meta").is_some());
    }

    #[test]
    fn test_inject_meta_invalid_json_passthrough() {
        let bad = "this is not json";
        let result = inject_meta(bad, None);
        assert_eq!(result, bad);
    }
}
