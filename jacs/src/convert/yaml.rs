//! JSON <-> YAML conversion for JACS documents.
//!
//! Provides lossless round-trip conversion between JSON and YAML, with the
//! guarantee that the RFC 8785 canonical JSON is byte-identical before and
//! after the round-trip.

use crate::error::JacsError;
use crate::protocol::canonicalize_json;

/// Convert a JSON string to YAML.
///
/// Parses the input as JSON, then serializes it as YAML. The resulting YAML
/// can be converted back to JSON with [`yaml_to_jacs`].
///
/// # Errors
///
/// Returns `JacsError::ConversionError` if the input is not valid JSON.
pub fn jacs_to_yaml(json_str: &str) -> Result<String, JacsError> {
    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| JacsError::conversion("JSON", "YAML", format!("invalid JSON input: {}", e)))?;

    serde_yaml_ng::to_string(&value).map_err(|e| {
        JacsError::conversion("JSON", "YAML", format!("YAML serialization failed: {}", e))
    })
}

/// Parse YAML into a `serde_json::Value`, rejecting bare scalars.
///
/// Shared helper used by [`yaml_to_jacs`] and [`yaml_to_jacs_canonical`] to
/// avoid duplicating the YAML parsing and validation logic.
fn parse_yaml_value(yaml_str: &str) -> Result<serde_json::Value, JacsError> {
    let value: serde_json::Value = serde_yaml_ng::from_str(yaml_str)
        .map_err(|e| JacsError::conversion("YAML", "JSON", format!("invalid YAML input: {}", e)))?;

    // Reject bare scalars -- JACS documents must be objects (or at minimum arrays)
    if !value.is_object() && !value.is_array() {
        return Err(JacsError::conversion(
            "YAML",
            "JSON",
            "YAML must deserialize to a JSON object or array, not a bare scalar",
        ));
    }

    Ok(value)
}

/// Convert a YAML string to pretty-printed JSON.
///
/// Parses the YAML input into a `serde_json::Value`, then serializes it as
/// pretty-printed JSON. This is the human-friendly output; for verification
/// purposes, use [`yaml_to_jacs_canonical`].
///
/// # Errors
///
/// Returns `JacsError::ConversionError` if:
/// - The input is not valid YAML
/// - The YAML deserializes to a non-object/non-array top-level value (bare scalar)
pub fn yaml_to_jacs(yaml_str: &str) -> Result<String, JacsError> {
    let value = parse_yaml_value(yaml_str)?;
    serde_json::to_string_pretty(&value).map_err(|e| {
        JacsError::conversion("YAML", "JSON", format!("JSON serialization failed: {}", e))
    })
}

/// Convert a YAML string to canonical JSON (RFC 8785 / JCS).
///
/// This is the same as [`yaml_to_jacs`] but outputs deterministically-sorted,
/// compact JSON suitable for hash computation and signature verification.
///
/// # Errors
///
/// Same as [`yaml_to_jacs`].
pub fn yaml_to_jacs_canonical(yaml_str: &str) -> Result<String, JacsError> {
    let value = parse_yaml_value(yaml_str)?;
    Ok(canonicalize_json(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assert that JSON -> YAML -> JSON round-trip preserves canonical form.
    fn assert_canonical_round_trip(json_str: &str) {
        let original: serde_json::Value =
            serde_json::from_str(json_str).expect("test input should be valid JSON");
        let original_canonical = canonicalize_json(&original);

        let yaml = jacs_to_yaml(json_str).expect("jacs_to_yaml should succeed");
        let round_tripped =
            yaml_to_jacs_canonical(&yaml).expect("yaml_to_jacs_canonical should succeed");

        assert_eq!(
            original_canonical, round_tripped,
            "Canonical JSON mismatch after YAML round-trip.\nOriginal: {}\nRound-tripped: {}",
            original_canonical, round_tripped
        );
    }

    #[test]
    fn yaml_round_trip_simple_object() {
        assert_canonical_round_trip(r#"{"key": "value"}"#);
    }

    #[test]
    fn yaml_round_trip_nested_object() {
        assert_canonical_round_trip(
            r#"{"outer": {"inner": {"deep": [1, 2, 3]}, "sibling": "value"}}"#,
        );
    }

    #[test]
    fn yaml_round_trip_null_values() {
        assert_canonical_round_trip(r#"{"key": null}"#);
    }

    #[test]
    fn yaml_round_trip_boolean_not_stringified() {
        let json_str = r#"{"flag": true}"#;
        let yaml = jacs_to_yaml(json_str).unwrap();
        let back = yaml_to_jacs(&yaml).unwrap();
        let value: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert!(
            value["flag"].is_boolean(),
            "Boolean should remain a boolean, not become a string"
        );
        assert_eq!(value["flag"], true);
    }

    #[test]
    fn yaml_round_trip_integer_preserved() {
        let json_str = r#"{"count": 42}"#;
        let yaml = jacs_to_yaml(json_str).unwrap();
        let back = yaml_to_jacs(&yaml).unwrap();
        let value: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert!(value["count"].is_number());
        assert_eq!(value["count"], 42);
    }

    #[test]
    fn yaml_round_trip_empty_object() {
        assert_canonical_round_trip(r#"{}"#);
    }

    #[test]
    fn yaml_round_trip_array() {
        assert_canonical_round_trip(r#"[1, "two", null, true]"#);
    }

    #[test]
    fn yaml_to_jacs_invalid_yaml_returns_error() {
        let result = yaml_to_jacs("{{{{ not yaml ::::");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Conversion from YAML to JSON failed"),
            "Error should mention conversion direction: {}",
            msg
        );
    }

    #[test]
    fn yaml_to_jacs_bare_scalar_returns_error() {
        let result = yaml_to_jacs("just a string");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bare scalar"),
            "Error should mention bare scalar: {}",
            msg
        );
    }

    #[test]
    fn jacs_to_yaml_invalid_json_returns_error() {
        let result = jacs_to_yaml("{not valid json}");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Conversion from JSON to YAML failed"),
            "Error should mention conversion direction: {}",
            msg
        );
    }

    #[test]
    fn yaml_output_is_valid_yaml() {
        let json_str = r#"{"hello": "world", "count": 42}"#;
        let yaml = jacs_to_yaml(json_str).unwrap();
        // The YAML output should be parseable back by serde_yaml_ng
        let _: serde_json::Value =
            serde_yaml_ng::from_str(&yaml).expect("YAML output should be valid YAML");
    }

    #[test]
    fn yaml_round_trip_unicode() {
        assert_canonical_round_trip(r#"{"name": "\u00e9"}"#);
        assert_canonical_round_trip(r#"{"emoji": "Hello \ud83c\udf0d"}"#);
        assert_canonical_round_trip(r#"{"cjk": "\u4e16\u754c"}"#);
    }

    // =========================================================================
    // Edge case tests (Task 006)
    // =========================================================================

    #[test]
    fn yaml_float_one_point_zero_round_trips() {
        // 1.0 in JSON is a float. YAML may normalize it.
        // serde_json::Value::Number distinguishes integer from float.
        let json_str = r#"{"val": 1.0}"#;
        let original: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let original_canonical = canonicalize_json(&original);

        let yaml = jacs_to_yaml(json_str).unwrap();
        let back = yaml_to_jacs(&yaml).unwrap();
        let reconstituted: serde_json::Value = serde_json::from_str(&back).unwrap();
        let reconstituted_canonical = canonicalize_json(&reconstituted);

        // Note: serde_json_canonicalizer may normalize 1.0 to 1 (both are valid JSON numbers).
        // The key invariant is that the CANONICAL forms match, not the pretty-printed forms.
        assert_eq!(
            original_canonical, reconstituted_canonical,
            "Canonical JSON should match for float 1.0"
        );
    }

    #[test]
    fn yaml_integer_stays_integer() {
        let json_str = r#"{"val": 42}"#;
        let yaml = jacs_to_yaml(json_str).unwrap();
        let back = yaml_to_jacs(&yaml).unwrap();
        let value: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert!(
            value["val"].is_number(),
            "42 should remain a number after YAML round-trip"
        );
        assert_eq!(value["val"], 42);
    }

    #[test]
    fn yaml_string_true_not_coerced_to_bool() {
        // The string "true" in JSON must not become boolean true in YAML.
        // Since we go JSON -> Value -> YAML -> Value, and serde_json::Value
        // knows that "true" is a String, serde_yaml_ng should quote it.
        let json_str = r#"{"val": "true"}"#;
        let yaml = jacs_to_yaml(json_str).unwrap();
        let back = yaml_to_jacs(&yaml).unwrap();
        let value: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert!(
            value["val"].is_string(),
            "String 'true' should remain a string, got {:?}",
            value["val"]
        );
        assert_eq!(value["val"].as_str().unwrap(), "true");
    }

    #[test]
    fn yaml_string_yes_not_coerced_to_bool() {
        let json_str = r#"{"val": "yes"}"#;
        let yaml = jacs_to_yaml(json_str).unwrap();
        let back = yaml_to_jacs(&yaml).unwrap();
        let value: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert!(
            value["val"].is_string(),
            "String 'yes' should remain a string, got {:?}",
            value["val"]
        );
        assert_eq!(value["val"].as_str().unwrap(), "yes");
    }

    #[test]
    fn yaml_string_null_not_coerced() {
        let json_str = r#"{"val": "null"}"#;
        let yaml = jacs_to_yaml(json_str).unwrap();
        let back = yaml_to_jacs(&yaml).unwrap();
        let value: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert!(
            value["val"].is_string(),
            "String 'null' should remain a string, got {:?}",
            value["val"]
        );
        assert_eq!(value["val"].as_str().unwrap(), "null");
    }

    #[test]
    fn yaml_large_integer_preserved() {
        // 2^53 + 1 -- exceeds JS Number.MAX_SAFE_INTEGER
        let json_str = r#"{"val": 9007199254740993}"#;
        assert_canonical_round_trip(json_str);
    }

    #[test]
    fn yaml_negative_zero() {
        // -0.0 in JSON. Document behavior -- canonical JSON may normalize.
        let json_str = r#"{"val": -0.0}"#;
        let original: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let original_canonical = canonicalize_json(&original);

        let yaml = jacs_to_yaml(json_str).unwrap();
        let back_canonical = yaml_to_jacs_canonical(&yaml).unwrap();

        // The canonical forms should match (both normalize -0 the same way)
        assert_eq!(
            original_canonical, back_canonical,
            "Canonical form of -0.0 should be consistent after round-trip"
        );
    }

    #[test]
    fn yaml_empty_string() {
        assert_canonical_round_trip(r#"{"val": ""}"#);
    }

    #[test]
    fn yaml_deeply_nested_object() {
        // 10 levels of nesting
        let json_str =
            r#"{"l1":{"l2":{"l3":{"l4":{"l5":{"l6":{"l7":{"l8":{"l9":{"l10":"deep"}}}}}}}}}}"#;
        assert_canonical_round_trip(json_str);
    }

    #[test]
    fn yaml_mixed_array_types() {
        assert_canonical_round_trip(r#"[1, "two", null, true, [3], {"four": 4}]"#);
    }

    #[test]
    fn yaml_special_json_keys() {
        assert_canonical_round_trip(r#"{"@context": "http://example.com", "$schema": "test"}"#);
    }

    #[test]
    fn yaml_multiline_string_value() {
        let json_str = r#"{"text": "line1\nline2\nline3"}"#;
        assert_canonical_round_trip(json_str);
    }

    #[test]
    fn yaml_escaped_characters() {
        let json_str = r#"{"val": "tab\there\nnewline"}"#;
        assert_canonical_round_trip(json_str);
    }
}
