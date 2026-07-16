//! Strict JSON decoding for cryptographic trust boundaries.
//!
//! `serde_json::Value` follows the common "last key wins" convention when
//! an object contains duplicate member names.  That behaviour is convenient
//! for ordinary application JSON, but ambiguous at a signing boundary: two
//! implementations can select different values before canonicalization.
//! These helpers reject duplicate decoded member names recursively, including
//! escape-equivalent spellings such as `"agentID"` and `"agent\u0049D"`.
//! They also enforce the I-JSON interoperable integer range so canonicalization
//! cannot collapse two distinct integral inputs onto the same IEEE-754 value.

use crate::CoreError;
use serde::de::DeserializeOwned;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::HashSet;
use std::fmt;

const MAX_I_JSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MIN_I_JSON_SAFE_INTEGER: i64 = -MAX_I_JSON_SAFE_INTEGER;

fn unsafe_integer_message(value: impl fmt::Display) -> String {
    format!(
        "JSON integer {value} is outside the I-JSON safe integer range \
         -9007199254740991..=9007199254740991"
    )
}

fn validate_integer_tokens(input: &[u8]) -> Result<(), CoreError> {
    const MAX_SAFE_DIGITS: &[u8] = b"9007199254740991";

    let mut index = 0;
    let mut in_string = false;
    while index < input.len() {
        match input[index] {
            b'"' => {
                in_string = !in_string;
                index += 1;
            }
            b'\\' if in_string => {
                // The JSON decoder performs full escape validation. Skipping
                // the escaped byte here is sufficient to avoid interpreting a
                // quoted numeric string as a JSON number token.
                index = index.saturating_add(2);
            }
            byte if !in_string && (byte == b'-' || byte.is_ascii_digit()) => {
                let start = index;
                index += 1;
                while index < input.len()
                    && matches!(input[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    index += 1;
                }
                let token = &input[start..index];
                if token.iter().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                    continue;
                }
                let digits = token.strip_prefix(b"-").unwrap_or(token);
                if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                    continue;
                }
                let significant = digits
                    .iter()
                    .position(|byte| *byte != b'0')
                    .map(|offset| &digits[offset..])
                    .unwrap_or(b"0");
                let outside_safe_range = significant.len() > MAX_SAFE_DIGITS.len()
                    || (significant.len() == MAX_SAFE_DIGITS.len()
                        && significant > MAX_SAFE_DIGITS);
                if outside_safe_range {
                    let shown = String::from_utf8_lossy(&token[..token.len().min(64)]);
                    let suffix = if token.len() > 64 { "…" } else { "" };
                    return Err(CoreError::MalformedDocument(unsafe_integer_message(
                        format_args!("{shown}{suffix}"),
                    )));
                }
            }
            _ => index += 1,
        }
    }
    Ok(())
}

/// Validate values that were constructed programmatically rather than decoded
/// through [`parse_strict_json`].
///
/// RFC 8785 serializes numbers with ECMAScript's binary64 representation. An
/// integral `serde_json::Number` outside JavaScript's exact integer range can
/// therefore canonicalize to the same bytes as a neighboring integer. Signing
/// and verification code must call this (directly or through
/// `canonicalize_json_try`) before treating canonical bytes as authoritative.
pub fn validate_i_json_numbers(value: &Value) -> Result<(), CoreError> {
    match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                if !(MIN_I_JSON_SAFE_INTEGER..=MAX_I_JSON_SAFE_INTEGER).contains(&integer) {
                    return Err(CoreError::MalformedDocument(unsafe_integer_message(
                        integer,
                    )));
                }
            } else if let Some(integer) = number.as_u64()
                && integer > MAX_I_JSON_SAFE_INTEGER as u64
            {
                return Err(CoreError::MalformedDocument(unsafe_integer_message(
                    integer,
                )));
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_i_json_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_i_json_numbers(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !(MIN_I_JSON_SAFE_INTEGER..=MAX_I_JSON_SAFE_INTEGER).contains(&value) {
            return Err(E::custom(unsafe_integer_message(value)));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value > MAX_I_JSON_SAFE_INTEGER as u64 {
            return Err(E::custom(unsafe_integer_message(value)));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite number is not valid JSON"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = HashSet::with_capacity(object.size_hint().unwrap_or(0));

        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }

        Ok(StrictValue(Value::Object(values)))
    }
}

/// Decode a UTF-8 JSON string while rejecting duplicate object keys and
/// integral values outside the I-JSON safe range at every nesting level.
pub fn parse_strict_json(input: &str) -> Result<Value, CoreError> {
    validate_integer_tokens(input.as_bytes())?;
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| CoreError::MalformedDocument(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| CoreError::MalformedDocument(error.to_string()))?;
    Ok(value.0)
}

/// Decode JSON bytes while rejecting duplicate object keys and integral values
/// outside the I-JSON safe range at every nesting level. Invalid UTF-8 is
/// reported as a malformed document.
pub fn parse_strict_json_slice(input: &[u8]) -> Result<Value, CoreError> {
    validate_integer_tokens(input)?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| CoreError::MalformedDocument(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| CoreError::MalformedDocument(error.to_string()))?;
    Ok(value.0)
}

/// Decode a UTF-8 JSON string into a typed value after enforcing the same
/// duplicate-key policy as [`parse_strict_json`].
pub fn deserialize_strict_json<T: DeserializeOwned>(input: &str) -> Result<T, CoreError> {
    let value = parse_strict_json(input)?;
    serde_json::from_value(value).map_err(|error| CoreError::MalformedDocument(error.to_string()))
}

/// Decode JSON bytes into a typed value after enforcing the same duplicate-key
/// policy as [`parse_strict_json_slice`].
pub fn deserialize_strict_json_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, CoreError> {
    let value = parse_strict_json_slice(input)?;
    serde_json::from_value(value).map_err(|error| CoreError::MalformedDocument(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{parse_strict_json, parse_strict_json_slice, validate_i_json_numbers};
    use serde_json::json;

    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

    #[test]
    fn rejects_duplicate_keys_recursively_after_escape_decoding() {
        for input in [
            r#"{"a":1,"a":2}"#,
            r#"{"nested":{"a":1,"a":2}}"#,
            r#"{"agentID":"one","agent\u0049D":"two"}"#,
            r#"[{"nonce":"one","nonce":"two"}]"#,
        ] {
            let error = parse_strict_json(input).expect_err("duplicate keys must be rejected");
            assert!(
                error.to_string().contains("duplicate JSON object key"),
                "unexpected error for {input}: {error}"
            );
        }
    }

    #[test]
    fn preserves_unambiguous_json_values() {
        let input = r#"{"object":{"a":1,"b":2},"array":[1,1,null,true],"unicode":"é"}"#;
        let actual = parse_strict_json(input).expect("unambiguous JSON should parse");
        assert_eq!(
            actual,
            json!({
                "object": {"a": 1, "b": 2},
                "array": [1, 1, null, true],
                "unicode": "é"
            })
        );
    }

    #[test]
    fn byte_parser_has_the_same_duplicate_policy() {
        let error = parse_strict_json_slice(br#"{"key":1,"key":2}"#)
            .expect_err("duplicate keys in byte input must be rejected");
        assert!(error.to_string().contains("duplicate JSON object key"));
    }

    #[test]
    fn rejects_positive_and_negative_integers_outside_the_i_json_safe_range() {
        for input in [
            "9007199254740992",
            "9007199254740993",
            "-9007199254740992",
            "-9007199254740993",
            "184467440737095516160000000000000000000000000000000000000000000000000",
        ] {
            let error = parse_strict_json(input).expect_err("unsafe integer must be rejected");
            let message = error.to_string();
            assert!(
                message.contains("outside the I-JSON safe integer range"),
                "unexpected error for {input}: {message}"
            );
            assert!(message.contains("-9007199254740991..=9007199254740991"));
        }
    }

    #[test]
    fn rejects_unsafe_integers_recursively_in_arrays_and_escaped_key_contexts() {
        for input in [
            r#"{"outer":[1,{"number":9007199254740992}]}"#,
            r#"[{"nested":[-9007199254740992]}]"#,
            r#"{"outer":{"\u006eumber":9007199254740993}}"#,
        ] {
            let error = parse_strict_json(input).expect_err("nested unsafe integer must fail");
            assert!(
                error
                    .to_string()
                    .contains("outside the I-JSON safe integer range"),
                "unexpected error for {input}: {error}"
            );
        }
    }

    #[test]
    fn accepts_exact_safe_integer_boundaries_and_numeric_strings() {
        let input = format!(
            r#"{{"bounds":[{MAX_SAFE_INTEGER},-{MAX_SAFE_INTEGER}],"numeric":"9007199254740992","escaped":"\u0039007199254740992","9007199254740993":"key"}}"#
        );
        let actual = parse_strict_json(&input).expect("safe boundaries and strings must parse");
        assert_eq!(actual["bounds"][0].as_i64(), Some(MAX_SAFE_INTEGER));
        assert_eq!(actual["bounds"][1].as_i64(), Some(-MAX_SAFE_INTEGER));
        assert_eq!(actual["numeric"], "9007199254740992");
        assert_eq!(actual["escaped"], "9007199254740992");
        assert_eq!(actual["9007199254740993"], "key");
    }

    #[test]
    fn accepts_normal_floats_and_rfc8785_number_forms() {
        let input = r#"[1.5,-0.125,333333333.33333329,1E30,4.50,2e-3,1e-27]"#;
        let actual = parse_strict_json(input).expect("RFC 8785 number forms must parse");
        assert_eq!(actual.as_array().map(Vec::len), Some(7));
    }

    #[test]
    fn byte_parser_rejects_unsafe_integers_recursively() {
        let error = parse_strict_json_slice(br#"{"items":[9007199254740992]}"#)
            .expect_err("unsafe integer in byte input must be rejected");
        assert!(
            error
                .to_string()
                .contains("outside the I-JSON safe integer range")
        );
    }

    #[test]
    fn value_validator_rejects_programmatically_constructed_unsafe_integers() {
        for value in [
            json!(9_007_199_254_740_992_u64),
            json!(-9_007_199_254_740_992_i64),
            json!({"nested": [9_007_199_254_740_993_u64]}),
        ] {
            let error = validate_i_json_numbers(&value)
                .expect_err("programmatic unsafe integer must be rejected");
            assert!(
                error
                    .to_string()
                    .contains("outside the I-JSON safe integer range")
            );
        }
    }

    #[test]
    fn value_validator_accepts_safe_boundaries_and_finite_floats() {
        let value = json!({
            "bounds": [MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER],
            "floats": [1.5, 1e30, 1e-27],
            "numeric_string": "9007199254740993"
        });
        validate_i_json_numbers(&value).expect("interoperable numbers must be accepted");
    }
}
