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
//! Existing entry points retain RFC 8785 binary64 rounding for nonintegral
//! decimals. Exact decimal preservation is a separately selected profile, not
//! an implicit change to readable legacy documents.

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

/// Default profile: RFC 8785 decimal conversion plus exact safe-integer checks.
pub const NUMERIC_PROFILE: &str = "jacs-json-rfc8785-binary64-v1";
/// Opt-in profile requiring the input decimal value to survive canonicalization.
pub const EXACT_DECIMAL_NUMERIC_PROFILE: &str = "jacs-json-safe-binary64-v1";

/// Closed numeric policy selected before decoding any signed input.
///
/// Both profiles reject duplicate members and unsafe mathematical integers,
/// including decimal/exponent spellings. A denial in `ExactDecimalV1` must not
/// be retried under the compatibility profile for that verification decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum NumericProfile {
    #[default]
    #[serde(rename = "jacs-json-rfc8785-binary64-v1")]
    Rfc8785CompatibleV1,
    #[serde(rename = "jacs-json-safe-binary64-v1")]
    ExactDecimalV1,
}

impl NumericProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfc8785CompatibleV1 => NUMERIC_PROFILE,
            Self::ExactDecimalV1 => EXACT_DECIMAL_NUMERIC_PROFILE,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExactDecimal {
    negative: bool,
    digits: Vec<u8>,
    exponent: i64,
}

impl ExactDecimal {
    fn parse(token: &[u8], profile: NumericProfile) -> Result<Self, CoreError> {
        let profile_name = profile.as_str();
        let invalid = || CoreError::MalformedDocument(format!("invalid number for {profile_name}"));
        if token.is_empty() {
            return Err(invalid());
        }
        if profile == NumericProfile::ExactDecimalV1 && token.len() > 128 {
            return Err(CoreError::MalformedDocument(format!(
                "{profile_name} limits number tokens to 128 bytes"
            )));
        }
        let negative = token[0] == b'-';
        let mut index = usize::from(negative);
        let mut digits = Vec::new();
        match token.get(index) {
            Some(b'0') => {
                digits.push(b'0');
                index += 1;
            }
            Some(b'1'..=b'9') => {
                while token.get(index).is_some_and(u8::is_ascii_digit) {
                    digits.push(token[index]);
                    index += 1;
                }
            }
            _ => return Err(invalid()),
        }
        let mut fraction_digits = 0_i64;
        if token.get(index) == Some(&b'.') {
            index += 1;
            while token.get(index).is_some_and(u8::is_ascii_digit) {
                digits.push(token[index]);
                fraction_digits += 1;
                index += 1;
            }
            if fraction_digits == 0 {
                return Err(invalid());
            }
        }
        if profile == NumericProfile::ExactDecimalV1 && digits.len() > 100 {
            return Err(CoreError::MalformedDocument(format!(
                "{profile_name} limits coefficients to 100 digits"
            )));
        }
        let mut exponent = 0_i64;
        // Compatibility retains historical token lengths without integer
        // overflow or exponent-sized allocation. An exponent larger than the
        // entire coefficient plus 17 already settles the safe-integer test;
        // saturating there preserves that classification in either direction.
        let exponent_limit = i64::try_from(token.len())
            .unwrap_or(i64::MAX - 17)
            .saturating_add(17);
        if matches!(token.get(index), Some(b'e' | b'E')) {
            index += 1;
            let exponent_negative = token.get(index) == Some(&b'-');
            if matches!(token.get(index), Some(b'+' | b'-')) {
                index += 1;
            }
            let start = index;
            while token.get(index).is_some_and(u8::is_ascii_digit) {
                exponent = exponent
                    .saturating_mul(10)
                    .saturating_add(i64::from(token[index] - b'0'));
                if profile == NumericProfile::ExactDecimalV1 && exponent > 10_000 {
                    return Err(CoreError::MalformedDocument(format!(
                        "{profile_name} limits exponent magnitude to 10000"
                    )));
                }
                if profile == NumericProfile::Rfc8785CompatibleV1 {
                    exponent = exponent.min(exponent_limit);
                }
                index += 1;
            }
            if start == index {
                return Err(invalid());
            }
            if exponent_negative {
                exponent = -exponent;
            }
        }
        if index != token.len() {
            return Err(invalid());
        }
        exponent -= fraction_digits;
        let Some(first_nonzero) = digits.iter().position(|digit| *digit != b'0') else {
            return Ok(Self {
                negative: false,
                digits: vec![b'0'],
                exponent: 0,
            });
        };
        digits.drain(..first_nonzero);
        while digits.last() == Some(&b'0') {
            digits.pop();
            exponent += 1;
        }
        Ok(Self {
            negative,
            digits,
            exponent,
        })
    }

    fn is_unsafe_integer(&self) -> bool {
        const MAX_SAFE_DIGITS: &[u8] = b"9007199254740991";
        if self.exponent < 0 {
            return false;
        }
        let length = self.digits.len().saturating_add(self.exponent as usize);
        length > MAX_SAFE_DIGITS.len()
            || (length == MAX_SAFE_DIGITS.len()
                && self
                    .digits
                    .iter()
                    .copied()
                    .chain(std::iter::repeat(b'0'))
                    .take(length)
                    .cmp(MAX_SAFE_DIGITS.iter().copied())
                    .is_gt())
    }
}

fn validate_number_token(token: &[u8], profile: NumericProfile) -> Result<(), CoreError> {
    let decimal = ExactDecimal::parse(token, profile)?;
    if decimal.is_unsafe_integer() {
        return Err(CoreError::MalformedDocument(unsafe_integer_message(
            String::from_utf8_lossy(token),
        )));
    }
    let text = std::str::from_utf8(token)
        .map_err(|error| CoreError::MalformedDocument(error.to_string()))?;
    let binary: f64 = text.parse().map_err(|error: std::num::ParseFloatError| {
        CoreError::MalformedDocument(error.to_string())
    })?;
    if !binary.is_finite() {
        return Err(CoreError::MalformedDocument(
            "non-finite number is not valid JSON".into(),
        ));
    }
    if profile == NumericProfile::ExactDecimalV1 {
        let canonical = serde_json_canonicalizer::to_string(&binary)
            .map_err(|error| CoreError::MalformedDocument(error.to_string()))?;
        if decimal != ExactDecimal::parse(canonical.as_bytes(), profile)? {
            return Err(CoreError::MalformedDocument(format!(
                "number changes decimal value under {}; use a string for exact quantities",
                profile.as_str()
            )));
        }
    }
    Ok(())
}

fn validate_number_tokens(input: &[u8], profile: NumericProfile) -> Result<(), CoreError> {
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
                validate_number_token(&input[start..index], profile)?;
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
            } else if number.is_f64() {
                validate_number_token(
                    number.to_string().as_bytes(),
                    NumericProfile::Rfc8785CompatibleV1,
                )?;
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
/// Nonintegral decimals retain RFC 8785 binary64 rounding. Use
/// [`parse_strict_json_with_numeric_profile`] to opt into exact decimals.
pub fn parse_strict_json(input: &str) -> Result<Value, CoreError> {
    parse_strict_json_with_numeric_profile(input, NumericProfile::Rfc8785CompatibleV1)
}

/// Decode under an explicit numeric profile, without fallback after denial.
/// Profile selection belongs to the protocol/verification policy; it is not
/// inferred from a failure or an unverified field inside the input.
pub fn parse_strict_json_with_numeric_profile(
    input: &str,
    profile: NumericProfile,
) -> Result<Value, CoreError> {
    parse_strict_json_slice_with_numeric_profile(input.as_bytes(), profile)
}

/// Decode JSON bytes while rejecting duplicate object keys and integral values
/// outside the I-JSON safe range at every nesting level. Invalid UTF-8 is
/// reported as a malformed document.
pub fn parse_strict_json_slice(input: &[u8]) -> Result<Value, CoreError> {
    parse_strict_json_slice_with_numeric_profile(input, NumericProfile::Rfc8785CompatibleV1)
}

/// Byte counterpart of [`parse_strict_json_with_numeric_profile`].
pub fn parse_strict_json_slice_with_numeric_profile(
    input: &[u8],
    profile: NumericProfile,
) -> Result<Value, CoreError> {
    validate_number_tokens(input, profile)?;
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
    deserialize_strict_json_with_numeric_profile(input, NumericProfile::Rfc8785CompatibleV1)
}

/// Typed decoding with an explicitly selected numeric profile.
pub fn deserialize_strict_json_with_numeric_profile<T: DeserializeOwned>(
    input: &str,
    profile: NumericProfile,
) -> Result<T, CoreError> {
    let value = parse_strict_json_with_numeric_profile(input, profile)?;
    serde_json::from_value(value).map_err(|error| CoreError::MalformedDocument(error.to_string()))
}

/// Decode JSON bytes into a typed value after enforcing the same duplicate-key
/// policy as [`parse_strict_json_slice`].
pub fn deserialize_strict_json_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, CoreError> {
    deserialize_strict_json_slice_with_numeric_profile(input, NumericProfile::Rfc8785CompatibleV1)
}

/// Typed byte decoding with an explicitly selected numeric profile.
pub fn deserialize_strict_json_slice_with_numeric_profile<T: DeserializeOwned>(
    input: &[u8],
    profile: NumericProfile,
) -> Result<T, CoreError> {
    let value = parse_strict_json_slice_with_numeric_profile(input, profile)?;
    serde_json::from_value(value).map_err(|error| CoreError::MalformedDocument(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        NumericProfile, parse_strict_json, parse_strict_json_slice,
        parse_strict_json_slice_with_numeric_profile, parse_strict_json_with_numeric_profile,
        validate_i_json_numbers,
    };
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
    fn compatibility_preserves_historical_rfc8785_decimal_forms() {
        let input =
            r#"[333333333.33333329,1.0000000000000001,1.5,-0.125,0.1,1e-30,4.50,2e-3,1e-27]"#;
        let actual = parse_strict_json(input).expect("RFC 8785 number forms must parse");
        assert_eq!(actual, parse_strict_json_slice(input.as_bytes()).unwrap());
        assert_eq!(
            crate::canonical::canonicalize_json_try(&actual).unwrap(),
            "[333333333.3333333,1,1.5,-0.125,0.1,1e-30,4.5,0.002,1e-27]"
        );
        assert_eq!(
            NumericProfile::default(),
            NumericProfile::Rfc8785CompatibleV1
        );
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
            "floats": [1.5, 1e-30, 1e-27],
            "numeric_string": "9007199254740993"
        });
        validate_i_json_numbers(&value).expect("interoperable numbers must be accepted");
    }

    #[test]
    fn numeric_profile_checks_exact_integral_decimal_and_exponent_forms() {
        for suffix in ["", ".0", "e0", ".00E+0"] {
            for sign in ["", "-"] {
                let boundary = format!("{sign}{MAX_SAFE_INTEGER}{suffix}");
                let outside = format!("{sign}{}{suffix}", MAX_SAFE_INTEGER + 1);
                for profile in [
                    NumericProfile::Rfc8785CompatibleV1,
                    NumericProfile::ExactDecimalV1,
                ] {
                    parse_strict_json_with_numeric_profile(&boundary, profile)
                        .expect("safe mathematical boundary is accepted");
                    assert!(
                        parse_strict_json_with_numeric_profile(&outside, profile)
                            .unwrap_err()
                            .to_string()
                            .contains("safe integer range")
                    );
                    assert!(
                        parse_strict_json_slice_with_numeric_profile(outside.as_bytes(), profile)
                            .is_err()
                    );
                }
            }
        }
        for number in ["1e16", "100000000000000000e-1"] {
            assert!(
                parse_strict_json(number).is_err(),
                "unsafe integer: {number}"
            );
        }
        assert!(validate_i_json_numbers(&json!(1e30)).is_err());
    }

    #[test]
    fn exact_decimal_profile_enforces_bounded_tokens_and_normalizes_exact_decimals() {
        for number in ["0", "-0.0", "0e10000", "0e-10000", "1.2300e-2", "10e-31"] {
            parse_strict_json_with_numeric_profile(number, NumericProfile::ExactDecimalV1)
                .expect("exact decimal normalization is accepted");
        }
        for number in [
            "0e10001".to_string(),
            format!("0.{}", "0".repeat(100)),
            format!("0e{}", "0".repeat(127)),
        ] {
            assert!(
                parse_strict_json_with_numeric_profile(&number, NumericProfile::ExactDecimalV1)
                    .is_err(),
                "over-limit token must fail"
            );
        }
    }

    #[test]
    fn exact_decimal_profile_is_explicit_and_never_falls_back() {
        for input in ["333333333.33333329", "1.0000000000000001", "1e-999"] {
            parse_strict_json(input).expect("historical binary64 conversion remains available");
            let error =
                parse_strict_json_with_numeric_profile(input, NumericProfile::ExactDecimalV1)
                    .expect_err("exact decimal profile must retain its refusal");
            assert!(error.to_string().contains("number changes decimal value"));
            assert!(
                parse_strict_json_slice_with_numeric_profile(
                    input.as_bytes(),
                    NumericProfile::ExactDecimalV1
                )
                .is_err()
            );
        }
        let long_fraction = format!("0.1{}", "0".repeat(160));
        parse_strict_json(&long_fraction)
            .expect("legacy decimal spelling is not given new token limits");
        assert!(
            parse_strict_json_with_numeric_profile(&long_fraction, NumericProfile::ExactDecimalV1)
                .is_err()
        );
        for profile in [
            NumericProfile::Rfc8785CompatibleV1,
            NumericProfile::ExactDecimalV1,
        ] {
            assert!(
                parse_strict_json_with_numeric_profile(r#"{"amount":1,"amount":2}"#, profile)
                    .is_err()
            );
        }
        assert_eq!(
            serde_json::to_value(NumericProfile::Rfc8785CompatibleV1).unwrap(),
            "jacs-json-rfc8785-binary64-v1"
        );
        assert_eq!(
            serde_json::to_value(NumericProfile::ExactDecimalV1).unwrap(),
            "jacs-json-safe-binary64-v1"
        );
        assert!(
            serde_json::from_value::<NumericProfile>(json!("unknown-numeric-profile")).is_err()
        );
    }
}
