//! Canonical JSON serialization per RFC 8785 (JSON Canonicalization Scheme).
//!
//! `jacs-core` is the single source for canonicalization across the
//! workspace. Every signing / verification / hashing path must route here
//! so the bytes produced for signing in one binding match the bytes
//! reconstructed for verification in another. Direct calls to
//! `serde_json_canonicalizer::to_string` elsewhere in `jacs/src/` are a
//! DRY violation — `scripts/forbidden-deps.sh` is not the watchdog for
//! that, but a grep guard in CI (Task 025 cleanup) is the long-term plan.
//!
//! Two entry points exist for historical reasons:
//!
//! - [`canonicalize_json`] — legacy infallible formatting helper (returns
//!   `"null"` on serializer failure). Do not use this entry point at a trust
//!   boundary with a programmatically constructed `Value`, because its return
//!   type cannot report non-I-JSON integral values.
//! - [`canonicalize_json_try`] — fallible, returns
//!   [`crate::CoreError::MalformedDocument`] on failure or an integral value
//!   outside the interoperable ±(2^53-1) range. Signing, verification, and
//!   hashing code must use this entry point.

use crate::CoreError;

/// Deterministically serialize a [`serde_json::Value`] per RFC 8785.
///
/// Returns the canonical UTF-8 string. On the rare serializer failure
/// (only possible for non-JSON-representable inputs that `serde_json`
/// already disallows in `Value`), returns `"null"` to match the
/// long-standing `jacs::protocol::canonicalize_json` contract.
pub fn canonicalize_json(value: &serde_json::Value) -> String {
    serde_json_canonicalizer::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// Trust-boundary variant of [`canonicalize_json`].
///
/// Returns [`CoreError::MalformedDocument`] on serializer failure and rejects
/// programmatically constructed integral values outside the I-JSON safe range
/// before RFC 8785's binary64 serialization can collapse neighboring values.
pub fn canonicalize_json_try(value: &serde_json::Value) -> Result<String, CoreError> {
    crate::strict_json::validate_i_json_numbers(value)?;
    serde_json_canonicalizer::to_string(value)
        .map_err(|e| CoreError::MalformedDocument(format!("canonicalize failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::canonicalize_json_try;
    use crate::strict_json::parse_strict_json;

    /// RFC 8785 section 3.2.2: the official serialization sample locks
    /// ECMAScript number formatting, literal ordering, Unicode preservation,
    /// and the required escaping of control characters, quotes, and slashes.
    #[test]
    fn rfc8785_serialization_sample() {
        let input = r##"{
            "numbers": [333333333.33333329, 1E30, 4.50,
                        2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
            "literals": [null, true, false]
        }"##;
        let expected = r##"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"##;

        let value = parse_strict_json(input).expect("official RFC input must parse");
        assert_eq!(
            canonicalize_json_try(&value).expect("official RFC input must canonicalize"),
            expected
        );
    }

    /// RFC 8785 section 3.2.3: property names are sorted by their raw UTF-16
    /// code units. This differs from both locale collation and Unicode scalar
    /// value ordering for the supplementary-plane emoji in this vector.
    #[test]
    fn rfc8785_property_sorting_sample() {
        let input = r##"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis"
        }"##;
        let expected = r##"{"\r":"Carriage Return","1":"One","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}"##;

        let value = parse_strict_json(input).expect("official RFC input must parse");
        assert_eq!(
            canonicalize_json_try(&value).expect("official RFC input must canonicalize"),
            expected
        );
    }

    #[test]
    fn fallible_canonicalization_rejects_unsafe_integral_values() {
        let unsafe_value = serde_json::json!({"amount": 9_007_199_254_740_993_u64});
        let error = canonicalize_json_try(&unsafe_value)
            .expect_err("unsafe integral values must not be canonicalized for signing");
        assert!(error.to_string().contains("safe integer range"));
    }
}
