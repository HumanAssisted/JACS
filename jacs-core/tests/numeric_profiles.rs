//! Ordinary numeric compatibility regressions, shared by portable signing.

use jacs_core::strict_json::{
    NumericProfile, deserialize_strict_json_with_numeric_profile, parse_strict_json,
    parse_strict_json_slice_with_numeric_profile, parse_strict_json_with_numeric_profile,
};
use jacs_core::{CoreAgent, SigningAlgorithm, canonical::canonicalize_json_try};
use serde_json::Value;

#[test]
fn historical_rfc8785_decimal_signs_and_remains_readable() {
    let payload = parse_strict_json(r#"{"amount":333333333.33333329,"unit":"example"}"#)
        .expect("historical nonintegral decimal remains accepted");
    assert_eq!(
        canonicalize_json_try(&payload).unwrap(),
        r#"{"amount":333333333.3333333,"unit":"example"}"#
    );
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let document = agent.sign_message(&payload).unwrap();
    let retained = serde_json::to_string(&document).unwrap();
    let readback = parse_strict_json(&retained).unwrap();
    assert!(agent.verify(&readback).unwrap().valid);
}

#[test]
fn explicit_exact_decimal_policy_has_no_compatibility_retry() {
    let input = r#"{"amount":333333333.33333329}"#;
    assert!(parse_strict_json(input).is_ok());
    assert!(parse_strict_json_with_numeric_profile(input, NumericProfile::ExactDecimalV1).is_err());
    assert!(
        parse_strict_json_slice_with_numeric_profile(
            input.as_bytes(),
            NumericProfile::ExactDecimalV1
        )
        .is_err()
    );
    assert!(
        deserialize_strict_json_with_numeric_profile::<Value>(
            input,
            NumericProfile::ExactDecimalV1
        )
        .is_err()
    );
}

#[test]
fn integral_spellings_share_the_same_range_in_both_profiles() {
    for profile in [
        NumericProfile::Rfc8785CompatibleV1,
        NumericProfile::ExactDecimalV1,
    ] {
        for input in [
            "9007199254740991",
            "9007199254740991.0",
            "9007199254740991e0",
        ] {
            assert!(parse_strict_json_with_numeric_profile(input, profile).is_ok());
        }
        for input in [
            "9007199254740992",
            "9007199254740992.0",
            "9007199254740992e0",
        ] {
            assert!(
                parse_strict_json_with_numeric_profile(input, profile)
                    .unwrap_err()
                    .to_string()
                    .contains("safe integer range")
            );
        }
    }
}
