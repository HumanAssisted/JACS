//! Time utilities for JACS.
//!
//! This module provides centralized timestamp handling functions used throughout
//! the crate for consistent time formatting, parsing, and validation.

use crate::error::JacsError;
use chrono::{DateTime, Utc};

/// Maximum clock drift tolerance for signature timestamps (in seconds).
/// Signatures dated more than this many seconds in the future are rejected.
pub const MAX_FUTURE_TIMESTAMP_SECONDS: i64 = 300;

/// Default maximum signature age (in seconds).
/// Default: 0 (no expiration). JACS documents are designed to be idempotent and eternal.
/// Set `JACS_MAX_SIGNATURE_AGE_SECONDS` to a positive value to enable expiration
/// (e.g., 7776000 for 90 days).
pub const MAX_SIGNATURE_AGE_SECONDS: i64 = 0;

/// Returns the current UTC timestamp in RFC 3339 format.
///
/// This is the standard format used throughout JACS for timestamps.
///
/// # Example
///
/// ```rust
/// use jacs::time_utils::now_rfc3339;
///
/// let timestamp = now_rfc3339();
/// // Example: "2025-01-15T14:30:00.123456789+00:00"
/// ```
#[inline]
#[must_use]
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// Returns the current UTC timestamp.
///
/// Use this when you need the `DateTime<Utc>` value directly for arithmetic
/// or other operations before formatting.
#[inline]
#[must_use]
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

/// Returns the current Unix timestamp in seconds.
///
/// Useful for timestamp comparisons where RFC 3339 parsing overhead is not needed.
#[inline]
#[must_use]
pub fn now_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// Parses an RFC 3339 timestamp string into a `DateTime<Utc>`.
///
/// # Arguments
///
/// * `s` - The RFC 3339 formatted timestamp string
///
/// # Returns
///
/// The parsed `DateTime<Utc>` or a `JacsError` if parsing fails.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::time_utils::parse_rfc3339;
///
/// let dt = parse_rfc3339("2025-01-15T14:30:00+00:00")?;
/// ```
pub fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, JacsError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            JacsError::ValidationError(format!(
                "Invalid RFC 3339 timestamp '{}': {}",
                s, e
            ))
        })
}

/// Parses an RFC 3339 timestamp string and returns the Unix timestamp.
///
/// # Arguments
///
/// * `s` - The RFC 3339 formatted timestamp string
///
/// # Returns
///
/// The Unix timestamp (seconds since epoch) or a `JacsError` if parsing fails.
pub fn parse_rfc3339_to_timestamp(s: &str) -> Result<i64, JacsError> {
    parse_rfc3339(s).map(|dt| dt.timestamp())
}

/// Validates that a timestamp is not too far in the future.
///
/// This function checks that the given timestamp is not more than
/// `MAX_FUTURE_TIMESTAMP_SECONDS` in the future, allowing for reasonable
/// clock drift between systems.
///
/// # Arguments
///
/// * `timestamp_str` - The RFC 3339 formatted timestamp string
///
/// # Returns
///
/// `Ok(())` if the timestamp is valid, or a `JacsError` describing the issue.
pub fn validate_timestamp_not_future(timestamp_str: &str) -> Result<(), JacsError> {
    validate_timestamp_not_future_with_skew(timestamp_str, MAX_FUTURE_TIMESTAMP_SECONDS)
}

/// Validates that a timestamp is not too far in the future with custom skew tolerance.
///
/// # Arguments
///
/// * `timestamp_str` - The RFC 3339 formatted timestamp string
/// * `max_skew_seconds` - Maximum allowed clock skew in seconds
///
/// # Returns
///
/// `Ok(())` if the timestamp is valid, or a `JacsError` describing the issue.
pub fn validate_timestamp_not_future_with_skew(
    timestamp_str: &str,
    max_skew_seconds: i64,
) -> Result<(), JacsError> {
    let timestamp = parse_rfc3339(timestamp_str)?;
    let now = Utc::now();
    let future_limit = now + chrono::Duration::seconds(max_skew_seconds);

    if timestamp > future_limit {
        return Err(JacsError::ValidationError(format!(
            "Timestamp '{}' is too far in the future (max {} seconds allowed). \
            This may indicate clock skew or a forged timestamp.",
            timestamp_str, max_skew_seconds
        )));
    }

    Ok(())
}

/// Validates that a timestamp is not too old.
///
/// # Arguments
///
/// * `timestamp_str` - The RFC 3339 formatted timestamp string
/// * `max_age_seconds` - Maximum allowed age in seconds
///
/// # Returns
///
/// `Ok(())` if the timestamp is valid, or a `JacsError` describing the issue.
pub fn validate_timestamp_not_expired(
    timestamp_str: &str,
    max_age_seconds: i64,
) -> Result<(), JacsError> {
    if max_age_seconds <= 0 {
        // Expiration checking disabled
        return Ok(());
    }

    let timestamp = parse_rfc3339(timestamp_str)?;
    let now = Utc::now();
    let expiry_limit = now - chrono::Duration::seconds(max_age_seconds);

    if timestamp < expiry_limit {
        return Err(JacsError::ValidationError(format!(
            "Timestamp '{}' is too old (max age {} seconds). \
            The document may need to be re-signed.",
            timestamp_str, max_age_seconds
        )));
    }

    Ok(())
}

/// Returns the effective maximum signature age in seconds.
///
/// Checks `JACS_MAX_SIGNATURE_AGE_SECONDS` environment variable first,
/// falls back to the compiled-in default (0 = no expiration).
/// Set to a positive value to enable expiration (e.g., 7776000 for 90 days).
pub fn max_signature_age() -> i64 {
    std::env::var("JACS_MAX_SIGNATURE_AGE_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_SIGNATURE_AGE_SECONDS)
}

/// Validates a signature timestamp.
///
/// This combines both future and expiration checks.
///
/// # Arguments
///
/// * `timestamp_str` - RFC 3339 formatted timestamp string
///
/// # Returns
///
/// `Ok(())` if the timestamp is valid, or a `JacsError` describing the issue.
///
/// # Validation Rules
///
/// 1. The timestamp must be a valid RFC 3339 / ISO 8601 format
/// 2. The timestamp must not be more than `MAX_FUTURE_TIMESTAMP_SECONDS` in the future
///    (allows for small clock drift between systems)
/// 3. If signature age limit > 0 (default: disabled), the timestamp must not be older than that.
///    Set `JACS_MAX_SIGNATURE_AGE_SECONDS` to a positive value to enable (e.g., 7776000 for 90 days).
pub fn validate_signature_timestamp(timestamp_str: &str) -> Result<(), JacsError> {
    // Parse the timestamp (validates format)
    let signature_time = parse_rfc3339(timestamp_str).map_err(|_| {
        JacsError::SignatureVerificationFailed {
            reason: format!("Invalid signature timestamp format '{}'", timestamp_str),
        }
    })?;

    let now = Utc::now();

    // Check for future timestamps (with clock drift tolerance)
    let future_limit = now + chrono::Duration::seconds(MAX_FUTURE_TIMESTAMP_SECONDS);
    if signature_time > future_limit {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "Signature timestamp {} is too far in the future (max {} seconds allowed). \
                This may indicate clock skew or a forged signature.",
                timestamp_str, MAX_FUTURE_TIMESTAMP_SECONDS
            ),
        });
    }

    // Check for expired signatures (if expiration is enabled)
    let age_limit = max_signature_age();
    if age_limit > 0 {
        let expiry_limit = now - chrono::Duration::seconds(age_limit);
        if signature_time < expiry_limit {
            return Err(JacsError::SignatureVerificationFailed {
                reason: format!(
                    "Signature timestamp {} is too old (max age {} seconds / {} days). \
                    The agent document may need to be re-signed. \
                    Set JACS_MAX_SIGNATURE_AGE_SECONDS=0 to disable expiration.",
                    timestamp_str, age_limit, age_limit / 86400
                ),
            });
        }
    }

    Ok(())
}

/// Generates a backup filename suffix based on current timestamp.
///
/// # Returns
///
/// A string like "backup-2025-01-15-14-30" suitable for backup filenames.
#[inline]
#[must_use]
pub fn backup_timestamp_suffix() -> String {
    Utc::now().format("backup-%Y-%m-%d-%H-%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_rfc3339_format() {
        let timestamp = now_rfc3339();
        // Should be parseable as RFC 3339
        assert!(DateTime::parse_from_rfc3339(&timestamp).is_ok());
    }

    #[test]
    fn test_parse_rfc3339_valid() {
        let result = parse_rfc3339("2025-01-15T14:30:00+00:00");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_rfc3339_invalid() {
        let result = parse_rfc3339("not a timestamp");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid RFC 3339 timestamp"));
    }

    #[test]
    fn test_validate_timestamp_not_future_current() {
        let now = now_rfc3339();
        let result = validate_timestamp_not_future(&now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timestamp_not_future_past() {
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let result = validate_timestamp_not_future(&past);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timestamp_not_future_slight_future() {
        // Within tolerance
        let slight_future = (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
        let result = validate_timestamp_not_future(&slight_future);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timestamp_not_future_far_future() {
        // Beyond tolerance
        let far_future = (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        let result = validate_timestamp_not_future(&far_future);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_signature_timestamp_valid() {
        let now = now_rfc3339();
        let result = validate_signature_timestamp(&now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signature_timestamp_far_future() {
        let far_future = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let result = validate_signature_timestamp(&far_future);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too far in the future"));
    }

    #[test]
    fn test_validate_timestamp_not_expired() {
        let recent = now_rfc3339();
        let result = validate_timestamp_not_expired(&recent, 3600);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timestamp_expired() {
        let old = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let result = validate_timestamp_not_expired(&old, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_timestamp_expiration_disabled() {
        let old = (Utc::now() - chrono::Duration::days(365)).to_rfc3339();
        // With max_age_seconds = 0, expiration is disabled
        let result = validate_timestamp_not_expired(&old, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_timestamp_suffix_format() {
        let suffix = backup_timestamp_suffix();
        assert!(suffix.starts_with("backup-"));
        // Should have format like "backup-2025-01-15-14-30"
        assert_eq!(suffix.len(), 23); // "backup-YYYY-MM-DD-HH-MM"
    }

    #[test]
    fn test_parse_rfc3339_to_timestamp() {
        let result = parse_rfc3339_to_timestamp("2025-01-15T00:00:00+00:00");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert!(ts > 0);
    }
}
