//! UTC timestamp spelling and validation shared by signed JACS documents.
use std::borrow::Cow;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(crate) fn now_rfc3339() -> String {
    format_utc(OffsetDateTime::now_utc(), "+00:00")
}

/// The signed metadata uses an explicit UTC offset. Observations and jacs-time-v1
/// use Z. Both retain the historical millisecond, microsecond or nanosecond width.
pub(crate) fn format_utc(value: OffsetDateTime, suffix: &str) -> String {
    let utc = value.to_offset(time::UtcOffset::UTC);
    let nanos = utc.nanosecond();
    let fraction = if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!(
        "{}T{:02}:{:02}:{:02}{fraction}{suffix}",
        utc.date(),
        utc.hour(),
        utc.minute(),
        utc.second(),
    )
}

pub(crate) fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, &'static str> {
    // Signed documents historically accepted a space or T in either case.
    // time's RFC3339 parser also accepts other bytes as the separator.
    if !matches!(value.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
        return Err("invalid RFC3339 date/time separator");
    }
    let mut value = Cow::Borrowed(value);
    // Preserve the UTC second of historical leap-second labels. POSIX counts
    // a leap second as the preceding second; the original signed text is retained.
    if value.as_bytes().get(17..19) == Some(b"60") {
        value.to_mut().replace_range(17..19, "59");
    }
    // The historical parser permitted a Unicode minus sign in a numeric offset.
    if let Some(start) = value.len().checked_sub("−00:00".len())
        && start >= 19
        && value.get(start..).is_some_and(|zone| zone.starts_with('−'))
    {
        value
            .to_mut()
            .replace_range(start..start + '−'.len_utf8(), "-");
    }
    OffsetDateTime::parse(value.as_ref(), &Rfc3339).map_err(|_| "invalid RFC3339 timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_timestamps_preserve_fraction_width_and_utc_offset() {
        for (nanos, fraction) in [
            (0, ""),
            (100_000_000, ".100"),
            (123_450_000, ".123450"),
            (123_456_780, ".123456780"),
        ] {
            let date = OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap();
            assert_eq!(
                format_utc(date, "+00:00"),
                format!("1970-01-01T00:00:00{fraction}+00:00")
            );
        }
    }

    #[test]
    fn archived_timestamp_spellings_identify_the_original_unix_second() {
        for value in [
            "1970-01-01T00:00:59Z",
            "1970-01-01t00:00:60.12345678901z",
            "1969-12-31 23:00:59−01:00",
            "1970-01-01T23:59:59+23:59",
        ] {
            assert_eq!(parse_rfc3339(value).unwrap().unix_timestamp(), 59);
        }
        for invalid in [
            "1970-01-01X00:00:00Z",
            "1970-01-01T00:00:00+24:00",
            "2026-02-29T00:00:00Z",
            "1970-01-01T00:00:00.9Zmore",
        ] {
            assert!(parse_rfc3339(invalid).is_err());
        }
    }
}
