//! Format detection via magic bytes.
//!
//! - PNG: `89 50 4E 47 0D 0A 1A 0A` (8 bytes)
//! - JPEG: `FF D8 FF` (3 bytes)
//! - WebP: RIFF container — `52 49 46 46 ?? ?? ?? ?? 57 45 42 50` (12 bytes)

use crate::MediaError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFormat {
    Png,
    Jpeg,
    WebP,
}

/// Detect the media format from magic bytes. Returns `UnsupportedFormat` for
/// unknown inputs (including empty and truncated buffers — never panics on
/// short inputs). Issue 004: ZIP / archive containers receive a hint
/// directing the caller to `sign_file --embed`, which is the documented
/// PRD §4.2.2 fallback for non-image binaries.
pub fn detect_format(bytes: &[u8]) -> Result<MediaFormat, MediaError> {
    if bytes.len() >= 8 && &bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        return Ok(MediaFormat::Png);
    }
    if bytes.len() >= 3 && &bytes[..3] == b"\xff\xd8\xff" {
        return Ok(MediaFormat::Jpeg);
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Ok(MediaFormat::WebP);
    }
    // ZIP local-file-header magic ("PK\x03\x04"). Surface a friendly hint —
    // archives are not in scope for `jacs-media` (PRD §4.2.2 says non-image
    // binaries use the existing detached-signature path).
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        return Err(MediaError::Unsupported(
            "ZIP archives are not supported by jacs-media; use \
             `jacs sign-file <archive>.zip --embed` to produce a detached \
             signature instead"
                .to_string(),
        ));
    }
    Err(MediaError::UnsupportedFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_png_magic() {
        let bytes = b"\x89PNG\r\n\x1a\n_rest";
        assert_eq!(detect_format(bytes).unwrap(), MediaFormat::Png);
    }

    #[test]
    fn detect_jpeg_magic() {
        let bytes = b"\xff\xd8\xff_rest";
        assert_eq!(detect_format(bytes).unwrap(), MediaFormat::Jpeg);
    }

    #[test]
    fn detect_webp_magic() {
        let bytes = b"RIFF\x00\x00\x00\x00WEBPrest";
        assert_eq!(detect_format(bytes).unwrap(), MediaFormat::WebP);
    }

    #[test]
    fn detect_unknown_returns_error() {
        assert!(detect_format(b"hello world").is_err());
    }

    #[test]
    fn detect_empty_input_returns_error() {
        assert!(detect_format(&[]).is_err());
    }

    #[test]
    fn detect_truncated_magic_returns_error() {
        // 1 byte of a PNG magic — must not panic or succeed.
        assert!(detect_format(&[0x89]).is_err());
        // Truncated JPEG.
        assert!(detect_format(&[0xff, 0xd8]).is_err());
        // Truncated WebP (RIFF but no WEBP).
        assert!(detect_format(b"RIFF\x00\x00\x00\x00XXXX").is_err());
    }

    /// Issue 004: ZIP archives receive a friendly directive to the existing
    /// `sign_file --embed` path, not the generic `UnsupportedFormat` enum.
    #[test]
    fn detect_zip_returns_friendly_directive() {
        let bytes = b"PK\x03\x04rest_of_zip";
        match detect_format(bytes) {
            Err(MediaError::Unsupported(msg)) => {
                assert!(
                    msg.contains("sign-file"),
                    "ZIP error must direct to sign-file --embed; got: {msg}"
                );
                assert!(
                    msg.contains("--embed"),
                    "ZIP error must mention --embed; got: {msg}"
                );
            }
            other => panic!("expected MediaError::Unsupported for ZIP, got: {other:?}"),
        }
    }
}
