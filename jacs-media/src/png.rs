//! PNG iTXt chunk embedding. Keyword `JACS-Signature`, language tag `en`,
//! uncompressed payload, chunk placed just before IEND.
//!
//! Derived from the PNG 1.2 spec (W3C, ISO/IEC 15948:2004) §11.3 iTXt chunk.

use crate::{MAX_PAYLOAD_BYTES_PNG, MediaError, PNG_KEYWORD};

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const IEND_TYPE: &[u8; 4] = b"IEND";
const ITXT_TYPE: &[u8; 4] = b"iTXt";

/// Walk PNG chunks and yield (chunk_type, chunk_body) tuples.
/// Returns Ok(chunks) or Err on structural failure.
fn parse_chunks(bytes: &[u8]) -> Result<Vec<(&[u8], &[u8], &[u8])>, MediaError> {
    // Each entry: (type_bytes, body_bytes, full_chunk_range for rebuild).
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Err(MediaError::Parse(
            "not a PNG (missing signature)".to_string(),
        ));
    }
    let mut pos = PNG_SIGNATURE.len();
    let mut out = Vec::new();
    while pos + 12 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let type_start = pos + 4;
        let type_end = type_start + 4;
        if type_end + len + 4 > bytes.len() {
            return Err(MediaError::Parse("truncated PNG chunk".to_string()));
        }
        let body_start = type_end;
        let body_end = body_start + len;
        let crc_end = body_end + 4;
        let chunk_type = &bytes[type_start..type_end];
        let body = &bytes[body_start..body_end];
        let full = &bytes[pos..crc_end];
        out.push((chunk_type, body, full));
        if chunk_type == IEND_TYPE {
            return Ok(out);
        }
        pos = crc_end;
    }
    Err(MediaError::Parse("PNG without IEND chunk".to_string()))
}

/// Parse an iTXt chunk body into (keyword, text_bytes) pairs, returning the
/// text only when we recognise it as a JACS signature (keyword == JACS-Signature,
/// compression flag 0).
fn parse_itxt_body(body: &[u8]) -> Option<String> {
    // keyword\0compression_flag(1)compression_method(1)language_tag\0translated_keyword\0text
    let keyword_end = body.iter().position(|&b| b == 0)?;
    let keyword = &body[..keyword_end];
    if keyword != PNG_KEYWORD.as_bytes() {
        return None;
    }
    let after_keyword_nul = keyword_end + 1;
    if after_keyword_nul + 2 > body.len() {
        return None;
    }
    let compression_flag = body[after_keyword_nul];
    // We only understand uncompressed iTXt (compression_flag == 0).
    if compression_flag != 0 {
        return None;
    }
    let compression_method_pos = after_keyword_nul + 1;
    let after_cm = compression_method_pos + 1;
    // language_tag
    let lang_end = body[after_cm..].iter().position(|&b| b == 0)? + after_cm;
    // translated_keyword
    let after_lang_nul = lang_end + 1;
    let tk_end = body[after_lang_nul..].iter().position(|&b| b == 0)? + after_lang_nul;
    let text_start = tk_end + 1;
    let text = &body[text_start..];
    std::str::from_utf8(text).ok().map(|s| s.to_string())
}

/// Build an iTXt chunk body for a `JACS-Signature` payload.
fn build_itxt_body(payload: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(PNG_KEYWORD.len() + 4 + 2 + payload.len());
    out.extend_from_slice(PNG_KEYWORD.as_bytes());
    out.push(0); // null terminator for keyword
    out.push(0); // compression flag = 0 (uncompressed)
    out.push(0); // compression method = 0
    out.extend_from_slice(b"en");
    out.push(0); // null terminator for language tag
    out.push(0); // null terminator for translated keyword (empty)
    out.extend_from_slice(payload.as_bytes());
    out
}

/// CRC-32 of PNG chunks. Implements the CRC-32-IEEE polynomial with the PNG
/// reference table. Implemented from the PNG 1.2 spec Annex D to avoid pulling
/// a crc32 crate.
fn png_crc32(type_bytes: &[u8], body: &[u8]) -> u32 {
    // Precompute the table once.
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for n in 0..256 {
            let mut c = n as u32;
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = 0xedb88320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }
            }
            t[n] = c;
        }
        t
    });

    let mut crc: u32 = 0xffffffff;
    for &b in type_bytes.iter().chain(body.iter()) {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffffffff
}

fn build_chunk(type_bytes: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(type_bytes);
    out.extend_from_slice(body);
    let crc = png_crc32(type_bytes, body);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

pub fn embed(
    bytes: &[u8],
    payload: &str,
    robust: bool,
    refuse_overwrite: bool,
) -> Result<Vec<u8>, MediaError> {
    if payload.len() > MAX_PAYLOAD_BYTES_PNG {
        return Err(MediaError::PayloadTooLarge {
            limit: MAX_PAYLOAD_BYTES_PNG,
            actual: payload.len(),
        });
    }

    let chunks = parse_chunks(bytes)?;

    // Check for existing JACS chunks.
    let mut jacs_count = 0;
    for (ty, body, _) in &chunks {
        if ty == ITXT_TYPE && parse_itxt_body(body).is_some() {
            jacs_count += 1;
        }
    }
    if jacs_count > 1 {
        return Err(MediaError::Parse(
            "duplicate JACS-Signature chunk".to_string(),
        ));
    }
    if refuse_overwrite && jacs_count > 0 {
        return Err(MediaError::Parse(
            "input already carries JACS signature".to_string(),
        ));
    }

    // Rebuild output: keep all chunks except existing JACS iTXt, then insert
    // our new iTXt just before IEND.
    let mut out = Vec::with_capacity(bytes.len() + payload.len() + 128);
    out.extend_from_slice(PNG_SIGNATURE);
    let new_chunk = build_chunk(ITXT_TYPE, &build_itxt_body(payload));

    for (ty, body, full) in &chunks {
        if ty == ITXT_TYPE && parse_itxt_body(body).is_some() {
            // Skip existing JACS iTXt.
            continue;
        }
        if ty == IEND_TYPE {
            // Insert our chunk before IEND.
            out.extend_from_slice(&new_chunk);
            out.extend_from_slice(full);
            continue;
        }
        out.extend_from_slice(full);
    }

    if robust {
        out = crate::robust::embed_lsb_png(&out, payload)?;
    }

    Ok(out)
}

pub fn extract(bytes: &[u8], scan_robust: bool) -> Result<Option<String>, MediaError> {
    let chunks = parse_chunks(bytes)?;
    let mut found = Vec::new();
    for (ty, body, _) in &chunks {
        if ty == ITXT_TYPE
            && let Some(text) = parse_itxt_body(body)
        {
            found.push(text);
        }
    }
    if found.len() > 1 {
        return Err(MediaError::Parse(
            "duplicate JACS-Signature chunk".to_string(),
        ));
    }
    if let Some(t) = found.into_iter().next() {
        return Ok(Some(t));
    }
    if scan_robust {
        return crate::robust::extract_lsb_png(bytes);
    }
    Ok(None)
}

/// Return PNG bytes with any `JACS-Signature` iTXt chunk removed. Used by
/// `canonical_hash`. Preserves every other chunk byte-for-byte.
pub fn bytes_without_jacs_chunk(bytes: &[u8]) -> Result<Vec<u8>, MediaError> {
    let chunks = parse_chunks(bytes)?;
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(PNG_SIGNATURE);
    for (ty, body, full) in &chunks {
        if ty == ITXT_TYPE && parse_itxt_body(body).is_some() {
            continue;
        }
        out.extend_from_slice(full);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_png() -> Vec<u8> {
        // 1x1 transparent PNG generated by the `image` crate.
        let img = image::RgbaImage::from_pixel(1, 1, image::Rgba([0, 0, 0, 0]));
        let mut buf = Vec::new();
        let mut cur = std::io::Cursor::new(&mut buf);
        img.write_to(&mut cur, image::ImageFormat::Png).unwrap();
        buf
    }

    #[test]
    fn png_itxt_roundtrip_1x1() {
        let input = minimal_png();
        let payload = "hello-json-signature";
        let signed = embed(&input, payload, false, false).expect("embed");
        let extracted = extract(&signed, false)
            .expect("extract")
            .expect("payload present");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn png_replaces_existing_jacs_chunk() {
        let input = minimal_png();
        let first = embed(&input, "payload-v1", false, false).expect("embed1");
        let second = embed(&first, "payload-v2", false, false).expect("embed2");
        let extracted = extract(&second, false).expect("ok").expect("present");
        assert_eq!(extracted, "payload-v2");
    }

    #[test]
    fn png_refuse_overwrite_on_signed_input() {
        let input = minimal_png();
        let first = embed(&input, "v1", false, false).expect("embed1");
        let err = embed(&first, "v2", false, true).unwrap_err();
        match err {
            MediaError::Parse(msg) => assert!(msg.contains("already carries")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn png_extract_from_no_chunk_returns_none() {
        let input = minimal_png();
        assert_eq!(extract(&input, false).unwrap(), None);
    }

    #[test]
    fn png_canonical_hash_excludes_our_chunk() {
        let input = minimal_png();
        let h_before = crate::canonical_hash(&input).unwrap();
        let signed = embed(&input, "some-payload", false, false).expect("embed");
        let h_after = crate::canonical_hash(&signed).unwrap();
        assert_eq!(
            h_before, h_after,
            "canonical_hash must ignore the JACS chunk"
        );
    }

    #[test]
    fn png_corrupted_returns_error() {
        let mut bytes = minimal_png();
        bytes.truncate(30); // leaves only IHDR fragment
        assert!(extract(&bytes, false).is_err());
    }

    #[test]
    fn png_payload_too_large() {
        let input = minimal_png();
        let huge = "A".repeat(MAX_PAYLOAD_BYTES_PNG + 1);
        let err = embed(&input, &huge, false, false).unwrap_err();
        match err {
            MediaError::PayloadTooLarge { limit, actual } => {
                assert_eq!(limit, MAX_PAYLOAD_BYTES_PNG);
                assert_eq!(actual, MAX_PAYLOAD_BYTES_PNG + 1);
            }
            other => panic!("{other:?}"),
        }
    }

    /// Issue 006 / PRD §4.2.2: boundary triplet (max-1, max, max+1).
    /// `max+1` is the existing `png_payload_too_large` test.
    #[test]
    fn png_payload_at_max_minus_one_embeds_cleanly() {
        let input = minimal_png();
        let payload = "B".repeat(MAX_PAYLOAD_BYTES_PNG - 1);
        let signed = embed(&input, &payload, false, false).expect("embed");
        let extracted = extract(&signed, false)
            .expect("extract ok")
            .expect("payload present");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn png_payload_at_max_embeds_cleanly() {
        let input = minimal_png();
        let payload = "B".repeat(MAX_PAYLOAD_BYTES_PNG);
        let signed = embed(&input, &payload, false, false).expect("embed");
        let extracted = extract(&signed, false)
            .expect("extract ok")
            .expect("payload present");
        assert_eq!(extracted, payload);
    }

    /// Issue 006: duplicate-chunk rejection MUST surface as `MediaError::Parse`.
    /// Constructs a PNG with two iTXt JACS-Signature chunks by hand.
    #[test]
    fn duplicate_jacs_chunk_png_returns_malformed() {
        let signed = embed(&minimal_png(), "first-payload", false, false).expect("embed");
        // Inject a second iTXt JACS-Signature chunk before IEND. We splice in
        // a fresh chunk built via build_itxt_body / build_chunk.
        let extra_chunk = build_chunk(ITXT_TYPE, &build_itxt_body("second-payload"));
        let iend_pos = signed
            .windows(8)
            .rposition(|w| {
                // `IEND` chunk header is 4 bytes length + b"IEND" — length is 0
                // for IEND, so we look for `\x00\x00\x00\x00IEND`.
                w == [0, 0, 0, 0, b'I', b'E', b'N', b'D']
            })
            .expect("IEND present");
        let mut bad = Vec::with_capacity(signed.len() + extra_chunk.len());
        bad.extend_from_slice(&signed[..iend_pos]);
        bad.extend_from_slice(&extra_chunk);
        bad.extend_from_slice(&signed[iend_pos..]);

        // embed must refuse to overwrite when two existing chunks are present
        // (the duplicate-chunk guard runs before any other check).
        let embed_err = embed(&bad, "third", false, false).unwrap_err();
        assert!(
            matches!(embed_err, MediaError::Parse(ref msg) if msg.contains("duplicate")),
            "expected Parse(duplicate ...) on embed; got {:?}",
            embed_err
        );

        // extract must also refuse on duplicate chunks (downstream verifier
        // guard).
        let extract_err = extract(&bad, false).unwrap_err();
        assert!(
            matches!(extract_err, MediaError::Parse(ref msg) if msg.contains("duplicate")),
            "expected Parse(duplicate ...) on extract; got {:?}",
            extract_err
        );
    }
}
