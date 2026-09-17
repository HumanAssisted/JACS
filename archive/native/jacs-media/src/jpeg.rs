//! JPEG APP11 segment embedding. Identifier `JACS\0`, length-prefixed payload.
//!
//! Derived from JFIF / Adobe APP11 documentation (JPEG XT spec, 2015).
//! We walk markers directly — no reliance on `img-parts` encoder path, so this
//! stays dependency-light and the behaviour is predictable.

use crate::{JPEG_IDENTIFIER, MAX_PAYLOAD_BYTES_JPEG, MediaError};

const SOI: [u8; 2] = [0xff, 0xd8];
const APP11: u8 = 0xeb;
const SOS: u8 = 0xda;

/// A JPEG segment parsed from the stream.
struct Segment {
    /// Full segment bytes including the `ff xx` marker + length field + body.
    /// For stand-alone markers (SOI/EOI/RST) only the 2-byte marker.
    bytes: Vec<u8>,
    /// The single marker byte (`xx` in `ff xx`).
    marker: u8,
}

/// Walk segments up to the SOS (start-of-scan) marker. Everything after SOS
/// is raw compressed data that we copy verbatim.
fn parse_segments_until_sos(bytes: &[u8]) -> Result<(Vec<Segment>, usize), MediaError> {
    if bytes.len() < 2 || bytes[..2] != SOI {
        return Err(MediaError::Parse("not a JPEG (missing SOI)".to_string()));
    }
    let mut out = vec![Segment {
        bytes: SOI.to_vec(),
        marker: 0xd8,
    }];
    let mut pos = 2usize;
    while pos < bytes.len() {
        // Skip fill bytes.
        while pos < bytes.len() && bytes[pos] == 0xff {
            pos += 1;
        }
        if pos >= bytes.len() {
            return Err(MediaError::Parse(
                "unexpected EOF in JPEG segments".to_string(),
            ));
        }
        let marker = bytes[pos];
        pos += 1;
        // Stand-alone markers (no length field).
        if matches!(marker, 0xd0..=0xd7) || marker == 0x01 || marker == 0xd8 || marker == 0xd9 {
            let seg_bytes = vec![0xff, marker];
            let m = marker;
            out.push(Segment {
                bytes: seg_bytes,
                marker: m,
            });
            if marker == 0xd9 {
                return Ok((out, pos));
            }
            continue;
        }
        // Length-prefixed segment.
        if pos + 2 > bytes.len() {
            return Err(MediaError::Parse(
                "JPEG segment length truncated".to_string(),
            ));
        }
        let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        if len < 2 {
            return Err(MediaError::Parse(
                "JPEG segment length too small".to_string(),
            ));
        }
        let body_end = pos + len;
        if body_end > bytes.len() {
            return Err(MediaError::Parse("JPEG segment body truncated".to_string()));
        }
        // Capture full segment bytes: `ff marker length body`.
        let mut seg_bytes = Vec::with_capacity(2 + len);
        seg_bytes.push(0xff);
        seg_bytes.push(marker);
        seg_bytes.extend_from_slice(&bytes[pos..body_end]);
        out.push(Segment {
            bytes: seg_bytes,
            marker,
        });
        pos = body_end;
        if marker == SOS {
            return Ok((out, pos));
        }
    }
    Err(MediaError::Parse("JPEG without SOS marker".to_string()))
}

/// Body of an APP11 segment = `length (already stripped) + body`. This function
/// receives the body-only slice (i.e., `bytes` after the 2-byte length).
fn app11_is_jacs(body: &[u8]) -> bool {
    body.starts_with(JPEG_IDENTIFIER)
}

fn parse_jacs_app11(seg_body: &[u8]) -> Option<&[u8]> {
    if !app11_is_jacs(seg_body) {
        return None;
    }
    Some(&seg_body[JPEG_IDENTIFIER.len()..])
}

fn build_jacs_app11(payload: &str) -> Vec<u8> {
    // Segment: ff eb len(2) JACS\0 payload
    let body_len = JPEG_IDENTIFIER.len() + payload.len() + 2; // +2 for length-field itself
    assert!(
        body_len <= 0xffff,
        "body_len computed > u16::MAX — caller must have caught PayloadTooLarge"
    );
    let mut out = Vec::with_capacity(body_len + 2);
    out.push(0xff);
    out.push(APP11);
    out.extend_from_slice(&(body_len as u16).to_be_bytes());
    out.extend_from_slice(JPEG_IDENTIFIER);
    out.extend_from_slice(payload.as_bytes());
    out
}

pub fn embed(
    bytes: &[u8],
    payload: &str,
    robust: bool,
    refuse_overwrite: bool,
) -> Result<Vec<u8>, MediaError> {
    if payload.len() > MAX_PAYLOAD_BYTES_JPEG {
        return Err(MediaError::PayloadTooLarge {
            limit: MAX_PAYLOAD_BYTES_JPEG,
            actual: payload.len(),
        });
    }
    let (segments, sos_end) = parse_segments_until_sos(bytes)?;

    let mut jacs_count = 0;
    for seg in &segments {
        if seg.marker == APP11 {
            // Strip the 4-byte prefix `ff eb ll ll` to get body.
            if seg.bytes.len() > 4 && app11_is_jacs(&seg.bytes[4..]) {
                jacs_count += 1;
            }
        }
    }
    if jacs_count > 1 {
        return Err(MediaError::Parse(
            "duplicate JACS-Signature segment".to_string(),
        ));
    }
    if refuse_overwrite && jacs_count > 0 {
        return Err(MediaError::Parse(
            "input already carries JACS signature".to_string(),
        ));
    }

    // Rebuild: SOI, our new APP11, then all non-JACS segments in order, then
    // the raw scan data (bytes[sos_end..]).
    let mut out = Vec::with_capacity(bytes.len() + payload.len() + 64);
    // SOI.
    out.extend_from_slice(&SOI);
    // Insert our new APP11 immediately after SOI (PRD §4.2.2 — before first DQT/DHT).
    out.extend_from_slice(&build_jacs_app11(payload));
    // Walk the original segments, skipping SOI (first) and any existing JACS APP11.
    for seg in segments.iter().skip(1) {
        if seg.marker == APP11 && seg.bytes.len() > 4 && app11_is_jacs(&seg.bytes[4..]) {
            continue;
        }
        out.extend_from_slice(&seg.bytes);
    }
    // Raw scan data.
    out.extend_from_slice(&bytes[sos_end..]);

    if robust {
        out = crate::robust::embed_lsb_jpeg(&out, payload)?;
    }

    Ok(out)
}

pub fn extract(bytes: &[u8], scan_robust: bool) -> Result<Option<String>, MediaError> {
    let (segments, _sos_end) = parse_segments_until_sos(bytes)?;
    let mut found = Vec::new();
    for seg in &segments {
        if seg.marker == APP11 && seg.bytes.len() > 4 {
            // body starts at offset 4 (skip ff eb ll ll).
            if let Some(payload_bytes) = parse_jacs_app11(&seg.bytes[4..])
                && let Ok(s) = std::str::from_utf8(payload_bytes)
            {
                found.push(s.to_string());
            }
        }
    }
    if found.len() > 1 {
        return Err(MediaError::Parse(
            "duplicate JACS-Signature segment".to_string(),
        ));
    }
    if let Some(t) = found.into_iter().next() {
        return Ok(Some(t));
    }
    if scan_robust {
        return crate::robust::extract_lsb_jpeg(bytes);
    }
    Ok(None)
}

pub fn bytes_without_jacs_segment(bytes: &[u8]) -> Result<Vec<u8>, MediaError> {
    let (segments, sos_end) = parse_segments_until_sos(bytes)?;
    let mut out = Vec::with_capacity(bytes.len());
    for seg in &segments {
        if seg.marker == APP11 && seg.bytes.len() > 4 && app11_is_jacs(&seg.bytes[4..]) {
            continue;
        }
        out.extend_from_slice(&seg.bytes);
    }
    out.extend_from_slice(&bytes[sos_end..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_jpeg() -> Vec<u8> {
        let img = image::RgbImage::from_pixel(1, 1, image::Rgb([128, 64, 32]));
        let mut buf = Vec::new();
        let mut cur = std::io::Cursor::new(&mut buf);
        img.write_to(&mut cur, image::ImageFormat::Jpeg).unwrap();
        buf
    }

    #[test]
    fn jpeg_app11_roundtrip() {
        let input = minimal_jpeg();
        let payload = "hello-jpeg-payload";
        let signed = embed(&input, payload, false, false).expect("embed");
        let extracted = extract(&signed, false).expect("ok").expect("present");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn jpeg_replaces_existing_jacs_app11() {
        let input = minimal_jpeg();
        let first = embed(&input, "v1", false, false).expect("embed1");
        let second = embed(&first, "v2", false, false).expect("embed2");
        let extracted = extract(&second, false).expect("ok").expect("present");
        assert_eq!(extracted, "v2");
    }

    #[test]
    fn jpeg_extract_from_no_segment_returns_none() {
        let input = minimal_jpeg();
        assert_eq!(extract(&input, false).unwrap(), None);
    }

    #[test]
    fn jpeg_canonical_hash_excludes_our_segment() {
        let input = minimal_jpeg();
        let h_before = crate::canonical_hash(&input).unwrap();
        let signed = embed(&input, "payload", false, false).expect("embed");
        let h_after = crate::canonical_hash(&signed).unwrap();
        assert_eq!(h_before, h_after);
    }

    #[test]
    fn jpeg_corrupted_returns_error() {
        let mut bytes = minimal_jpeg();
        bytes.truncate(15);
        assert!(extract(&bytes, false).is_err());
    }

    #[test]
    fn jpeg_payload_at_max_embeds_cleanly() {
        let input = minimal_jpeg();
        let payload = "A".repeat(MAX_PAYLOAD_BYTES_JPEG);
        let signed = embed(&input, &payload, false, false).expect("embed at exactly max");
        let extracted = extract(&signed, false).expect("ok").expect("present");
        assert_eq!(extracted.len(), MAX_PAYLOAD_BYTES_JPEG);
    }

    #[test]
    fn jpeg_payload_at_max_plus_one_returns_too_large() {
        let input = minimal_jpeg();
        let payload = "A".repeat(MAX_PAYLOAD_BYTES_JPEG + 1);
        let err = embed(&input, &payload, false, false).unwrap_err();
        match err {
            MediaError::PayloadTooLarge { limit, actual } => {
                assert_eq!(limit, MAX_PAYLOAD_BYTES_JPEG);
                assert_eq!(actual, MAX_PAYLOAD_BYTES_JPEG + 1);
            }
            other => panic!("{other:?}"),
        }
    }

    /// Issue 006 / PRD §4.2.2: third leg of the boundary triplet.
    #[test]
    fn jpeg_payload_at_max_minus_one_embeds_cleanly() {
        let input = minimal_jpeg();
        let payload = "B".repeat(MAX_PAYLOAD_BYTES_JPEG - 1);
        let signed = embed(&input, &payload, false, false).expect("embed at max-1");
        let extracted = extract(&signed, false).expect("ok").expect("present");
        assert_eq!(extracted.len(), MAX_PAYLOAD_BYTES_JPEG - 1);
    }

    /// Issue 006: duplicate APP11 JACS segments must surface as `MediaError::Parse`.
    #[test]
    fn duplicate_jacs_chunk_jpeg_returns_malformed() {
        let signed = embed(&minimal_jpeg(), "first-payload", false, false).expect("embed");
        // Splice in a second JACS APP11 segment immediately after the first.
        let extra_segment = build_jacs_app11("second-payload");
        // Find the start of the first APP11/JACS segment marker (0xFF 0xEB) so we
        // can append our extra segment right after the existing one — both end
        // up before SOS so embed/extract will see two JACS APP11s.
        let mut bad = Vec::with_capacity(signed.len() + extra_segment.len());
        let mut spliced = false;
        let mut i = 0;
        while i + 1 < signed.len() {
            // FFEB marker: APP11 segment.
            if signed[i] == 0xff && signed[i + 1] == APP11 && !spliced {
                // Read segment length (big-endian u16) at i+2..i+4.
                if i + 4 <= signed.len() {
                    let seg_len = u16::from_be_bytes([signed[i + 2], signed[i + 3]]) as usize;
                    let seg_end = i + 2 + seg_len; // marker (2 bytes not included in length field)
                    if seg_end <= signed.len() {
                        // Copy original segment, then append extra one.
                        bad.extend_from_slice(&signed[i..seg_end]);
                        bad.extend_from_slice(&extra_segment);
                        i = seg_end;
                        spliced = true;
                        continue;
                    }
                }
            }
            bad.push(signed[i]);
            i += 1;
        }
        if i < signed.len() {
            bad.push(signed[i]);
        }
        assert!(spliced, "test setup failed: did not splice extra APP11");

        let embed_err = embed(&bad, "third", false, false).unwrap_err();
        assert!(
            matches!(embed_err, MediaError::Parse(ref msg) if msg.contains("duplicate")),
            "expected Parse(duplicate) on embed; got {:?}",
            embed_err
        );
        let extract_err = extract(&bad, false).unwrap_err();
        assert!(
            matches!(extract_err, MediaError::Parse(ref msg) if msg.contains("duplicate")),
            "expected Parse(duplicate) on extract; got {:?}",
            extract_err
        );
    }
}
