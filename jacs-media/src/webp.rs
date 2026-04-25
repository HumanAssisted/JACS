//! WebP XMP chunk embedding. Payload is an XMP packet whose `JACS:Signature`
//! property carries the base64url payload.
//!
//! WebP files are RIFF containers. We walk RIFF chunks directly — simpler and
//! more predictable than relying on `img-parts`' WebP encoder paths.
//!
//! References: WebP Container Specification (Google, 2010; RIFF-based).

use crate::{MAX_PAYLOAD_BYTES_WEBP, MediaError, WEBP_XMP_KEY};

const RIFF: &[u8; 4] = b"RIFF";
const WEBP: &[u8; 4] = b"WEBP";
const XMP_FOURCC: &[u8; 4] = b"XMP ";

/// Minimal XMP packet wrapping a single JACS property.
fn build_xmp_packet(payload: &str) -> String {
    // Keep the packet tiny — just enough XMP boilerplate that common readers
    // recognise it. The `JACS:Signature` attribute carries the payload.
    format!(
        "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description rdf:about=\"\" xmlns:JACS=\"https://jacs.dev/ns/\" JACS:Signature=\"{}\"/>\
</rdf:RDF></x:xmpmeta>\
<?xpacket end=\"w\"?>",
        payload
    )
}

fn extract_signature_from_xmp_packet(packet: &str) -> Option<String> {
    // Very narrow parser: look for the literal `JACS:Signature="..."` attr.
    let key = "JACS:Signature=\"";
    let start = packet.find(key)? + key.len();
    let end_offset = packet[start..].find('"')?;
    Some(packet[start..start + end_offset].to_string())
}

/// Returns chunks as (fourcc, body, full_chunk). Full chunk includes the
/// 8-byte header and padding byte (WebP chunks have an odd-length padding byte).
fn parse_chunks(bytes: &[u8]) -> Result<(Vec<(&[u8], &[u8], &[u8])>, u32), MediaError> {
    if bytes.len() < 12 || &bytes[..4] != RIFF || &bytes[8..12] != WEBP {
        return Err(MediaError::Parse("not a WebP RIFF container".to_string()));
    }
    let riff_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    // File ends at byte 8 + riff_size.
    let file_end = 8usize + riff_size as usize;
    if file_end > bytes.len() {
        return Err(MediaError::Parse("WebP RIFF size exceeds file bytes".to_string()));
    }
    let mut pos = 12usize;
    let mut out = Vec::new();
    while pos + 8 <= file_end {
        let fourcc = &bytes[pos..pos + 4];
        let chunk_size =
            u32::from_le_bytes([bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]]) as usize;
        let body_start = pos + 8;
        let body_end = body_start + chunk_size;
        // Padding byte for odd-length chunks.
        let padded_end = if chunk_size % 2 == 1 { body_end + 1 } else { body_end };
        if padded_end > file_end {
            return Err(MediaError::Parse("WebP chunk exceeds RIFF bounds".to_string()));
        }
        out.push((fourcc, &bytes[body_start..body_end], &bytes[pos..padded_end]));
        pos = padded_end;
    }
    Ok((out, riff_size))
}

fn build_chunk(fourcc: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len() + 1);
    out.extend_from_slice(fourcc);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    if body.len() % 2 == 1 {
        out.push(0);
    }
    out
}

fn is_jacs_xmp(body: &[u8]) -> bool {
    // Treat body as UTF-8; only react if it's an XMP packet and contains our key.
    if let Ok(s) = std::str::from_utf8(body) {
        s.contains(WEBP_XMP_KEY)
    } else {
        false
    }
}

pub fn embed(
    bytes: &[u8],
    payload: &str,
    refuse_overwrite: bool,
) -> Result<Vec<u8>, MediaError> {
    if payload.len() > MAX_PAYLOAD_BYTES_WEBP {
        return Err(MediaError::PayloadTooLarge {
            limit: MAX_PAYLOAD_BYTES_WEBP,
            actual: payload.len(),
        });
    }
    let (chunks, _riff_size) = parse_chunks(bytes)?;

    let mut jacs_count = 0;
    for (fourcc, body, _full) in &chunks {
        if fourcc == XMP_FOURCC && is_jacs_xmp(body) {
            jacs_count += 1;
        }
    }
    if jacs_count > 1 {
        return Err(MediaError::Parse("duplicate JACS-Signature chunk".to_string()));
    }
    if refuse_overwrite && jacs_count > 0 {
        return Err(MediaError::Parse(
            "input already carries JACS signature".to_string(),
        ));
    }

    // Build the new XMP packet.
    let xmp_body = build_xmp_packet(payload);
    let new_chunk = build_chunk(XMP_FOURCC, xmp_body.as_bytes());

    // Rebuild without any existing JACS XMP chunk, then append our new chunk
    // at the end of the chunk list.
    let mut body_out = Vec::with_capacity(bytes.len() + new_chunk.len());
    body_out.extend_from_slice(WEBP);
    for (fourcc, body, full) in &chunks {
        if fourcc == XMP_FOURCC && is_jacs_xmp(body) {
            continue;
        }
        body_out.extend_from_slice(full);
    }
    body_out.extend_from_slice(&new_chunk);

    // Construct the RIFF header.
    let new_riff_size = (body_out.len()) as u32; // body_out already includes WEBP fourcc
    let mut out = Vec::with_capacity(8 + body_out.len());
    out.extend_from_slice(RIFF);
    out.extend_from_slice(&new_riff_size.to_le_bytes());
    out.extend_from_slice(&body_out);
    Ok(out)
}

pub fn extract(bytes: &[u8]) -> Result<Option<String>, MediaError> {
    let (chunks, _) = parse_chunks(bytes)?;
    let mut found = Vec::new();
    for (fourcc, body, _full) in &chunks {
        if fourcc == XMP_FOURCC {
            if let Ok(s) = std::str::from_utf8(body) {
                if let Some(sig) = extract_signature_from_xmp_packet(s) {
                    found.push(sig);
                }
            }
        }
    }
    if found.len() > 1 {
        return Err(MediaError::Parse("duplicate JACS-Signature chunk".to_string()));
    }
    Ok(found.into_iter().next())
}

pub fn bytes_without_jacs_chunk(bytes: &[u8]) -> Result<Vec<u8>, MediaError> {
    let (chunks, _) = parse_chunks(bytes)?;
    let mut body_out = Vec::with_capacity(bytes.len());
    body_out.extend_from_slice(WEBP);
    for (fourcc, body, full) in &chunks {
        if fourcc == XMP_FOURCC && is_jacs_xmp(body) {
            continue;
        }
        body_out.extend_from_slice(full);
    }
    let new_riff_size = body_out.len() as u32;
    let mut out = Vec::with_capacity(8 + body_out.len());
    out.extend_from_slice(RIFF);
    out.extend_from_slice(&new_riff_size.to_le_bytes());
    out.extend_from_slice(&body_out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal unsigned 1-byte VP8L WebP container. Does not have to
    /// be a valid decodable image — our parser is chunk-level.
    fn minimal_webp() -> Vec<u8> {
        // RIFF header + WEBP + VP8L chunk with trivial body.
        let body = vec![0u8; 4]; // 4 bytes of dummy VP8L body
        let mut chunks = Vec::new();
        chunks.extend_from_slice(WEBP);
        chunks.extend_from_slice(&build_chunk(b"VP8L", &body));
        let riff_size = chunks.len() as u32;
        let mut out = Vec::new();
        out.extend_from_slice(RIFF);
        out.extend_from_slice(&riff_size.to_le_bytes());
        out.extend_from_slice(&chunks);
        out
    }

    #[test]
    fn webp_xmp_roundtrip() {
        let input = minimal_webp();
        let payload = "webp-signature-payload";
        let signed = embed(&input, payload, false).expect("embed");
        let extracted = extract(&signed).expect("ok").expect("present");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn webp_replaces_existing_jacs_xmp() {
        let input = minimal_webp();
        let first = embed(&input, "v1", false).expect("embed1");
        let second = embed(&first, "v2", false).expect("embed2");
        let extracted = extract(&second).expect("ok").expect("present");
        assert_eq!(extracted, "v2");
    }

    #[test]
    fn webp_extract_from_no_chunk_returns_none() {
        let input = minimal_webp();
        assert_eq!(extract(&input).unwrap(), None);
    }

    #[test]
    fn webp_corrupted_returns_error() {
        let mut bytes = minimal_webp();
        bytes.truncate(10);
        assert!(extract(&bytes).is_err());
    }

    #[test]
    fn webp_canonical_hash_excludes_our_chunk() {
        let input = minimal_webp();
        let h_before = crate::canonical_hash(&input).unwrap();
        let signed = embed(&input, "payload", false).expect("embed");
        let h_after = crate::canonical_hash(&signed).unwrap();
        assert_eq!(h_before, h_after);
    }
}
