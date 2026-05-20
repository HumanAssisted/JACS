//! WebP XMP chunk embedding. Payload is an XMP packet whose `JACS:Signature`
//! property carries the base64url payload.
//!
//! WebP files are RIFF containers. We walk RIFF chunks directly — simpler and
//! more predictable than relying on `img-parts`' WebP encoder paths.
//!
//! References: WebP Container Specification (Google, 2010; RIFF-based).

use crate::{MAX_PAYLOAD_BYTES_WEBP, MediaError};

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

type ChunkList<'a> = Vec<(&'a [u8], &'a [u8], &'a [u8])>;

fn parse_chunks(bytes: &[u8]) -> Result<(ChunkList<'_>, u32), MediaError> {
    if bytes.len() < 12 || &bytes[..4] != RIFF || &bytes[8..12] != WEBP {
        return Err(MediaError::Parse("not a WebP RIFF container".to_string()));
    }
    let riff_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    // File ends at byte 8 + riff_size.
    let file_end = 8usize + riff_size as usize;
    if file_end > bytes.len() {
        return Err(MediaError::Parse(
            "WebP RIFF size exceeds file bytes".to_string(),
        ));
    }
    let mut pos = 12usize;
    let mut out = Vec::new();
    while pos + 8 <= file_end {
        let fourcc = &bytes[pos..pos + 4];
        let chunk_size = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        let body_start = pos + 8;
        let body_end = body_start + chunk_size;
        // Padding byte for odd-length chunks.
        let padded_end = if chunk_size % 2 == 1 {
            body_end + 1
        } else {
            body_end
        };
        if padded_end > file_end {
            return Err(MediaError::Parse(
                "WebP chunk exceeds RIFF bounds".to_string(),
            ));
        }
        out.push((
            fourcc,
            &bytes[body_start..body_end],
            &bytes[pos..padded_end],
        ));
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
    // R-006: match the EXACT attribute syntax our embedder writes
    // (`JACS:Signature="`) — not the bare namespace prefix string, which can
    // legitimately appear as prose inside any XMP packet (e.g. an
    // `<rdf:Description>` block describing this attribute). The extractor
    // (`extract_signature_from_xmp_packet`) uses the same precise key, so
    // duplicate-detection now agrees with extraction.
    if let Ok(s) = std::str::from_utf8(body) {
        s.contains(concat!("JACS:Signature", "=\""))
    } else {
        false
    }
}

pub fn embed(bytes: &[u8], payload: &str, refuse_overwrite: bool) -> Result<Vec<u8>, MediaError> {
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
        return Err(MediaError::Parse(
            "duplicate JACS-Signature chunk".to_string(),
        ));
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
        if fourcc == XMP_FOURCC
            && let Ok(s) = std::str::from_utf8(body)
            && let Some(sig) = extract_signature_from_xmp_packet(s)
        {
            found.push(sig);
        }
    }
    if found.len() > 1 {
        return Err(MediaError::Parse(
            "duplicate JACS-Signature chunk".to_string(),
        ));
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

    /// Issue 006 / PRD §4.2.2: boundary triplet for WebP (max-1, max, max+1).
    /// WebP previously had no boundary tests at all.
    #[test]
    fn webp_payload_at_max_minus_one_embeds_cleanly() {
        let input = minimal_webp();
        let payload = "C".repeat(MAX_PAYLOAD_BYTES_WEBP - 1);
        let signed = embed(&input, &payload, false).expect("embed at max-1");
        let extracted = extract(&signed).expect("ok").expect("present");
        assert_eq!(extracted.len(), MAX_PAYLOAD_BYTES_WEBP - 1);
    }

    #[test]
    fn webp_payload_at_max_embeds_cleanly() {
        let input = minimal_webp();
        let payload = "C".repeat(MAX_PAYLOAD_BYTES_WEBP);
        let signed = embed(&input, &payload, false).expect("embed at max");
        let extracted = extract(&signed).expect("ok").expect("present");
        assert_eq!(extracted.len(), MAX_PAYLOAD_BYTES_WEBP);
    }

    #[test]
    fn webp_payload_at_max_plus_one_returns_too_large() {
        let input = minimal_webp();
        let payload = "C".repeat(MAX_PAYLOAD_BYTES_WEBP + 1);
        let err = embed(&input, &payload, false).unwrap_err();
        match err {
            MediaError::PayloadTooLarge { limit, actual } => {
                assert_eq!(limit, MAX_PAYLOAD_BYTES_WEBP);
                assert_eq!(actual, MAX_PAYLOAD_BYTES_WEBP + 1);
            }
            other => panic!("{other:?}"),
        }
    }

    /// R-006: `is_jacs_xmp` must NOT treat an arbitrary XMP packet that
    /// merely *mentions* the substring "JACS:Signature" (e.g. as prose inside
    /// an `<rdf:Description>` block) as a JACS-Signature chunk. The chunk is
    /// only ours if it carries the literal attribute syntax
    /// `JACS:Signature="..."`.
    ///
    /// Before the R-006 fix, a third-party XMP packet that documented the
    /// JACS namespace prefix would:
    ///   - Falsely count as a JACS XMP chunk during embed/extract
    ///   - Trigger "duplicate JACS-Signature chunk" if a real JACS chunk
    ///     was also present
    ///   - Trigger "input already carries JACS signature" under refuse_overwrite
    #[test]
    fn webp_innocent_xmp_mentioning_jacs_signature_is_not_duplicate() {
        // Build an XMP packet that mentions `JACS:Signature` only as prose
        // (no `="..."` value form). With the loose match this would be
        // mis-classified as a JACS chunk.
        let innocent_xmp = "\
            <?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\
            <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
            <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
            <rdf:Description rdf:about=\"\">\
            <dc:description>This file documents the JACS:Signature attribute used by jacs.</dc:description>\
            </rdf:Description>\
            </rdf:RDF></x:xmpmeta>\
            <?xpacket end=\"w\"?>";
        let innocent_chunk = build_chunk(XMP_FOURCC, innocent_xmp.as_bytes());

        // Splice the innocent XMP into a base WebP. Then sign it. With the
        // loose `contains("JACS:Signature")` match, embed sees jacs_count=1
        // BEFORE we add the real JACS chunk; if we run a second embed, it
        // sees jacs_count=2 (innocent + first JACS) and rejects as duplicate.
        let base = minimal_webp();
        let mut input_with_innocent = base.clone();
        input_with_innocent.extend_from_slice(&innocent_chunk);
        let new_riff_size = (input_with_innocent.len() - 8) as u32;
        input_with_innocent[4..8].copy_from_slice(&new_riff_size.to_le_bytes());

        // Step 1: embed our real signature. With the LOOSE match the innocent
        // chunk would be counted as a duplicate and the second embed would
        // fail. With the TIGHT match it succeeds.
        let signed = embed(&input_with_innocent, "real-payload", false)
            .expect("embed should succeed when innocent XMP only mentions JACS:Signature as prose");

        // Step 2: extract returns ONLY the real payload — not the innocent
        // mention.
        let extracted = extract(&signed).expect("extract ok");
        assert_eq!(
            extracted.as_deref(),
            Some("real-payload"),
            "extract must return the real payload, not the innocent mention"
        );

        // Step 3: refuse_overwrite=true on the freshly signed bytes must
        // report "input already carries JACS signature" — but only because
        // of the REAL chunk we added, not because of the innocent mention.
        // To prove the latter, run refuse_overwrite=true on the
        // input-with-innocent (no real chunk yet) — it should succeed.
        let _resigned = embed(&input_with_innocent, "another-payload", true)
            .expect("refuse_overwrite=true on input with only innocent XMP must succeed");
    }

    /// R-006 follow-up: an UNSIGNED WebP whose XMP packet only mentions
    /// `JACS:Signature` as prose (no real JACS chunk anywhere) must extract
    /// to `Ok(None)`. Before the R-006 fix this would have surfaced the
    /// XMP body as a "JACS chunk" and either returned the prose as the
    /// alleged payload or raised a parse error.
    #[test]
    fn webp_unsigned_with_innocent_jacs_mention_extracts_to_none() {
        let innocent_xmp = "\
            <?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\
            <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
            <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
            <rdf:Description rdf:about=\"\">\
            <dc:description>Documents the JACS:Signature attribute</dc:description>\
            </rdf:Description>\
            </rdf:RDF></x:xmpmeta>\
            <?xpacket end=\"w\"?>";
        let innocent_chunk = build_chunk(XMP_FOURCC, innocent_xmp.as_bytes());

        let mut bytes = minimal_webp();
        bytes.extend_from_slice(&innocent_chunk);
        let new_riff_size = (bytes.len() - 8) as u32;
        bytes[4..8].copy_from_slice(&new_riff_size.to_le_bytes());

        let res = extract(&bytes).expect("extract on unsigned webp must not error");
        assert_eq!(
            res, None,
            "unsigned webp with prose-only JACS mention must extract to None; got {:?}",
            res
        );
    }

    /// Issue 006: duplicate JACS XMP chunks must surface as `MediaError::Parse`.
    #[test]
    fn duplicate_jacs_chunk_webp_returns_malformed() {
        let signed = embed(&minimal_webp(), "first-payload", false).expect("embed");
        // Append a second JACS XMP chunk at the end of the chunk list inside
        // the RIFF body. We rebuild the file: keep RIFF header, original chunks,
        // then add an extra XMP chunk + recompute RIFF size.
        let extra_xmp_packet = build_xmp_packet("second-payload");
        let extra_chunk = build_chunk(XMP_FOURCC, extra_xmp_packet.as_bytes());

        // Splice the extra chunk in immediately before EOF.
        let mut bad = signed.clone();
        bad.extend_from_slice(&extra_chunk);
        // Recompute RIFF size: original RIFF size + extra_chunk.len(). RIFF size
        // is at bytes 4..8 in little-endian.
        let new_riff_size = (bad.len() - 8) as u32;
        bad[4..8].copy_from_slice(&new_riff_size.to_le_bytes());

        let embed_err = embed(&bad, "third", false).unwrap_err();
        assert!(
            matches!(embed_err, MediaError::Parse(ref msg) if msg.contains("duplicate")),
            "expected Parse(duplicate) on embed; got {:?}",
            embed_err
        );
        let extract_err = extract(&bad).unwrap_err();
        assert!(
            matches!(extract_err, MediaError::Parse(ref msg) if msg.contains("duplicate")),
            "expected Parse(duplicate) on extract; got {:?}",
            extract_err
        );
    }
}
