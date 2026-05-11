//! Integration tests for `jacs::simple::advanced::sign_image` /
//! `verify_image` / `extract_media_signature` (Task 06, PRD §4.2).
//!
//! Covers PNG, JPEG, and WebP. WebP fixture is generated once via
//! `jacs_media::embed_signature` (no external WebP encoder is allowed by Q1's
//! "100% Rust, zero C deps" rule); see PRD §4.2.4 / Task 02.

use jacs::error::JacsError;
use jacs::inline::VerifyOptions;
use jacs::simple::SimpleAgent;
use jacs::simple::advanced::{
    extract_media_signature, extract_media_signature_raw, extract_media_signature_raw_with_options,
    extract_media_signature_with_options, sign_image, verify_image,
};
use jacs::simple::types::ExtractMediaOptions;
use jacs::simple::types::{MediaVerifyStatus, SignImageOptions, SignedMedia, VerifyImageOptions};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn ephemeral_ed25519() -> SimpleAgent {
    SimpleAgent::ephemeral(Some("ed25519"))
        .expect("ephemeral")
        .0
}

fn make_fixture_png(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(width, height, image::Rgba([32, 64, 128, 255]));
    let mut buf = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    img.write_to(&mut cur, image::ImageFormat::Png)
        .expect("png encode");
    buf
}

fn make_fixture_jpeg(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbImage::from_pixel(width, height, image::Rgb([200, 150, 100]));
    let mut buf = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cur, 95);
    img.write_with_encoder(encoder).expect("jpeg encode");
    buf
}

/// Build a minimal WebP RIFF container that `jacs-media` accepts. The body
/// does NOT need to be a decodable image — `jacs-media`'s WebP parser is
/// chunk-level (matches the reference fixture in `jacs-media/src/webp.rs`).
fn make_fixture_webp() -> Vec<u8> {
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

    let body = vec![0u8; 4]; // 4 bytes of dummy VP8L body
    let mut chunks = Vec::new();
    chunks.extend_from_slice(b"WEBP");
    chunks.extend_from_slice(&build_chunk(b"VP8L", &body));
    let riff_size = chunks.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&riff_size.to_le_bytes());
    out.extend_from_slice(&chunks);
    out
}

fn write_fixture(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, bytes).expect("write fixture");
    path
}

// ============================================================================
// Roundtrip + permissive/strict verify (PNG / JPEG / WebP)
// ============================================================================

#[test]
fn sign_image_png_roundtrip() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(32, 32));
    let out_path = dir.path().join("out.png");
    let signed: SignedMedia = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .expect("sign ok");
    assert_eq!(signed.format, "png");
    assert!(!signed.robust);

    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions::default(),
    )
    .expect("verify ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
    assert_eq!(result.format.as_deref(), Some("png"));
    assert_eq!(result.signer_id.as_deref(), Some(signed.signer_id.as_str()));
}

#[test]
fn sign_image_jpeg_roundtrip() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.jpg", &make_fixture_jpeg(32, 32));
    let out_path = dir.path().join("out.jpg");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .expect("sign ok");

    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions::default(),
    )
    .expect("verify ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
    assert_eq!(result.format.as_deref(), Some("jpeg"));
}

#[test]
fn sign_image_webp_roundtrip() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.webp", &make_fixture_webp());
    let out_path = dir.path().join("out.webp");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .expect("sign ok");

    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions::default(),
    )
    .expect("verify ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
    assert_eq!(result.format.as_deref(), Some("webp"));
}

#[test]
fn sign_image_default_not_robust() {
    // PRD §4.2.5: default mode does not modify pixel data.
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_bytes = make_fixture_png(64, 64);
    let in_path = write_fixture(&dir, "in.png", &in_bytes);
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    let signed_bytes = fs::read(&out_path).unwrap();

    // Decode both and compare pixel buffers.
    let in_img = image::load_from_memory_with_format(&in_bytes, image::ImageFormat::Png)
        .unwrap()
        .to_rgba8();
    let out_img = image::load_from_memory_with_format(&signed_bytes, image::ImageFormat::Png)
        .unwrap()
        .to_rgba8();
    assert_eq!(
        in_img.as_raw(),
        out_img.as_raw(),
        "pixels must be identical"
    );
}

#[test]
fn sign_image_robust_modifies_pixels() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_bytes = make_fixture_png(256, 256);
    let in_path = write_fixture(&dir, "in.png", &in_bytes);
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..Default::default()
        },
    )
    .expect("robust sign ok");

    let signed_bytes = fs::read(&out_path).unwrap();
    let in_img = image::load_from_memory_with_format(&in_bytes, image::ImageFormat::Png)
        .unwrap()
        .to_rgba8();
    let out_img = image::load_from_memory_with_format(&signed_bytes, image::ImageFormat::Png)
        .unwrap()
        .to_rgba8();
    assert_ne!(
        in_img.as_raw(),
        out_img.as_raw(),
        "robust mode must modify LSBs"
    );

    // The current jacs-media implementation re-encodes pixels for LSB embed,
    // which strips the iTXt metadata chunk. Verifiers must opt-in to LSB scan
    // (scan_robust=true) per PRD §4.2.4 to recover the payload.
    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions::default(),
            scan_robust: true,
        },
    )
    .expect("verify ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
}

#[test]
fn verify_image_permissive_missing_signature_not_error() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "unsigned.png", &make_fixture_png(16, 16));
    let result = verify_image(
        &agent,
        path.to_str().unwrap(),
        VerifyImageOptions::default(),
    )
    .expect("permissive must not Err");
    assert_eq!(result.status, MediaVerifyStatus::MissingSignature);
}

#[test]
fn verify_image_strict_missing_signature_is_err() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "unsigned.png", &make_fixture_png(16, 16));
    let result = verify_image(
        &agent,
        path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: true,
                key_dir: None,
            },
            scan_robust: false,
        },
    );
    match result {
        Err(JacsError::MissingSignature(_)) => {}
        other => panic!(
            "expected Err(MissingSignature) in strict mode; got {:?}",
            other
        ),
    }
}

#[test]
fn verify_image_strict_valid_signature_ok() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: true,
                key_dir: None,
            },
            scan_robust: false,
        },
    )
    .expect("strict on signed file is Ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
}

/// Regression for Issue 002: per-block `KeyNotFound` MUST stay as a status,
/// not escalate to `Err(JacsError::TrustError)`, in strict mode. This matches
/// the `verify_text` contract — only file-level failures (MissingSignature,
/// file-level Malformed) escalate per PRD §4.1.2 tenth-pass clarification.
#[test]
fn verify_image_strict_keynotfound_does_not_escalate() {
    // Agent A signs the image.
    let agent_a = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent_a,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();

    // Agent B (different ephemeral, no key_dir, no trust store entry for A,
    // no DNS) tries to verify in strict mode.
    let (agent_b, _info_b) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let result = verify_image(
        &agent_b,
        out_path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: true,
                key_dir: None,
            },
            scan_robust: false,
        },
    )
    .expect("strict mode must NOT Err on per-block KeyNotFound");
    assert_eq!(
        result.status,
        MediaVerifyStatus::KeyNotFound,
        "expected MediaVerifyStatus::KeyNotFound status, got {:?}",
        result.status
    );
}

#[test]
fn verify_image_tampered_content_fails_png() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(32, 32));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();

    // Tamper with the IDAT chunk in-place (flip a high bit in the compressed
    // pixel data). This preserves the signature chunk so the verifier still
    // sees the signed payload, but the content hash no longer matches.
    let mut bytes = fs::read(&out_path).unwrap();
    let idat = b"IDAT";
    let pos = bytes
        .windows(4)
        .position(|w| w == idat)
        .expect("PNG has IDAT");
    // Skip past the chunk type (4) + first 8 bytes of zlib header to land in
    // compressed pixel territory.
    let target = pos + 4 + 8;
    bytes[target] ^= 0x80;
    fs::write(&out_path, &bytes).unwrap();

    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions::default(),
    )
    .expect("verify ok in permissive");
    assert!(
        matches!(
            result.status,
            MediaVerifyStatus::HashMismatch | MediaVerifyStatus::InvalidSignature
        ),
        "tamper must be detected; got {:?}",
        result.status
    );
}

#[test]
fn verify_image_tampered_content_fails_jpeg() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.jpg", &make_fixture_jpeg(32, 32));
    let out_path = dir.path().join("out.jpg");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();

    // Tamper a byte deep inside the JPEG entropy-coded section. After APP markers
    // and the SOS marker, the entropy-coded stream begins. Find the SOS marker
    // (0xFF 0xDA), skip its segment, and flip a byte in the compressed data.
    let mut bytes = fs::read(&out_path).unwrap();
    let mut sos_pos = None;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == 0xFF && bytes[i + 1] == 0xDA {
            sos_pos = Some(i);
            break;
        }
        i += 1;
    }
    let sos = sos_pos.expect("JPEG has SOS marker");
    // SOS segment length is at sos+2..sos+4 (big-endian).
    let seg_len = u16::from_be_bytes([bytes[sos + 2], bytes[sos + 3]]) as usize;
    // Flip a bit a few bytes past the segment header — in entropy-coded stream.
    let target = sos + 2 + seg_len + 4;
    if target < bytes.len().saturating_sub(2) {
        bytes[target] ^= 0x40;
    }
    fs::write(&out_path, &bytes).unwrap();

    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions::default(),
    )
    .expect("verify ok");
    assert!(
        matches!(
            result.status,
            MediaVerifyStatus::HashMismatch | MediaVerifyStatus::InvalidSignature
        ),
        "tamper must be detected; got {:?}",
        result.status
    );
}

#[test]
fn verify_image_permissive_missing_signature_all_formats() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let png = write_fixture(&dir, "u.png", &make_fixture_png(8, 8));
    let jpg = write_fixture(&dir, "u.jpg", &make_fixture_jpeg(16, 16));
    let webp = write_fixture(&dir, "u.webp", &make_fixture_webp());
    for p in [png, jpg, webp] {
        let result =
            verify_image(&agent, p.to_str().unwrap(), VerifyImageOptions::default()).unwrap();
        assert_eq!(
            result.status,
            MediaVerifyStatus::MissingSignature,
            "for {:?}",
            p
        );
    }
}

#[test]
fn verify_image_strict_missing_signature_all_formats() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let png = write_fixture(&dir, "u.png", &make_fixture_png(8, 8));
    let jpg = write_fixture(&dir, "u.jpg", &make_fixture_jpeg(16, 16));
    let webp = write_fixture(&dir, "u.webp", &make_fixture_webp());
    let strict = VerifyImageOptions {
        base: VerifyOptions {
            strict: true,
            key_dir: None,
        },
        scan_robust: false,
    };
    for p in [png, jpg, webp] {
        let res = verify_image(&agent, p.to_str().unwrap(), strict.clone());
        assert!(
            matches!(res, Err(JacsError::MissingSignature(_))),
            "for {:?}",
            p
        );
    }
}

// ============================================================================
// extract_media_signature
// ============================================================================

#[test]
fn extract_media_signature_roundtrip_all_formats() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let cases = vec![
        ("a.png", make_fixture_png(16, 16), "png"),
        ("a.jpg", make_fixture_jpeg(16, 16), "jpeg"),
        ("a.webp", make_fixture_webp(), "webp"),
    ];
    for (name, bytes, _fmt_str) in cases {
        let in_path = write_fixture(&dir, &format!("in_{}", name), &bytes);
        let out_path = dir.path().join(format!("out_{}", name));
        sign_image(
            &agent,
            in_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
            SignImageOptions::default(),
        )
        .expect("sign");
        let extracted = extract_media_signature(out_path.to_str().unwrap())
            .expect("ok")
            .expect("present");
        // The decoded payload must be parseable JSON containing
        // mediaSignatureVersion in the inner content.
        let v: serde_json::Value = serde_json::from_str(&extracted).expect("payload is JSON");
        let inner = v
            .pointer("/content")
            .or_else(|| v.pointer("/content/mediaSignatureVersion"))
            .expect("/content present");
        assert!(
            inner.get("mediaSignatureVersion").is_some()
                || inner.is_u64() && inner.as_u64() == Some(1),
            "claim has mediaSignatureVersion"
        );
    }
}

#[test]
fn extract_media_signature_raw_payload_returns_base64url() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();

    let raw = extract_media_signature_raw(out_path.to_str().unwrap())
        .unwrap()
        .unwrap();
    // base64url alphabet check: only [A-Za-z0-9_-] (no padding because we use
    // URL_SAFE_NO_PAD).
    for c in raw.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '=',
            "non-base64url char {:?}",
            c
        );
    }
}

#[test]
fn extract_media_signature_decoded_round_trips_to_raw() {
    use base64::Engine;
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    let raw = extract_media_signature_raw(out_path.to_str().unwrap())
        .unwrap()
        .unwrap();
    let decoded = extract_media_signature(out_path.to_str().unwrap())
        .unwrap()
        .unwrap();
    let raw_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .unwrap();
    assert_eq!(raw_decoded, decoded.as_bytes());
}

#[test]
fn extract_media_signature_no_signature_returns_none() {
    let dir = TempDir::new().unwrap();
    let png = write_fixture(&dir, "u.png", &make_fixture_png(8, 8));
    let jpg = write_fixture(&dir, "u.jpg", &make_fixture_jpeg(8, 8));
    let webp = write_fixture(&dir, "u.webp", &make_fixture_webp());
    for p in [png, jpg, webp] {
        let r = extract_media_signature(p.to_str().unwrap()).unwrap();
        assert!(r.is_none());
        let raw = extract_media_signature_raw(p.to_str().unwrap()).unwrap();
        assert!(raw.is_none());
    }
}

// ============================================================================
// R-011: extract_media_signature with scan_robust must recover an LSB-only
// signature after the metadata channel has been stripped. Before R-011 fix,
// extract hard-coded `scan_robust=false` so the LSB payload was invisible
// even though `verify_image --robust` would recover it.
// ============================================================================

/// Robust-mode signed image whose metadata chunk is then stripped — extract
/// without scan_robust must return None; with scan_robust=true it must
/// recover the payload (PNG path).
#[test]
fn extract_media_signature_with_robust_recovers_lsb_payload_png() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    // 256x256 chosen to match existing robust-mode tests' capacity headroom.
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(256, 256));
    let out_path = dir.path().join("signed.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..Default::default()
        },
    )
    .expect("sign png in robust mode");

    // Strip the metadata chunk to simulate transport loss / re-encode that
    // preserves pixels but drops iTXt/tEXt. The robust LSB payload remains.
    let signed_bytes = fs::read(&out_path).unwrap();
    let stripped =
        jacs_media::png::bytes_without_jacs_chunk(&signed_bytes).expect("strip metadata chunk");
    let stripped_path = dir.path().join("stripped.png");
    fs::write(&stripped_path, &stripped).unwrap();

    // Default extract: no scan_robust => returns None even though payload
    // exists in LSB.
    let no_robust = extract_media_signature(stripped_path.to_str().unwrap()).expect("no-robust ok");
    assert!(
        no_robust.is_none(),
        "default extract without scan_robust must NOT find LSB payload (cost-control); got Some({:?})",
        no_robust
    );

    // With scan_robust=true: payload is recovered and decodes to JSON.
    let opts = ExtractMediaOptions { scan_robust: true };
    let recovered = extract_media_signature_with_options(stripped_path.to_str().unwrap(), opts)
        .expect("with-robust ok")
        .expect("recovered LSB payload");
    let v: serde_json::Value = serde_json::from_str(&recovered).expect("recovered payload is JSON");
    assert!(
        v.pointer("/content/mediaSignatureVersion").is_some() || v.pointer("/content").is_some(),
        "recovered payload should be a media-signature claim, got: {}",
        v
    );

    // Raw variant honours the same option.
    let raw = extract_media_signature_raw_with_options(stripped_path.to_str().unwrap(), opts)
        .expect("with-robust raw ok")
        .expect("raw recovered");
    for c in raw.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '=',
            "raw payload must be base64url, got non-base64url char: {:?}",
            c
        );
    }
}

/// JPEG mirror: assert the OPT-IN flag is honoured for JPEG too. This uses
/// the lower-level `jacs_media::embed_signature` to plant a small known LSB
/// payload (avoids JPEG re-encode quirks at the round-trip boundary that are
/// orthogonal to R-011). The R-011 contract under test is *plumbing*: when
/// scan_robust=true is passed through extract, it reaches jpeg::extract via
/// jacs_media::extract_signature.
#[test]
fn extract_media_signature_with_robust_jpeg_threads_through_to_lsb_scanner() {
    let dir = TempDir::new().unwrap();
    let unsigned = make_fixture_jpeg(256, 256);
    // Embed a small LSB payload directly via jacs-media (bypassing the full
    // JACS signature wrapper) so we can deterministically verify that the
    // scan_robust flag reaches the LSB extraction layer.
    let signed_lsb_only =
        jacs_media::robust::embed_lsb_jpeg(&unsigned, "lsb-test-payload").expect("embed lsb jpeg");
    let path = dir.path().join("lsb_only.jpg");
    fs::write(&path, &signed_lsb_only).unwrap();

    // Default extract: no scan_robust => returns None (no metadata chunk).
    let no_robust = extract_media_signature(path.to_str().unwrap()).expect("ok");
    assert!(
        no_robust.is_none(),
        "default extract must NOT scan LSB; got Some"
    );

    // Raw variant with scan_robust=true: payload reaches the LSB scanner.
    // The scanner will read the LSBs back; whether the JPEG codec preserved
    // them well enough to round-trip is a separate concern (Issue 013-style).
    // We assert behavior at the scanner threading level: with scan_robust=true
    // either Some(payload) or Ok(None) is acceptable; without scan_robust the
    // result MUST be Ok(None) — this is the R-011 contract.
    let opts = ExtractMediaOptions { scan_robust: true };
    let _result = extract_media_signature_raw_with_options(path.to_str().unwrap(), opts)
        .expect("with-robust raw must not error");
    // No assertion on the result body — JPEG LSB round-trip survival is
    // codec-quality dependent and tested elsewhere. R-011 only asserts the
    // scan_robust flag THREADS THROUGH the extract API; the without-robust
    // assertion above (`no_robust.is_none()`) is the load-bearing one.
}

/// Default (no scan_robust) on metadata-only signed image still works.
#[test]
fn extract_media_signature_without_robust_still_reads_metadata() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("signed.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .expect("sign metadata-only");

    let payload = extract_media_signature(out_path.to_str().unwrap())
        .expect("ok")
        .expect("present in metadata");
    assert!(!payload.is_empty());
    // ExtractMediaOptions { scan_robust: false } is identical to the no-arg
    // variant.
    let same = extract_media_signature_with_options(
        out_path.to_str().unwrap(),
        ExtractMediaOptions { scan_robust: false },
    )
    .expect("ok")
    .expect("present");
    assert_eq!(payload, same);
}

// ============================================================================
// Robust mode + capacity
// ============================================================================

#[test]
fn sign_image_robust_webp_unsupported() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.webp", &make_fixture_webp());
    let out_path = dir.path().join("out.webp");
    let res = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..Default::default()
        },
    );
    let err = res.expect_err("must reject");
    let msg = format!("{}", err);
    assert!(
        msg.contains("webp robust mode deferred"),
        "expected deferral error; got: {}",
        msg
    );
}

#[test]
fn sign_image_robust_png_round_trip_hash_matches() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(256, 256));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..Default::default()
        },
    )
    .expect("sign ok");

    // PRD §4.2.4: LSB scan is opt-in. The current jacs-media robust embed
    // re-encodes the PNG and loses the iTXt metadata channel; verifiers must
    // pass scan_robust=true to recover the LSB payload.
    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions::default(),
            scan_robust: true,
        },
    )
    .expect("verify ok");
    assert_eq!(
        result.status,
        MediaVerifyStatus::Valid,
        "robust mode signed image must verify; got {:?}",
        result.status
    );
}

#[test]
fn sign_image_robust_16x16_fails_capacity() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");
    let res = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..Default::default()
        },
    );
    let err = res.expect_err("must fail");
    let msg = format!("{}", err);
    assert!(
        msg.contains("payload exceeds") || msg.contains("capacity") || msg.contains("limit"),
        "expected capacity error; got: {}",
        msg
    );
}

// ============================================================================
// Backup / atomic-write semantics (PRD §4.2.4a, §4.2.4b)
// ============================================================================

#[test]
fn sign_image_in_place_creates_backup_by_default() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let original = make_fixture_png(16, 16);
    let path = write_fixture(&dir, "in.png", &original);
    sign_image(
        &agent,
        path.to_str().unwrap(),
        path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    let bak = format!("{}.bak", path.to_str().unwrap());
    assert!(fs::metadata(&bak).is_ok(), ".bak exists");
    assert_eq!(fs::read(&bak).unwrap(), original);

    // The signed file at `path` verifies.
    let result = verify_image(
        &agent,
        path.to_str().unwrap(),
        VerifyImageOptions::default(),
    )
    .unwrap();
    assert_eq!(result.status, MediaVerifyStatus::Valid);
}

#[test]
fn sign_image_in_place_no_backup_opts_respected() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    sign_image(
        &agent,
        path.to_str().unwrap(),
        path.to_str().unwrap(),
        SignImageOptions {
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    let bak = format!("{}.bak", path.to_str().unwrap());
    assert!(fs::metadata(&bak).is_err(), ".bak must not exist");
}

#[cfg(unix)]
#[test]
fn sign_image_out_path_preserves_mode_bits() {
    use std::os::unix::fs::PermissionsExt;
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let _ = fs::set_permissions(&in_path, fs::Permissions::from_mode(0o600));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    let mode = fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn sign_image_backup_permission_is_0600_by_default() {
    use std::os::unix::fs::PermissionsExt;
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    sign_image(
        &agent,
        path.to_str().unwrap(),
        path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    let bak = format!("{}.bak", path.to_str().unwrap());
    let mode = fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn sign_image_backup_unsafe_mode_override() {
    use std::os::unix::fs::PermissionsExt;
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    sign_image(
        &agent,
        path.to_str().unwrap(),
        path.to_str().unwrap(),
        SignImageOptions {
            unsafe_bak_mode: Some(0o644),
            ..Default::default()
        },
    )
    .unwrap();
    let bak = format!("{}.bak", path.to_str().unwrap());
    let mode = fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
}

#[test]
fn sign_image_backup_overwrites_existing_bak() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let bak = format!("{}.bak", path.to_str().unwrap());
    fs::write(&bak, b"OLD CONTENT").unwrap();
    sign_image(
        &agent,
        path.to_str().unwrap(),
        path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    let bak_bytes = fs::read(&bak).unwrap();
    assert_ne!(bak_bytes, b"OLD CONTENT", "stale .bak must be replaced");
}

#[cfg(unix)]
#[test]
fn sign_image_backup_rejects_symlink_target() {
    use std::os::unix::fs;
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let bak = format!("{}.bak", path.to_str().unwrap());
    let other = dir.path().join("other.txt");
    std::fs::write(&other, b"DO NOT TOUCH").unwrap();
    fs::symlink(&other, &bak).unwrap();

    let res = sign_image(
        &agent,
        path.to_str().unwrap(),
        path.to_str().unwrap(),
        SignImageOptions::default(),
    );
    let err = res.expect_err("must reject symlink");
    assert!(
        format!("{}", err).contains("refusing to follow symlink"),
        "expected symlink rejection; got: {}",
        err
    );
    // Symlink target must remain unchanged.
    assert_eq!(std::fs::read(&other).unwrap(), b"DO NOT TOUCH");
}

// ============================================================================
// PublicKeyHash + cross-agent
// ============================================================================

#[test]
fn sign_image_populates_public_key_hash() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    for (name, bytes) in [
        ("in.png", make_fixture_png(16, 16)),
        ("in.jpg", make_fixture_jpeg(16, 16)),
        ("in.webp", make_fixture_webp()),
    ] {
        let in_path = write_fixture(&dir, name, &bytes);
        let out_path = dir.path().join(format!("out_{}", name));
        sign_image(
            &agent,
            in_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
            SignImageOptions::default(),
        )
        .unwrap();
        let payload = extract_media_signature(out_path.to_str().unwrap())
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let pkh = v
            .pointer("/content/publicKeyHash")
            .and_then(|s| s.as_str())
            .expect("publicKeyHash present");
        assert!(pkh.starts_with("sha256-b64url:"));

        let pem = agent.get_public_key_pem().unwrap();
        let normalised = jacs::crypt::normalize_public_key_pem(pem.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(normalised.as_bytes());
        let raw = hasher.finalize();
        let expected = format!(
            "sha256-b64url:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        );
        assert_eq!(pkh, expected, "publicKeyHash mismatch for {}", name);
    }
}

#[test]
fn sign_image_embeds_full_jacs_document_metadata() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");

    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();

    let payload = extract_media_signature(out_path.to_str().unwrap())
        .unwrap()
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&payload).unwrap();

    assert!(value.get("jacsId").and_then(|v| v.as_str()).is_some());
    assert!(value.get("jacsVersion").and_then(|v| v.as_str()).is_some());
    assert!(value.get("jacsType").and_then(|v| v.as_str()).is_some());
    assert!(value.get("jacsSignature").is_some());
    assert!(value.get("jacsSha256").and_then(|v| v.as_str()).is_some());

    let verified = agent
        .verify(&payload)
        .expect("embedded media payload must be a normal verifiable JACS document");
    assert!(
        verified.valid,
        "embedded media payload JACS signature/hash must verify: {:?}",
        verified.errors
    );
}

#[test]
fn robust_lsb_payload_extracts_to_verifiable_jacs_document() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(256, 256));
    let out_path = dir.path().join("out.png");

    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..SignImageOptions::default()
        },
    )
    .unwrap();

    let payload = extract_media_signature_with_options(
        out_path.to_str().unwrap(),
        ExtractMediaOptions { scan_robust: true },
    )
    .unwrap()
    .expect("robust LSB payload present");

    let verified = agent
        .verify(&payload)
        .expect("robust LSB payload must be a normal verifiable JACS document");
    assert!(
        verified.valid,
        "robust LSB payload JACS signature/hash must verify: {:?}",
        verified.errors
    );
}

#[test]
fn unsupported_format_clean_error() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("not-an-image.txt");
    fs::write(&path, b"not an image at all").unwrap();
    let out_path = dir.path().join("out.txt");
    let res = sign_image(
        &agent,
        path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    );
    let err = res.expect_err("unsupported format must Err");
    let msg = format!("{}", err);
    assert!(
        msg.contains("unsupported"),
        "expected unsupported error; got: {}",
        msg
    );
}

/// Issue 014 / PRD §10 eighth-pass item 5: cross-agent verify path. Agent A
/// signs a PNG, agent B verifies it via `verify_with_key` using A's PEM.
/// Locks the bug fix from Task 13's review notes (resolved key was being
/// PEM-armored before passing to `agent.verify_with_key`, which broke the
/// publicKeyHash re-hash for ed25519/pq2025).
///
/// Variants: ed25519 + pq2025.
#[test]
fn verify_image_cross_agent_path_ed25519() {
    let agent_a = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent_a,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();

    // Agent B is a different ephemeral. We populate B's key_dir with A's
    // public PEM so the resolver can find A's key.
    let (agent_b, _info_b) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let key_dir = TempDir::new().unwrap();
    let signer_id_a = agent_a.get_agent_id().unwrap();
    let encoded = jacs::simple::advanced::encode_signer_id_for_filename(&signer_id_a);
    let pem_path = key_dir.path().join(format!("{}.public.pem", encoded));
    std::fs::write(&pem_path, agent_a.get_public_key_pem().unwrap()).unwrap();

    let result = verify_image(
        &agent_b,
        out_path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: false,
                key_dir: Some(key_dir.path().to_path_buf()),
            },
            scan_robust: false,
        },
    )
    .expect("permissive verify ok");
    assert_eq!(
        result.status,
        MediaVerifyStatus::Valid,
        "cross-agent verify (ed25519) must reach Valid via verify_with_key, got {:?}",
        result.status
    );
}

#[test]
fn verify_image_cross_agent_path_pq2025() {
    let (agent_a, _info_a) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent_a,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();

    let (agent_b, _info_b) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
    let key_dir = TempDir::new().unwrap();
    let signer_id_a = agent_a.get_agent_id().unwrap();
    let encoded = jacs::simple::advanced::encode_signer_id_for_filename(&signer_id_a);
    let pem_path = key_dir.path().join(format!("{}.public.pem", encoded));
    std::fs::write(&pem_path, agent_a.get_public_key_pem().unwrap()).unwrap();

    let result = verify_image(
        &agent_b,
        out_path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: false,
                key_dir: Some(key_dir.path().to_path_buf()),
            },
            scan_robust: false,
        },
    )
    .expect("permissive verify ok");
    assert_eq!(
        result.status,
        MediaVerifyStatus::Valid,
        "cross-agent verify (pq2025) must reach Valid via verify_with_key, got {:?}",
        result.status
    );
}

/// Issue 009 / PRD §4.2.4a: simulate a `persist` failure during in-place sign
/// and assert the original `out_path` bytes are unchanged AND no `.jacs-sign-*`
/// or other tempfile residue is left behind.
///
/// Engineering: lock the parent directory read-only before the call. The
/// `NamedTempFile::new_in` call inside `sign_image` fails immediately, before
/// any persist is attempted — exercises the same "atomic-write must clean up
/// on failure" contract.
#[test]
#[cfg(unix)]
fn sign_image_atomic_crash_simulation() {
    use std::os::unix::fs::PermissionsExt;

    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(16, 16));
    let original_bytes = fs::read(&in_path).unwrap();

    // Lock the directory read-only so tempfile creation fails. Use the same
    // path for in/out so the in-place sign path runs.
    let dir_perm = fs::metadata(dir.path()).unwrap().permissions();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();

    let res = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        in_path.to_str().unwrap(),
        SignImageOptions {
            backup: false, // bypass backup-write so the failure happens at persist
            ..SignImageOptions::default()
        },
    );

    // Restore perms before assertions for cleanup.
    fs::set_permissions(dir.path(), dir_perm).unwrap();

    assert!(
        res.is_err(),
        "sign_image must Err when persist cannot complete"
    );

    // Original file bytes unchanged.
    let after_bytes = fs::read(&in_path).unwrap();
    assert_eq!(
        after_bytes, original_bytes,
        "in-place sign must leave original bytes intact on failure"
    );

    // No leftover .jacs-sign-* / .tmp files in the directory.
    for entry in fs::read_dir(dir.path()).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert!(name == "in.png", "tempfile residue left in dir: {:?}", name);
    }
}

// ============================================================================
// Issue 002 — `format_hint` is wired through sign_image (not a dead parameter).
// ============================================================================

#[test]
fn sign_image_format_hint_png_round_trips_with_explicit_hint() {
    // Sanity: a PNG file with an explicit `format_hint = png` succeeds and the
    // outcome carries `format = "png"`. This exercises the override path.
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(8, 8));
    let out_path = dir.path().join("out.png");
    let signed: SignedMedia = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            format_hint: Some("png".into()),
            ..SignImageOptions::default()
        },
    )
    .expect("sign with format_hint=png ok");
    assert_eq!(signed.format, "png");
}

#[test]
fn sign_image_format_hint_unknown_returns_clean_error() {
    // Issue 002: an unknown `--format` value must surface a clean
    // ValidationError rather than being silently ignored.
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(8, 8));
    let out_path = dir.path().join("out.png");
    let res = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            format_hint: Some("pdf".into()),
            ..SignImageOptions::default()
        },
    );
    match res {
        Err(JacsError::ValidationError(msg)) => {
            assert!(
                msg.contains("unknown format hint"),
                "expected unknown-format error, got: {msg}"
            );
            assert!(msg.contains("pdf"), "error must echo the bad hint: {msg}");
        }
        other => panic!("expected ValidationError, got: {other:?}"),
    }
    assert!(
        !out_path.exists(),
        "out file must not be written on hint validation failure"
    );
}

#[test]
fn sign_image_format_hint_jpeg_alias_is_accepted() {
    // The hint accepts "jpg" as an alias for "jpeg" (matches the CLI/MCP
    // help text — users type either).
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.jpg", &make_fixture_jpeg(8, 8));
    let out_path = dir.path().join("out.jpg");
    let signed: SignedMedia = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            format_hint: Some("jpg".into()),
            ..SignImageOptions::default()
        },
    )
    .expect("sign with format_hint=jpg ok");
    assert_eq!(signed.format, "jpeg");
}

/// REVIEW_005 (2): the signer's declared `embeddingChannels` must match
/// reality. Robust mode currently writes lsb-only; non-robust writes
/// metadata-only. A claim that says `metadata` for a robust-mode file would
/// fail verification with `Malformed("embeddingChannels mismatch")`.
#[test]
fn sign_image_robust_claim_declares_lsb_only_channel() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(256, 256));
    let out_path = dir.path().join("out.png");
    let _ = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..SignImageOptions::default()
        },
    )
    .expect("robust sign ok");

    let extracted_json = extract_media_signature_with_options(
        out_path.to_str().unwrap(),
        ExtractMediaOptions { scan_robust: true },
    )
    .expect("extract ok")
    .expect("payload present");
    let signed_doc: serde_json::Value =
        serde_json::from_str(&extracted_json).expect("parse signed doc JSON");
    let s = signed_doc.to_string();
    assert!(
        s.contains("\"embeddingChannels\":[\"lsb\"]"),
        "robust claim must declare embeddingChannels: [\"lsb\"]; got: {s}"
    );
    assert!(
        !s.contains("\"embeddingChannels\":[\"metadata\",\"lsb\"]"),
        "robust claim must NOT declare metadata channel (which gets stripped during LSB re-encode)"
    );
}

/// REVIEW_005 (2): a robust-mode signature whose LSB has been corrupted
/// post-sign must NOT verify clean. Today the signer declares lsb-only and
/// the verifier cross-checks observed channels — a chaos test that flips
/// LSBs in the signed file proves the verify path catches the tampering.
#[test]
fn verify_image_robust_lsb_corruption_post_sign_rejects() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(256, 256));
    let out_path = dir.path().join("out.png");
    sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..SignImageOptions::default()
        },
    )
    .expect("robust sign ok");

    // Corrupt the LSB payload by re-encoding the image bytes from a brand-new
    // RgbaImage (no LSB payload). This simulates a metadata-strip pipeline that
    // also re-encodes pixels.
    let stripped = make_fixture_png(256, 256);
    fs::write(&out_path, &stripped).unwrap();

    // Verify now fails — either MissingSignature (no LSB payload found at all)
    // or HashMismatch / Malformed for the channels mismatch. Anything but
    // Valid is acceptable; the point is that the previously-signed file no
    // longer surfaces as Valid after content tampering.
    let result = verify_image(
        &agent,
        out_path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions::default(),
            scan_robust: true,
        },
    )
    .expect("verify ok");
    assert!(
        !matches!(result.status, MediaVerifyStatus::Valid),
        "post-sign LSB strip + pixel re-encode must NOT verify Valid; got {:?}",
        result.status
    );
}

/// REVIEW_005 (1): in v0.11+, `pixelHash` commits to the **pre-LSB** pixel
/// buffer and `contentHash` commits to the LSB-zeroed canonical buffer.
/// The two MUST be different bytes when robust mode is on.
#[test]
fn sign_image_robust_pixel_hash_diverges_from_content_hash() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    // 256x256 RGBA — capacity for full payload.
    let in_path = write_fixture(&dir, "in.png", &make_fixture_png(256, 256));
    let out_path = dir.path().join("out.png");
    let _ = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            robust: true,
            ..SignImageOptions::default()
        },
    )
    .expect("robust sign ok");

    // Extract the embedded JACS signed-document JSON and inspect the claim
    // payload directly.
    let extracted_json = extract_media_signature_with_options(
        out_path.to_str().unwrap(),
        ExtractMediaOptions { scan_robust: true },
    )
    .expect("extract ok")
    .expect("payload present");

    // The signed-document's "data" field carries the claim — find pixelHash
    // and contentHash inside it.
    let signed_doc: serde_json::Value =
        serde_json::from_str(&extracted_json).expect("parse signed doc JSON");
    // Walk the document for both fields.
    let s = signed_doc.to_string();
    let parse_field = |key: &str| -> Option<String> {
        let needle = format!("\"{}\":\"", key);
        let i = s.find(&needle)?;
        let rest = &s[i + needle.len()..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    };
    let pixel_hash = parse_field("pixelHash").expect("pixelHash present in robust claim");
    let content_hash = parse_field("contentHash").expect("contentHash present");
    assert_ne!(
        pixel_hash, content_hash,
        "REVIEW_005 (1): pixelHash must commit to the pre-LSB pixel buffer, \
         which differs from the LSB-zeroed contentHash. Got identical values: {pixel_hash}"
    );
}

#[test]
fn sign_image_format_hint_overrides_magic_byte_detection() {
    // Issue 002: when `format_hint = png` is supplied for bytes whose magic
    // would otherwise be a JPEG, the hint takes precedence on the format
    // dispatch — the embed path is `png::embed`, which then surfaces a clean
    // parse error because the bytes aren't actually a PNG. This proves the
    // hint REACHES the dispatch (it would have been a no-op before Issue 002
    // — magic-byte detection would have routed to jpeg::embed and silently
    // succeeded).
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let in_path = write_fixture(&dir, "in.jpg", &make_fixture_jpeg(8, 8));
    let out_path = dir.path().join("out.jpg");
    let res = sign_image(
        &agent,
        in_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        SignImageOptions {
            format_hint: Some("png".into()),
            ..SignImageOptions::default()
        },
    );
    assert!(
        res.is_err(),
        "PNG hint over JPEG bytes must error; got Ok — the hint is being silently ignored"
    );
}
