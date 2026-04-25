//! CLI integration tests for `jacs sign-image`, `jacs verify-image`,
//! `jacs extract-media-signature`. PRD §3.2 / §4.2.
//!
//! Generates fixtures in-process via the `image` crate (PNG + JPEG only;
//! WebP is built byte-by-byte as a minimal RIFF container — same approach
//! as `jacs/tests/image_signature_tests.rs`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestSignImage!2026";

fn cmd() -> Command {
    let mut c = Command::cargo_bin("jacs").expect("jacs binary should exist");
    c.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    c
}

fn fresh_tmpdir() -> TempDir {
    TempDir::new().expect("tmpdir")
}

/// Bootstrap a persistent agent in `dir` via `jacs quickstart`. Required for
/// sign + verify across multiple CLI invocations to use the same agent key.
fn bootstrap_agent(dir: &TempDir, algorithm: &str) {
    cmd()
        .current_dir(dir.path())
        .args([
            "quickstart",
            "--algorithm",
            algorithm,
            "--name",
            "test-agent",
            "--domain",
            "localhost",
        ])
        .assert()
        .success();
}

// ============================================================================
// Fixtures
// ============================================================================

fn make_png(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(width, height, image::Rgba([32, 64, 128, 255]));
    let mut buf = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    img.write_to(&mut cur, image::ImageFormat::Png)
        .expect("png encode");
    buf
}

fn make_jpeg(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbImage::from_pixel(width, height, image::Rgb([200, 150, 100]));
    let mut buf = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cur, 95);
    img.write_with_encoder(encoder).expect("jpeg encode");
    buf
}

/// Minimal valid WebP RIFF container — chunk-level only, no decodable
/// pixels. Matches the fixture pattern in jacs/tests/image_signature_tests.rs.
fn make_webp() -> Vec<u8> {
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
    let body = vec![0u8; 4];
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
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

fn signed_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

// ============================================================================
// sign-image — formats + flags
// ============================================================================

#[test]
fn sign_image_png_exit_zero() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let in_path = write_fixture(&dir, "in.png", &make_png(32, 32));
    let out_path = dir.path().join("out.png");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();
    assert!(out_path.exists(), "signed PNG must be written");
    assert!(signed_size(&out_path) > 0);
}

#[test]
fn sign_image_jpeg_exit_zero() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let in_path = write_fixture(&dir, "in.jpg", &make_jpeg(32, 32));
    let out_path = dir.path().join("out.jpg");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();
    assert!(out_path.exists());
}

#[test]
fn sign_image_webp_exit_zero() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let in_path = write_fixture(&dir, "in.webp", &make_webp());
    let out_path = dir.path().join("out.webp");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();
    assert!(out_path.exists());
}

#[test]
fn sign_image_robust_flag_round_trip() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    // Robust mode embeds the JACS signed-document JSON via LSB. Need a
    // sufficiently large image — 256x256 RGBA = 65536 pixels = ~32 KiB
    // theoretical capacity (4 bits per pixel after LSB), enough for the
    // ~2 KiB JACS signed-document payload.
    let in_path = write_fixture(&dir, "in.png", &make_png(256, 256));
    let out_path = dir.path().join("out.png");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image", "--robust"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();

    // Robust mode writes LSB-only (no metadata chunk) per Wave 2a handoff —
    // verify must use --robust to find the payload.
    cmd()
        .current_dir(dir.path())
        .args(["verify-image", "--robust"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn sign_image_format_override() {
    // --format png on a renamed file (extension doesn't match) still works
    // because the actual magic bytes match the explicit hint.
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let in_path = write_fixture(&dir, "in.bin", &make_png(32, 32));
    let out_path = dir.path().join("out.png");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image", "--format", "png"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();
    assert!(out_path.exists());
}

// ============================================================================
// verify-image — strict / permissive
// ============================================================================

#[test]
fn verify_image_permissive_missing_signature_exit_two() {
    let dir = fresh_tmpdir();
    let path = write_fixture(&dir, "unsigned.png", &make_png(32, 32));

    cmd()
        .current_dir(dir.path())
        .args(["verify-image"])
        .arg(path.to_str().unwrap())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no JACS signature found"));
}

#[test]
fn verify_image_strict_missing_signature_exit_one() {
    let dir = fresh_tmpdir();
    let path = write_fixture(&dir, "unsigned.png", &make_png(32, 32));

    cmd()
        .current_dir(dir.path())
        .args(["verify-image", "--strict"])
        .arg(path.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no JACS signature found"));
}

#[test]
fn verify_image_strict_valid_exit_zero() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let in_path = write_fixture(&dir, "in.png", &make_png(32, 32));
    let out_path = dir.path().join("out.png");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .current_dir(dir.path())
        .args(["verify-image", "--strict"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();
}

// ============================================================================
// extract-media-signature — decoded vs raw
// ============================================================================

fn sign_format(dir: &TempDir, fmt: &str) -> PathBuf {
    let in_name = format!("in.{}", fmt);
    let out_name = format!("out.{}", fmt);
    let bytes = match fmt {
        "png" => make_png(32, 32),
        "jpg" | "jpeg" => make_jpeg(32, 32),
        "webp" => make_webp(),
        _ => panic!("unsupported fmt"),
    };
    let in_path = write_fixture(dir, &in_name, &bytes);
    let out_path = dir.path().join(out_name);
    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(out_path.to_str().unwrap())
        .assert()
        .success();
    out_path
}

#[test]
fn extract_media_signature_prints_decoded_json_by_default() {
    for fmt in ["png", "jpg", "webp"] {
        let dir = fresh_tmpdir();
        bootstrap_agent(&dir, "ed25519");
        let signed = sign_format(&dir, fmt);
        let output = cmd()
            .current_dir(dir.path())
            .args(["extract-media-signature"])
            .arg(signed.to_str().unwrap())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        // Default behaviour: decoded JSON. Must parse, must contain
        // mediaSignatureVersion field.
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap_or_else(|e| {
            panic!(
                "extract-media-signature default must emit parseable JSON for {}: {}",
                fmt, e
            )
        });
        let stdout_str = String::from_utf8_lossy(&output);
        assert!(
            stdout_str.contains("mediaSignatureVersion"),
            "decoded JSON must contain mediaSignatureVersion field for {}: got {}",
            fmt,
            stdout_str
        );
        // Sanity: it's an object/structure (not just a number).
        assert!(
            value.is_object() || value.is_array(),
            "JSON must be a structure for {}",
            fmt
        );
    }
}

#[test]
fn extract_media_signature_raw_payload_prints_base64url() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let signed = sign_format(&dir, "png");
    let output = cmd()
        .current_dir(dir.path())
        .args(["extract-media-signature", "--raw-payload"])
        .arg(signed.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&output);
    assert!(
        s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=' || c == '\n' || c == '\r'
        }),
        "raw-payload must contain only base64url chars (and newlines); got {:?}",
        s.chars()
            .filter(|c| !(c.is_ascii_alphanumeric()
                || *c == '-'
                || *c == '_'
                || *c == '='
                || *c == '\n'
                || *c == '\r'))
            .collect::<String>()
    );
    // Confirm it really is base64url (would not parse as JSON).
    assert!(
        serde_json::from_slice::<serde_json::Value>(&output).is_err(),
        "raw payload should NOT be valid JSON"
    );
}

#[test]
fn extract_media_signature_no_signature_exit_two_all_formats() {
    for fmt in ["png", "jpg", "webp"] {
        let dir = fresh_tmpdir();
        let bytes = match fmt {
            "png" => make_png(16, 16),
            "jpg" => make_jpeg(16, 16),
            "webp" => make_webp(),
            _ => panic!("unsupported"),
        };
        let path = write_fixture(&dir, &format!("unsigned.{}", fmt), &bytes);
        let assert = cmd()
            .current_dir(dir.path())
            .args(["extract-media-signature"])
            .arg(path.to_str().unwrap())
            .assert()
            .code(2);
        let stdout = assert.get_output().stdout.clone();
        assert!(
            stdout.is_empty(),
            "stdout must be empty when no signature ({}); got {:?}",
            fmt,
            String::from_utf8_lossy(&stdout)
        );
    }
}

// ============================================================================
// PRD §4.2.2 refuse-overwrite
// ============================================================================

#[test]
fn sign_image_refuse_overwrite_errors_on_signed_input() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let in_path = write_fixture(&dir, "foo.png", &make_png(32, 32));
    let signed_path = dir.path().join("foo.signed.png");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(signed_path.to_str().unwrap())
        .assert()
        .success();

    // Re-sign the already-signed file with --refuse-overwrite. Must error.
    let signed2_path = dir.path().join("foo.signed2.png");
    cmd()
        .current_dir(dir.path())
        .args(["sign-image", "--refuse-overwrite"])
        .arg(signed_path.to_str().unwrap())
        .args(["--out"])
        .arg(signed2_path.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already carries a JACS signature"));
}

#[test]
fn sign_image_default_overwrites_existing_signature() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let in_path = write_fixture(&dir, "foo1.png", &make_png(32, 32));
    let signed_path = dir.path().join("signed.png");

    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(in_path.to_str().unwrap())
        .args(["--out"])
        .arg(signed_path.to_str().unwrap())
        .assert()
        .success();

    // Default sign-image (no --refuse-overwrite) replaces the signature.
    // Re-sign signed.png in place.
    cmd()
        .current_dir(dir.path())
        .args(["sign-image"])
        .arg(signed_path.to_str().unwrap())
        .args(["--out"])
        .arg(signed_path.to_str().unwrap())
        .assert()
        .success();

    // Verify still works (one signer, just the latest).
    cmd()
        .current_dir(dir.path())
        .args(["verify-image"])
        .arg(signed_path.to_str().unwrap())
        .assert()
        .success();
}
