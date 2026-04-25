//! Provenance fixture generator (Task 13).
//!
//! Generates cross-language fixtures under
//! `jacs/tests/fixtures/provenance/` so every binding (Rust, Python, Node, Go)
//! can verify the same Rust-signed inputs.
//!
//! The fixtures are committed to git and treated as golden snapshots. To
//! regenerate them, run:
//!
//! ```bash
//! UPDATE_PROVENANCE_FIXTURES=1 cargo test -p jacs --test provenance_cross_language_tests \
//!     -- --nocapture regenerate_provenance_fixtures
//! ```
//!
//! The generator uses ephemeral agents — agent IDs and timestamps will change
//! every run. Reviewers should diff carefully and re-run all binding tests
//! after regenerating.

use jacs::simple::SimpleAgent;
use jacs::simple::advanced::{encode_signer_id_for_filename, sign_image, sign_text_file};
use jacs::simple::types::{SignImageOptions, SignTextOptions};
use std::fs;
use std::path::{Path, PathBuf};

/// Markdown content used for every text-based fixture. Sticking to a single
/// canonical body lets the lock-test (`all_bindings_share_canonical_content_hash`)
/// compare the unsigned and signed fixtures directly.
pub const FIXTURE_MARKDOWN: &str =
    "# JACS Cross-Language Fixture\n\nProvenance over text content.\n";

pub fn fixtures_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tests").join("fixtures").join("provenance")
}

pub fn keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}

/// Build a 16x16 PNG.
pub fn make_unsigned_png() -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(16, 16, image::Rgba([32, 64, 128, 255]));
    let mut buf = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    img.write_to(&mut cur, image::ImageFormat::Png)
        .expect("png encode");
    buf
}

/// Build a 16x16 JPEG at quality 95 (matches the fixture body in image_signature_tests.rs).
pub fn make_unsigned_jpeg() -> Vec<u8> {
    let img = image::RgbImage::from_pixel(16, 16, image::Rgb([200, 150, 100]));
    let mut buf = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cur, 95);
    img.write_with_encoder(encoder).expect("jpeg encode");
    buf
}

/// Minimal RIFF / WebP container (chunk-level, body is opaque). The
/// `jacs-media` parser is chunk-aware and is happy with this — see
/// `jacs/tests/image_signature_tests.rs::make_fixture_webp`.
pub fn make_unsigned_webp() -> Vec<u8> {
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

/// Materialise the public key file for `agent` under
/// `<keys_dir>/<encoded_signer_id>.public.pem` (same naming convention used
/// by `verify_text_file`'s `--key-dir` resolver — see PRD §4.1.5).
///
/// Each binding loads the same file when invoking verify with this directory.
pub fn write_public_key_file(agent: &SimpleAgent, dir: &Path) -> std::io::Result<()> {
    let signer_id = agent.get_agent_id().expect("agent id");
    let pem = agent.get_public_key_pem().expect("public key pem");
    let encoded = encode_signer_id_for_filename(&signer_id);
    let key_path = dir.join(format!("{}.public.pem", encoded));
    fs::write(&key_path, pem.as_bytes())
}

/// Optional metadata sidecar so each binding can assert agent IDs and
/// algorithms. Mirrors the metadata.json used in `tests/cross_language/`.
pub fn write_metadata(
    out_dir: &Path,
    agent_ed25519: &SimpleAgent,
    agent_pq2025: &SimpleAgent,
) -> std::io::Result<()> {
    let metadata = serde_json::json!({
        "schema": "jacs-provenance-fixture-v1",
        "generated_by": "rust",
        "jacs_version": env!("CARGO_PKG_VERSION"),
        "agent_ed25519": {
            "agent_id": agent_ed25519.get_agent_id().expect("ed25519 id"),
            "algorithm": "ed25519",
            "public_key_filename": format!(
                "{}.public.pem",
                encode_signer_id_for_filename(&agent_ed25519.get_agent_id().expect("id"))
            ),
        },
        "agent_pq2025": {
            "agent_id": agent_pq2025.get_agent_id().expect("pq2025 id"),
            "algorithm": "pq2025",
            "public_key_filename": format!(
                "{}.public.pem",
                encode_signer_id_for_filename(&agent_pq2025.get_agent_id().expect("id"))
            ),
        },
        "files": {
            "unsigned_text": "unsigned.md",
            "rust_signed_ed25519_text": "rust_signed_ed25519.md",
            "rust_signed_pq2025_text": "rust_signed_pq2025.md",
            "rust_signed_multi_algo_text": "rust_signed_multi_algo.md",
            "unsigned_png": "unsigned.png",
            "unsigned_jpeg": "unsigned.jpg",
            "unsigned_webp": "unsigned.webp",
            "rust_signed_ed25519_png": "rust_signed_ed25519.png",
            "rust_signed_ed25519_jpeg": "rust_signed_ed25519.jpg",
            "rust_signed_ed25519_webp": "rust_signed_ed25519.webp",
        },
    });
    let path = out_dir.join("metadata.json");
    fs::write(&path, serde_json::to_string_pretty(&metadata).unwrap())
}

/// Regenerate all fixtures under `jacs/tests/fixtures/provenance/`. Idempotent
/// from the binding-test point of view (committed snapshots are stable until
/// rerun), but agent identities + signatures change every invocation.
pub fn regenerate_all() -> std::io::Result<()> {
    let out_dir = fixtures_dir();
    let key_dir = keys_dir();
    fs::create_dir_all(&out_dir)?;
    fs::create_dir_all(&key_dir)?;

    // Two ephemeral agents: ed25519 + pq2025. These power both the markdown
    // multi-algo fixture and the per-format coverage matrix.
    let (agent_ed25519, _) = SimpleAgent::ephemeral(Some("ed25519")).expect("ephemeral ed25519");
    let (agent_pq2025, _) = SimpleAgent::ephemeral(Some("pq2025")).expect("ephemeral pq2025");

    // ----- Unsigned text fixture (also serves as canonical content for the
    // signed text fixtures and for the lock test).
    let unsigned_md = out_dir.join("unsigned.md");
    fs::write(&unsigned_md, FIXTURE_MARKDOWN)?;

    // ----- rust_signed_ed25519.md (single ed25519 block).
    let signed_ed25519_md = out_dir.join("rust_signed_ed25519.md");
    fs::write(&signed_ed25519_md, FIXTURE_MARKDOWN)?;
    sign_text_file(
        &agent_ed25519,
        signed_ed25519_md.to_str().unwrap(),
        SignTextOptions {
            backup: false,
            allow_duplicate: false,
        },
    )
    .expect("sign rust_signed_ed25519.md");

    // ----- rust_signed_pq2025.md (single pq2025 block).
    let signed_pq2025_md = out_dir.join("rust_signed_pq2025.md");
    fs::write(&signed_pq2025_md, FIXTURE_MARKDOWN)?;
    sign_text_file(
        &agent_pq2025,
        signed_pq2025_md.to_str().unwrap(),
        SignTextOptions {
            backup: false,
            allow_duplicate: false,
        },
    )
    .expect("sign rust_signed_pq2025.md");

    // ----- rust_signed_multi_algo.md — both blocks (ed25519 then pq2025).
    let signed_multi_md = out_dir.join("rust_signed_multi_algo.md");
    fs::write(&signed_multi_md, FIXTURE_MARKDOWN)?;
    sign_text_file(
        &agent_ed25519,
        signed_multi_md.to_str().unwrap(),
        SignTextOptions {
            backup: false,
            allow_duplicate: false,
        },
    )
    .expect("sign rust_signed_multi_algo.md (ed25519)");
    sign_text_file(
        &agent_pq2025,
        signed_multi_md.to_str().unwrap(),
        SignTextOptions {
            backup: false,
            allow_duplicate: false,
        },
    )
    .expect("sign rust_signed_multi_algo.md (pq2025)");

    // ----- Unsigned image fixtures (one per format).
    let unsigned_png = out_dir.join("unsigned.png");
    fs::write(&unsigned_png, make_unsigned_png())?;
    let unsigned_jpg = out_dir.join("unsigned.jpg");
    fs::write(&unsigned_jpg, make_unsigned_jpeg())?;
    let unsigned_webp = out_dir.join("unsigned.webp");
    fs::write(&unsigned_webp, make_unsigned_webp())?;

    // ----- Signed image fixtures: ed25519 against each format.
    sign_image(
        &agent_ed25519,
        unsigned_png.to_str().unwrap(),
        out_dir.join("rust_signed_ed25519.png").to_str().unwrap(),
        SignImageOptions {
            backup: false,
            ..Default::default()
        },
    )
    .expect("sign rust_signed_ed25519.png");
    sign_image(
        &agent_ed25519,
        unsigned_jpg.to_str().unwrap(),
        out_dir.join("rust_signed_ed25519.jpg").to_str().unwrap(),
        SignImageOptions {
            backup: false,
            ..Default::default()
        },
    )
    .expect("sign rust_signed_ed25519.jpg");
    sign_image(
        &agent_ed25519,
        unsigned_webp.to_str().unwrap(),
        out_dir.join("rust_signed_ed25519.webp").to_str().unwrap(),
        SignImageOptions {
            backup: false,
            ..Default::default()
        },
    )
    .expect("sign rust_signed_ed25519.webp");

    // ----- Public key files for both agents (key_dir convention).
    write_public_key_file(&agent_ed25519, &key_dir)?;
    write_public_key_file(&agent_pq2025, &key_dir)?;

    // ----- Metadata sidecar (each binding pulls agent IDs from here so we
    // don't have to re-derive them at verify time).
    write_metadata(&out_dir, &agent_ed25519, &agent_pq2025)?;

    Ok(())
}

/// True when the env var `UPDATE_PROVENANCE_FIXTURES` is set to "1" / "true" / "yes".
pub fn should_regenerate() -> bool {
    matches!(
        std::env::var("UPDATE_PROVENANCE_FIXTURES")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}
