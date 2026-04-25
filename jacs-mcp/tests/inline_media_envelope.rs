#![cfg(feature = "mcp")]
//! Runtime envelope tests for the inline-text and media MCP tools (Task 09).
//!
//! These tests spin up the MCP server with the Ed25519 fixture agent and
//! exercise jacs_verify_text / jacs_verify_image in both permissive (default)
//! and strict (C1) modes — verifying the JSON envelope shape per PRD §4.1, §4.2.
//!
//! They also exercise jacs_sign_image across all three supported formats (PNG,
//! JPEG, WebP) and confirm that jacs_extract_media_signature returns a
//! non-`None` payload for each.

use std::fs;
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

use rmcp::{
    RoleClient, ServiceExt,
    model::CallToolRequestParam,
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
};

mod support;
use support::{TEST_PASSWORD, prepare_temp_workspace_ed25519 as prepare_temp_workspace};

static STDIO_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));
const TIMEOUT: Duration = Duration::from_secs(30);

type McpClient = RunningService<RoleClient, ()>;

struct Session {
    client: McpClient,
    base: std::path::PathBuf,
}

impl Session {
    async fn spawn() -> anyhow::Result<Self> {
        let (config, base) = prepare_temp_workspace();
        let bin = support::jacs_cli_bin();
        let cmd = tokio::process::Command::new(&bin).configure(|c| {
            c.arg("mcp")
                .current_dir(&base)
                .env("JACS_CONFIG", &config)
                .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
                .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
                .env("RUST_LOG", "warn")
                .env_remove("JACS_KEY_DIRECTORY")
                .env_remove("JACS_DATA_DIRECTORY")
                .env_remove("JACS_AGENT_ID_AND_VERSION")
                .env_remove("JACS_AGENT_KEY_ALGORITHM")
                .env_remove("JACS_AGENT_PRIVATE_KEY_FILENAME")
                .env_remove("JACS_AGENT_PUBLIC_KEY_FILENAME")
                .env_remove("JACS_DEFAULT_STORAGE");
        });
        let (transport, _) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::null())
            .spawn()?;
        let client = tokio::time::timeout(TIMEOUT, ().serve(transport))
            .await
            .map_err(|_| anyhow::anyhow!("init timeout"))??;
        Ok(Self { client, base })
    }

    async fn call(&self, name: &str, args: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let resp = tokio::time::timeout(
            TIMEOUT,
            self.client.call_tool(CallToolRequestParam {
                name: name.to_string().into(),
                arguments: args.as_object().cloned(),
            }),
        )
        .await
        .map_err(|_| anyhow::anyhow!("call timeout: {}", name))??;
        let text = resp
            .content
            .iter()
            .find_map(|item| item.as_text().map(|t| t.text.clone()))
            .unwrap_or_default();
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::json!({ "_raw": text })))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

// ============================================================================
// jacs_verify_text — permissive (default) and strict (C1) envelopes
// ============================================================================

/// Permissive (default): missing signature returns `success: true` with
/// `status: "missing_signature"`.
#[tokio::test]
async fn jacs_verify_text_permissive_missing_signature_envelope() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Create an unsigned markdown file inside the MCP base dir.
    let target_path = s.base.join("plain.md");
    fs::write(&target_path, "Hello, world. No signature here.\n")?;

    let result = s
        .call(
            "jacs_verify_text",
            serde_json::json!({ "file_path": "plain.md" }),
        )
        .await?;

    assert_eq!(result["success"], true, "envelope: {}", result);
    assert_eq!(
        result["status"], "missing_signature",
        "expected status: missing_signature, got envelope: {}",
        result
    );
    assert!(
        result.get("error").is_none() || result["error"].is_null(),
        "permissive mode should not set error, got: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

/// Strict (C1): missing signature returns `success: false` with
/// `error: "no JACS signature found ..."`. The MCP response itself remains a
/// well-formed JSON-RPC success — only the envelope flips to `success: false`.
#[tokio::test]
async fn jacs_verify_text_strict_missing_signature_envelope() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    let target_path = s.base.join("plain.md");
    fs::write(&target_path, "Hello, world. No signature here.\n")?;

    let result = s
        .call(
            "jacs_verify_text",
            serde_json::json!({ "file_path": "plain.md", "strict": true }),
        )
        .await?;

    assert_eq!(
        result["success"], false,
        "strict mode should report success: false, envelope: {}",
        result
    );
    assert_eq!(
        result["status"], "missing_signature",
        "envelope: {}",
        result
    );
    let err = result["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("no JACS signature found"),
        "expected error to contain 'no JACS signature found', got: {}",
        err
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

// ============================================================================
// jacs_verify_image — permissive (default) and strict (C1) envelopes
// ============================================================================

/// Build an in-memory unsigned PNG (1x1 white pixel).
fn unsigned_png_bytes() -> Vec<u8> {
    use image::{ImageBuffer, Rgb};
    let img = ImageBuffer::<Rgb<u8>, _>::from_pixel(1, 1, Rgb([255, 255, 255]));
    let mut bytes = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut bytes),
        image::ImageFormat::Png,
    )
    .expect("encode PNG");
    bytes
}

/// Build an in-memory unsigned JPEG (1x1 white pixel).
fn unsigned_jpeg_bytes() -> Vec<u8> {
    use image::{ImageBuffer, Rgb};
    let img = ImageBuffer::<Rgb<u8>, _>::from_pixel(8, 8, Rgb([255, 255, 255]));
    let mut bytes = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut bytes),
        image::ImageFormat::Jpeg,
    )
    .expect("encode JPEG");
    bytes
}

/// Build an in-memory unsigned WebP (8x8 white pixel) using the image crate.
fn unsigned_webp_bytes() -> Vec<u8> {
    use image::{ImageBuffer, Rgb};
    let img = ImageBuffer::<Rgb<u8>, _>::from_pixel(8, 8, Rgb([255, 255, 255]));
    let mut bytes = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut bytes),
        image::ImageFormat::WebP,
    )
    .expect("encode WebP");
    bytes
}

#[tokio::test]
async fn jacs_verify_image_permissive_missing_signature_envelope() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    let png = s.base.join("plain.png");
    fs::write(&png, unsigned_png_bytes())?;

    let result = s
        .call(
            "jacs_verify_image",
            serde_json::json!({ "file_path": "plain.png" }),
        )
        .await?;

    assert_eq!(
        result["success"], true,
        "permissive: success should be true, envelope: {}",
        result
    );
    assert_eq!(
        result["status"], "missing_signature",
        "envelope: {}",
        result
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_verify_image_strict_missing_signature_envelope() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    let png = s.base.join("plain.png");
    fs::write(&png, unsigned_png_bytes())?;

    let result = s
        .call(
            "jacs_verify_image",
            serde_json::json!({ "file_path": "plain.png", "strict": true }),
        )
        .await?;

    assert_eq!(
        result["success"], false,
        "strict: success should be false, envelope: {}",
        result
    );
    assert_eq!(
        result["status"], "missing_signature",
        "envelope: {}",
        result
    );
    let err = result["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("no JACS signature found"),
        "expected error to contain 'no JACS signature found', got: {}",
        err
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

// ============================================================================
// jacs_sign_image must dispatch to PNG / JPEG / WebP — each format produces
// an output whose extract_media_signature returns a non-None payload.
// ============================================================================

async fn sign_and_extract_round_trip(
    s: &Session,
    fname_in: &str,
    fname_out: &str,
    bytes: Vec<u8>,
    expected_format: &str,
) -> anyhow::Result<()> {
    fs::write(s.base.join(fname_in), bytes)?;

    let sign_result = s
        .call(
            "jacs_sign_image",
            serde_json::json!({
                "input_path": fname_in,
                "output_path": fname_out,
            }),
        )
        .await?;
    assert_eq!(
        sign_result["success"], true,
        "sign-image failed for {}: {}",
        expected_format, sign_result
    );
    assert_eq!(
        sign_result["format"], expected_format,
        "format mismatch for {}: {}",
        expected_format, sign_result
    );

    let extract_result = s
        .call(
            "jacs_extract_media_signature",
            serde_json::json!({ "file_path": fname_out }),
        )
        .await?;
    assert_eq!(
        extract_result["success"], true,
        "extract failed for {}: {}",
        expected_format, extract_result
    );
    assert_eq!(
        extract_result["present"], true,
        "extract reported no payload for {}: {}",
        expected_format, extract_result
    );
    let payload = extract_result["payload"].as_str().unwrap_or_default();
    assert!(
        !payload.is_empty(),
        "extract returned empty payload for {}: {}",
        expected_format,
        extract_result
    );

    Ok(())
}

#[tokio::test]
async fn jacs_sign_image_covers_png_jpeg_webp() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    sign_and_extract_round_trip(&s, "in.png", "out.png", unsigned_png_bytes(), "png").await?;
    sign_and_extract_round_trip(&s, "in.jpg", "out.jpg", unsigned_jpeg_bytes(), "jpeg").await?;
    sign_and_extract_round_trip(&s, "in.webp", "out.webp", unsigned_webp_bytes(), "webp").await?;

    s.client.cancellation_token().cancel();
    Ok(())
}
