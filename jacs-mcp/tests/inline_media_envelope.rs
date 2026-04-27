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
use support::{TEST_PASSWORD, prepare_temp_workspace_ed25519};

static STDIO_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));
const TIMEOUT: Duration = Duration::from_secs(30);

type McpClient = RunningService<RoleClient, ()>;

struct Session {
    client: McpClient,
    base: std::path::PathBuf,
}

impl Session {
    async fn spawn() -> anyhow::Result<Self> {
        Self::spawn_with_env(&[]).await
    }

    /// Spawn the MCP server, layering extra env vars on top of the default set.
    /// Used by path-policy tests to inject `JACS_MCP_BASE_DIR` (R-003 regression).
    async fn spawn_with_env(extra_env: &[(&str, &str)]) -> anyhow::Result<Self> {
        let (config, base) = prepare_temp_workspace_ed25519();
        let bin = support::jacs_cli_bin();
        let extras: Vec<(String, String)> = extra_env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
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
            for (k, v) in &extras {
                c.env(k, v);
            }
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

/// REVIEW_006 / Issue 006: an absent input path inside the MCP base dir
/// passes the path policy (containment-only) and the verb surfaces a clean
/// FileReadFailed-style error envelope rather than a stack trace or a
/// path-policy denial. This test pins the observable behaviour the policy
/// fixture's `missing_input_inside_base_passes_policy` case maps to.
#[tokio::test]
async fn jacs_verify_text_missing_input_returns_clean_error_envelope() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Note: we deliberately do NOT create the file. The path is inside the
    // base dir so the policy accepts it; the verb hits I/O and surfaces the
    // failure cleanly.
    let result = s
        .call(
            "jacs_verify_text",
            serde_json::json!({ "file_path": "does_not_exist.md" }),
        )
        .await?;

    assert_eq!(
        result["success"], false,
        "missing input must surface success: false, envelope: {}",
        result
    );
    let err = result.get("error").and_then(|e| e.as_str()).unwrap_or("");
    let err_lower = err.to_lowercase();
    assert!(
        err_lower.contains("read")
            || err_lower.contains("filereadfailed")
            || err_lower.contains("no such file")
            || err_lower.contains("not found"),
        "missing input error must reference a read failure (FileReadFailed / 'no such file'), got: {err}"
    );
    assert!(
        !err_lower.contains("rejected"),
        "missing input must NOT be path-policy rejected (containment-only); got: {err}"
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

// ============================================================================
// Symlink-escape regression (Issue 020): an MCP client passing
// `link.png -> /etc/passwd` (or any path outside the MCP base dir) MUST be
// rejected by `path_policy::resolve` before any fs::read happens. The
// envelope returned to the client surfaces `success: false` with a path-
// validation error.
// ============================================================================
#[cfg(unix)]
#[tokio::test]
async fn jacs_sign_image_rejects_symlink_escape() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;
    let _g = STDIO_LOCK.lock().await;
    let s = Session::spawn().await?;

    // Plant a sensitive target outside the MCP base dir, then point a
    // symlink-named-as-png inside the base dir at it.
    let outside = tempfile::TempDir::new()?;
    let secret = outside.path().join("secret.txt");
    fs::write(&secret, b"top-secret")?;
    let link = s.base.join("evil_link.png");
    symlink(&secret, &link)?;

    let result = s
        .call(
            "jacs_sign_image",
            serde_json::json!({
                "input_path": "evil_link.png",
                "output_path": "out.png"
            }),
        )
        .await?;

    assert_eq!(
        result["success"], false,
        "expected reject for symlink-escape input, got: {}",
        result
    );
    let err = result["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("PATH")
            || err.to_lowercase().contains("symlink")
            || err.to_lowercase().contains("rejected"),
        "expected path-policy error in envelope, got: {}",
        err
    );

    s.client.cancellation_token().cancel();
    Ok(())
}

// ============================================================================
// R-003 Critical regression: every wave-3 tool MUST honour path_policy and
// reject paths that resolve outside `JACS_MCP_BASE_DIR`. The previous
// implementation only used `require_relative_path_safe` which lets a bare
// relative name (e.g. `outside.md`) escape via the server CWD.
//
// Test setup pattern:
//   - Server CWD is `s.base` (set by Session::spawn_with_env).
//   - JACS_MCP_BASE_DIR is set to `<base>/sandbox` — a *subdirectory* of CWD.
//   - A target file is planted at `<base>/outside.md` (CWD-relative, but
//     OUTSIDE the configured base dir).
//   - Calling a wave-3 tool with file_path="outside.md" SHOULD be rejected.
//     Before R-003 fix: the env var is silently ignored and the tool reads
//     `<base>/outside.md` because that is CWD-relative — bug.
//     After R-003 fix: path_policy::resolve_input_path treats the path as
//     base_dir-relative, the candidate becomes `<base>/sandbox/outside.md`
//     (which doesn't exist) and is rejected by the canon-confinement check.
// ============================================================================

/// Spawn a session, then plant a sandbox subdir and a target file outside
/// it, then return both. Used by R-003 base-dir-confinement tests.
async fn spawn_with_sandbox_and_outside_file(
    outside_filename: &str,
    outside_contents: &[u8],
) -> anyhow::Result<Session> {
    // 1. Pick up a fresh workspace + spawn parameters, build the sandbox dir
    //    BEFORE the server starts so JACS_MCP_BASE_DIR can canonicalise it.
    let (config, base) = prepare_temp_workspace_ed25519();
    let sandbox = base.join("sandbox");
    fs::create_dir_all(&sandbox)?;
    fs::write(base.join(outside_filename), outside_contents)?;

    // 2. Spawn the server with JACS_MCP_BASE_DIR=<base>/sandbox while the
    //    server CWD remains <base>. This is the realistic operator setup
    //    where MCP-client-supplied paths SHOULD be confined to a subdir even
    //    though plain CWD-relative resolution would walk up to <base>.
    let bin = support::jacs_cli_bin();
    let cmd = tokio::process::Command::new(&bin).configure(|c| {
        c.arg("mcp")
            .current_dir(&base)
            .env("JACS_CONFIG", &config)
            .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
            .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
            .env("JACS_MCP_BASE_DIR", &sandbox)
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
    Ok(Session { client, base })
}

/// Assert an MCP envelope reflects an R-003 path-policy rejection. After the
/// fix, calling a wave-3 tool with a path that resolves outside the
/// configured base dir must produce `success: false` with an error mentioning
/// the path-policy decision. Before the fix, the call silently succeeds
/// against the CWD-relative target.
fn assert_path_policy_reject(envelope: &serde_json::Value, ctx: &str) {
    let success = envelope["success"].as_bool().unwrap_or(true);
    let err = envelope["error"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        !success
            && (err.contains("path")
                || err.contains("rejected")
                || err.contains("outside")
                || err.contains("base")
                || err.contains("traversal")
                || err.contains("blocked")),
        "[{}] expected R-003 path_policy rejection; got envelope: {}",
        ctx,
        envelope
    );
}

#[tokio::test]
async fn jacs_verify_text_honours_base_dir_confinement() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = spawn_with_sandbox_and_outside_file("outside.md", b"Outside any sandbox.\n").await?;

    // file_path="outside.md" — CWD-relative => <base>/outside.md (exists).
    // After R-003 fix, path_policy treats it as base_dir-relative
    // => <base>/sandbox/outside.md (does NOT exist) and rejects.
    let result = s
        .call(
            "jacs_verify_text",
            serde_json::json!({ "file_path": "outside.md" }),
        )
        .await?;
    assert_path_policy_reject(&result, "jacs_verify_text outside.md");

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_sign_text_honours_base_dir_confinement() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = spawn_with_sandbox_and_outside_file("outside.md", b"Outside any sandbox.\n").await?;

    let result = s
        .call(
            "jacs_sign_text",
            serde_json::json!({ "file_path": "outside.md", "no_backup": true }),
        )
        .await?;
    assert_path_policy_reject(&result, "jacs_sign_text outside.md");

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_verify_image_honours_base_dir_confinement() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = spawn_with_sandbox_and_outside_file("outside.png", &unsigned_png_bytes()).await?;

    let result = s
        .call(
            "jacs_verify_image",
            serde_json::json!({ "file_path": "outside.png" }),
        )
        .await?;
    assert_path_policy_reject(&result, "jacs_verify_image outside.png");

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_extract_media_signature_honours_base_dir_confinement() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = spawn_with_sandbox_and_outside_file("outside.png", &unsigned_png_bytes()).await?;

    let result = s
        .call(
            "jacs_extract_media_signature",
            serde_json::json!({ "file_path": "outside.png" }),
        )
        .await?;
    assert_path_policy_reject(&result, "jacs_extract_media_signature outside.png");

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_sign_image_input_path_honours_base_dir_confinement() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    let s = spawn_with_sandbox_and_outside_file("outside.png", &unsigned_png_bytes()).await?;

    // input_path is OUTSIDE the sandbox; output_path is inside.
    let result = s
        .call(
            "jacs_sign_image",
            serde_json::json!({ "input_path": "outside.png", "output_path": "out.png" }),
        )
        .await?;
    assert_path_policy_reject(&result, "jacs_sign_image input_path outside.png");

    s.client.cancellation_token().cancel();
    Ok(())
}

#[tokio::test]
async fn jacs_sign_image_output_path_honours_base_dir_confinement() -> anyhow::Result<()> {
    let _g = STDIO_LOCK.lock().await;
    // Plant a valid PNG INSIDE the sandbox; the output_path tries to escape.
    let (config, base) = prepare_temp_workspace_ed25519();
    let sandbox = base.join("sandbox");
    fs::create_dir_all(&sandbox)?;
    fs::write(sandbox.join("inside.png"), unsigned_png_bytes())?;

    let bin = support::jacs_cli_bin();
    let cmd = tokio::process::Command::new(&bin).configure(|c| {
        c.arg("mcp")
            .current_dir(&base)
            .env("JACS_CONFIG", &config)
            .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
            .env("JACS_MAX_IAT_SKEW_SECONDS", "0")
            .env("JACS_MCP_BASE_DIR", &sandbox)
            .env("RUST_LOG", "warn");
    });
    let (transport, _) = TokioChildProcess::builder(cmd)
        .stderr(Stdio::null())
        .spawn()?;
    let client = tokio::time::timeout(TIMEOUT, ().serve(transport))
        .await
        .map_err(|_| anyhow::anyhow!("init timeout"))??;

    // output_path tries to escape via traversal "../".
    let resp = tokio::time::timeout(
        TIMEOUT,
        client.call_tool(CallToolRequestParam {
            name: "jacs_sign_image".to_string().into(),
            arguments: Some(
                serde_json::json!({
                    "input_path": "inside.png",
                    "output_path": "../escape.png"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("call timeout"))??;
    let text = resp
        .content
        .iter()
        .find_map(|item| item.as_text().map(|t| t.text.clone()))
        .unwrap_or_default();
    let result: serde_json::Value =
        serde_json::from_str(&text).unwrap_or(serde_json::json!({ "_raw": text }));
    assert_path_policy_reject(&result, "jacs_sign_image output_path traversal");

    client.cancellation_token().cancel();
    let _ = fs::remove_dir_all(&base);
    Ok(())
}
