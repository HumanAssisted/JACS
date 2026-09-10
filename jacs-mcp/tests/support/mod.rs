#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Once};
use std::time::{SystemTime, UNIX_EPOCH};

/// Password used to encrypt test fixture keys in jacs/tests/fixtures/keys/
/// Note: intentional typo "secretpassord" matches TEST_PASSWORD_LEGACY in jacs/tests/utils.rs
pub const TEST_PASSWORD: &str = "secretpassord";
pub const LEGACY_SIGNATURE_CONTENT_ENV_VAR: &str = "JACS_ALLOW_LEGACY_SIGNATURE_CONTENT";
const IAT_SKEW_ENV_VAR: &str = "JACS_MAX_IAT_SKEW_SECONDS";

static FIXTURE_IAT_INIT: Once = Once::new();
static WORKSPACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub static ENV_LOCK: LazyLock<std::sync::Mutex<()>> = LazyLock::new(|| std::sync::Mutex::new(()));

pub struct ScopedEnvVar {
    key: &'static str,
    original: Option<OsString>,
}

impl ScopedEnvVar {
    pub fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let original = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, original }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => unsafe {
                std::env::set_var(self.key, value);
            },
            None => unsafe {
                std::env::remove_var(self.key);
            },
        }
    }
}

fn configure_fixture_iat_policy() {
    // These integration tests use committed fixture agents whose signature
    // timestamps are intentionally stable snapshots. Disable skew checks to
    // avoid false failures unrelated to MCP behavior under test.
    FIXTURE_IAT_INIT.call_once(|| unsafe {
        std::env::set_var(IAT_SKEW_ENV_VAR, "0");
    });
}

/// Create a temp workspace with a freshly generated agent, keys, and signed config.
/// Returns (config_path, base_dir). Config uses relative paths so tests can
/// verify the loader resolves them from the config path rather than the CWD.
///
pub fn prepare_temp_workspace() -> (PathBuf, PathBuf) {
    prepare_temp_workspace_ed25519()
}

/// Create a temp workspace backed by the Ed25519 agent fixture. Use this
/// variant for tests that need deterministic key material.
pub fn prepare_temp_workspace_ed25519() -> (PathBuf, PathBuf) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = WORKSPACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_root = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    let base = temp_root.join(format!(
        "jacs_mcp_ws_{}_{}_{}",
        std::process::id(),
        ts,
        sequence
    ));
    let data_dir = base.join("jacs_data");
    let keys_dir = base.join("jacs_keys");
    let cfg_path = base.join("jacs.config.json");

    let params = jacs::simple::CreateAgentParams::builder()
        .name(&format!("jacs-mcp-test-{ts}"))
        .password(TEST_PASSWORD)
        .algorithm("ed25519")
        .data_directory(data_dir.to_str().expect("UTF-8 data directory"))
        .key_directory(keys_dir.to_str().expect("UTF-8 key directory"))
        .config_path(cfg_path.to_str().expect("UTF-8 config path"))
        .default_storage("fs")
        .build();
    jacs::simple::SimpleAgent::create_with_params(params).expect("create signed MCP test identity");

    configure_fixture_iat_policy();

    (cfg_path, base)
}

/// Resolve the `jacs` binary from jacs-cli in the workspace target directory.
/// Requires `cargo build -p jacs-cli` to have been run first.
pub fn jacs_cli_bin() -> PathBuf {
    let current_exe = std::env::current_exe().expect("current_exe");
    let target_dir = current_exe
        .parent()
        .and_then(Path::parent)
        .expect("target dir for integration test binary");
    let bin = target_dir.join(format!("jacs{}", std::env::consts::EXE_SUFFIX));
    assert!(
        bin.exists(),
        "jacs binary not found at {}. Run `cargo build -p jacs-cli` first.",
        bin.display()
    );
    bin
}

pub fn run_server_with_fixture(extra_env: &[(&str, &str)]) -> (std::process::Output, PathBuf) {
    let (config, base) = prepare_temp_workspace();

    let bin_path = jacs_cli_bin();
    let mut command = std::process::Command::new(&bin_path);
    command
        .arg("mcp")
        .current_dir(&base)
        .env("JACS_CONFIG", &config)
        .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
        .env(LEGACY_SIGNATURE_CONTENT_ENV_VAR, "true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    for (k, v) in extra_env {
        command.env(k, v);
    }

    let output = command.output().expect("failed to run jacs mcp");
    (output, base)
}

pub fn assert_server_reaches_initialized_request(output: &std::process::Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reached_initialized_request = stderr.contains("connection closed: initialized request")
        || stderr.contains("connection closed: initialize request");
    assert!(
        reached_initialized_request,
        "Expected server to reach initialized-request state ({context}).\n\
         Exit code: {:?}\n\
         stdout:\n{}\n\
         stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        stderr
    );

    let had_startup_failure = stderr.contains("JACS_CONFIG environment variable is not set")
        || stderr.contains("Config file not found")
        || stderr.contains("Failed to load agent");
    assert!(
        !had_startup_failure,
        "Server reported startup failure ({context}).\nstderr:\n{}",
        stderr
    );
}

pub fn cleanup_workspace(path: &Path) {
    let _ = fs::remove_dir_all(path);
}
