#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Once};
use std::time::{SystemTime, UNIX_EPOCH};

/// Ed25519 agent fixture in jacs/tests/fixtures/agent/. Use this variant
/// for tests that load fixture agents and tests that sign new documents.
const AGENT_ID_ED25519: &str =
    "22dbef6c-b85e-40e5-b82e-f95a4259339a:a51ece55-0fa1-4576-b9d6-eea351bb132a";

/// Password used to encrypt test fixture keys in jacs/tests/fixtures/keys/
/// Note: intentional typo "secretpassord" matches TEST_PASSWORD_LEGACY in jacs/tests/utils.rs
pub const TEST_PASSWORD: &str = "secretpassord";
const IAT_SKEW_ENV_VAR: &str = "JACS_MAX_IAT_SKEW_SECONDS";

static FIXTURE_IAT_INIT: Once = Once::new();
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

fn jacs_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Create a temp workspace with agent JSON, keys, and config.
/// Returns (config_path, base_dir). Config uses relative paths so tests can
/// verify the loader resolves them from the config path rather than the CWD.
///
pub fn prepare_temp_workspace() -> (PathBuf, PathBuf) {
    prepare_temp_workspace_ed25519()
}

/// Create a temp workspace backed by the Ed25519 agent fixture. Use this
/// variant for tests that need deterministic key material.
pub fn prepare_temp_workspace_ed25519() -> (PathBuf, PathBuf) {
    prepare_temp_workspace_with_fixture(
        AGENT_ID_ED25519,
        "ring-Ed25519",
        "agent-ed25519.private.pem.enc",
        "agent-ed25519.public.pem",
    )
}

fn prepare_temp_workspace_with_fixture(
    agent_id: &str,
    algorithm: &str,
    private_key_filename: &str,
    public_key_filename: &str,
) -> (PathBuf, PathBuf) {
    configure_fixture_iat_policy();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_root = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    let base = temp_root.join(format!("jacs_mcp_ws_{}_{}", std::process::id(), ts));
    let data_dir = base.join("jacs_data");
    let keys_dir = base.join("jacs_keys");
    fs::create_dir_all(data_dir.join("agent")).expect("mkdir data/agent");
    fs::create_dir_all(&keys_dir).expect("mkdir keys");

    let root = jacs_root();

    let agent_src = root.join(format!("jacs/tests/fixtures/agent/{}.json", agent_id));
    let agent_dst = data_dir.join(format!("agent/{}.json", agent_id));
    fs::copy(&agent_src, &agent_dst).unwrap_or_else(|e| {
        panic!(
            "copy agent fixture from {:?} to {:?}: {}",
            agent_src, agent_dst, e
        )
    });

    let keys_fixture = root.join("jacs/tests/fixtures/keys");
    fs::copy(
        keys_fixture.join(private_key_filename),
        keys_dir.join(private_key_filename),
    )
    .expect("copy private key");
    fs::copy(
        keys_fixture.join(public_key_filename),
        keys_dir.join(public_key_filename),
    )
    .expect("copy public key");

    let config_json = serde_json::json!({
        "jacs_agent_id_and_version": agent_id,
        "jacs_agent_key_algorithm": algorithm,
        "jacs_agent_private_key_filename": private_key_filename,
        "jacs_agent_public_key_filename": public_key_filename,
        "jacs_data_directory": "jacs_data",
        "jacs_default_storage": "fs",
        "jacs_key_directory": "jacs_keys",
        "jacs_use_security": "false"
    });
    let cfg_path = base.join("jacs.config.json");
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&config_json).unwrap(),
    )
    .expect("write config");

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
