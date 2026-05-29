//! Observability regression tests for the `jacs mcp` serve path (#6).
//!
//! CLAUDE.md norm: `jacs mcp` and the CLI must initialize a tracing subscriber
//! before serving — silent stdio is not acceptable, and (critically) the
//! subscriber MUST write to STDERR because `jacs mcp`'s STDOUT is the JSON-RPC
//! transport. A stray log byte on stdout corrupts the protocol.

use assert_cmd::Command;
use tempfile::TempDir;

/// Running `jacs mcp` must (a) emit its startup line to STDERR (proving a
/// subscriber is installed and security/audit events are not dropped) and
/// (b) keep STDOUT byte-clean before the first JSON-RPC frame.
///
/// We run in an empty directory with no config so the server fails fast after
/// logging its startup line — we don't need a live stdio session to assert the
/// wiring. Empty stdin (EOF) + a timeout guarantee the process never hangs,
/// regardless of whether it fails on config load or reaches the serve loop.
#[test]
fn mcp_emits_startup_log_to_stderr_and_keeps_stdout_clean() {
    let dir = TempDir::new().expect("tempdir");

    let assert = Command::cargo_bin("jacs")
        .expect("jacs binary should exist")
        .env("RUST_LOG", "info")
        .env_remove("JACS_CONFIG")
        .current_dir(dir.path())
        .arg("mcp")
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(30))
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.is_empty(),
        "`jacs mcp` must not write to stdout (it is the JSON-RPC transport); got stdout: {:?}",
        stdout
    );
    assert!(
        stderr.contains("mcp_server_starting"),
        "`jacs mcp` must emit a startup log line to stderr (subscriber installed); got stderr: {}",
        stderr
    );
}
