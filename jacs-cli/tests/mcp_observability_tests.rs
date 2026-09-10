//! Observability regression tests for the `jacs` binary (#6, Issue 016).
//!
//! CLAUDE.md norm: `jacs mcp` and the CLI must initialize a tracing subscriber
//! before serving — silent stdio is not acceptable, and (critically) the
//! subscriber MUST write to STDERR because `jacs mcp`'s STDOUT is the JSON-RPC
//! transport. A stray log byte on stdout corrupts the protocol.
//!
//! Since Issue 016, main() installs the stderr subscriber for EVERY command
//! (not just the mcp serve arm): one-shot commands default to `jacs=warn`
//! when `RUST_LOG` is unset, so the §9.8 structured WARN events
//! (`compatibility_key_missing`, `content_export_scope_denied`, ...) reach
//! the operator's stderr, while STDOUT stays byte-clean for machine-readable
//! output (`verify --json`, `agent export-jwks`, `quickstart --sign`, ...).

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "McpObsCliTest!2026";

fn jacs_cmd() -> Command {
    let mut c = Command::cargo_bin("jacs").expect("jacs binary should exist");
    c.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    c
}

fn bootstrap_agent(dir: &TempDir) {
    jacs_cmd()
        .current_dir(dir.path())
        .args([
            "quickstart",
            "--name",
            "mcp-obs-cli-test",
            "--domain",
            "localhost",
        ])
        .assert()
        .success();
}

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

/// P2 Task 007: an identity/compat export failure through the CLI binary
/// must emit an actionable structured diagnostic on STDERR and a non-zero
/// exit code. The library WARNs `compatibility_key_missing` with the
/// requested path and the `add-compat-key` hint at the failing call site;
/// since Issue 016 every CLI command installs the stderr subscriber, so the
/// operator sees BOTH the structured WARN event (with `RUST_LOG=warn` — also
/// the one-shot default) AND the typed error text carrying the same
/// remediation hint.
#[test]
fn cli_identity_export_failure_emits_actionable_diagnostic_on_stderr() {
    let dir = TempDir::new().expect("tempdir");
    bootstrap_agent(&dir);

    // Simulate a pre-P2 / air-gapped agent that never minted (or lost)
    // the ES256 compat key: the exact `compatibility_key_missing` state.
    std::fs::remove_file(dir.path().join("jacs_keys/jacs.ecosystem.private.pem.enc"))
        .expect("remove compat private key");

    jacs_cmd()
        .current_dir(dir.path())
        .env("RUST_LOG", "warn")
        .args(["agent", "export-jwks"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("compatibility_key_missing"))
        .stderr(predicate::str::contains("Failed to export JWKS"))
        .stderr(predicate::str::contains("add-compat-key"));
}

/// P2 Task 007: a content export denied by the binding scope must fail
/// through the CLI with a diagnostic naming the missing scope and the
/// re-issue remediation. The library WARNs `content_export_scope_denied`
/// (and bumps `jacs_content_export_scope_denied_total{format}`) at the
/// denial site; since Issue 016 that structured WARN reaches stderr through
/// the CLI's subscriber, alongside the matching typed error text.
#[test]
fn cli_content_export_scope_denial_emits_actionable_diagnostic_on_stderr() {
    let dir = TempDir::new().expect("tempdir");
    bootstrap_agent(&dir);

    // Identity-only binding: the ap2-mandate content scope is never
    // auto-issued, so the export below must be denied.
    jacs_cmd()
        .current_dir(dir.path())
        .args(["agent", "issue-compat-binding"])
        .assert()
        .success();

    let checkout = r#"{
        "id": "checkout_obs_cli_001",
        "status": "ready_for_payment",
        "currency": "USD",
        "line_items": [
            { "id": "li_1", "title": "Widget", "quantity": 1, "base_amount": 990, "total_amount": 990 }
        ],
        "totals": [
            { "type": "total", "display_text": "Total", "amount": 990 }
        ]
    }"#;
    std::fs::write(dir.path().join("checkout.json"), checkout).expect("write checkout");

    jacs_cmd()
        .current_dir(dir.path())
        .env("RUST_LOG", "warn")
        .args(["ap2", "export-mandate", "--input", "checkout.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("content_export_scope_denied"))
        .stderr(predicate::str::contains("Failed to export AP2 mandate"))
        .stderr(predicate::str::contains("ap2-mandate"))
        .stderr(predicate::str::contains("scope"));
}

/// Issue 016 stdout-purity guard: installing the process-wide stderr
/// subscriber must not leak a single log byte onto STDOUT of the
/// machine-readable commands — even with `RUST_LOG=info` forcing
/// success-path INFO events (e.g. quickstart's "found existing config") to
/// fire. Each captured stdout must parse as clean JSON on its own.
#[test]
fn machine_readable_stdout_stays_pure_json_with_rust_log_info() {
    let dir = TempDir::new().expect("tempdir");
    bootstrap_agent(&dir);

    // `jacs quickstart --sign`: signed document on stdout.
    let sign_assert = jacs_cmd()
        .current_dir(dir.path())
        .env("RUST_LOG", "info")
        .args([
            "quickstart",
            "--name",
            "mcp-obs-cli-test",
            "--domain",
            "localhost",
            "--sign",
        ])
        .write_stdin(r#"{"hello":"purity"}"#)
        .assert()
        .success();
    let signed_stdout = String::from_utf8_lossy(&sign_assert.get_output().stdout).into_owned();
    let signed: serde_json::Value = serde_json::from_str(&signed_stdout)
        .expect("`quickstart --sign` stdout must parse as clean JSON with RUST_LOG=info");
    assert!(
        signed.get("jacsSignature").is_some(),
        "signed doc must carry jacsSignature; got: {}",
        signed_stdout
    );
    std::fs::write(dir.path().join("signed.json"), signed_stdout.trim()).expect("write signed doc");

    // `jacs verify --json` on the signed doc.
    let verify_assert = jacs_cmd()
        .current_dir(dir.path())
        .env("RUST_LOG", "info")
        .args(["verify", "--json", "signed.json"])
        .assert()
        .success();
    let verify_stdout = String::from_utf8_lossy(&verify_assert.get_output().stdout).into_owned();
    let verdict: serde_json::Value = serde_json::from_str(&verify_stdout)
        .expect("`verify --json` stdout must parse as clean JSON with RUST_LOG=info");
    assert_eq!(
        verdict["valid"],
        serde_json::Value::Bool(true),
        "self-signed doc must verify; got: {}",
        verify_stdout
    );

    // `jacs agent export-jwks`: JWKS document on stdout.
    let jwks_assert = jacs_cmd()
        .current_dir(dir.path())
        .env("RUST_LOG", "info")
        .args(["agent", "export-jwks"])
        .assert()
        .success();
    let jwks_stdout = String::from_utf8_lossy(&jwks_assert.get_output().stdout).into_owned();
    let jwks: serde_json::Value = serde_json::from_str(&jwks_stdout)
        .expect("`agent export-jwks` stdout must parse as clean JSON with RUST_LOG=info");
    assert!(
        jwks["keys"].is_array(),
        "JWKS must have a keys array; got: {}",
        jwks_stdout
    );
}

#[test]
fn quickstart_sign_rejects_duplicate_json_keys_before_signing() {
    let dir = TempDir::new().expect("tempdir");
    bootstrap_agent(&dir);

    jacs_cmd()
        .current_dir(dir.path())
        .args([
            "quickstart",
            "--name",
            "duplicate-json-test",
            "--domain",
            "localhost",
            "--sign",
        ])
        .write_stdin(r#"{"decision":"allow","decision":"deny"}"#)
        .assert()
        .failure()
        .stderr(predicate::str::contains("duplicate JSON object key"));
}
