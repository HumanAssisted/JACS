//! P2 Task 004b — CLI surface for the AP2 mandate export.
//!
//! `jacs ap2 export-mandate` is CLI + binding only (FR19). The
//! `ap2-mandate` content scope is never auto-issued: the flow is
//! quickstart → `jacs agent issue-compat-binding --scopes ...,ap2-mandate`
//! → export. The same issue command is the post-rotation re-issue path
//! required by FR24.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestAp2Mandate!2026";

fn cmd() -> Command {
    let mut c = Command::cargo_bin("jacs").expect("jacs binary should exist");
    c.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    c
}

fn bootstrap_agent(dir: &TempDir) {
    cmd()
        .current_dir(dir.path())
        .args([
            "quickstart",
            "--name",
            "ap2-mandate-cli-test",
            "--domain",
            "localhost",
        ])
        .assert()
        .success();
}

const CHECKOUT: &str = r#"{
    "id": "checkout_cli_001",
    "status": "ready_for_payment",
    "currency": "USD",
    "line_items": [
        { "id": "li_1", "title": "Widget", "quantity": 1, "base_amount": 990, "total_amount": 990 }
    ],
    "totals": [
        { "type": "total", "display_text": "Total", "amount": 990 }
    ]
}"#;

#[test]
#[serial]
fn ap2_export_mandate_full_cli_flow() {
    let dir = TempDir::new().unwrap();
    bootstrap_agent(&dir);
    let checkout_path = dir.path().join("checkout.json");
    std::fs::write(&checkout_path, CHECKOUT).unwrap();

    // Without any binding: denied, never auto-issued for content scopes.
    cmd()
        .current_dir(dir.path())
        .args(["ap2", "export-mandate", "--input", "checkout.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("binding"));

    // Grant the content scope explicitly (PQ root signs the binding).
    cmd()
        .current_dir(dir.path())
        .args([
            "agent",
            "issue-compat-binding",
            "--scopes",
            "jwks,did,a2a-agent-card,w3c-agent-identity,ap2-mandate",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ap2-mandate"));

    // File input.
    let out = cmd()
        .current_dir(dir.path())
        .args(["ap2", "export-mandate", "--input", "checkout.json"])
        .assert()
        .success();
    let export: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("export is JSON");
    assert_eq!(export["format"], "ap2-mandate");
    assert_eq!(export["role"], "merchant-authorization");
    let jws = export["detachedJws"].as_str().unwrap();
    assert!(jws.contains(".."), "detached form <header>..<signature>");
    assert_eq!(
        export["checkout"]["ap2"]["merchant_authorization"]
            .as_str()
            .unwrap(),
        jws
    );

    // Stdin form (`--input -`), like the rest of the JSON-taking commands.
    cmd()
        .current_dir(dir.path())
        .args(["ap2", "export-mandate", "--input", "-"])
        .write_stdin(CHECKOUT)
        .assert()
        .success()
        .stdout(predicate::str::contains("detachedJws"));

    // Typed-input boundary holds on the CLI path too.
    cmd()
        .current_dir(dir.path())
        .args([
            "ap2",
            "export-mandate",
            "--input",
            r#"{"not":"a checkout"}"#,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ap2-mandate"));
}

#[test]
#[serial]
fn issue_compat_binding_rejects_unknown_scope() {
    let dir = TempDir::new().unwrap();
    bootstrap_agent(&dir);

    cmd()
        .current_dir(dir.path())
        .args(["agent", "issue-compat-binding", "--scopes", "everything"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}
