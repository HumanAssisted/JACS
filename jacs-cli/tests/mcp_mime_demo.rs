#![cfg(all(feature = "mcp", unix))]

use assert_cmd::Command;
use serde_json::Value;
use std::time::Duration;

/// Actual CLI setup, two MCP servers, MIME parsing in a separate Python process,
/// and real native rejection checks. No mocked reports or installed JACS binary.
#[test]
fn mcp_signed_report_survives_mime_and_verifies_in_an_isolated_recipient() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mcp_mime_demo.py");
    let output = Command::new("python3")
        .args(["-I", script.to_str().expect("script path"), "--jacs-bin"])
        .arg(env!("CARGO_BIN_EXE_jacs"))
        .arg("--temp-root")
        .arg(scratch.path())
        .arg("--json")
        .current_dir(scratch.path())
        .timeout(Duration::from_secs(360))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).expect("public evidence JSON");
    println!("{result}"); // Public build/process evidence for a --nocapture run.
    for field in [
        "mime_bytes_preserved",
        "signature_verified",
        "recipient_has_no_private_identity",
        "sender_keys_deleted_before_recipient",
        "outer_email_edit_preserves_attachment_verification",
        "sender_shutdown_clean",
        "recipient_shutdown_clean",
        "temporary_files_cleaned",
    ] {
        assert_eq!(result[field], true, "{field}: {result}");
    }
    assert_ne!(result["driver_pid"], result["recipient_pid"]);
    assert_eq!(result["refused"].as_array().unwrap().len(), 6);
    for field in [
        "human_approval_inferred",
        "agreement_policy_acceptance_inferred",
        "contact_authority_inferred",
        "mailbox_identity_inferred",
    ] {
        assert_eq!(result[field], false, "{field}: {result}");
    }
    assert_eq!(result["binary_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}
