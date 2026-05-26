//! CLI integration tests for the W3C DID interop helpers.
//!
//! Exercises a real developer flow: create an agent, export discovery
//! artifacts, sign a concrete HTTP request, verify it, and reject substitutions.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "W3cCli!Pass2026";
const ORIGIN: &str = "https://agent.example.com";
const REQUEST_URL: &str = "https://api.example.com/tasks?priority=high";
const REQUEST_BODY: &str = "{\"task\":\"review proposal\",\"ok\":true}";

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
            "--algorithm",
            "ed25519",
            "--name",
            "w3c-cli-agent",
            "--domain",
            "agent.example.com",
        ])
        .assert()
        .success();
}

fn stdout_json(assert: assert_cmd::assert::Assert) -> Value {
    let output = assert.success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap_or_else(|e| {
        panic!(
            "stdout should be JSON: {}\n{}",
            e,
            String::from_utf8_lossy(&output)
        )
    })
}

#[test]
fn w3c_cli_generates_discovery_and_verifies_request_bound_proof() {
    let dir = TempDir::new().expect("tempdir");
    bootstrap_agent(&dir);

    let did_output = cmd()
        .current_dir(dir.path())
        .args(["w3c", "did", "--origin", ORIGIN])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let did = String::from_utf8(did_output)
        .expect("did utf8")
        .trim()
        .to_string();
    assert!(
        did.starts_with("did:wba:agent.example.com:agent:"),
        "unexpected DID: {}",
        did
    );

    let did_document = stdout_json(
        cmd()
            .current_dir(dir.path())
            .args(["w3c", "did-document", "--origin", ORIGIN])
            .assert(),
    );
    assert_eq!(did_document["id"].as_str(), Some(did.as_str()));
    assert_eq!(
        did_document["authentication"][0].as_str(),
        did_document["verificationMethod"][0]["id"].as_str()
    );
    assert!(
        did_document["jacs"]["jacsId"].as_str().is_some(),
        "DID document must preserve canonical jacsId"
    );

    let agent_description = stdout_json(
        cmd()
            .current_dir(dir.path())
            .args(["w3c", "agent-description", "--origin", ORIGIN])
            .assert(),
    );
    assert_eq!(agent_description["did"].as_str(), Some(did.as_str()));
    assert_eq!(
        agent_description["jacs"]["jacsId"],
        did_document["jacs"]["jacsId"]
    );

    let public_dir = dir.path().join("public");
    cmd()
        .current_dir(dir.path())
        .args([
            "w3c",
            "well-known",
            "--origin",
            ORIGIN,
            "--out",
            public_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote 3 W3C discovery documents"));

    assert!(public_dir.join(".well-known/agent-descriptions").exists());
    let jacs_id = did_document["jacs"]["jacsId"].as_str().expect("jacsId");
    assert!(
        public_dir
            .join(format!("agent/{}/description.json", jacs_id))
            .exists()
    );
    assert!(
        public_dir
            .join(format!("agent/{}/did.json", jacs_id))
            .exists()
    );

    let proof = stdout_json(
        cmd()
            .current_dir(dir.path())
            .args([
                "w3c",
                "sign-request",
                "--method",
                "POST",
                "--url",
                REQUEST_URL,
                "--body",
                REQUEST_BODY,
                "--origin",
                ORIGIN,
            ])
            .assert(),
    );
    assert_eq!(proof["did"].as_str(), Some(did.as_str()));
    assert_eq!(proof["method"].as_str(), Some("POST"));
    assert!(proof["contentDigest"].as_str().is_some());

    let proof_path = dir.path().join("proof.json");
    let did_path = dir.path().join("did.json");
    std::fs::write(
        &proof_path,
        serde_json::to_string_pretty(&proof).expect("proof json"),
    )
    .expect("write proof");
    std::fs::write(
        &did_path,
        serde_json::to_string_pretty(&did_document).expect("did json"),
    )
    .expect("write did doc");

    let verification = stdout_json(
        cmd()
            .current_dir(dir.path())
            .args([
                "w3c",
                "verify-request",
                "--method",
                "POST",
                "--url",
                REQUEST_URL,
                "--proof",
                proof_path.to_str().unwrap(),
                "--did-document",
                did_path.to_str().unwrap(),
                "--body",
                REQUEST_BODY,
            ])
            .assert(),
    );
    assert_eq!(verification["valid"], true);
    assert_eq!(verification["expectedRequestChecked"], true);

    cmd()
        .current_dir(dir.path())
        .args([
            "w3c",
            "verify-request",
            "--method",
            "POST",
            "--url",
            "https://api.example.com/other",
            "--proof",
            proof_path.to_str().unwrap(),
            "--did-document",
            did_path.to_str().unwrap(),
            "--body",
            REQUEST_BODY,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Request proof target URI does not match actual request URI",
        ));

    cmd()
        .current_dir(dir.path())
        .args([
            "w3c",
            "verify-request",
            "--method",
            "POST",
            "--url",
            REQUEST_URL,
            "--proof",
            proof_path.to_str().unwrap(),
            "--did-document",
            did_path.to_str().unwrap(),
            "--body",
            "{\"task\":\"tampered\",\"ok\":false}",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Request body digest does not match proof contentDigest",
        ));
}
