use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestAgreementV2!2026";

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
            "agreement-v2-cli-test",
            "--domain",
            "localhost",
        ])
        .assert()
        .success();
}

fn configured_agent_id(dir: &TempDir) -> String {
    let config: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("jacs.config.json")).unwrap(),
    )
    .expect("config json");
    config["jacs_agent_id_and_version"]
        .as_str()
        .expect("configured agent id")
        .split(':')
        .next()
        .expect("agent id")
        .to_string()
}

fn write_json(dir: &TempDir, name: &str, value: &Value) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value).expect("json bytes")).expect("write");
    path
}

fn output_json(dir: &TempDir, args: &[&str]) -> Value {
    let output = cmd()
        .current_dir(dir.path())
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON: {}\n{}",
            err,
            String::from_utf8_lossy(&output)
        )
    })
}

fn output_json_with_paths(dir: &TempDir, args: &[&str], paths: &[&Path]) -> Value {
    let mut command = cmd();
    command.current_dir(dir.path()).args(args);
    for path in paths {
        command.arg(path);
    }
    let output = command.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON: {}\n{}",
            err,
            String::from_utf8_lossy(&output)
        )
    })
}

fn output_json_owned(dir: &TempDir, args: &[String]) -> Value {
    let output = cmd()
        .current_dir(dir.path())
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON: {}\n{}",
            err,
            String::from_utf8_lossy(&output)
        )
    })
}

fn base_input(agent_id: &str) -> Value {
    json!({
        "title": "Agreement v2 CLI parity",
        "description": "The CLI must execute the Rust core agreement workflow.",
        "terms": "CLI commands create, mutate, sign, verify, and reconcile agreements.",
        "termsFormat": "text/plain",
        "status": "proposed",
        "parties": [
            {"agentId": agent_id, "agentType": "ai", "role": "signer"}
        ],
        "signaturePolicy": {
            "partyQuorum": "all",
            "witnessRequired": 0,
            "notaryRequired": 0,
            "requiredAlgorithms": ["ring-Ed25519"],
            "minimumStrength": "classical"
        },
        "controllers": [agent_id]
    })
}

fn transcript_ref(index: u8) -> Value {
    json!({
        "jacsId": format!("00000000-0000-4000-8000-{:012}", index),
        "jacsVersion": format!("10000000-0000-4000-8000-{:012}", index),
        "jacsSha256": format!("sha256-test-{}", index)
    })
}

#[test]
fn agreement_v2_cli_executes_full_public_workflow() {
    let dir = TempDir::new().expect("tmpdir");
    bootstrap_agent(&dir);
    let agent_id = configured_agent_id(&dir);

    let input_path = write_json(&dir, "agreement-input.json", &base_input(&agent_id));
    let created =
        output_json_with_paths(&dir, &["agreement-v2", "create", "--input"], &[&input_path]);
    assert_eq!(created["jacsType"], json!("agreement"));

    let created_path = write_json(&dir, "created.json", &created);
    let signed = output_json_with_paths(
        &dir,
        &["agreement-v2", "sign", "--agreement"],
        &[&created_path],
    );
    assert_eq!(signed["agreementSignatures"][0]["role"], json!("signer"));

    let signed_path = write_json(&dir, "signed.json", &signed);
    let report = output_json_with_paths(
        &dir,
        &["agreement-v2", "verify", "--agreement"],
        &[&signed_path],
    );
    assert_eq!(report["valid"], json!(true));
    assert_eq!(report["expectedStatus"], json!("final"));

    let left_mutation = write_json(
        &dir,
        "left-transcript.json",
        &json!({"type": "appendTranscript", "entry": transcript_ref(1)}),
    );
    let right_mutation = write_json(
        &dir,
        "right-transcript.json",
        &json!({"type": "appendTranscript", "entry": transcript_ref(2)}),
    );
    let left = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            left_mutation.to_string_lossy().into_owned(),
        ],
    );
    let right = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            right_mutation.to_string_lossy().into_owned(),
        ],
    );
    let left_path = write_json(&dir, "left.json", &left);
    let right_path = write_json(&dir, "right.json", &right);

    let analysis = output_json(
        &dir,
        &[
            "agreement-v2",
            "detect-conflict",
            "--base",
            created_path.to_str().unwrap(),
            "--left",
            left_path.to_str().unwrap(),
            "--right",
            right_path.to_str().unwrap(),
        ],
    );
    assert_eq!(analysis["autoMergeable"], json!(true));

    let merged = output_json(
        &dir,
        &[
            "agreement-v2",
            "merge-transcript",
            "--base",
            created_path.to_str().unwrap(),
            "--left",
            left_path.to_str().unwrap(),
            "--right",
            right_path.to_str().unwrap(),
        ],
    );
    assert_eq!(merged["transcript"].as_array().unwrap().len(), 2);

    let left_terms_mutation = write_json(
        &dir,
        "left-terms.json",
        &json!({"type": "updateTerms", "terms": "Left terms."}),
    );
    let right_terms_mutation = write_json(
        &dir,
        "right-terms.json",
        &json!({"type": "updateTerms", "terms": "Right terms."}),
    );
    let left_terms = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            left_terms_mutation.to_string_lossy().into_owned(),
        ],
    );
    let right_terms = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            right_terms_mutation.to_string_lossy().into_owned(),
        ],
    );
    let left_terms_path = write_json(&dir, "left-terms-doc.json", &left_terms);
    let right_terms_path = write_json(&dir, "right-terms-doc.json", &right_terms);
    let resolution = write_json(
        &dir,
        "resolution.json",
        &json!({"type": "updateTerms", "terms": "Resolved terms."}),
    );
    let resolved = output_json(
        &dir,
        &[
            "agreement-v2",
            "resolve-conflict",
            "--base",
            created_path.to_str().unwrap(),
            "--previous",
            left_terms_path.to_str().unwrap(),
            "--side",
            right_terms_path.to_str().unwrap(),
            "--mutation",
            resolution.to_str().unwrap(),
        ],
    );
    assert_eq!(resolved["terms"], json!("Resolved terms."));
    assert_eq!(
        resolved["links"][0],
        json!({
            "jacsId": right_terms["jacsId"],
            "jacsVersion": right_terms["jacsVersion"]
        })
    );
}
