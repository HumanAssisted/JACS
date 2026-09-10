use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "DocumentCreateTest!2026";

fn cmd() -> Command {
    let mut command = Command::cargo_bin("jacs").expect("jacs binary should exist");
    command.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    command
}

fn bootstrap_agent(directory: &TempDir) {
    cmd()
        .current_dir(directory.path())
        .args([
            "quickstart",
            "--name",
            "document-create-test",
            "--domain",
            "example.test",
            "--algorithm",
            "ed25519",
        ])
        .assert()
        .success();
}

#[test]
fn document_create_requires_an_input_at_parse_time() {
    cmd()
        .args(["document", "create"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required arguments"))
        .stderr(predicate::str::contains("-f <filename>"));
}

#[test]
#[serial]
fn document_create_missing_file_is_clean_failure_not_panic() {
    let directory = TempDir::new().expect("temp dir");
    bootstrap_agent(&directory);

    cmd()
        .current_dir(directory.path())
        .args(["document", "create", "-f", "missing.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to load document file"))
        .stderr(predicate::str::contains("panicked").not());
}

#[test]
#[serial]
fn document_create_reports_saved_path_and_that_path_verifies() {
    let directory = TempDir::new().expect("temp dir");
    bootstrap_agent(&directory);
    std::fs::write(
        directory.path().join("input.json"),
        r#"{"action":"approve"}"#,
    )
    .expect("write input");

    let output = cmd()
        .current_dir(directory.path())
        .args(["document", "create", "-f", "input.json", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).expect("JSON result");
    assert_eq!(result["status"], "created");
    let saved_path = result["documents"][0]["saved_path"]
        .as_str()
        .expect("saved path");
    assert!(
        directory.path().join(saved_path).is_file(),
        "reported path must exist: {saved_path}"
    );

    cmd()
        .current_dir(directory.path())
        .args(["verify", saved_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    cmd()
        .current_dir(directory.path())
        .args([
            "document",
            "create",
            "-f",
            "input.json",
            "--output",
            "signed-document.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Saved signed document: jacs_data/signed-document.json",
        ));
}

#[test]
fn documented_quickstarts_verify_the_path_document_create_writes() {
    let documented_create = "jacs document create -f mydata.json --output signed-document.json";
    let documented_verify = "jacs verify jacs_data/signed-document.json";
    let readmes = [
        ("README.md", include_str!("../../README.md")),
        ("jacs/README.md", include_str!("../../jacs/README.md")),
        ("jacs-cli/README.md", include_str!("../README.md")),
    ];

    for (path, readme) in readmes {
        assert!(
            readme.contains(documented_create),
            "{path} must document the canonical create command"
        );
        assert!(
            readme.contains(documented_verify),
            "{path} must verify the path emitted by document create"
        );
    }
}
