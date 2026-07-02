//! P2 Task 002 — CLI surface for the ES256 ecosystem compatibility key.
//!
//! New agents (quickstart/init/create) mint the compat key eagerly; the
//! `--no-compat-key` flag opts out; existing agents migrate explicitly via
//! `jacs agent add-compat-key` (loading never creates keys).

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestCompatKey!2026";

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
            "compat-key-cli-test",
            "--domain",
            "localhost",
        ])
        .assert()
        .success();
}

#[test]
#[serial]
fn quickstart_creates_compat_key_eagerly() {
    let dir = TempDir::new().unwrap();
    bootstrap_agent(&dir);

    assert!(
        dir.path()
            .join("jacs_keys/jacs.ecosystem.private.pem.enc")
            .exists(),
        "quickstart must mint the encrypted ES256 compat key"
    );
    assert!(
        dir.path()
            .join("jacs_keys/jacs.ecosystem.public.pem")
            .exists()
    );
    let keyring =
        std::fs::read_to_string(dir.path().join("jacs_keys/jacs.keyring.json")).expect("keyring");
    assert!(keyring.contains("ecosystem_signing"));
    assert!(keyring.contains("native_root"));
}

#[test]
#[serial]
fn agent_add_compat_key_migrates_existing_agent() {
    let dir = TempDir::new().unwrap();
    bootstrap_agent(&dir);

    // Simulate a pre-P2 agent: strip the compat key + keyring.
    for f in [
        "jacs_keys/jacs.ecosystem.private.pem.enc",
        "jacs_keys/jacs.ecosystem.public.pem",
        "jacs_keys/jacs.keyring.json",
    ] {
        let _ = std::fs::remove_file(dir.path().join(f));
    }

    cmd()
        .current_dir(dir.path())
        .args(["agent", "add-compat-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Ecosystem compatibility key added",
        ))
        .stdout(predicate::str::contains("ES256"));

    assert!(
        dir.path()
            .join("jacs_keys/jacs.ecosystem.private.pem.enc")
            .exists(),
        "migration writes the encrypted ES256 key"
    );
}

#[test]
#[serial]
fn duplicate_add_compat_key_fails_with_typed_error() {
    let dir = TempDir::new().unwrap();
    bootstrap_agent(&dir);

    cmd()
        .current_dir(dir.path())
        .args(["agent", "add-compat-key"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn no_compat_key_flag_is_exposed_on_init_and_create() {
    cmd()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--no-compat-key"));
    cmd()
        .args(["agent", "create", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--no-compat-key"));
    cmd()
        .args(["agent", "add-compat-key", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("explicit migration"));
}
