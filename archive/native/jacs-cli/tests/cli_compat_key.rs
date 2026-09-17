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

/// Run `jacs init` end-to-end in `dir`. Empty stdin (EOF) drives every
/// interactive prompt to its default (pq2025 algorithm, ./jacs_keys key
/// dir); the password comes from JACS_PRIVATE_KEY_PASSWORD; `--yes` skips
/// the config-update confirmation.
fn run_init(dir: &TempDir, extra_args: &[&str]) -> assert_cmd::assert::Assert {
    let mut args = vec!["init", "--yes"];
    args.extend_from_slice(extra_args);
    cmd()
        .current_dir(dir.path())
        .args(&args)
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(120))
        .assert()
}

/// Issue 019: behavioral (not help-text) coverage of the `--no-compat-key`
/// wiring through the real binary: the ES256 key files and the
/// `ecosystem_signing` keyring role must be absent, while the native root
/// keys exist as usual.
#[test]
#[serial]
fn init_no_compat_key_skips_es256_key() {
    let dir = TempDir::new().unwrap();
    run_init(&dir, &["--no-compat-key"]).success();

    // Native root keys exist (default filenames from `jacs init`).
    assert!(
        dir.path().join("jacs_keys/jacs.private.pem.enc").exists(),
        "init must still create the native private key"
    );
    assert!(
        dir.path().join("jacs_keys/jacs.public.pem").exists(),
        "init must still create the native public key"
    );

    // ES256 compat key files must be absent.
    assert!(
        !dir.path()
            .join("jacs_keys/jacs.ecosystem.private.pem.enc")
            .exists(),
        "--no-compat-key must skip the encrypted ES256 private key"
    );
    assert!(
        !dir.path()
            .join("jacs_keys/jacs.ecosystem.public.pem")
            .exists(),
        "--no-compat-key must skip the ES256 public key"
    );

    // Keyring must have no ecosystem_signing role entry (the file is not
    // written at all on this path today, but the invariant is the role).
    let keyring_path = dir.path().join("jacs_keys/jacs.keyring.json");
    if keyring_path.exists() {
        let keyring = std::fs::read_to_string(&keyring_path).expect("keyring readable");
        assert!(
            !keyring.contains("ecosystem_signing"),
            "--no-compat-key must not record an ecosystem_signing role; keyring: {}",
            keyring
        );
    }
}

/// Issue 019: `jacs init` must tell the user what keys they now hold — a
/// summary naming the pq2025 native root and the ES256 ecosystem
/// compatibility key with its kid (the kid recorded in the keyring).
#[test]
#[serial]
fn init_outputs_pq_root_and_es256_compatibility_summary() {
    let dir = TempDir::new().unwrap();
    let assert = run_init(&dir, &[]).success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();

    for expected in ["native_root", "pq2025", "ecosystem_signing", "ES256"] {
        assert!(
            stdout.contains(expected),
            "init summary must mention '{}'; stdout:\n{}",
            expected,
            stdout
        );
    }

    // The kid shown to the user must be the one recorded in the keyring.
    let keyring: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("jacs_keys/jacs.keyring.json"))
            .expect("keyring exists after plain init"),
    )
    .expect("keyring parses");
    let eco_kid = keyring["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .find(|k| k["role"] == "ecosystem_signing")
        .expect("ecosystem_signing entry")["kid"]
        .as_str()
        .expect("kid string")
        .to_string();
    assert!(
        stdout.contains(&eco_kid),
        "init summary must show the ES256 kid {}; stdout:\n{}",
        eco_kid,
        stdout
    );
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
