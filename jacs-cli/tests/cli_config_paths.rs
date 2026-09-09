use assert_cmd::Command;
use jacs::crypt::hash::hash_public_key;
use jacs::keystore::RotationJournal;
use predicates::prelude::*;
use serial_test::serial;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "CliConfigPaths!2026";

fn temp_root() -> TempDir {
    tempfile::Builder::new()
        .prefix("jacs-cli-config-paths-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temp dir"),
        )
        .expect("temp root")
}

fn cmd() -> Command {
    let mut command = Command::cargo_bin("jacs").expect("jacs binary should exist");
    command.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    command.env_remove("JACS_ALLOW_UNSIGNED_AGENT_CONFIG");
    command
}

fn bootstrap_project(root: &TempDir) -> std::path::PathBuf {
    let project = root.path().join("project");
    std::fs::create_dir(&project).expect("create nested project");
    cmd()
        .current_dir(&project)
        .args([
            "quickstart",
            "--name",
            "config-path-test",
            "--domain",
            "example.test",
            "--algorithm",
            "pq2025",
        ])
        .assert()
        .success();
    project
}

#[test]
#[serial]
fn keys_list_resolves_relative_key_directory_from_config_location() {
    let root = temp_root();
    let project = bootstrap_project(&root);

    cmd()
        .current_dir(root.path())
        .args(["agent", "keys-list", "--config", "project/jacs.config.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Active:"))
        .stdout(predicate::str::contains("jacs.public.pem"))
        .stdout(predicate::str::contains("no public key found").not());

    assert!(project.join("jacs_keys/jacs.public.pem").is_file());
}

#[test]
#[serial]
fn repair_resolves_relative_journal_from_config_location() {
    let root = temp_root();
    let project = bootstrap_project(&root);
    let config_path = project.join("jacs.config.json");
    let key_dir = project.join("jacs_keys");

    let stale_config = std::fs::read_to_string(&config_path).expect("read initial config");
    let stale_value: serde_json::Value =
        serde_json::from_str(&stale_config).expect("parse initial config");
    let lookup = stale_value["jacs_agent_id_and_version"]
        .as_str()
        .expect("signed config lookup");
    let (agent_id, old_version) = lookup.split_once(':').expect("agent ID and version");
    let old_public_key =
        std::fs::read(key_dir.join("jacs.public.pem")).expect("read old public key");
    let old_key_hash = hash_public_key(&old_public_key);

    cmd()
        .current_dir(&project)
        .args(["agent", "rotate-keys"])
        .assert()
        .success();

    std::fs::write(&config_path, stale_config).expect("restore stale signed config");
    let mut journal = RotationJournal::create(
        key_dir.to_str().expect("UTF-8 key directory"),
        agent_id,
        old_version,
        &old_key_hash,
        "pq2025",
        config_path.to_str().expect("UTF-8 config path"),
    )
    .expect("create recovery journal");
    journal
        .advance("agent_saved")
        .expect("model crash after rotated agent save");

    cmd()
        .current_dir(root.path())
        .args(["agent", "repair", "--config", "project/jacs.config.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Config repaired successfully"));

    assert!(
        !std::path::Path::new(&RotationJournal::journal_path(
            key_dir.to_str().expect("UTF-8 key directory")
        ))
        .exists(),
        "repair should remove the config-relative journal"
    );
}
