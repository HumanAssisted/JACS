use assert_cmd::Command;
use jacs_cli::build_cli;
use serial_test::serial;

const TEST_PASSWORD: &str = "AlgorithmLabels!2026";

fn assert_parses(args: &[&str]) {
    build_cli()
        .try_get_matches_from(args)
        .unwrap_or_else(|error| panic!("CLI should accept {args:?}: {error}"));
}

#[test]
fn quickstart_surfaces_accept_consistent_algorithm_labels() {
    for algorithm in ["pq2025", "ed25519", "ring-Ed25519"] {
        assert_parses(&[
            "jacs",
            "quickstart",
            "--name",
            "test",
            "--domain",
            "example.test",
            "--algorithm",
            algorithm,
        ]);
        assert_parses(&[
            "jacs",
            "a2a",
            "quickstart",
            "--name",
            "test",
            "--domain",
            "example.test",
            "--algorithm",
            algorithm,
        ]);
    }
}

fn assert_quickstart_emits_requested_algorithm(
    requested: &str,
    expected: &str,
    expected_public_key_bytes: usize,
) {
    let directory = tempfile::Builder::new()
        .prefix("jacs-cli-algorithm-label-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temp dir"),
        )
        .expect("temporary quickstart directory");
    let mut command = Command::cargo_bin("jacs").expect("jacs binary should exist");
    command
        .current_dir(directory.path())
        .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
        .env_remove("JACS_CONFIG")
        .env_remove("JACS_DATA_DIRECTORY")
        .env_remove("JACS_KEY_DIRECTORY")
        .env_remove("JACS_AGENT_KEY_ALGORITHM")
        .env_remove("JACS_ALLOW_UNSIGNED_AGENT_CONFIG")
        .args([
            "quickstart",
            "--name",
            "algorithm-label-test",
            "--domain",
            "example.test",
            "--algorithm",
            requested,
            "--sign",
        ])
        .write_stdin(r#"{"probe":true}"#);

    let output = command.output().expect("run jacs quickstart");
    assert!(
        output.status.success(),
        "quickstart {requested} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("signed JSON on stdout");
    assert_eq!(
        signed["jacsSignature"]["signingAlgorithm"], expected,
        "CLI signature metadata must match the requested algorithm"
    );

    let config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.path().join("jacs.config.json")).expect("signed config"),
    )
    .expect("config JSON");
    assert_eq!(
        config["jacs_agent_key_algorithm"], expected,
        "persisted key metadata must match the signature algorithm"
    );
    let key_directory = config["jacs_key_directory"]
        .as_str()
        .expect("config key directory");
    let public_key_filename = config["jacs_agent_public_key_filename"]
        .as_str()
        .expect("config public-key filename");
    let public_key = std::fs::read(
        directory
            .path()
            .join(key_directory)
            .join(public_key_filename),
    )
    .expect("configured public key");
    assert_eq!(
        public_key.len(),
        expected_public_key_bytes,
        "configured public-key shape must match the requested algorithm"
    );
}

#[test]
#[serial]
fn quickstart_ed25519_emits_ring_ed25519_metadata() {
    assert_quickstart_emits_requested_algorithm("ed25519", "ring-Ed25519", 32);
}

#[test]
#[serial]
fn quickstart_ring_ed25519_alias_emits_ring_ed25519_metadata() {
    assert_quickstart_emits_requested_algorithm("ring-Ed25519", "ring-Ed25519", 32);
}

#[test]
#[serial]
fn quickstart_pq2025_emits_pq2025_metadata() {
    assert_quickstart_emits_requested_algorithm("pq2025", "pq2025", 2592);
}
