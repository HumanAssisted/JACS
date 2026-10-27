use jacs_cli::build_cli;
use predicates::prelude::*;
use serde_json::Value;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "A2aAlgorithmTest!2026";

fn command(directory: &std::path::Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("jacs-compat"));
    command
        .current_dir(directory)
        .env("JACS_PRIVATE_KEY_PASSWORD", PASSWORD)
        .env_remove("JACS_CONFIG")
        .env_remove("JACS_DATA_DIRECTORY")
        .env_remove("JACS_KEY_DIRECTORY")
        .env_remove("JACS_AGENT_KEY_ALGORITHM")
        .env_remove("JACS_ALLOW_UNSIGNED_AGENT_CONFIG");
    command
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn served_discovery(directory: &std::path::Path, args: &[&str], algorithm: &str) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let stderr = tempfile::NamedTempFile::new().expect("server stderr");
    let mut server = Server(
        command(directory)
            .args(args)
            .args(["--port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .expect("start A2A server"),
    );
    let origin = format!("http://127.0.0.1:{port}");
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let card: Value = loop {
        if let Ok(response) = client
            .get(format!("{origin}/.well-known/agent-card.json"))
            .send()
        {
            break response.error_for_status().unwrap().json().unwrap();
        }
        assert!(
            server.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "A2A server failed to become ready: {}",
            std::fs::read_to_string(stderr.path()).unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let jwks: Value = client
        .get(format!("{origin}/.well-known/jwks.json"))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(jwks["keys"][0]["alg"], algorithm);
    assert!(
        card["supportedInterfaces"][0]["url"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{origin}/agent/"))
    );
    let signed: jacs::a2a::AgentCard = serde_json::from_value(card.clone()).unwrap();
    let jwk: jacs::a2a::keys::Jwk = serde_json::from_value(jwks["keys"][0].clone()).unwrap();
    let public_key = if algorithm == "ES256" {
        jacs::a2a::keys::es256_jwk_public_pem(&jwk)
            .unwrap()
            .into_bytes()
    } else {
        jacs::a2a::keys::mldsa87_jwk_public_key(&jwk).unwrap()
    };
    assert!(jacs::a2a::extension::verify_agent_card_jws(&signed, &public_key, algorithm).unwrap());
    let binding = client
        .get(format!("{origin}/.well-known/jacs-compat-binding.json"))
        .send()
        .unwrap();
    if algorithm == "ES256" {
        let binding: Value = binding.error_for_status().unwrap().json().unwrap();
        assert_eq!(binding["jacsSignature"]["signingAlgorithm"], "ring-Ed25519");
        assert_eq!(
            card["metadata"]["jacsCompatBindingHash"],
            binding["jacsSha256"]
        );
    } else {
        assert_eq!(binding.status(), reqwest::StatusCode::NOT_FOUND);
        assert!(card["metadata"].get("jacsCompatKid").is_none());
    }
}

#[test]
fn both_server_commands_default_to_pq_and_accept_only_explicit_supported_algorithms() {
    for mut args in [
        vec!["jacs", "a2a", "serve"],
        vec![
            "jacs",
            "a2a",
            "quickstart",
            "--name",
            "test",
            "--domain",
            "example.test",
        ],
    ] {
        let parsed = build_cli().try_get_matches_from(&args).unwrap();
        let (_, leaf) = parsed.subcommand().unwrap().1.subcommand().unwrap();
        assert_eq!(
            leaf.get_one::<String>("a2a-algorithm").unwrap(),
            "ML-DSA-87"
        );
        args.push("--a2a-algorithm");
        for algorithm in ["ML-DSA-87", "ES256"] {
            let mut selected = args.clone();
            selected.push(algorithm);
            build_cli().try_get_matches_from(selected).unwrap();
        }
        for algorithm in ["EdDSA", "ed25519", "RS256", "invalid"] {
            let mut invalid = args.clone();
            invalid.push(algorithm);
            let error = build_cli().try_get_matches_from(invalid).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
            assert!(error.to_string().contains("--a2a-algorithm"));
        }
    }
}

#[test]
fn default_quickstart_and_serve_publish_verified_pq_discovery() {
    let directory = tempfile::tempdir().unwrap();
    served_discovery(
        directory.path(),
        &[
            "a2a",
            "quickstart",
            "--name",
            "pq-server",
            "--domain",
            "example.test",
        ],
        "ML-DSA-87",
    );
    served_discovery(directory.path(), &["a2a", "serve"], "ML-DSA-87");
}

#[test]
fn classical_root_requires_explicit_es256_for_quickstart_and_serve() {
    use assert_cmd::assert::OutputAssertExt;
    let directory = tempfile::tempdir().unwrap();
    let quickstart = [
        "a2a",
        "quickstart",
        "--name",
        "classical-server",
        "--domain",
        "example.test",
        "--algorithm",
        "ed25519",
    ];
    for args in [&quickstart[..], &["a2a", "serve"][..]] {
        command(directory.path())
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("requires a loaded pq2025 root"))
            .stderr(predicate::str::contains("--a2a-algorithm ES256"));
    }
    let mut explicit = quickstart.to_vec();
    explicit.extend(["--a2a-algorithm", "ES256"]);
    served_discovery(directory.path(), &explicit, "ES256");
    served_discovery(
        directory.path(),
        &["a2a", "serve", "--a2a-algorithm", "ES256"],
        "ES256",
    );
    // Persisted compatibility artifacts must not opt later invocations into ES256.
    command(directory.path())
        .args(["a2a", "serve"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires a loaded pq2025 root"));
}
