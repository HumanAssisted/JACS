use jacs_cli::{build_cli, generate_a2a_serve_documents, resolve_a2a_serve_origin};
use predicates::prelude::*;
use serial_test::serial;

#[test]
fn a2a_serve_defaults_to_the_exact_loopback_listener_origin() {
    assert_eq!(
        resolve_a2a_serve_origin("127.0.0.1", 8080, None).expect("loopback origin"),
        "http://127.0.0.1:8080"
    );
    assert_eq!(
        resolve_a2a_serve_origin("localhost", 9090, None).expect("localhost origin"),
        "http://localhost:9090"
    );
    assert_eq!(
        resolve_a2a_serve_origin("::1", 7070, None).expect("IPv6 loopback origin"),
        "http://[::1]:7070"
    );
}

#[test]
fn a2a_serve_requires_an_explicit_https_origin_for_non_loopback_bindings() {
    let error = resolve_a2a_serve_origin("0.0.0.0", 8080, None)
        .expect_err("wildcard binding is not a trustworthy discovery origin");
    assert!(error.contains("--origin"), "unexpected error: {error}");

    assert_eq!(
        resolve_a2a_serve_origin("0.0.0.0", 8080, Some("https://agent.example.com:8443/"),)
            .expect("explicit production origin"),
        "https://agent.example.com:8443"
    );
}

#[test]
fn a2a_serve_rejects_ambiguous_or_insecure_explicit_origins() {
    for origin in [
        "http://agent.example.com",
        "https://user:pass@agent.example.com",
        "https://agent.example.com/path",
        "https://agent.example.com?tenant=a",
        "https://agent.example.com#fragment",
        "http://2130706433:8080",
    ] {
        assert!(
            resolve_a2a_serve_origin("127.0.0.1", 8080, Some(origin)).is_err(),
            "origin must fail closed: {origin}"
        );
    }
}

#[test]
fn a2a_server_commands_expose_a_canonical_origin_option() {
    build_cli()
        .try_get_matches_from([
            "jacs",
            "a2a",
            "serve",
            "--origin",
            "https://agent.example.com",
        ])
        .expect("serve accepts --origin");
    build_cli()
        .try_get_matches_from([
            "jacs",
            "a2a",
            "quickstart",
            "--name",
            "origin-test",
            "--domain",
            "agent.example.com",
            "--origin",
            "https://agent.example.com",
        ])
        .expect("quickstart accepts --origin");
}

#[test]
fn public_plaintext_listener_fails_before_agent_or_password_setup() {
    let mut command = assert_cmd::Command::cargo_bin("jacs").expect("jacs binary");
    command
        .args(["a2a", "serve", "--host", "0.0.0.0", "--port", "8080"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--origin https://agent.example.com",
        ));
}

#[test]
#[serial(jacs_env, cwd_env)]
fn generated_card_signs_the_exact_canonical_serving_origin() {
    struct Guard {
        cwd: std::path::PathBuf,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.cwd);
            unsafe {
                std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
            }
        }
    }

    let cwd = std::env::current_dir().expect("cwd");
    let temp = tempfile::tempdir().expect("tempdir");
    std::env::set_current_dir(temp.path()).expect("enter tempdir");
    let _guard = Guard { cwd };
    let password = "A2aCliOriginTest!2026";
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", password);
    }
    let params = jacs::simple::CreateAgentParams::builder()
        .name("cli-origin-test")
        .password(password)
        .domain("https://wrong-origin.example")
        .key_directory("./keys")
        .data_directory("./data")
        .config_path("./jacs.config.json")
        .build();
    let (_simple, _) =
        jacs::simple::SimpleAgent::create_with_params(params).expect("create test agent");
    let config = jacs::config::Config::from_file("./jacs.config.json").expect("read config");
    let mut agent = jacs::agent::Agent::from_config(config, Some(password)).expect("load agent");

    let canonical_origin = "http://127.0.0.1:38080";
    let (_card, documents) = generate_a2a_serve_documents(&mut agent, canonical_origin)
        .expect("generate origin-bound documents");
    let document = |path: &str| {
        documents
            .iter()
            .find(|(candidate, _)| candidate == path)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("missing {path}"))
    };
    let card_value = document("/.well-known/agent-card.json");
    let jwks = document("/.well-known/jwks.json");
    assert_eq!(
        card_value["supportedInterfaces"][0]["url"]
            .as_str()
            .and_then(|url| reqwest::Url::parse(url).ok())
            .map(|url| url.origin().ascii_serialization()),
        Some(canonical_origin.to_string())
    );

    let card: jacs::a2a::AgentCard =
        serde_json::from_value(card_value).expect("decode signed card");
    let jwk: jacs::a2a::keys::Jwk =
        serde_json::from_value(jwks["keys"][0].clone()).expect("decode ES256 JWK");
    let public_pem = jacs::a2a::keys::es256_jwk_public_pem(&jwk).expect("convert JWK");
    assert!(
        jacs::a2a::extension::verify_agent_card_jws(&card, public_pem.as_bytes(), "ES256")
            .expect("verify signed Agent Card"),
        "the canonical interface URL must be inside the verified JWS payload"
    );
}
