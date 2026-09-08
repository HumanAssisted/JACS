#![cfg(feature = "mcp")]

use assert_cmd::Command;
use jacs_cli::build_cli;
use predicates::prelude::*;
use tempfile::TempDir;

fn documented_desktop_config() -> serde_json::Value {
    let readme = include_str!("../../README.md");
    let section = readme
        .split_once("## MCP server")
        .expect("root README MCP section")
        .1;
    let json = section
        .split_once("```json\n")
        .expect("root README desktop JSON fence")
        .1
        .split_once("\n```")
        .expect("root README desktop JSON closing fence")
        .0;
    serde_json::from_str(json).expect("documented desktop config must be valid JSON")
}

#[test]
fn absent_cli_profile_remains_absent_for_environment_resolution() {
    let matches = build_cli()
        .try_get_matches_from(["jacs", "mcp"])
        .expect("mcp command should parse");
    let (_, mcp) = matches.subcommand().expect("mcp subcommand");

    assert!(
        mcp.get_one::<String>("profile").is_none(),
        "Clap must not synthesize a verify-only value that masks JACS_MCP_PROFILE"
    );
}

#[test]
fn explicit_cli_profile_is_preserved() {
    let matches = build_cli()
        .try_get_matches_from(["jacs", "mcp", "--profile", "verify-only"])
        .expect("mcp command should parse");
    let (_, mcp) = matches.subcommand().expect("mcp subcommand");

    assert_eq!(
        mcp.get_one::<String>("profile").map(String::as_str),
        Some("verify-only")
    );
}

#[test]
fn explicit_local_signing_config_is_preserved() {
    let matches = build_cli()
        .try_get_matches_from([
            "jacs",
            "mcp",
            "--profile",
            "local-sign",
            "--config",
            "./jacs.config.json",
        ])
        .expect("explicit local configuration");
    let (_, mcp) = matches.subcommand().unwrap();
    assert_eq!(
        mcp.get_one::<String>("config").map(String::as_str),
        Some("./jacs.config.json")
    );
}

#[test]
fn local_signing_profile_without_config_cannot_start() {
    Command::cargo_bin("jacs")
        .expect("jacs binary")
        .env_remove("JACS_CONFIG")
        .args(["mcp", "--profile", "local-sign"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mcp_local_signing_denied"))
        .stderr(predicate::str::contains("local-sign requires --config"));
}

#[test]
fn invalid_cli_profile_fails_before_agent_loading() {
    Command::cargo_bin("jacs")
        .expect("jacs binary")
        .env_remove("JACS_CONFIG")
        .args(["mcp", "--profile", "nonsense"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mcp_profile_invalid"))
        .stderr(predicate::str::contains(
            "invalid MCP profile 'nonsense'; expected exactly 'verify-only', 'local-sign', 'trust-admin', or 'legacy-core'",
        ));
}

#[test]
fn verify_only_startup_does_not_require_agent_config() {
    Command::cargo_bin("jacs")
        .expect("jacs binary")
        .env("RUST_LOG", "info")
        .env("JACS_MCP_PROFILE", "verify-only")
        .env_remove("JACS_CONFIG")
        .arg("mcp")
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .failure()
        .stderr(predicate::str::contains("profile=verify-only"))
        .stderr(predicate::str::contains("JACS_CONFIG environment variable").not())
        .stderr(predicate::str::contains("Failed to load agent").not());
}

#[test]
fn invalid_environment_profile_fails_before_agent_loading() {
    Command::cargo_bin("jacs")
        .expect("jacs binary")
        .env("JACS_MCP_PROFILE", "nonsense")
        .env_remove("JACS_CONFIG")
        .arg("mcp")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("mcp_profile_invalid"))
        .stderr(predicate::str::contains(
            "invalid MCP profile 'nonsense'; expected exactly 'verify-only', 'local-sign', 'trust-admin', or 'legacy-core'",
        ))
        .stderr(predicate::str::contains("JACS_CONFIG environment variable").not());
}

#[test]
fn documented_desktop_config_launches_without_signing_configuration() {
    let temp_root = std::env::temp_dir()
        .canonicalize()
        .expect("canonical temp root");
    let directory = TempDir::new_in(temp_root).expect("temp dir");
    let documented = documented_desktop_config();
    let server = &documented["mcpServers"]["jacs"];
    assert_eq!(server["command"], "jacs");
    assert_eq!(server["args"], serde_json::json!(["mcp"]));
    assert!(server.get("env").is_none());

    let output = Command::cargo_bin("jacs")
        .expect("jacs binary")
        .current_dir(directory.path())
        .env_remove("JACS_CONFIG")
        .env_remove("JACS_PRIVATE_KEY_PASSWORD")
        .env("RUST_LOG", "info,rmcp=warn")
        .args(["mcp"])
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(30))
        .output()
        .expect("documented MCP launch");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.is_empty(),
        "stdio protocol stdout must stay clean: {stdout}"
    );
    assert!(
        stderr.contains("connection closed: initialized request")
            || stderr.contains("connection closed: initialize request"),
        "documented launch never initialized: {stderr}"
    );
    assert!(
        !stderr.contains("JACS_CONFIG environment variable is not set")
            && !stderr.contains("Config file not found")
            && !stderr.contains("Failed to load agent")
            && !stderr.contains("must-not-be-read"),
        "documented launch reported startup failure: {stderr}"
    );
}
