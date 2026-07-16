#![cfg(feature = "mcp")]

use assert_cmd::Command;
use jacs_cli::build_cli;
use predicates::prelude::*;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "McpDocumentedLaunch!2026";

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
        "Clap must not synthesize a core value that masks JACS_MCP_PROFILE"
    );
}

#[test]
fn explicit_cli_profile_is_preserved() {
    let matches = build_cli()
        .try_get_matches_from(["jacs", "mcp", "--profile", "full"])
        .expect("mcp command should parse");
    let (_, mcp) = matches.subcommand().expect("mcp subcommand");

    assert_eq!(
        mcp.get_one::<String>("profile").map(String::as_str),
        Some("full")
    );
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
            "invalid MCP profile 'nonsense'; expected 'core' or 'full'",
        ));
}

#[test]
fn environment_profile_is_used_when_cli_flag_is_absent() {
    Command::cargo_bin("jacs")
        .expect("jacs binary")
        .env("RUST_LOG", "info")
        .env("JACS_MCP_PROFILE", "full")
        .env_remove("JACS_CONFIG")
        .arg("mcp")
        .assert()
        .failure()
        .stderr(predicate::str::contains("profile=full"))
        .stderr(predicate::str::contains(
            "JACS_CONFIG environment variable is not set",
        ));
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
            "invalid MCP profile 'nonsense'; expected 'core' or 'full'",
        ))
        .stderr(predicate::str::contains("JACS_CONFIG environment variable").not());
}

#[test]
fn documented_desktop_config_launches_cleanly_with_its_declared_environment() {
    let temp_root = std::env::temp_dir()
        .canonicalize()
        .expect("canonical temp root");
    let directory = TempDir::new_in(temp_root).expect("temp dir");
    Command::cargo_bin("jacs")
        .expect("jacs binary")
        .current_dir(directory.path())
        .env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD)
        .args([
            "quickstart",
            "--name",
            "documented-mcp-launch",
            "--domain",
            "example.test",
            "--algorithm",
            "ed25519",
        ])
        .assert()
        .success();

    let password_file = directory.path().join("jacs-password");
    std::fs::write(&password_file, format!("{TEST_PASSWORD}\n")).expect("password file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only password file");
    }

    let documented = documented_desktop_config();
    let server = &documented["mcpServers"]["jacs"];
    assert_eq!(server["command"], "jacs");
    assert_eq!(server["args"], serde_json::json!(["mcp"]));
    assert!(server["env"]["JACS_CONFIG"].is_string());
    assert!(server["env"]["JACS_PASSWORD_FILE"].is_string());
    assert!(server["env"]["JACS_MCP_BASE_DIR"].is_string());

    let output = Command::cargo_bin("jacs")
        .expect("jacs binary")
        .current_dir(directory.path())
        .env_remove("JACS_PRIVATE_KEY_PASSWORD")
        .env("JACS_CONFIG", directory.path().join("jacs.config.json"))
        .env("JACS_PASSWORD_FILE", &password_file)
        .env("JACS_MCP_BASE_DIR", directory.path())
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
            && !stderr.contains("Failed to load agent"),
        "documented launch reported startup failure: {stderr}"
    );
}
