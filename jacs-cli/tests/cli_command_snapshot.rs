//! CLI command parity snapshot test.
//!
//! Validates that `jacs-cli/contract/cli_commands.json` accurately lists all
//! CLI commands. If a command is added to or removed from the CLI without
//! updating the fixture, this test fails.
//!
//! This is the CLI equivalent of the MCP contract snapshot test.

use serde_json::Value;

fn load_cli_commands_fixture() -> Value {
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/contract/cli_commands.json");
    let data = std::fs::read_to_string(fixture_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read cli_commands.json at {}: {}",
            fixture_path, e
        )
    });
    serde_json::from_str(&data).expect("cli_commands.json should be valid JSON")
}

/// Hardcoded list of all CLI command paths.
///
/// This MUST be updated when a command is added to or removed from
/// `jacs-cli/src/main.rs`. It serves as a compile-time anchor.
fn known_command_paths() -> Vec<&'static str> {
    let mut paths = vec![
        "version",
        "config create",
        "config read",
        "agent dns",
        "agent create",
        "agent verify",
        "agent lookup",
        "task create",
        "document create",
        "document update",
        "document check-agreement",
        "document create-agreement",
        "document sign-agreement",
        "document verify",
        "document extract",
        "key reencrypt",
        "mcp",
        "a2a assess",
        "a2a trust",
        "a2a discover",
        "a2a serve",
        "a2a quickstart",
        "quickstart",
        "init",
        "attest create",
        "attest verify",
        "attest export-dsse",
        "verify",
        "convert",
    ];
    paths.sort();
    paths
}

/// Hardcoded list of feature-gated command paths.
fn known_feature_gated_paths() -> Vec<&'static str> {
    let mut paths = vec![
        "keychain set",
        "keychain get",
        "keychain delete",
        "keychain status",
    ];
    paths.sort();
    paths
}

#[test]
fn test_cli_commands_snapshot_matches_fixture() {
    let fixture = load_cli_commands_fixture();

    // Extract command paths from fixture
    let mut fixture_paths: Vec<String> = fixture["commands"]
        .as_array()
        .expect("commands should be an array")
        .iter()
        .map(|cmd| {
            cmd["path"]
                .as_str()
                .expect("path should be a string")
                .to_string()
        })
        .collect();
    fixture_paths.sort();

    let known = known_command_paths();
    let known_strings: Vec<String> = known.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        fixture_paths,
        known_strings,
        "\nCLI commands fixture does not match known commands.\n\
         \nFixture has {} commands, known list has {} commands.\n\
         \nIn fixture but not in known: {:?}\n\
         In known but not in fixture: {:?}\n\
         \nIf you added a CLI command, update BOTH:\n\
         1. jacs-cli/contract/cli_commands.json\n\
         2. The known_command_paths() list in jacs-cli/tests/cli_command_snapshot.rs",
        fixture_paths.len(),
        known_strings.len(),
        fixture_paths
            .iter()
            .filter(|p| !known_strings.contains(p))
            .collect::<Vec<_>>(),
        known_strings
            .iter()
            .filter(|p| !fixture_paths.contains(p))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn test_cli_feature_gated_commands_snapshot() {
    let fixture = load_cli_commands_fixture();

    let mut fixture_paths: Vec<String> = fixture["feature_gated_commands"]
        .as_array()
        .expect("feature_gated_commands should be an array")
        .iter()
        .map(|cmd| {
            cmd["path"]
                .as_str()
                .expect("path should be a string")
                .to_string()
        })
        .collect();
    fixture_paths.sort();

    let known = known_feature_gated_paths();
    let known_strings: Vec<String> = known.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        fixture_paths,
        known_strings,
        "\nFeature-gated commands fixture does not match known commands.\n\
         \nIn fixture but not in known: {:?}\n\
         In known but not in fixture: {:?}",
        fixture_paths
            .iter()
            .filter(|p| !known_strings.contains(p))
            .collect::<Vec<_>>(),
        known_strings
            .iter()
            .filter(|p| !fixture_paths.contains(p))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn test_cli_commands_fixture_count() {
    let fixture = load_cli_commands_fixture();

    let commands = fixture["commands"]
        .as_array()
        .expect("commands should be an array");
    assert_eq!(
        commands.len(),
        29,
        "CLI should have exactly 29 commands. Found {}. \
         If you added or removed a command, update cli_commands.json.",
        commands.len()
    );

    let feature_gated = fixture["feature_gated_commands"]
        .as_array()
        .expect("feature_gated_commands should be an array");
    assert_eq!(
        feature_gated.len(),
        4,
        "CLI should have exactly 4 feature-gated commands. Found {}.",
        feature_gated.len()
    );
}

#[test]
fn test_cli_commands_fixture_structure() {
    let fixture = load_cli_commands_fixture();

    assert_eq!(
        fixture["schema_version"].as_i64().unwrap(),
        1,
        "schema_version should be 1"
    );
    assert_eq!(
        fixture["cli_name"].as_str().unwrap(),
        "jacs",
        "cli_name should be 'jacs'"
    );

    // Every command should have path and about
    for cmd in fixture["commands"].as_array().unwrap() {
        assert!(
            cmd["path"].as_str().is_some(),
            "command missing 'path': {:?}",
            cmd
        );
        assert!(
            cmd["about"].as_str().is_some(),
            "command missing 'about': {:?}",
            cmd
        );
    }

    // Every feature-gated command should have path, feature, and about
    for cmd in fixture["feature_gated_commands"].as_array().unwrap() {
        assert!(
            cmd["path"].as_str().is_some(),
            "feature-gated command missing 'path': {:?}",
            cmd
        );
        assert!(
            cmd["feature"].as_str().is_some(),
            "feature-gated command missing 'feature': {:?}",
            cmd
        );
        assert!(
            cmd["about"].as_str().is_some(),
            "feature-gated command missing 'about': {:?}",
            cmd
        );
    }
}
