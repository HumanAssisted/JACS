//! CLI command parity snapshot test.
//!
//! Validates that `jacs-cli/contract/cli_commands.json` accurately lists all
//! CLI commands. If a command is added to or removed from the CLI without
//! updating the fixture, this test fails.
//!
//! This test extracts commands programmatically from the Clap `Command` tree
//! via `build_cli()`, so adding a new subcommand in `main.rs` without
//! updating the fixture is caught automatically -- no hardcoded list to
//! maintain.
//!
//! This is the CLI equivalent of the MCP contract snapshot test.

use clap::Command;
use jacs_cli::build_cli;
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

/// Extract all command paths from the Clap tree built by `build_cli()`.
///
/// Skips hidden (deprecated) subcommands. Feature-gated commands (like
/// keychain) are separated into a second return value so that the fixture's
/// `commands` vs `feature_gated_commands` can be validated independently.
fn extract_clap_command_paths() -> Vec<String> {
    let cli = build_cli();
    let mut paths = Vec::new();

    // Commands that belong in the feature_gated_commands section of the fixture.
    // When compiled with the feature, they appear in the Clap tree, but the
    // fixture tracks them separately.
    let feature_gated_parents: std::collections::HashSet<&str> =
        ["keychain"].iter().copied().collect();

    for sub in cli.get_subcommands() {
        let name = sub.get_name();

        // Skip feature-gated parent commands (tracked separately in fixture)
        if feature_gated_parents.contains(name) {
            continue;
        }

        // Collect visible (non-hidden) children
        let visible_children: Vec<&Command> = sub
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .collect();

        if visible_children.is_empty() {
            // Leaf command or command with only hidden subcommands
            // (e.g., "mcp" has hidden deprecated install/run)
            paths.push(name.to_string());
        } else {
            // Has visible subcommands (e.g., "config create", "config read")
            for child in visible_children {
                paths.push(format!("{} {}", name, child.get_name()));
            }
        }
    }

    paths.sort();
    paths
}

#[test]
fn test_cli_commands_fixture_matches_clap_tree() {
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

    let clap_paths = extract_clap_command_paths();

    assert_eq!(
        fixture_paths,
        clap_paths,
        "\nCLI commands fixture does not match the actual Clap command tree.\n\
         \nFixture has {} commands, Clap tree has {} commands.\n\
         \nIn fixture but not in Clap tree: {:?}\n\
         In Clap tree but not in fixture: {:?}\n\
         \nIf you added a CLI command, update jacs-cli/contract/cli_commands.json",
        fixture_paths.len(),
        clap_paths.len(),
        fixture_paths
            .iter()
            .filter(|p| !clap_paths.contains(p))
            .collect::<Vec<_>>(),
        clap_paths
            .iter()
            .filter(|p| !fixture_paths.contains(p))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn test_cli_feature_gated_commands_in_fixture() {
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

    // Feature-gated commands (keychain) are only in the Clap tree when
    // compiled with --features keychain. We can't test them programmatically
    // without that feature, so we validate the fixture has the expected set.
    //
    // When the keychain feature IS enabled at compile time, the commands
    // will also appear in the Clap tree and be caught by the main test above.
    let mut expected = vec![
        "keychain set",
        "keychain get",
        "keychain delete",
        "keychain status",
    ];
    expected.sort();
    let expected_strings: Vec<String> = expected.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        fixture_paths,
        expected_strings,
        "\nFeature-gated commands fixture does not match expected.\n\
         \nIn fixture but not expected: {:?}\n\
         Expected but not in fixture: {:?}",
        fixture_paths
            .iter()
            .filter(|p| !expected_strings.contains(p))
            .collect::<Vec<_>>(),
        expected_strings
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

    // Count should match what the Clap tree produces
    let clap_count = extract_clap_command_paths().len();
    assert_eq!(
        commands.len(),
        clap_count,
        "Fixture has {} commands but Clap tree has {}. Update cli_commands.json.",
        commands.len(),
        clap_count
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
