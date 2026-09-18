//! CLI-MCP alignment parity test.
//!
//! Validates that `binding-core/tests/fixtures/cli_mcp_alignment.json`
//! accounts for every CLI command (from `jacs-cli/contract/cli_commands.json`)
//! and every MCP tool (from `jacs-mcp/contract/jacs-mcp-contract.json`).
//!
//! If a CLI command or MCP tool is added without updating the alignment
//! fixture, this test fails. This ensures the CLI-MCP boundary is
//! explicitly documented and tracked.

use serde_json::Value;
use std::collections::HashSet;

fn load_alignment_fixture() -> Value {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/cli_mcp_alignment.json"
    );
    let data = std::fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read cli_mcp_alignment.json: {}", e));
    serde_json::from_str(&data).expect("cli_mcp_alignment.json should be valid JSON")
}

fn load_cli_commands_fixture() -> Value {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../jacs-cli/contract/cli_commands.json"
    );
    let data = std::fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read cli_commands.json: {}", e));
    serde_json::from_str(&data).expect("cli_commands.json should be valid JSON")
}

fn load_mcp_contract() -> Value {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../jacs-mcp/contract/jacs-mcp-contract.json"
    );
    let data = std::fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read jacs-mcp-contract.json: {}", e));
    serde_json::from_str(&data).expect("jacs-mcp-contract.json should be valid JSON")
}

/// Every CLI command from cli_commands.json must appear in either
/// `alignments[].cli_command` or `cli_only[].cli_command` in the
/// alignment fixture.
#[test]
fn test_all_cli_commands_are_in_alignment_fixture() {
    let alignment = load_alignment_fixture();
    let cli = load_cli_commands_fixture();

    // Collect all CLI commands from the fixture
    let mut cli_commands: HashSet<String> = HashSet::new();
    for cmd in cli["commands"].as_array().expect("commands array") {
        cli_commands.insert(cmd["path"].as_str().unwrap().to_string());
    }

    // Collect CLI commands referenced in alignment fixture
    let mut alignment_cli: HashSet<String> = HashSet::new();

    // From alignments (paired commands)
    for entry in alignment["alignments"]
        .as_array()
        .expect("alignments array")
    {
        alignment_cli.insert(entry["cli_command"].as_str().unwrap().to_string());
    }

    // From cli_only
    for entry in alignment["cli_only"].as_array().expect("cli_only array") {
        alignment_cli.insert(entry["cli_command"].as_str().unwrap().to_string());
    }

    let missing: Vec<&String> = cli_commands.difference(&alignment_cli).collect();
    let extra: Vec<&String> = alignment_cli.difference(&cli_commands).collect();

    assert!(
        missing.is_empty(),
        "CLI commands in cli_commands.json but NOT in cli_mcp_alignment.json: {:?}\n\
         Add them to either 'alignments' or 'cli_only' in the alignment fixture.",
        missing
    );
    assert!(
        extra.is_empty(),
        "CLI commands in cli_mcp_alignment.json but NOT in cli_commands.json: {:?}\n\
         Remove stale entries from the alignment fixture.",
        extra
    );
}

/// Every feature-gated CLI command must appear in `cli_only_feature_gated[]`.
#[test]
fn test_all_feature_gated_cli_commands_are_in_alignment_fixture() {
    let alignment = load_alignment_fixture();
    let cli = load_cli_commands_fixture();

    let mut cli_gated: HashSet<String> = HashSet::new();
    for cmd in cli["feature_gated_commands"]
        .as_array()
        .expect("feature_gated_commands array")
    {
        cli_gated.insert(cmd["path"].as_str().unwrap().to_string());
    }

    let mut alignment_gated: HashSet<String> = HashSet::new();
    for entry in alignment["cli_only_feature_gated"]
        .as_array()
        .expect("cli_only_feature_gated array")
    {
        alignment_gated.insert(entry["cli_command"].as_str().unwrap().to_string());
    }

    let missing: Vec<&String> = cli_gated.difference(&alignment_gated).collect();
    let extra: Vec<&String> = alignment_gated.difference(&cli_gated).collect();

    assert!(
        missing.is_empty(),
        "Feature-gated CLI commands not in alignment fixture: {:?}",
        missing
    );
    assert!(
        extra.is_empty(),
        "Stale feature-gated entries in alignment fixture: {:?}",
        extra
    );
}

/// Every MCP tool from jacs-mcp-contract.json must appear in either
/// `alignments[].mcp_tool` or `mcp_only[].mcp_tool`.
#[test]
fn test_all_mcp_tools_are_in_alignment_fixture() {
    let alignment = load_alignment_fixture();
    let mcp = load_mcp_contract();

    // Collect all MCP tools from the contract
    let mut mcp_tools: HashSet<String> = HashSet::new();
    for tool in mcp["tools"].as_array().expect("tools array") {
        mcp_tools.insert(tool["name"].as_str().unwrap().to_string());
    }

    // Collect MCP tools referenced in alignment fixture
    let mut alignment_mcp: HashSet<String> = HashSet::new();

    // From alignments (paired tools)
    for entry in alignment["alignments"]
        .as_array()
        .expect("alignments array")
    {
        alignment_mcp.insert(entry["mcp_tool"].as_str().unwrap().to_string());
    }

    // From mcp_only
    for entry in alignment["mcp_only"].as_array().expect("mcp_only array") {
        alignment_mcp.insert(entry["mcp_tool"].as_str().unwrap().to_string());
    }

    let missing: Vec<&String> = mcp_tools.difference(&alignment_mcp).collect();
    let extra: Vec<&String> = alignment_mcp.difference(&mcp_tools).collect();

    assert!(
        missing.is_empty(),
        "MCP tools in jacs-mcp-contract.json but NOT in cli_mcp_alignment.json: {:?}\n\
         Add them to either 'alignments' or 'mcp_only' in the alignment fixture.",
        missing
    );
    assert!(
        extra.is_empty(),
        "MCP tools in cli_mcp_alignment.json but NOT in jacs-mcp-contract.json: {:?}\n\
         Remove stale entries from the alignment fixture.",
        extra
    );
}

/// Summary counts in the fixture must be accurate.
#[test]
fn test_alignment_summary_counts_are_accurate() {
    let alignment = load_alignment_fixture();
    let summary = &alignment["summary"];

    let alignments_count = alignment["alignments"]
        .as_array()
        .expect("alignments array")
        .len();
    let cli_only_count = alignment["cli_only"]
        .as_array()
        .expect("cli_only array")
        .len();
    let cli_only_gated_count = alignment["cli_only_feature_gated"]
        .as_array()
        .expect("cli_only_feature_gated array")
        .len();
    let mcp_only_arr = alignment["mcp_only"].as_array().expect("mcp_only array");
    let mcp_only_count = mcp_only_arr.len();

    let mcp_only_intentional = mcp_only_arr
        .iter()
        .filter(|e| e["classification"].as_str() == Some("intentional"))
        .count();
    let mcp_only_gap = mcp_only_arr
        .iter()
        .filter(|e| e["classification"].as_str() == Some("gap"))
        .count();

    assert_eq!(
        summary["aligned_pairs"].as_u64().unwrap() as usize,
        alignments_count,
        "summary.aligned_pairs does not match alignments array length"
    );
    assert_eq!(
        summary["cli_only_count"].as_u64().unwrap() as usize,
        cli_only_count,
        "summary.cli_only_count does not match cli_only array length"
    );
    assert_eq!(
        summary["cli_only_feature_gated_count"].as_u64().unwrap() as usize,
        cli_only_gated_count,
        "summary.cli_only_feature_gated_count does not match"
    );
    assert_eq!(
        summary["mcp_only_count"].as_u64().unwrap() as usize,
        mcp_only_count,
        "summary.mcp_only_count does not match mcp_only array length"
    );
    assert_eq!(
        summary["mcp_only_intentional"].as_u64().unwrap() as usize,
        mcp_only_intentional,
        "summary.mcp_only_intentional does not match actual count"
    );
    assert_eq!(
        summary["mcp_only_gap"].as_u64().unwrap() as usize,
        mcp_only_gap,
        "summary.mcp_only_gap does not match actual count"
    );
}

/// Every MCP-only entry must have a valid classification.
#[test]
fn test_mcp_only_entries_have_valid_classification() {
    let alignment = load_alignment_fixture();
    let valid_classifications = ["intentional", "gap"];

    for entry in alignment["mcp_only"].as_array().expect("mcp_only array") {
        let tool = entry["mcp_tool"].as_str().unwrap();
        let classification = entry["classification"]
            .as_str()
            .unwrap_or_else(|| panic!("MCP-only tool {} missing 'classification' field", tool));
        assert!(
            valid_classifications.contains(&classification),
            "MCP-only tool {} has invalid classification '{}'. Must be one of: {:?}",
            tool,
            classification,
            valid_classifications
        );
        assert!(
            entry["reason"].as_str().is_some() && !entry["reason"].as_str().unwrap().is_empty(),
            "MCP-only tool {} missing 'reason' field",
            tool
        );
    }
}
