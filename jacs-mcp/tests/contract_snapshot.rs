#![cfg(feature = "mcp")]

use jacs_mcp::{JacsMcpContractSnapshot, canonical_contract_snapshot};

/// The full contract snapshot test requires all 42 tools to be compiled in.
/// The checked-in contract artifact contains all tools, so this test only
/// makes sense with `full-tools`.
#[cfg(feature = "full-tools")]
#[test]
fn canonical_contract_snapshot_matches_checked_in_artifact() {
    let actual = canonical_contract_snapshot();
    let expected: JacsMcpContractSnapshot =
        serde_json::from_str(include_str!("../contract/jacs-mcp-contract.json"))
            .expect("checked-in canonical contract should parse");

    assert_eq!(
        actual, expected,
        "canonical Rust MCP contract changed; regenerate jacs-mcp/contract/jacs-mcp-contract.json"
    );
}

/// With default features, the contract should contain only core tools.
#[cfg(not(feature = "full-tools"))]
#[test]
fn canonical_contract_snapshot_contains_core_tools() {
    let actual = canonical_contract_snapshot();

    // Core: state(6) + document(3) + trust(5) + audit(4) + memory(5) + search(1) + key(4) = 28
    assert_eq!(
        actual.tools.len(),
        28,
        "default-feature contract should have 28 core tools, got {}",
        actual.tools.len()
    );

    // Verify server metadata is still correct
    assert_eq!(actual.server.name, "jacs-mcp");
    assert_eq!(actual.schema_version, 1);
}
