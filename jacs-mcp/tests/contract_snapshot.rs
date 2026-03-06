#![cfg(feature = "mcp")]

use jacs_mcp::{JacsMcpContractSnapshot, canonical_contract_snapshot};

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
