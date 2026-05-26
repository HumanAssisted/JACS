#![cfg(feature = "mcp")]

#[cfg(feature = "full-tools")]
use jacs_mcp::JacsMcpContractSnapshot;
use jacs_mcp::canonical_contract_snapshot;

/// The full contract snapshot test requires all current tools to be compiled in.
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

    assert_eq!(
        actual.tools.len(),
        25,
        "default-feature contract should have 25 core tools, got {}",
        actual.tools.len()
    );

    // Verify server metadata is still correct
    assert_eq!(actual.server.name, "jacs-mcp");
    assert_eq!(actual.schema_version, 1);
}

#[cfg(not(feature = "full-tools"))]
#[test]
fn sign_text_contract_has_required_params() {
    let snapshot = canonical_contract_snapshot();
    let tool = snapshot
        .tools
        .iter()
        .find(|t| t.name == "jacs_sign_text")
        .expect("jacs_sign_text must be in canonical snapshot");
    let required = tool
        .input_schema
        .get("required")
        .and_then(|v| v.as_array())
        .expect("jacs_sign_text input_schema.required must be an array");
    assert!(required.iter().any(|v| v.as_str() == Some("file_path")));
}

/// C1: verify tools must have `strict` in properties but NOT in required.
#[cfg(not(feature = "full-tools"))]
#[test]
fn verify_text_contract_has_optional_strict() {
    let snapshot = canonical_contract_snapshot();
    let tool = snapshot
        .tools
        .iter()
        .find(|t| t.name == "jacs_verify_text")
        .expect("jacs_verify_text must be in canonical snapshot");
    let props = tool
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("properties must be an object");
    assert!(
        props.contains_key("strict"),
        "strict must be exposed as a param"
    );
    let required = tool
        .input_schema
        .get("required")
        .and_then(|v| v.as_array())
        .expect("required must be an array");
    assert!(
        !required.iter().any(|v| v.as_str() == Some("strict")),
        "strict must NOT be required — default is permissive"
    );
}

#[cfg(not(feature = "full-tools"))]
#[test]
fn verify_image_contract_has_optional_strict() {
    let snapshot = canonical_contract_snapshot();
    let tool = snapshot
        .tools
        .iter()
        .find(|t| t.name == "jacs_verify_image")
        .expect("jacs_verify_image must be in canonical snapshot");
    let props = tool
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("properties must be an object");
    assert!(
        props.contains_key("strict"),
        "strict must be exposed as a param"
    );
    let required = tool
        .input_schema
        .get("required")
        .and_then(|v| v.as_array())
        .expect("required must be an array");
    assert!(
        !required.iter().any(|v| v.as_str() == Some("strict")),
        "strict must NOT be required — default is permissive"
    );
}
