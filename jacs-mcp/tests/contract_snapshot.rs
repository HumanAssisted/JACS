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

// =============================================================================
// P2 Task 006 — MCP surface guardrails.
//
// P2's ES256 projections are deliberately narrow. These tests scan the
// checked-in contract artifact (which lists ALL tools regardless of the
// tool-family features compiled into this test binary) to prove no generic
// projection tool and no AP2 / Agreement-VC tool leaked onto the MCP surface.
// =============================================================================

fn checked_in_contract_tool_names() -> Vec<String> {
    let contract: serde_json::Value =
        serde_json::from_str(include_str!("../contract/jacs-mcp-contract.json"))
            .expect("checked-in canonical contract should parse");
    contract["tools"]
        .as_array()
        .expect("contract tools should be an array")
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .expect("tool name should be a string")
                .to_string()
        })
        .collect()
}

/// `data.?integrity` from the guardrail pattern: "data" then "integrity"
/// with at most one character between (tool names are ASCII snake_case).
fn contains_data_integrity(name: &str) -> bool {
    let mut cursor = 0;
    while let Some(rel) = name[cursor..].find("data") {
        let after = cursor + rel + "data".len();
        let rest = &name[after..];
        if rest.starts_with("integrity") || (rest.len() > 1 && rest[1..].starts_with("integrity")) {
            return true;
        }
        cursor = after;
    }
    false
}

/// The projection pattern /dsse|jws|data.?integrity|credential|\bvc\b/i.
/// The `vc` check treats `_` and `-` as boundaries (stricter than regex
/// `\b`, which counts `_` as a word character) so `agreement_vc`-style
/// names are also caught.
fn matches_projection_pattern(tool_name: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    name.contains("dsse")
        || name.contains("jws")
        || name.contains("credential")
        || contains_data_integrity(&name)
        || name
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|token| token == "vc")
}

/// Exception first: NG6 explicitly grandfathers the pre-existing
/// `jacs_attest_export_dsse` tool. It must remain the ONLY tool whose name
/// matches the projection pattern /dsse|jws|data.?integrity|credential|\bvc\b/i
/// — any second match means a generic envelope/credential projection
/// reopened on the MCP surface (P2 Task 006).
#[test]
fn mcp_contract_only_projection_tool_is_grandfathered_dsse_export() {
    let matches: Vec<String> = checked_in_contract_tool_names()
        .into_iter()
        .filter(|name| matches_projection_pattern(name))
        .collect();

    assert_eq!(
        matches,
        vec!["jacs_attest_export_dsse".to_string()],
        "the NG6-grandfathered jacs_attest_export_dsse must be the ONLY tool \
         matching /dsse|jws|data.?integrity|credential|\\bvc\\b/i — every \
         other projection stays a named CLI/binding exporter, not an MCP tool"
    );
}

/// AP2 mandate and Agreement-v2 VC exports are CLI-only in P2
/// (`jacs ap2 export-mandate`, `jacs agreement-v2 export-vc`). No MCP tool
/// may expose them (P2 Task 006).
#[test]
fn mcp_contract_has_no_ap2_or_agreement_vc_tools() {
    let offenders: Vec<String> = checked_in_contract_tool_names()
        .into_iter()
        .filter(|name| {
            let name = name.to_ascii_lowercase();
            name.contains("ap2")
                || name.contains("mandate")
                || name.contains("agreement_vc")
                || name.contains("agreement-vc")
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "AP2 / Agreement-VC exports are CLI-only in P2; remove these MCP \
         tool(s): {:?}",
        offenders
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
