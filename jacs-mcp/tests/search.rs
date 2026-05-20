#![cfg(feature = "mcp")]
//! Contract-level tests for the unified search tool.

use jacs_mcp::tools::SearchParams;

#[test]
fn search_params_schema_uses_generic_document_types() {
    let schema = schemars::schema_for!(SearchParams);
    let json = serde_json::to_string_pretty(&schema).unwrap();

    assert!(json.contains("jacs_type"));
    assert!(json.contains("agreement"));
    assert!(json.contains("agent"));
    assert!(!json.contains("legacy state document"));
}
