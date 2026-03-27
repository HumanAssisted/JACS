//! Framework adapter inventory structural test.
//!
//! Validates that `adapter_inventory.json` is well-formed and internally
//! consistent. Each language binding has its own test that validates
//! the adapters listed for that language actually exist.

use serde_json::Value;

fn load_adapter_inventory() -> Value {
    let fixture_bytes = include_bytes!("fixtures/adapter_inventory.json");
    serde_json::from_slice(fixture_bytes).expect("adapter_inventory.json should be valid JSON")
}

#[test]
fn test_adapter_inventory_is_valid_json() {
    let inventory = load_adapter_inventory();
    assert!(
        inventory["adapters"].is_object(),
        "adapter_inventory.json should have an 'adapters' object"
    );
}

#[test]
fn test_adapter_inventory_has_expected_languages() {
    let inventory = load_adapter_inventory();
    let adapters = inventory["adapters"]
        .as_object()
        .expect("adapters should be an object");

    assert!(
        adapters.contains_key("python"),
        "adapter inventory should have 'python' entry"
    );
    assert!(
        adapters.contains_key("node"),
        "adapter inventory should have 'node' entry"
    );
    assert!(
        adapters.contains_key("go"),
        "adapter inventory should have 'go' entry"
    );
}

#[test]
fn test_adapter_inventory_python_has_expected_adapters() {
    let inventory = load_adapter_inventory();
    let python = inventory["adapters"]["python"]
        .as_object()
        .expect("python should be an object");

    let expected_adapters = ["mcp", "langchain", "crewai", "fastapi", "anthropic"];
    for adapter in &expected_adapters {
        assert!(
            python.contains_key(*adapter),
            "Python should have '{}' adapter entry",
            adapter
        );
    }
    assert_eq!(
        python.len(),
        expected_adapters.len(),
        "Python should have exactly {} adapters. Found {}.",
        expected_adapters.len(),
        python.len()
    );
}

#[test]
fn test_adapter_inventory_node_has_expected_adapters() {
    let inventory = load_adapter_inventory();
    let node = inventory["adapters"]["node"]
        .as_object()
        .expect("node should be an object");

    assert!(
        node.contains_key("mcp"),
        "Node should have 'mcp' adapter entry"
    );
}

#[test]
fn test_adapter_inventory_entries_have_required_fields() {
    let inventory = load_adapter_inventory();
    let adapters = inventory["adapters"].as_object().unwrap();

    for (lang, lang_adapters) in adapters {
        if let Some(obj) = lang_adapters.as_object() {
            for (adapter_name, adapter) in obj {
                // Skip _note fields
                if adapter_name.starts_with('_') {
                    continue;
                }
                assert!(
                    adapter["module"].is_string(),
                    "{}/{} should have a 'module' string",
                    lang,
                    adapter_name
                );
                assert!(
                    adapter["public_functions"].is_array(),
                    "{}/{} should have a 'public_functions' array",
                    lang,
                    adapter_name
                );
                let funcs = adapter["public_functions"].as_array().unwrap();
                assert!(
                    !funcs.is_empty(),
                    "{}/{} should have at least one public function",
                    lang,
                    adapter_name
                );
            }
        }
    }
}
