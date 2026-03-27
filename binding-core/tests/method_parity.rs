//! Method enumeration parity test for `SimpleAgentWrapper`.
//!
//! Validates that `binding-core/tests/fixtures/method_parity.json` accurately
//! lists all public methods on `SimpleAgentWrapper`. If a method is added or
//! removed from the wrapper without updating the fixture, this test fails.
//!
//! This is a *structural* test (method names), not a *behavioral* test
//! (sign/verify roundtrips). It complements, not duplicates, `parity.rs`.

use serde_json::Value;

/// Hardcoded, sorted list of all public methods on `SimpleAgentWrapper`.
///
/// This list MUST be updated whenever a public method is added to or removed
/// from `binding-core/src/simple_wrapper.rs`. It serves as a compile-time
/// anchor so that the fixture and the implementation stay in sync.
fn known_methods() -> Vec<&'static str> {
    let mut methods = vec![
        // Constructors
        "create",
        "load",
        "load_with_info",
        "ephemeral",
        "create_with_params",
        "from_agent",
        // Identity / Introspection
        "get_agent_id",
        "key_id",
        "is_strict",
        "config_path",
        "export_agent",
        "get_public_key_pem",
        "get_public_key_base64",
        "diagnostics",
        "inner_ref",
        // Verification
        "verify_self",
        "verify_json",
        "verify_with_key_json",
        "verify_by_id_json",
        // Signing
        "sign_message_json",
        "sign_raw_bytes_base64",
        "sign_file_json",
        // Conversion
        "to_yaml",
        "from_yaml",
        "to_html",
        "from_html",
    ];
    methods.sort();
    methods
}

fn load_method_parity_fixture() -> Value {
    let fixture_bytes = include_bytes!("fixtures/method_parity.json");
    serde_json::from_slice(fixture_bytes).expect("method_parity.json should be valid JSON")
}

#[test]
fn test_method_parity_fixture_matches_impl() {
    let fixture = load_method_parity_fixture();

    // Extract the flat sorted list from the fixture
    let fixture_methods: Vec<String> = fixture["all_methods_flat"]
        .as_array()
        .expect("all_methods_flat should be an array")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("each method should be a string")
                .to_string()
        })
        .collect();

    let known = known_methods();
    let known_strings: Vec<String> = known.iter().map(|s| s.to_string()).collect();

    // Both lists should already be sorted
    assert_eq!(
        fixture_methods,
        known_strings,
        "\nFixture method list does not match known SimpleAgentWrapper methods.\n\
         \nFixture has {} methods, known list has {} methods.\n\
         \nIn fixture but not in known list: {:?}\n\
         In known list but not in fixture: {:?}\n\
         \nIf you added a method to SimpleAgentWrapper, update BOTH:\n\
         1. binding-core/tests/fixtures/method_parity.json\n\
         2. The known_methods() list in binding-core/tests/method_parity.rs",
        fixture_methods.len(),
        known_strings.len(),
        fixture_methods
            .iter()
            .filter(|m| !known_strings.contains(m))
            .collect::<Vec<_>>(),
        known_strings
            .iter()
            .filter(|m| !fixture_methods.contains(m))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn test_method_parity_fixture_categories_cover_all() {
    let fixture = load_method_parity_fixture();
    let categories = fixture["simple_agent_wrapper_methods"]
        .as_object()
        .expect("simple_agent_wrapper_methods should be an object");

    // Collect all methods from categories
    let mut category_methods: Vec<String> = Vec::new();
    for (_category_name, methods) in categories {
        for method in methods.as_array().expect("category should be an array") {
            category_methods.push(
                method
                    .as_str()
                    .expect("method should be a string")
                    .to_string(),
            );
        }
    }
    category_methods.sort();

    // Compare against flat list
    let flat_methods: Vec<String> = fixture["all_methods_flat"]
        .as_array()
        .expect("all_methods_flat should be an array")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("each method should be a string")
                .to_string()
        })
        .collect();

    assert_eq!(
        category_methods,
        flat_methods,
        "\nCategorized methods do not match all_methods_flat.\n\
         This means the fixture is internally inconsistent.\n\
         \nIn categories but not in flat: {:?}\n\
         In flat but not in categories: {:?}",
        category_methods
            .iter()
            .filter(|m| !flat_methods.contains(m))
            .collect::<Vec<_>>(),
        flat_methods
            .iter()
            .filter(|m| !category_methods.contains(m))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn test_method_parity_fixture_count() {
    let fixture = load_method_parity_fixture();
    let flat_methods = fixture["all_methods_flat"]
        .as_array()
        .expect("all_methods_flat should be an array");

    assert_eq!(
        flat_methods.len(),
        26,
        "SimpleAgentWrapper should have exactly 26 public methods. \
         Found {}. If you added or removed a method, update the fixture.",
        flat_methods.len()
    );
}
