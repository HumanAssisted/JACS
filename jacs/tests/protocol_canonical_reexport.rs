//! Wave 2 / Task 005: confirm `jacs::protocol::canonicalize_json` still
//! produces the Task 001 golden bytes after being moved into
//! `jacs_core::canonical` and re-exported via `pub use`.
//!
//! This is the cross-compat oracle that PRD §5.2 calls out — the bytes
//! signed by native code must equal the bytes verified anywhere the
//! library runs.

use serde_json::Value;

#[derive(serde::Deserialize)]
struct Sample {
    name: String,
    data: Value,
}

#[test]
fn jacs_protocol_canonicalize_json_reexport_produces_goldens() {
    let inputs: Vec<Sample> =
        serde_json::from_str(include_str!("fixtures/wasm_compat/canonical_inputs.json"))
            .expect("canonical_inputs.json parses");
    let outputs: std::collections::HashMap<String, String> =
        serde_json::from_str(include_str!("fixtures/wasm_compat/canonical_outputs.json"))
            .expect("canonical_outputs.json parses");

    for sample in inputs {
        let actual = jacs::protocol::canonicalize_json(&sample.data);
        let expected = outputs.get(&sample.name).expect("golden present");
        assert_eq!(
            &actual, expected,
            "jacs::protocol::canonicalize_json drift for {}",
            sample.name
        );
    }
}
