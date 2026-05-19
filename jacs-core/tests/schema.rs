//! Wave 2 / Task 006: jacs-core embedded schemas + portable resolver tests.

use jacs_core::CoreError;
use jacs_core::schema::{
    CONFIG_SCHEMA_STRING, DEFAULT_SCHEMA_STRINGS, EmbeddedSchemaResolver, SCHEMA_SHORT_NAME,
};

const EXPECTED_KEYS: &[&str] = &[
    "schemas/agent/v1/agent.schema.json",
    "schemas/header/v1/header.schema.json",
    "schemas/components/signature/v1/signature.schema.json",
    "schemas/components/files/v1/files.schema.json",
    "schemas/components/agreement/v1/agreement.schema.json",
    "schemas/components/action/v1/action.schema.json",
    "schemas/components/unit/v1/unit.schema.json",
    "schemas/components/tool/v1/tool.schema.json",
    "schemas/components/service/v1/service.schema.json",
    "schemas/components/contact/v1/contact.schema.json",
    "schemas/task/v1/task.schema.json",
    "schemas/message/v1/message.schema.json",
    "schemas/eval/v1/eval.schema.json",
    "schemas/program/v1/program.schema.json",
    "schemas/node/v1/node.schema.json",
    "schemas/components/embedding/v1/embedding.schema.json",
    "schemas/agentstate/v1/agentstate.schema.json",
    "schemas/commitment/v1/commitment.schema.json",
    "schemas/todo/v1/todo.schema.json",
    "schemas/components/todoitem/v1/todoitem.schema.json",
    "schemas/attestation/v1/attestation.schema.json",
];

#[test]
fn default_schema_strings_present() {
    assert_eq!(
        DEFAULT_SCHEMA_STRINGS.len(),
        EXPECTED_KEYS.len(),
        "DEFAULT_SCHEMA_STRINGS cardinality drifted",
    );
    for key in EXPECTED_KEYS {
        let body = DEFAULT_SCHEMA_STRINGS
            .get(key)
            .copied()
            .unwrap_or_else(|| panic!("missing embedded schema for {key}"));
        assert!(!body.is_empty(), "schema {key} body was empty");
        let parsed: serde_json::Value =
            serde_json::from_str(body).unwrap_or_else(|e| panic!("schema {key} did not parse as JSON: {e}"));
        assert!(parsed.is_object(), "schema {key} was not a JSON object");
    }
}

#[test]
fn config_schema_string_parses_as_json_object() {
    let v: serde_json::Value =
        serde_json::from_str(CONFIG_SCHEMA_STRING).expect("config schema parses");
    assert!(v.is_object());
}

#[test]
fn schema_short_name_returns_expected_slot_for_known_id() {
    // SCHEMA_SHORT_NAME doesn't enumerate every embedded schema (program,
    // embedding, todoitem, component are referenced by $ref but don't
    // need their own slot). We only assert the document-typed entries
    // that the native side already tracked.
    let cases: &[(&str, &str)] = &[
        ("https://hai.ai/schemas/agent/v1/agent.schema.json", "agent"),
        ("https://hai.ai/schemas/task/v1/task.schema.json", "task"),
        (
            "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json",
            "agreement",
        ),
        ("https://hai.ai/schemas/header/v1/header.schema.json", "header"),
        ("document", "document"),
    ];
    for (id, expected) in cases {
        let got = SCHEMA_SHORT_NAME
            .get(id)
            .unwrap_or_else(|| panic!("SCHEMA_SHORT_NAME missing $id {id}"));
        assert_eq!(*got, *expected, "wrong short name for {id}");
    }
}

#[test]
fn embedded_resolver_returns_known_schema() {
    // EmbeddedSchemaResolver::resolve accepts both the bare key and the
    // leading-slash variant that jsonschema::Uri::path() would emit.
    let v = EmbeddedSchemaResolver::resolve("schemas/agent/v1/agent.schema.json")
        .expect("known schema resolves");
    assert!(v.is_object());

    let v_slash = EmbeddedSchemaResolver::resolve("/schemas/agent/v1/agent.schema.json")
        .expect("leading-slash variant resolves");
    assert_eq!(v, v_slash);
}

#[test]
fn embedded_resolver_unknown_ref_errors() {
    let err =
        EmbeddedSchemaResolver::resolve("/schemas/does-not-exist/v1/does-not-exist.schema.json")
            .expect_err("unknown ref errors");
    assert!(matches!(err, CoreError::SchemaInvalid(_)));
    let msg = err.to_string();
    assert!(msg.contains("does-not-exist"), "error message includes the missing path: {msg}");
}

#[test]
fn embedded_resolver_implements_retrieve_trait() {
    // This exercises the path through `jsonschema::Retrieve` — the same
    // shape used by validator construction. Build a fake URI by going
    // through the jsonschema::Uri parser.
    use jsonschema::Retrieve;
    let resolver = EmbeddedSchemaResolver::new();
    // jsonschema::Uri::from_str via the referencing crate would normally
    // be how a URI is constructed; the simplest portable path is to use
    // referencing::Uri directly via the re-export.
    let uri: jsonschema::Uri<String> =
        "https://hai.ai/schemas/agent/v1/agent.schema.json".parse().expect("uri parses");
    let v = resolver.retrieve(&uri).expect("retrieve resolves known schema");
    assert!(v.is_object());
}
