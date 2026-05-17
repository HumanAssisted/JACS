//! Wave 2 / Task 006: confirm `jacs::schema::utils::DEFAULT_SCHEMA_STRINGS`
//! is the same map as `jacs_core::schema::DEFAULT_SCHEMA_STRINGS` after the
//! move. If a downstream caller depends on a key being present, this test
//! catches accidental drops during the re-export.

use jacs::schema::utils::{CONFIG_SCHEMA_STRING, DEFAULT_SCHEMA_STRINGS, SCHEMA_SHORT_NAME};

#[test]
fn jacs_schema_utils_reexport_default_schema_strings() {
    // The agent schema is the canonical smoke check — it's the one every
    // signing path references.
    let body = DEFAULT_SCHEMA_STRINGS
        .get("schemas/agent/v1/agent.schema.json")
        .expect("agent schema present after re-export");
    assert!(body.contains("$id"), "agent schema body looks like JSON");
}

#[test]
fn jacs_schema_utils_reexport_short_name_lookup() {
    let got = SCHEMA_SHORT_NAME
        .get("https://hai.ai/schemas/agent/v1/agent.schema.json")
        .expect("agent $id is mapped after re-export");
    assert_eq!(*got, "agent");
}

#[test]
fn jacs_schema_utils_reexport_config_schema() {
    let v: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA_STRING).expect("config schema parses");
    assert!(v.is_object());
}

#[test]
fn jacs_and_jacs_core_default_schema_strings_are_identical() {
    // Pointer-equality on the `&'static` map — this is what `pub use`
    // gives us; it confirms there is exactly one map in the program,
    // not two copies that happen to look alike.
    let jacs_ptr =
        &jacs::schema::utils::DEFAULT_SCHEMA_STRINGS as *const _ as *const u8;
    let core_ptr =
        &jacs_core::schema::DEFAULT_SCHEMA_STRINGS as *const _ as *const u8;
    assert_eq!(jacs_ptr, core_ptr, "re-export should point at the same map");
}
