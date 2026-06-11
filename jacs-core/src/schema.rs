//! Embedded JACS JSON schemas + a portable [`Retrieve`] resolver.
//!
//! Every JACS document carries a `$id` pointing at a schema like
//! `https://hai.ai/schemas/agent/v1/agent.schema.json`. The schemas are
//! shipped in-tree so validation works offline and in browsers where
//! `resolve-http`/`resolve-file` are unavailable.
//!
//! `jsonschema` is pulled in with `default-features = false` so the
//! crate compiles for `wasm32-unknown-unknown` (the default features
//! contain `compile_error!` for wasm32).
//!
//! The native `jacs::schema::utils::EmbeddedSchemaResolver` wraps this
//! resolver and adds optional filesystem + HTTP fallbacks; the wasm/core
//! one here is **embedded-only** and never reaches the filesystem or
//! network.

use crate::CoreError;
use jsonschema::Retrieve;
use phf::phf_map;
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;

/// Canonical schema identity for standalone agreement v2 documents.
pub const V2_SCHEMA_ID: &str = "https://hai.ai/schemas/agreement/v2/agreement.schema.json";

/// Static map of `schemas/<path>` keys to their JSON contents. The wasm
/// build needs this to resolve every `$ref` without disk access.
pub static DEFAULT_SCHEMA_STRINGS: phf::Map<&'static str, &'static str> = phf_map! {
    "schemas/agent/v1/agent.schema.json" => include_str!("../schemas/agent/v1/agent.schema.json"),
    "schemas/header/v1/header.schema.json" => include_str!("../schemas/header/v1/header.schema.json"),
    "schemas/components/signature/v1/signature.schema.json" => include_str!("../schemas/components/signature/v1/signature.schema.json"),
    "schemas/components/files/v1/files.schema.json" => include_str!("../schemas/components/files/v1/files.schema.json"),
    "schemas/components/agreement/v1/agreement.schema.json" => include_str!("../schemas/components/agreement/v1/agreement.schema.json"),
    "schemas/agreement/v2/agreement.schema.json" => include_str!("../schemas/agreement/v2/agreement.schema.json"),
    "schemas/attestation/v1/attestation.schema.json" => include_str!("../schemas/attestation/v1/attestation.schema.json"),
};

/// Maps fully qualified `$id` URLs to short JACS document-type names
/// (`"agent"`, `"task"`, …). Used by `get_short_name` in the native side
/// to pick a per-type validation slot.
pub static SCHEMA_SHORT_NAME: phf::Map<&'static str, &'static str> = phf_map! {
    "https://hai.ai/schemas/agent/v1/agent.schema.json" => "agent",
    "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json" => "agreement",
    "https://hai.ai/schemas/agreement/v2/agreement.schema.json" => "agreement",
    "https://hai.ai/schemas/components/files/v1/files.schema.json" => "files",
    "https://hai.ai/schemas/components/signature/v1/signature.schema.json" => "signature",
    "https://hai.ai/schemas/header/v1/header.schema.json" => "header",
    "document" => "document",
    "https://hai.ai/schemas/attestation/v1/attestation.schema.json" => "attestation",
};

/// The embedded JACS config schema, used to validate `jacs.config.json`.
pub static CONFIG_SCHEMA_STRING: &str = include_str!("../schemas/jacs.config.schema.json");

/// Embedded-only [`Retrieve`] impl: every lookup goes through
/// [`DEFAULT_SCHEMA_STRINGS`]. No filesystem, no network — safe for wasm.
///
/// The native side wraps this with a richer resolver that adds
/// filesystem / HTTP fallbacks; that wrapper lives in
/// `jacs::schema::utils`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbeddedSchemaResolver;

impl EmbeddedSchemaResolver {
    /// Create a new resolver. Cheap; no allocation.
    pub fn new() -> Self {
        EmbeddedSchemaResolver
    }

    /// Look up a schema by either its plain path key
    /// (`"schemas/agent/v1/agent.schema.json"`) or its leading-slash
    /// variant (`"/schemas/agent/v1/agent.schema.json"`, what
    /// `jsonschema::Uri::path()` returns for `hai.ai`-hosted refs).
    /// Returns `None` if the schema is not bundled.
    pub fn lookup(path: &str) -> Option<&'static str> {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        DEFAULT_SCHEMA_STRINGS.get(trimmed).copied()
    }

    /// Resolve a path string to a parsed `Value`. Returns
    /// `CoreError::SchemaInvalid` for unknown refs or unparsable JSON.
    pub fn resolve(path: &str) -> Result<Value, CoreError> {
        let body = Self::lookup(path)
            .ok_or_else(|| CoreError::SchemaInvalid(format!("unknown schema $ref '{path}'")))?;
        serde_json::from_str(body)
            .map_err(|e| CoreError::SchemaInvalid(format!("failed to parse schema '{path}': {e}")))
    }
}

impl Retrieve for EmbeddedSchemaResolver {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        Self::resolve(uri.path().as_str()).map_err(|e| {
            // jsonschema's Retrieve trait expects a boxed std::error::Error.
            // CoreError implements std::error::Error via thiserror.
            Box::new(e) as Box<dyn Error + Send + Sync>
        })
    }
}

/// Validate a standalone agreement v2 document with the authoritative shared
/// gate used by both native JACS and portable/browser JACS engines.
///
/// This pins the v2 schema identity, validates against the embedded draft-07
/// schema with format assertions enabled, rejects unknown root-level fields
/// derived from the embedded schemas, and manually checks UUID fields that
/// draft-07 format validation does not enforce in `jsonschema`.
pub fn validate_agreement_v2_document(document: &Value) -> Result<(), CoreError> {
    let object = document.as_object().ok_or_else(|| {
        CoreError::SchemaInvalid("agreement v2 document must be an object".into())
    })?;

    if let Some(schema_id) = object.get("$schema")
        && schema_id.as_str() != Some(V2_SCHEMA_ID)
    {
        return Err(CoreError::SchemaInvalid(format!(
            "agreement v2 document declares unsupported $schema '{}'",
            schema_id.as_str().unwrap_or("<non-string>")
        )));
    }
    if object.get("jacsType").and_then(Value::as_str) != Some("agreement") {
        return Err(CoreError::SchemaInvalid(
            "agreement v2 document must declare jacsType 'agreement'".into(),
        ));
    }
    if let Some(level) = object.get("jacsLevel")
        && level.as_str() != Some("artifact")
    {
        return Err(CoreError::SchemaInvalid(
            "agreement v2 document must declare jacsLevel 'artifact'".into(),
        ));
    }

    let agreement_schema = embedded_schema_value("schemas/agreement/v2/agreement.schema.json")?;
    let validator = jsonschema::Validator::options()
        .with_draft(jsonschema::Draft::Draft7)
        .with_retriever(EmbeddedSchemaResolver::new())
        .should_validate_formats(true)
        .build(&agreement_schema)
        .map_err(|err| {
            CoreError::SchemaInvalid(format!("failed to compile agreement v2 schema: {err}"))
        })?;
    let schema_check_doc = normalize_signing_algorithm_for_schema(document);
    validator.validate(&schema_check_doc).map_err(|err| {
        CoreError::SchemaInvalid(format!(
            "agreement v2 schema validation failed at '{}': {}",
            err.instance_path, err
        ))
    })?;

    validate_agreement_v2_root_fields(document, &agreement_schema)?;
    validate_agreement_v2_uuids(document)?;
    Ok(())
}

/// jsonschema validates `signingAlgorithm` against the native enum
/// ["ring-Ed25519","pq2025"]. The portable engine writes the equivalent
/// "ed25519" spelling, which `SigningAlgorithm::from_wire_str` treats as
/// the same algorithm. Both forms are byte-stable in their own signatures,
/// so we only normalize a throwaway clone for the structural schema check;
/// the real document (and its signed bytes) are never altered.
fn normalize_signing_algorithm_for_schema(document: &Value) -> Value {
    fn walk(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(algo)) = map.get_mut("signingAlgorithm")
                    && algo == "ed25519"
                {
                    *algo = "ring-Ed25519".to_string();
                }
                for (_k, v) in map.iter_mut() {
                    walk(v);
                }
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    walk(item);
                }
            }
            _ => {}
        }
    }

    let mut cloned = document.clone();
    walk(&mut cloned);
    cloned
}

fn embedded_schema_value(path: &str) -> Result<Value, CoreError> {
    let body = DEFAULT_SCHEMA_STRINGS
        .get(path)
        .copied()
        .ok_or_else(|| CoreError::SchemaInvalid(format!("missing embedded schema '{path}'")))?;
    serde_json::from_str(body)
        .map_err(|err| CoreError::SchemaInvalid(format!("failed to parse schema '{path}': {err}")))
}

fn validate_agreement_v2_root_fields(
    document: &Value,
    agreement_schema: &Value,
) -> Result<(), CoreError> {
    let mut allowed = HashSet::new();
    allowed.insert("$schema".to_string());
    allowed.insert("$id".to_string());

    for branch in agreement_schema
        .get("allOf")
        .and_then(Value::as_array)
        .ok_or_else(|| CoreError::SchemaInvalid("agreement v2 schema missing allOf".into()))?
    {
        if let Some(properties) = branch.get("properties").and_then(Value::as_object) {
            allowed.extend(properties.keys().cloned());
        }
    }

    let header_schema = embedded_schema_value("schemas/header/v1/header.schema.json")?;
    let header_properties = header_schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| CoreError::SchemaInvalid("header schema missing properties".into()))?;
    allowed.extend(header_properties.keys().cloned());

    let object = document.as_object().ok_or_else(|| {
        CoreError::MalformedDocument("agreement v2 document must be an object".into())
    })?;
    for key in object.keys() {
        if !allowed.contains(key) {
            return Err(CoreError::MalformedDocument(format!(
                "unknown top-level field '{}' is not permitted on agreement v2 documents",
                key
            )));
        }
    }
    Ok(())
}

fn validate_agreement_v2_uuids(document: &Value) -> Result<(), CoreError> {
    validate_uuid_field(document, "jacsId")?;
    validate_uuid_array(document, "controllers")?;
    validate_uuid_array(document, "owners")?;
    validate_uuid_array(document, "allPreviousVersions")?;

    if let Some(parties) = document.get("parties").and_then(Value::as_array) {
        for (index, party) in parties.iter().enumerate() {
            validate_uuid_named_field(party, "agentId", &format!("parties[{index}].agentId"))?;
            validate_uuid_named_field(
                party,
                "agentVersion",
                &format!("parties[{index}].agentVersion"),
            )?;
        }
    }
    Ok(())
}

fn validate_uuid_array(document: &Value, field: &str) -> Result<(), CoreError> {
    if let Some(values) = document.get(field).and_then(Value::as_array) {
        for (index, value) in values.iter().enumerate() {
            validate_uuid_value(value, &format!("{field}[{index}]"))?;
        }
    }
    Ok(())
}

fn validate_uuid_field(document: &Value, field: &str) -> Result<(), CoreError> {
    validate_uuid_named_field(document, field, field)
}

fn validate_uuid_named_field(
    document: &Value,
    json_key: &str,
    display_field: &str,
) -> Result<(), CoreError> {
    if let Some(value) = document.get(json_key) {
        validate_uuid_value(value, display_field)?;
    }
    Ok(())
}

fn validate_uuid_value(value: &Value, field: &str) -> Result<(), CoreError> {
    if let Some(value) = value.as_str()
        && uuid::Uuid::parse_str(value).is_err()
    {
        return Err(CoreError::MalformedDocument(format!(
            "field '{}' must be a valid UUID",
            field
        )));
    }
    Ok(())
}
