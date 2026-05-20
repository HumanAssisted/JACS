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
use std::error::Error;

/// Static map of `schemas/<path>` keys to their JSON contents. The wasm
/// build needs this to resolve every `$ref` without disk access.
pub static DEFAULT_SCHEMA_STRINGS: phf::Map<&'static str, &'static str> = phf_map! {
    "schemas/agent/v1/agent.schema.json" => include_str!("../schemas/agent/v1/agent.schema.json"),
    "schemas/header/v1/header.schema.json" => include_str!("../schemas/header/v1/header.schema.json"),
    "schemas/components/signature/v1/signature.schema.json" => include_str!("../schemas/components/signature/v1/signature.schema.json"),
    "schemas/components/files/v1/files.schema.json" => include_str!("../schemas/components/files/v1/files.schema.json"),
    "schemas/components/agreement/v1/agreement.schema.json" => include_str!("../schemas/components/agreement/v1/agreement.schema.json"),
    "schemas/attestation/v1/attestation.schema.json" => include_str!("../schemas/attestation/v1/attestation.schema.json"),
};

/// Maps fully qualified `$id` URLs to short JACS document-type names
/// (`"agent"`, `"task"`, …). Used by `get_short_name` in the native side
/// to pick a per-type validation slot.
pub static SCHEMA_SHORT_NAME: phf::Map<&'static str, &'static str> = phf_map! {
    "https://hai.ai/schemas/agent/v1/agent.schema.json" => "agent",
    "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json" => "agreement",
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
        let body = Self::lookup(path).ok_or_else(|| {
            CoreError::SchemaInvalid(format!("unknown schema $ref '{path}'"))
        })?;
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
