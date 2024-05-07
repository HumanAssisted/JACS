use crate::schema::Url;
use log::debug;
use log::error;

use phf::phf_map;

use jsonschema::SchemaResolver;
use jsonschema::SchemaResolverError;
use serde_json::Value;
use std::sync::Arc;

use std::error::Error;
use std::fmt;

pub const ACCEPT_INVALID_CERTS: bool = true;
pub static DEFAULT_SCHEMA_STRINGS: phf::Map<&'static str, &'static str> = phf_map! {
    "schemas/agent/v1/agent.schema.json" => include_str!("../../schemas/agent/v1/agent.schema.json"),
    "schemas/header/v1/header.schema.json"=> include_str!("../../schemas/header/v1/header.schema.json"),
    "schemas/components/signature/v1/signature.schema.json" => include_str!("../../schemas/components/signature/v1/signature.schema.json"),
    "schemas/components/files/v1/files.schema.json" => include_str!("../../schemas/components/files/v1/files.schema.json"),
    "schemas/components/agreement/v1/agreement.schema.json" => include_str!("../../schemas/components/agreement/v1/agreement.schema.json"),
    "schemas/components/action/v1/action.schema.json" => include_str!("../../schemas/components/action/v1/action.schema.json"),
    "schemas/components/unit/v1/unit.schema.json" => include_str!("../../schemas/components/unit/v1/unit.schema.json"),
    "schemas/components/tool/v1/tool.schema.json" => include_str!("../../schemas/components/tool/v1/tool.schema.json"),
    "schemas/components/service/v1/service.schema.json" => include_str!("../../schemas/components/service/v1/service.schema.json"),
     "schemas/components/contact/v1/contact.schema.json" => include_str!("../../schemas/components/contact/v1/contact.schema.json"),
     "schemas/task/v1/task.schema.json" => include_str!("../../schemas/task/v1/task.schema.json"),
     "schemas/message/v1/message.schema.json" => include_str!("../../schemas/message/v1/message.schema.json"),
     "schemas/eval/v1/eval.schema.json" => include_str!("../../schemas/eval/v1/eval.schema.json")
     // todo get all files in a schemas directory, dynamically
    // "schemas/jacs.config.schema.json" => include_str!("../../schemas/jacs.config.schema.json"),
};

pub static CONFIG_SCHEMA_STRING: &str = include_str!("../../schemas/jacs.config.schema.json");

#[derive(Debug)]
pub struct SchemaResolverErrorWrapper(pub String);

impl fmt::Display for SchemaResolverErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for SchemaResolverErrorWrapper {}

// todo move
pub trait ValueExt {
    fn get_str(&self, field: &str) -> Option<String>;
    fn get_i64(&self, key: &str) -> Option<i64>;
    fn get_bool(&self, key: &str) -> Option<bool>;
}

impl ValueExt for Value {
    fn get_str(&self, field: &str) -> Option<String> {
        self.get(field)?.as_str().map(String::from)
    }
    fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_i64())
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }
}

/// Custom Resolver that resolves schemas from memory
pub struct EmbeddedSchemaResolver {}

impl EmbeddedSchemaResolver {
    // Constructor to create a new resolver
    pub fn new() -> Self {
        EmbeddedSchemaResolver {}
    }
}

impl SchemaResolver for EmbeddedSchemaResolver {
    fn resolve(
        &self,
        _root_schema: &Value,
        url: &Url,
        _original_reference: &str,
    ) -> Result<Arc<Value>, SchemaResolverError> {
        let path = url.path();
        resolve_schema(path)
    }
}

// todo handle case for url retrieval
pub fn resolve_schema(rawpath: &str) -> Result<Arc<Value>, SchemaResolverError> {
    debug!("Entering resolve_schema function with path: {}", rawpath);
    let schema_value: Value;
    let path: &str;
    if rawpath.starts_with('/') {
        // Remove the leading slash and use the remaining path as the key
        path = &rawpath[1..];
    } else {
        // Use the full path as the key (relative or URI)
        path = rawpath;
    };

    // Check if ACCEPT_INVALID_CERTS is set to true and resolve schema from mock server URLs during tests
    if std::env::var("ACCEPT_INVALID_CERTS").unwrap_or_else(|_| "false".to_string()) == "true" {
        if let Some(schema_json) = DEFAULT_SCHEMA_STRINGS.get(path) {
            schema_value = serde_json::from_str(&schema_json)?;
            debug!("Successfully resolved schema from mock server: {}", path);
            return Ok(Arc::new(schema_value));
        }
    }

    error!("Failed to resolve schema: {}", path);
    Err(SchemaResolverError::new(SchemaResolverErrorWrapper(
        format!("Failed to fetch schema from URL {} ", path,),
    )))
}
