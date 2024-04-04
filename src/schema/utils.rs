use crate::schema::Url;
use log::debug;
use phf::phf_map;

use jsonschema::SchemaResolver;
use jsonschema::SchemaResolverError;
use serde_json::Value;
use std::{fs, path::PathBuf, sync::Arc};

use std::error::Error;
use std::fmt;

pub static DEFAULT_SCHEMA_STRINGS: phf::Map<&'static str, &'static str> = phf_map! {
    "schemas/agent/v1/agent.schema.json" => include_str!("../../schemas/agent/v1/agent.schema.json"),
    "schemas/header/v1/header.schema.json"=> include_str!("../../schemas/header/v1/header.schema.json"),
    "schemas/components/signature/v1/signature.schema.json" => include_str!("../../schemas/components/signature/v1/signature.schema.json"),
    // todo get all files in a schemas directory, dynamically
    // "schemas/jacs.config.schema.json" => include_str!("../../schemas/jacs.config.schema.json"),
};

pub static CONFIG_SCHEMA_STRING: &str = include_str!("../../schemas/jacs.config.schema.json");

#[derive(Debug)]
struct SchemaResolverErrorWrapper(String);

impl fmt::Display for SchemaResolverErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for SchemaResolverErrorWrapper {}

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

/// Custom Resolver that resolves schemas from the local filesystem
pub struct LocalSchemaResolver {
    base_path: PathBuf,
}

impl LocalSchemaResolver {
    // Constructor to create a new resolver with a specified base path
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }
}

impl SchemaResolver for LocalSchemaResolver {
    fn resolve(
        &self,
        _root_schema: &Value,
        url: &Url,
        _original_reference: &str,
    ) -> Result<Arc<Value>, SchemaResolverError> {
        let relative_path = url.path().trim_start_matches('/'); // Strips leading slash
        let path = self.base_path.join(relative_path);

        let schema_json = fs::read_to_string(&path).map_err(|io_err| {
            // Map I/O errors
            // SchemaResolverError::new(format!("{:?} {}", io_err, url.clone()))
            io_err
        })?;

        let schema_value: Value = serde_json::from_str(&schema_json).map_err(|serde_err| {
            // Map JSON parsing errors
            //SchemaResolverError::new(format!("{:?} {}", serde_err, url.clone()))
            serde_err
        })?;

        Ok(Arc::new(schema_value))
    }
}

/// Custom Resolver that resolves schemas from memory
pub struct EmbeddedSchemaResolver {}

impl EmbeddedSchemaResolver {
    // Constructor to create a new resolver with a specified base path
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
        let relative_path = url.path().trim_start_matches('/'); // Strips leading slash

        debug!(" url, relative_path {} {}", url, relative_path);
        let schema_json = super::DEFAULT_SCHEMA_STRINGS
            .get(relative_path)
            .ok_or_else(|| {
                SchemaResolverError::new(SchemaResolverErrorWrapper(format!(
                    "Schema not found: {}",
                    url.clone()
                )))
            })?;

        let schema_value: Value = serde_json::from_str(schema_json).map_err(|serde_err| {
            // Map JSON parsing errors
            SchemaResolverError::new(SchemaResolverErrorWrapper(format!(
                "{:?} {}",
                serde_err,
                url.clone()
            )))
        })?;

        Ok(Arc::new(schema_value))
    }
}
