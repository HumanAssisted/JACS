use crate::schema::Url;
use std::collections::HashMap;

use jsonschema::SchemaResolver;
use jsonschema::SchemaResolverError;
use serde_json::Value;
use std::{fs, path::PathBuf, sync::Arc};

use std::error::Error;
use std::fmt;

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
}

impl ValueExt for Value {
    fn get_str(&self, field: &str) -> Option<String> {
        self.get(field)?.as_str().map(String::from)
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
pub struct EmbeddedSchemaResolver {
    schemas: HashMap<String, &'static str>,
}

impl EmbeddedSchemaResolver {
    // Constructor to create a new resolver with a specified base path
    pub fn new(base_path: PathBuf) -> Self {
        let mut schemas = HashMap::new();
        // todo get all files in schema directory
        schemas.insert(
            "agent/v1/agent.schema.json".to_string(),
            include_str!("../../schemas/agent/v1/agent.schema.json"),
        );
        schemas.insert(
            "header/v1/header.schema.json".to_string(),
            include_str!("../../schemas/header/v1/header.schema.json"),
        );
        schemas.insert(
            "components/permission/v1/permission.schema.json".to_string(),
            include_str!("../../schemas/components/permission/v1/permission.schema.json"),
        );
        schemas.insert(
            "components/signature/v1/signature.schema.json".to_string(),
            include_str!("../../schemas/components/signature/v1/signature.schema.json"),
        );
        EmbeddedSchemaResolver { schemas }
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

        let schema_json = self.schemas.get(relative_path).ok_or_else(|| {
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
