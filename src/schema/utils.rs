use crate::schema::Url;

use jsonschema::SchemaResolver;
use jsonschema::SchemaResolverError;
use serde_json::Value;
use std::{fs, path::PathBuf, sync::Arc};

pub trait ValueExt {
    fn get_str(&self, field: &str) -> Option<String>;
}

impl ValueExt for Value {
    fn get_str(&self, field: &str) -> Option<String> {
        self.get(field)?.as_str().map(String::from)
    }
}

// Custom Resolver that resolves schemas from the local filesystem
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
