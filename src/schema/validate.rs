use jsonschema::SchemaResolverError;
use jsonschema::{Draft, JSONSchema, SchemaResolver};
use log::{debug, error, warn};
use serde_json::Value;
use std::env;
use std::io::Error;
use std::{fs, path::PathBuf, sync::Arc};
use url::Url;

// Custom Resolver that resolves schemas from the local filesystem
struct LocalSchemaResolver {
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

pub struct Schema {
    schema: Value,
}

impl Schema {
    pub fn new(schema_type: &str, version: &str) -> Result<Self, Error> {
        let current_dir = env::current_dir()?;
        let schema_path: PathBuf = current_dir
            .join("schemas")
            .join(schema_type)
            .join(version)
            .join(format!("{}.schema.json", schema_type));

        let data = match fs::read_to_string(schema_path.clone()) {
            Ok(data) => {
                debug!("Schema is {:?}", data);
                data
            }
            Err(e) => {
                let error_message = format!("Failed to read schema file: {}", e);
                error!("{}", error_message);
                return Err(e);
            }
        };

        let schema: Value = serde_json::from_str(&data)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        let base_path = PathBuf::from(".");

        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON: {}", e);
                warn!("validate error {:?}", error_message);
                return Err(error_message);
            }
        };
        let localresolver = LocalSchemaResolver::new(base_path);

        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(localresolver)
            .compile(&self.schema)
            .expect("A valid schema");

        let validation_result = compiled.validate(&instance);

        match validation_result {
            Ok(_) => Ok(()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                if let Some(error_message) = error_messages.first() {
                    Err(error_message.clone())
                } else {
                    Err("Unexpected error during validation: no error messages found".to_string())
                }
            }
        }
    }
}
