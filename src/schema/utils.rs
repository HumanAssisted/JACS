use crate::schema::Url;
use log::debug;
use log::error;
use log::info;
use std::path::Path;

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
     "schemas/eval/v1/eval.schema.json" => include_str!("../../schemas/eval/v1/eval.schema.json"),
     "schemas/program/v1/program.schema.json" => include_str!("../../schemas/program/v1/program.schema.json"),
     "schemas/node/v1/node.schema.json" => include_str!("../../schemas/node/v1/node.schema.json")
     // todo get all files in a schemas directory, dynamically
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

    // in case the path is cached
    let schema_json_result = DEFAULT_SCHEMA_STRINGS.get(path);
    match schema_json_result {
        Some(schema_json) => {
            schema_value = serde_json::from_str(schema_json)?;
            return Ok(Arc::new(schema_value));
        }
        _ => {}
    }

    if path.starts_with("http://") || path.starts_with("https://") {
        debug!("Attempting to fetch schema from URL: {}", path);
        if path.starts_with("https://hai.ai") {
            let relative_path = path.trim_start_matches("https://hai.ai/");
            let schema_json = DEFAULT_SCHEMA_STRINGS.get(relative_path).ok_or_else(|| {
                error!("Error: Schema not found for URL: {}", path);
                SchemaResolverError::new(SchemaResolverErrorWrapper(format!(
                    "Schema not found: {}",
                    path
                )))
            })?;
            schema_value = serde_json::from_str(&schema_json)?;
            return Ok(Arc::new(schema_value));
        } else {
            // Create a reqwest client with SSL verification disabled
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(ACCEPT_INVALID_CERTS)
                .build()
                .map_err(|err| {
                    error!("Error fetching schema from URL: {}, error: {}", path, err);
                    SchemaResolverError::new(SchemaResolverErrorWrapper(format!(
                        "Failed to create reqwest client: {}",
                        err
                    )))
                })?;

            // Fetch the schema using the reqwest client
            let schema_response = client.get(path).send().map_err(|err| {
                error!("Error fetching schema from URL: {}, error: {}", path, err);
                SchemaResolverError::new(SchemaResolverErrorWrapper(format!(
                    "Failed to fetch schema from given URL {}: {}",
                    path, err
                )))
            })?;

            if schema_response.status().is_success() {
                schema_value = schema_response.json().map_err(|err| {
                    error!("Error parsing schema from URL: {}, error: {}", path, err);
                    SchemaResolverError::new(SchemaResolverErrorWrapper(format!(
                        "Failed to parse schema from URL {}: {}",
                        path, err
                    )))
                })?;
                return Ok(Arc::new(schema_value));
            } else {
                Err(SchemaResolverError::new(SchemaResolverErrorWrapper(
                    format!("Failed to get schema from URL {} rawpath {}", path, rawpath),
                )))
            }
        }
    } else if Path::new(path).exists() {
        // add default directory
        // todo secure with let pathstring: &String = &env::var("JACS_KEY_DIRECTORY").expect("JACS_DATA_DIRECTORY");
        println!("loading custom local schema {}", path);
        let schema_json = std::fs::read_to_string(path)?;
        let schema_value: Value = serde_json::from_str(&schema_json)?;
        return Ok(Arc::new(schema_value));
    } else {
        return Err(SchemaResolverError::new(SchemaResolverErrorWrapper(
            format!("Failed all attempts to retrieve schema {} ", path,),
        )));
    }
}
