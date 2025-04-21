use crate::storage::MultiStorage;
use jsonschema::Retrieve;
use log::debug;
use phf::phf_map;
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

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
     "schemas/node/v1/node.schema.json" => include_str!("../../schemas/node/v1/node.schema.json"),
     "schemas/components/embedding/v1/embedding.schema.json" => include_str!("../../schemas/components/embedding/v1/embedding.schema.json")     // todo get all files in a schemas directory, dynamically
};

pub static SCHEMA_SHORT_NAME: phf::Map<&'static str, &'static str> = phf_map! {

    "https://hai.ai/schemas/agent/v1/agent.schema.json" => "agent" ,
    "https://hai.ai/schemas/components/action/v1/action-schema.json" => "action" ,
    "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json" => "agreement" ,
    "https://hai.ai/schemas/contact/v1/contact.schema.json" => "contact" ,
    "https://hai.ai/schemas/components/files/v1/files.schema.json" => "files" ,
    "https://hai.ai/schemas/service/v1/service.schema.json" => "service" ,
    "https://hai.ai/schemas/components/signature/v1/signature.schema.json" => "signature" ,
    "https://hai.ai/schemas/components/tool/v1/tool-schema.json" => "tool" ,
    "https://hai.ai/schemas/components/unit/v1/unit.schema.json" => "unit" ,
    "https://hai.ai/schemas/eval/v1/eval.schema.json" => "eval" ,
    "https://hai.ai/schemas/header/v1/header.schema.json" => "header" ,
    "https://hai.ai/schemas/message/v1/message.schema.json" => "message" ,
    "https://hai.ai/schemas/node/v1/node.schema.json" => "node" ,
    "https://hai.ai/schemas/task/v1/task-schema.json" => "task" ,
    "document" => "document" ,
};

pub fn get_short_name(jacs_document: &Value) -> Result<String, Box<dyn Error>> {
    let id: String = jacs_document
        .get_str("$id")
        .unwrap_or((&"document").to_string());
    return Ok(SCHEMA_SHORT_NAME
        .get(&id)
        .unwrap_or(&"document")
        .to_string());
}

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
    fn as_string(&self) -> String;
}

impl ValueExt for Value {
    fn as_string(&self) -> String {
        serde_json::to_string_pretty(self).expect("error")
    }

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

/// A schema retriever that primarily uses embedded schemas, with fallbacks to local filesystem
/// and remote URLs.
pub struct EmbeddedSchemaResolver {}

impl EmbeddedSchemaResolver {
    pub fn new() -> Self {
        EmbeddedSchemaResolver {}
    }
}

impl Retrieve for EmbeddedSchemaResolver {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let path = uri.path().as_str();
        resolve_schema(path).map(|arc| (*arc).clone()).map_err(|e| {
            let err_msg = e.to_string();
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, err_msg))
                as Box<dyn Error + Send + Sync>
        })
    }
}

/// Fetches a schema from a remote URL using reqwest.
///
/// Security: This function accepts invalid certificates and makes unrestricted HTTP requests.
/// It should only be used in development or controlled environments.
///
/// Not available in WASM builds.
#[cfg(not(target_arch = "wasm32"))]
fn get_remote_schema(url: &str) -> Result<Arc<Value>, Box<dyn Error>> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(ACCEPT_INVALID_CERTS)
        .build()?;

    let response = client.get(url).send()?;

    if response.status().is_success() {
        let schema_value: Value = response.json()?;
        Ok(Arc::new(schema_value))
    } else {
        Err(format!("Failed to get schema from URL {}", url).into())
    }
}

/// Disabled version of remote schema fetching for WASM targets.
/// Always returns an error indicating remote schemas are not supported.
#[cfg(target_arch = "wasm32")]
fn get_remote_schema(url: &str) -> Result<Arc<Value>, Box<dyn Error>> {
    Err(format!("Remote URL schemas disabled in WASM: {}", url).into())
}

/// Resolves a schema from various sources based on the provided path.
///
/// # Arguments
/// * `rawpath` - The path or URL to the schema. Can be:
///   - A key in DEFAULT_SCHEMA_STRINGS
///   - A https://hai.ai URL (will be converted to embedded schema)
///   - A remote URL (will attempt fetch)
///   - A local filesystem path
///
/// # Resolution Order
/// 1. Removes leading slash if present
/// 2. Checks DEFAULT_SCHEMA_STRINGS for direct match
/// 3. For URLs:
///    - hai.ai URLs: Converts to embedded schema lookup
///    - Other URLs: Attempts remote fetch
/// 4. Checks local filesystem
///
/// # Security Considerations
/// - Allows unrestricted remote URL fetching
/// - Allows unrestricted filesystem access
/// - Accepts invalid SSL certificates for remote fetching
pub fn resolve_schema(rawpath: &str) -> Result<Arc<Value>, Box<dyn Error>> {
    debug!("Entering resolve_schema function with path: {}", rawpath);
    let path = if rawpath.starts_with('/') {
        &rawpath[1..]
    } else {
        rawpath
    };

    // Check embedded schemas
    if let Some(schema_json) = DEFAULT_SCHEMA_STRINGS.get(path) {
        let schema_value: Value = serde_json::from_str(schema_json)?;
        return Ok(Arc::new(schema_value));
    }

    if path.starts_with("http://") || path.starts_with("https://") {
        debug!("Attempting to fetch schema from URL: {}", path);
        if path.starts_with("https://hai.ai") {
            let relative_path = path.trim_start_matches("https://hai.ai/");
            if let Some(schema_json) = DEFAULT_SCHEMA_STRINGS.get(relative_path) {
                let schema_value: Value = serde_json::from_str(schema_json)?;
                return Ok(Arc::new(schema_value));
            }
            return Err("Schema not found".into());
        } else {
            return get_remote_schema(path);
        }
    } else {
        // check filesystem
        let storage = MultiStorage::default_new()?;
        if storage.file_exists(path, None)? {
            let schema_json = String::from_utf8(storage.get_file(path, None)?)?;
            let schema_value: Value = serde_json::from_str(&schema_json)?;
            return Ok(Arc::new(schema_value));
        } else {
            Err(format!("Schema file not found: {}", path).into())
        }
    }
}
