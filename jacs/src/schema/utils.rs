use crate::error::JacsError;
use crate::storage::MultiStorage;
use jsonschema::Retrieve;
use phf::phf_map;
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use tracing::{debug, warn};

/// Whether to accept invalid TLS certificates when fetching remote schemas.
///
/// **Security Warning**: This is `false` by default for security.
/// Setting this to `true` allows MITM attacks when fetching remote schemas.
///
/// To enable insecure mode for development, set the environment variable:
/// `JACS_ACCEPT_INVALID_CERTS=true`
pub const ACCEPT_INVALID_CERTS: bool = false;

/// Returns whether to accept invalid TLS certificates.
/// Checks the environment variable `JACS_ACCEPT_INVALID_CERTS` first,
/// then falls back to the compile-time constant.
#[cfg(not(target_arch = "wasm32"))]
fn should_accept_invalid_certs() -> bool {
    match std::env::var("JACS_ACCEPT_INVALID_CERTS") {
        Ok(val) => {
            let accept = val.eq_ignore_ascii_case("true") || val == "1";
            if accept {
                warn!("SECURITY WARNING: Accepting invalid TLS certificates due to JACS_ACCEPT_INVALID_CERTS=true");
            }
            accept
        }
        Err(_) => ACCEPT_INVALID_CERTS,
    }
}
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
    Ok(SCHEMA_SHORT_NAME
        .get(&id)
        .unwrap_or(&"document")
        .to_string())
}

pub static CONFIG_SCHEMA_STRING: &str = include_str!("../../schemas/jacs.config.schema.json");

// Error type for future schema resolution error handling
#[derive(Debug)]
#[allow(dead_code)]
struct SchemaResolverErrorWrapper(String);

impl fmt::Display for SchemaResolverErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for SchemaResolverErrorWrapper {}

/// Extension trait for `serde_json::Value` providing convenient accessor methods.
///
/// These helpers reduce boilerplate for common JSON access patterns like:
/// - `value.get("field").and_then(|v| v.as_str())` -> `value.get_str("field")`
/// - `value["a"]["b"].as_str().unwrap_or("")` -> `value.get_path_str_or(&["a", "b"], "")`
/// - `value["a"]["b"].as_str().ok_or_else(...)` -> `value.get_path_str_required(&["a", "b"])`
pub trait ValueExt {
    /// Gets a string field, returning `Some(String)` if present and a string.
    fn get_str(&self, field: &str) -> Option<String>;

    /// Gets a string field, returning the provided default if missing or not a string.
    fn get_str_or(&self, field: &str, default: &str) -> String;

    /// Gets a required string field, returning an error if missing.
    fn get_str_required(&self, field: &str) -> Result<String, JacsError>;

    /// Gets an i64 field, returning `Some(i64)` if present and numeric.
    fn get_i64(&self, key: &str) -> Option<i64>;

    /// Gets a bool field, returning `Some(bool)` if present and boolean.
    fn get_bool(&self, key: &str) -> Option<bool>;

    /// Serializes the value to a pretty-printed JSON string.
    fn as_string(&self) -> String;

    /// Traverses a path of keys and returns the value at that path.
    ///
    /// # Example
    /// ```ignore
    /// let sig = value.get_path(&["jacsSignature", "publicKeyHash"]);
    /// ```
    fn get_path(&self, path: &[&str]) -> Option<&Value>;

    /// Traverses a path of keys and returns the string value at that path.
    ///
    /// # Example
    /// ```ignore
    /// let hash = value.get_path_str(&["jacsSignature", "publicKeyHash"]);
    /// ```
    fn get_path_str(&self, path: &[&str]) -> Option<String>;

    /// Traverses a path and returns the string value, or a default if not found.
    ///
    /// # Example
    /// ```ignore
    /// let agent_id = value.get_path_str_or(&["jacsSignature", "agentID"], "");
    /// ```
    fn get_path_str_or(&self, path: &[&str], default: &str) -> String;

    /// Traverses a path and returns a required string value, or an error.
    ///
    /// The error message includes the full dotted path for debugging.
    ///
    /// # Example
    /// ```ignore
    /// let hash = value.get_path_str_required(&["jacsSignature", "publicKeyHash"])?;
    /// ```
    fn get_path_str_required(&self, path: &[&str]) -> Result<String, JacsError>;

    /// Traverses a path and returns the array value at that path.
    fn get_path_array(&self, path: &[&str]) -> Option<&Vec<Value>>;

    /// Traverses a path and returns a required array, or an error.
    fn get_path_array_required(&self, path: &[&str]) -> Result<&Vec<Value>, JacsError>;
}

impl ValueExt for Value {
    fn as_string(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| {
            format!("{{\"error\": \"Failed to serialize JSON: {}\"}}", e)
        })
    }

    fn get_str(&self, field: &str) -> Option<String> {
        self.get(field)?.as_str().map(String::from)
    }

    fn get_str_or(&self, field: &str, default: &str) -> String {
        self.get(field)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    }

    fn get_str_required(&self, field: &str) -> Result<String, JacsError> {
        self.get_str(field).ok_or_else(|| JacsError::DocumentMalformed {
            field: field.to_string(),
            reason: format!("Missing or invalid field: {}", field),
        })
    }

    fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_i64())
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    fn get_path(&self, path: &[&str]) -> Option<&Value> {
        let mut current = self;
        for key in path {
            current = current.get(key)?;
        }
        Some(current)
    }

    fn get_path_str(&self, path: &[&str]) -> Option<String> {
        self.get_path(path)?.as_str().map(String::from)
    }

    fn get_path_str_or(&self, path: &[&str], default: &str) -> String {
        self.get_path_str(path).unwrap_or_else(|| default.to_string())
    }

    fn get_path_str_required(&self, path: &[&str]) -> Result<String, JacsError> {
        let dotted_path = path.join(".");
        self.get_path_str(path).ok_or_else(|| JacsError::DocumentMalformed {
            field: dotted_path.clone(),
            reason: format!("Missing or invalid field: {}", dotted_path),
        })
    }

    fn get_path_array(&self, path: &[&str]) -> Option<&Vec<Value>> {
        self.get_path(path)?.as_array()
    }

    fn get_path_array_required(&self, path: &[&str]) -> Result<&Vec<Value>, JacsError> {
        let dotted_path = path.join(".");
        self.get_path_array(path).ok_or_else(|| JacsError::DocumentMalformed {
            field: dotted_path.clone(),
            reason: format!("Missing or invalid array field: {}", dotted_path),
        })
    }
}

/// A schema retriever that primarily uses embedded schemas, with fallbacks to local filesystem
/// and remote URLs.
pub struct EmbeddedSchemaResolver {}

impl Default for EmbeddedSchemaResolver {
    fn default() -> Self {
        Self::new()
    }
}

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
            Box::new(std::io::Error::other(err_msg)) as Box<dyn Error + Send + Sync>
        })
    }
}

/// Fetches a schema from a remote URL using reqwest.
///
/// # Security
///
/// By default, this function validates TLS certificates. To skip validation
/// (for development only), set the environment variable `JACS_ACCEPT_INVALID_CERTS=true`.
///
/// **Warning**: Accepting invalid certificates allows MITM attacks.
///
/// Not available in WASM builds.
#[cfg(not(target_arch = "wasm32"))]
fn get_remote_schema(url: &str) -> Result<Arc<Value>, Box<dyn Error>> {
    let accept_invalid = should_accept_invalid_certs();
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(accept_invalid)
        .build()?;

    let response = client.get(url).send()?;

    if response.status().is_success() {
        let schema_value: Value = response.json()?;
        Ok(Arc::new(schema_value))
    } else {
        Err(JacsError::SchemaError(format!("Failed to get schema from URL {}", url)).into())
    }
}

/// Disabled version of remote schema fetching for WASM targets.
/// Always returns an error indicating remote schemas are not supported.
#[cfg(target_arch = "wasm32")]
fn get_remote_schema(url: &str) -> Result<Arc<Value>, Box<dyn Error>> {
    Err(JacsError::SchemaError(format!("Remote URL schemas disabled in WASM: {}", url)).into())
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
    let path = rawpath.strip_prefix('/').unwrap_or(rawpath);

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
            Err(JacsError::SchemaError(format!(
                "Schema not found in embedded schemas: '{}' (relative path: '{}'). Available schemas: {:?}",
                path, relative_path, DEFAULT_SCHEMA_STRINGS.keys().collect::<Vec<_>>()
            )).into())
        } else {
            get_remote_schema(path)
        }
    } else {
        // check filesystem
        let storage = MultiStorage::default_new()?;
        if storage.file_exists(path, None)? {
            let schema_json = String::from_utf8(storage.get_file(path, None)?)?;
            let schema_value: Value = serde_json::from_str(&schema_json)?;
            Ok(Arc::new(schema_value))
        } else {
            Err(JacsError::FileNotFound { path: path.to_string() }.into())
        }
    }
}
