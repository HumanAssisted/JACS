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
/// **Default behavior**: `true` - accepts invalid certs with a warning.
/// This allows the application to continue working in development environments
/// with self-signed certificates while alerting users to the security risk.
///
/// To enforce strict TLS validation (recommended for production), set:
/// `JACS_STRICT_TLS=true`
///
/// **Security Warning**: Accepting invalid certificates allows MITM attacks.
pub const ACCEPT_INVALID_CERTS_DEFAULT: bool = false;

/// Default allowed domains for remote schema fetching.
///
/// Only URLs from these domains will be fetched when resolving remote schemas.
/// Additional domains can be added via the `JACS_SCHEMA_ALLOWED_DOMAINS` environment variable.
pub const DEFAULT_ALLOWED_SCHEMA_DOMAINS: &[&str] = &["hai.ai", "schema.hai.ai"];

/// Check if a URL is allowed for schema fetching.
///
/// A URL is allowed if its host matches one of the allowed domains (either from
/// `DEFAULT_ALLOWED_SCHEMA_DOMAINS` or from the `JACS_SCHEMA_ALLOWED_DOMAINS` env var).
///
/// # Arguments
/// * `url` - The URL to check
///
/// # Returns
/// * `Ok(())` if the URL is allowed
/// * `Err(JacsError)` if the URL is blocked
/// Default maximum document size in bytes (10MB).
pub const DEFAULT_MAX_DOCUMENT_SIZE: usize = 10 * 1024 * 1024;

/// Returns the maximum allowed document size in bytes.
///
/// The default is 10MB (10 * 1024 * 1024 bytes). This can be overridden by setting
/// the `JACS_MAX_DOCUMENT_SIZE` environment variable to a number of bytes.
///
/// # Example
/// ```bash
/// # Set max document size to 50MB
/// export JACS_MAX_DOCUMENT_SIZE=52428800
/// ```
pub fn max_document_size() -> usize {
    std::env::var("JACS_MAX_DOCUMENT_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_DOCUMENT_SIZE)
}

/// Checks if a document's size is within the allowed limit.
///
/// # Arguments
/// * `data` - The document data as a string slice
///
/// # Returns
/// * `Ok(())` if the document size is within limits
/// * `Err(JacsError::DocumentTooLarge)` if the document exceeds the maximum size
///
/// # Example
/// ```rust,ignore
/// use jacs::schema::utils::check_document_size;
///
/// let large_doc = "x".repeat(100_000_000); // 100MB
/// assert!(check_document_size(&large_doc).is_err());
/// ```
pub fn check_document_size(data: &str) -> Result<(), JacsError> {
    let max = max_document_size();
    let size = data.len();
    if size > max {
        return Err(JacsError::DocumentTooLarge {
            size,
            max_size: max,
        });
    }
    Ok(())
}

/// Extra allowed domains parsed from `JACS_SCHEMA_ALLOWED_DOMAINS`, cached once.
static EXTRA_ALLOWED_SCHEMA_DOMAINS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

fn get_extra_allowed_domains() -> &'static Vec<String> {
    EXTRA_ALLOWED_SCHEMA_DOMAINS.get_or_init(|| {
        std::env::var("JACS_SCHEMA_ALLOWED_DOMAINS")
            .map(|env_domains| {
                env_domains
                    .split(',')
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    })
}

fn is_schema_url_allowed(url: &str) -> Result<(), JacsError> {
    // Parse the URL to extract the host
    let parsed = url::Url::parse(url)
        .map_err(|e| JacsError::SchemaError(format!("Invalid URL '{}': {}", url, e)))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| JacsError::SchemaError(format!("URL '{}' has no host", url)))?;

    // Build the list of allowed domains from defaults + cached env var
    let extra = get_extra_allowed_domains();
    let mut allowed_domains: Vec<&str> = DEFAULT_ALLOWED_SCHEMA_DOMAINS.to_vec();
    for domain in extra {
        allowed_domains.push(domain.as_str());
    }

    // Check if the host matches any allowed domain
    let host_lower = host.to_lowercase();
    for allowed in &allowed_domains {
        let allowed_lower = allowed.to_lowercase();
        // Match exactly or as a subdomain (e.g., "foo.hai.ai" matches "hai.ai")
        if host_lower == allowed_lower || host_lower.ends_with(&format!(".{}", allowed_lower)) {
            return Ok(());
        }
    }

    Err(JacsError::SchemaError(format!(
        "Remote schema URL '{}' is not from an allowed domain. \
        Allowed domains: {:?}. \
        To add additional domains, set JACS_SCHEMA_ALLOWED_DOMAINS environment variable (comma-separated).",
        url, allowed_domains
    )))
}

/// Returns whether to accept invalid TLS certificates.
///
/// By default, accepts invalid certs but logs a warning.
/// Set `JACS_STRICT_TLS=true` to enforce certificate validation (recommended for production).
#[cfg(not(target_arch = "wasm32"))]
fn should_accept_invalid_certs() -> bool {
    // Check for strict mode first - if enabled, always validate certs
    if let Ok(val) = std::env::var("JACS_STRICT_TLS") {
        if val.eq_ignore_ascii_case("true") || val == "1" {
            return false; // Don't accept invalid certs in strict mode
        }
    }

    // Check legacy env var for explicit override
    if let Ok(val) = std::env::var("JACS_ACCEPT_INVALID_CERTS") {
        let accept = val.eq_ignore_ascii_case("true") || val == "1";
        if accept {
            warn!(
                "SECURITY WARNING: Accepting invalid TLS certificates due to JACS_ACCEPT_INVALID_CERTS=true"
            );
        }
        return accept;
    }

    // Default: accept invalid certs but warn
    if ACCEPT_INVALID_CERTS_DEFAULT {
        warn!(
            "TLS certificate validation is disabled by default. \
            For production, set JACS_STRICT_TLS=true to enforce certificate validation."
        );
    }
    ACCEPT_INVALID_CERTS_DEFAULT
}

/// Check TLS strictness considering verification claim.
///
/// Verified claims (`verified` or `verified-hai.ai`) ALWAYS require strict TLS.
/// This enforces the principle: "If you claim it, you must prove it."
///
/// # Arguments
/// * `claim` - The agent's verification claim, if any
///
/// # Returns
/// * `false` for verified claims (never accept invalid certs)
/// * Falls back to `should_accept_invalid_certs()` for unverified/missing claims
///
/// # Security
///
/// This function ensures that agents claiming verified status cannot have their
/// connections intercepted via MITM attacks using invalid TLS certificates.
///
/// # Example
/// ```rust,ignore
/// use jacs::schema::utils::should_accept_invalid_certs_for_claim;
///
/// // Verified agents always require strict TLS
/// assert!(!should_accept_invalid_certs_for_claim(Some("verified")));
/// assert!(!should_accept_invalid_certs_for_claim(Some("verified-hai.ai")));
///
/// // Unverified agents use env-var based logic
/// let result = should_accept_invalid_certs_for_claim(None);
/// let result2 = should_accept_invalid_certs_for_claim(Some("unverified"));
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn should_accept_invalid_certs_for_claim(claim: Option<&str>) -> bool {
    // Verified claims ALWAYS require strict TLS
    match claim {
        Some("verified") | Some("verified-hai.ai") => false,
        _ => should_accept_invalid_certs(), // existing env-var check
    }
}

/// WASM version of claim-aware TLS check.
/// Always returns false (strict TLS) since WASM doesn't support relaxed TLS.
#[cfg(target_arch = "wasm32")]
pub fn should_accept_invalid_certs_for_claim(_claim: Option<&str>) -> bool {
    false
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
     "schemas/components/embedding/v1/embedding.schema.json" => include_str!("../../schemas/components/embedding/v1/embedding.schema.json"),
     "schemas/agentstate/v1/agentstate.schema.json" => include_str!("../../schemas/agentstate/v1/agentstate.schema.json"),
     "schemas/commitment/v1/commitment.schema.json" => include_str!("../../schemas/commitment/v1/commitment.schema.json"),
     "schemas/todo/v1/todo.schema.json" => include_str!("../../schemas/todo/v1/todo.schema.json"),
     "schemas/components/todoitem/v1/todoitem.schema.json" => include_str!("../../schemas/components/todoitem/v1/todoitem.schema.json")
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
    "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json" => "agentstate" ,
    "https://hai.ai/schemas/commitment/v1/commitment.schema.json" => "commitment" ,
    "https://hai.ai/schemas/todo/v1/todo.schema.json" => "todo" ,
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
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize JSON: {}\"}}", e))
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
        self.get_str(field)
            .ok_or_else(|| JacsError::DocumentMalformed {
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
        self.get_path_str(path)
            .unwrap_or_else(|| default.to_string())
    }

    fn get_path_str_required(&self, path: &[&str]) -> Result<String, JacsError> {
        let dotted_path = path.join(".");
        self.get_path_str(path)
            .ok_or_else(|| JacsError::DocumentMalformed {
                field: dotted_path.clone(),
                reason: format!("Missing or invalid field: {}", dotted_path),
            })
    }

    fn get_path_array(&self, path: &[&str]) -> Option<&Vec<Value>> {
        self.get_path(path)?.as_array()
    }

    fn get_path_array_required(&self, path: &[&str]) -> Result<&Vec<Value>, JacsError> {
        let dotted_path = path.join(".");
        self.get_path_array(path)
            .ok_or_else(|| JacsError::DocumentMalformed {
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
/// By default, this function accepts invalid TLS certificates but logs a warning.
/// This allows development environments with self-signed certs to work out of the box.
///
/// For production, set `JACS_STRICT_TLS=true` to enforce certificate validation.
///
/// **Warning**: Accepting invalid certificates allows MITM attacks.
///
/// Not available in WASM builds.
#[cfg(not(target_arch = "wasm32"))]
fn get_remote_schema(url: &str) -> Result<Arc<Value>, Box<dyn Error>> {
    // Check if the URL is from an allowed domain
    is_schema_url_allowed(url)?;

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

/// Check if filesystem schema access is allowed and the path is safe.
///
/// Filesystem schema access is disabled by default. To enable it, set:
/// `JACS_ALLOW_FILESYSTEM_SCHEMAS=true`
///
/// When enabled, paths are restricted to:
/// - The `JACS_DATA_DIRECTORY` if set
/// - The `JACS_SCHEMA_DIRECTORY` if set
/// - Paths must not contain path traversal sequences (`..`)
///
/// # Arguments
/// * `path` - The filesystem path to check
///
/// # Returns
/// * `Ok(())` if filesystem access is allowed and the path is safe
/// * `Err(JacsError)` if access is denied or the path is unsafe
fn check_filesystem_schema_access(path: &str) -> Result<(), JacsError> {
    // Check if filesystem schemas are enabled
    let fs_enabled = std::env::var("JACS_ALLOW_FILESYSTEM_SCHEMAS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    if !fs_enabled {
        return Err(JacsError::SchemaError(format!(
            "Filesystem schema access is disabled. Path '{}' cannot be loaded. \
            To enable filesystem schemas, set JACS_ALLOW_FILESYSTEM_SCHEMAS=true",
            path
        )));
    }

    // Block path traversal attempts
    if path.contains("..") {
        return Err(JacsError::SchemaError(format!(
            "Path traversal detected in schema path '{}'. \
            Schema paths must not contain '..' sequences.",
            path
        )));
    }

    // Get allowed directories
    let data_dir = std::env::var("JACS_DATA_DIRECTORY").ok();
    let schema_dir = std::env::var("JACS_SCHEMA_DIRECTORY").ok();

    // If specific directories are configured, check that the path is within them
    if data_dir.is_some() || schema_dir.is_some() {
        let path_canonical = std::path::Path::new(path);

        // Try to canonicalize the path for comparison (handles symlinks)
        // If canonicalization fails (file doesn't exist yet), fall back to the original path
        let path_str = if let Ok(canonical) = path_canonical.canonicalize() {
            canonical.to_string_lossy().to_string()
        } else {
            path.to_string()
        };

        let mut allowed = false;

        if let Some(ref data) = data_dir {
            let data_path = std::path::Path::new(data);
            if let Ok(data_canonical) = data_path.canonicalize() {
                if path_str.starts_with(&data_canonical.to_string_lossy().to_string()) {
                    allowed = true;
                }
            } else if path_str.starts_with(data) {
                // Fall back to string prefix check if canonicalization fails
                allowed = true;
            }
        }

        if let Some(ref schema) = schema_dir {
            let schema_path = std::path::Path::new(schema);
            if let Ok(schema_canonical) = schema_path.canonicalize() {
                if path_str.starts_with(&schema_canonical.to_string_lossy().to_string()) {
                    allowed = true;
                }
            } else if path_str.starts_with(schema) {
                allowed = true;
            }
        }

        if !allowed {
            return Err(JacsError::SchemaError(format!(
                "Schema path '{}' is outside allowed directories. \
                Schemas must be within JACS_DATA_DIRECTORY ({:?}) or JACS_SCHEMA_DIRECTORY ({:?}).",
                path, data_dir, schema_dir
            )));
        }
    }

    Ok(())
}

/// Resolves a schema from various sources based on the provided path.
///
/// # Arguments
/// * `rawpath` - The path or URL to the schema. Can be:
///   - A key in DEFAULT_SCHEMA_STRINGS
///   - A <https://hai.ai> URL (will be converted to embedded schema)
///   - A remote URL (will attempt fetch, subject to domain allowlist)
///   - A local filesystem path (requires `JACS_ALLOW_FILESYSTEM_SCHEMAS=true`)
///
/// # Resolution Order
/// 1. Removes leading slash if present
/// 2. Checks DEFAULT_SCHEMA_STRINGS for direct match
/// 3. For URLs:
///    - hai.ai URLs: Converts to embedded schema lookup
///    - Other URLs: Checks domain allowlist, then attempts remote fetch
/// 4. Checks local filesystem (if enabled via `JACS_ALLOW_FILESYSTEM_SCHEMAS`)
///
/// # Security Considerations
/// - Remote URLs are restricted to allowed domains (see `DEFAULT_ALLOWED_SCHEMA_DOMAINS`)
/// - Filesystem access is disabled by default (opt-in via `JACS_ALLOW_FILESYSTEM_SCHEMAS`)
/// - Path traversal (`..`) is blocked for filesystem paths
/// - TLS certificate validation is enabled by default (can be relaxed for development)
pub fn resolve_schema(rawpath: &str) -> Result<Arc<Value>, Box<dyn Error>> {
    debug!("Entering resolve_schema function with path: {}", rawpath);
    let path = rawpath.strip_prefix('/').unwrap_or(rawpath);

    // Check embedded schemas first (always allowed, no security concerns)
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
            // get_remote_schema already checks the domain allowlist
            get_remote_schema(path)
        }
    } else {
        // Filesystem path - check security restrictions
        check_filesystem_schema_access(path)?;

        let storage = MultiStorage::default_new()?;
        if storage.file_exists(path, None)? {
            let schema_json = String::from_utf8(storage.get_file(path, None)?)?;
            let schema_value: Value = serde_json::from_str(&schema_json)?;
            Ok(Arc::new(schema_value))
        } else {
            Err(JacsError::FileNotFound {
                path: path.to_string(),
            }
            .into())
        }
    }
}
