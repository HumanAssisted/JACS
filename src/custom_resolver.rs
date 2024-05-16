use jsonschema::SchemaResolverError;
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use url::Url;

// Define a custom error type that implements `Error` and `fmt::Display`.
#[derive(Debug)]
struct UnsupportedSchemeError;

impl fmt::Display for UnsupportedSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unsupported URL scheme")
    }
}

impl Error for UnsupportedSchemeError {}

pub struct MyCustomResolver;

impl jsonschema::SchemaResolver for MyCustomResolver {
    fn resolve(
        &self,
        _root_schema: &Value,
        url: &Url,
        _original_reference: &str,
    ) -> Result<Arc<Value>, SchemaResolverError> {
        match url.scheme() {
            "http" | "https" => {
                // Here we would load the schema from a local file or return a mocked schema
                // For now, we return a dummy schema for demonstration purposes
                Ok(Arc::new(
                    serde_json::json!({ "description": "an external schema" }),
                ))
            }
            _ => Err(SchemaResolverError::new(UnsupportedSchemeError)),
        }
    }
}
