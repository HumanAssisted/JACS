use crate::agent::document::JACSDocument;
use jsonschema::JSONSchema;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::Mutex;

// Custom error type to wrap jsonschema::ValidationError
#[derive(Debug)]
pub struct ValidationError {
    pub errors: Vec<String>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for error in &self.errors {
            writeln!(f, "{}", error)?;
        }
        Ok(())
    }
}

impl Error for ValidationError {}

// Reintroducing the DEFAULT_SCHEMA_STRINGS hashmap containing schema strings
static DEFAULT_SCHEMA_STRINGS: Lazy<Mutex<HashMap<String, &'static str>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
pub struct Schema {
    // Fields to store JSONSchema instances
    pub headerschema: JSONSchema,
    pub agentschema: JSONSchema,
    pub signatureschema: JSONSchema,
    // ... other schema fields ...
    // Fields to store Value instances for schemas
    pub header_value: Value,
    pub agent_value: Value,
    pub signature_value: Value,
    // ... other Value fields ...
}

impl Schema {
    pub fn new(base_url: &str) -> Self {
        let mut schema_strings = DEFAULT_SCHEMA_STRINGS.lock().unwrap();
        if schema_strings.is_empty() {
            // Populate the hashmap with schema strings
            schema_strings.insert(
                format!("{}/schemas/header/v1/header.schema.json", base_url),
                include_str!("../../schemas/header/v1/header.schema.json"),
            );
            schema_strings.insert(
                format!("{}/schemas/agent/v1/agent.schema.json", base_url),
                include_str!("../../schemas/agent/v1/agent.schema.json"),
            );
            schema_strings.insert(
                format!(
                    "{}/schemas/components/signature/v1/signature.schema.json",
                    base_url
                ),
                include_str!("../../schemas/components/signature/v1/signature.schema.json"),
            );
            // ... insert additional schema strings as needed ...
        }
        drop(schema_strings); // Release the lock

        // Proceed to create Value instances from the schema strings as before
        let header_value = serde_json::from_str::<Value>(
            DEFAULT_SCHEMA_STRINGS
                .lock()
                .unwrap()
                .get(&format!(
                    "{}/schemas/header/v1/header.schema.json",
                    base_url
                ))
                .expect("Header schema not found"),
        )
        .expect("Invalid header schema JSON");

        let agent_value = serde_json::from_str::<Value>(
            DEFAULT_SCHEMA_STRINGS
                .lock()
                .unwrap()
                .get(&format!("{}/schemas/agent/v1/agent.schema.json", base_url))
                .expect("Agent schema not found"),
        )
        .expect("Invalid agent schema JSON");

        let signature_value = serde_json::from_str::<Value>(
            DEFAULT_SCHEMA_STRINGS
                .lock()
                .unwrap()
                .get(&format!(
                    "{}/schemas/components/signature/v1/signature.schema.json",
                    base_url
                ))
                .expect("Signature schema not found"),
        )
        .expect("Invalid signature schema JSON");
        // ... other Value instances ...

        // Compile JSONSchema objects from the Value instances
        let headerschema =
            JSONSchema::compile(&header_value).expect("Failed to compile header schema");
        let agentschema =
            JSONSchema::compile(&agent_value).expect("Failed to compile agent schema");
        let signatureschema =
            JSONSchema::compile(&signature_value).expect("Failed to compile signature schema");
        // ... other JSONSchema compilations ...

        Self {
            headerschema,
            agentschema,
            signatureschema,
            // ... assign other schema fields ...
            header_value,
            agent_value,
            signature_value,
            // ... assign other Value fields ...
        }
    }

    pub fn validate_header(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let header: Value = serde_json::from_str(json)?;
        self.headerschema.validate(&header).map_err(|e| {
            Box::new(ValidationError {
                errors: e.into_iter().map(|err| err.to_string()).collect(),
            }) as Box<dyn Error>
        })?;
        Ok(header)
    }

    pub fn validate_agent(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let agent: Value = serde_json::from_str(json)?;
        self.agentschema.validate(&agent).map_err(|e| {
            Box::new(ValidationError {
                errors: e.into_iter().map(|err| err.to_string()).collect(),
            }) as Box<dyn Error>
        })?;
        Ok(agent)
    }

    pub fn validate_signature(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let signature: Value = serde_json::from_str(json)?;
        self.signatureschema.validate(&signature).map_err(|e| {
            Box::new(ValidationError {
                errors: e.into_iter().map(|err| err.to_string()).collect(),
            }) as Box<dyn Error>
        })?;
        Ok(signature)
    }

    /// Validates the agent configuration JSON string against the configuration schema.
    pub fn validate_config(&self, json: &str) -> Result<(), Box<dyn Error>> {
        let config: Value = serde_json::from_str(json)?;
        let config_schema_lock = DEFAULT_SCHEMA_STRINGS.lock().unwrap();
        let config_schema_str = config_schema_lock
            .get("http://127.0.0.1:12345/schemas/jacs.config.schema.json")
            .expect("Config schema not found");
        let config_schema_value = serde_json::from_str::<Value>(config_schema_str)?;
        let config_schema = JSONSchema::compile(&config_schema_value).map_err(|e| {
            Box::new(ValidationError {
                errors: vec![e.to_string()],
            })
        })?;

        config_schema
            .validate(&config)
            .map_err(|e| {
                Box::new(ValidationError {
                    errors: e.into_iter().map(|err| err.to_string()).collect(),
                }) as Box<dyn Error>
            })
            .map(|_| ())
    }

    // ... other validation functions ...

    /// Creates a new JACSDocument instance from a JSON string after validating it against the schema.
    pub fn create(&self, json: &str) -> Result<JACSDocument, Box<dyn Error>> {
        // Parse the JSON string into a Value
        let value: Value = serde_json::from_str(json)?;

        // Validate the Value against the schema
        self.validate_header(&json)?;

        // If validation is successful, create and return a new JACSDocument instance
        Ok(JACSDocument {
            id: value["jacsId"]
                .as_str()
                .ok_or("Missing 'jacsId' field in value")?
                .to_string(),
            version: value["jacsVersion"]
                .as_str()
                .ok_or("Missing 'jacsVersion' field in value")?
                .to_string(),
            value,
        })
    }
}

pub mod action_crud;
pub mod agent_crud;
pub mod contact_crud;
pub mod message_crud;
pub mod service_crud;
pub mod signature;
pub mod task_crud;
pub mod tools_crud;
pub mod utils;

pub use crate::schema::utils::SchemaResolverErrorWrapper;
