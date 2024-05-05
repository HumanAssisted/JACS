use jsonschema::JSONSchema;
use serde_json::Value;
use std::sync::Arc;
use url::Url;

pub mod action_crud;
pub mod agent_crud;
pub mod contact_crud;
pub mod message_crud;
pub mod service_crud;
pub mod signature;
pub mod task_crud;
pub mod tools_crud;
pub mod utils;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

// Custom error type
#[derive(Debug)]
struct ValidationError(String);

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Validation error: {}", self.0)
    }
}

impl Error for ValidationError {}

#[derive(Debug)]
pub struct Schema {
    pub headerschema: JSONSchema,
    pub agentschema: JSONSchema,
    #[allow(dead_code)]
    signatureschema: JSONSchema,
    #[allow(dead_code)]
    jacsconfigschema: JSONSchema,
    #[allow(dead_code)]
    agreementschema: JSONSchema,
    #[allow(dead_code)]
    serviceschema: JSONSchema,
    #[allow(dead_code)]
    unitschema: JSONSchema,
    #[allow(dead_code)]
    actionschema: JSONSchema,
    #[allow(dead_code)]
    toolschema: JSONSchema,
    #[allow(dead_code)]
    contactschema: JSONSchema,
    pub taskschema: JSONSchema,
    #[allow(dead_code)]
    messageschema: JSONSchema,
    #[allow(dead_code)]
    evalschema: JSONSchema,
}

// static EXCLUDE_FIELDS: [&str; 2] = ["$schema", "$id"];

lazy_static! {
    static ref HEADERSCHEMA_VALUE_ARC: Arc<Value> = Arc::new(
        serde_json::from_str(
            DEFAULT_SCHEMA_STRINGS
                .get("http://127.0.0.1:12345/schemas/header/mock_version/header.schema.json")
                .unwrap()
        )
        .unwrap()
    );
    static ref AGENTSCHEMA_VALUE_ARC: Arc<Value> = Arc::new(
        serde_json::from_str(
            DEFAULT_SCHEMA_STRINGS
                .get("http://127.0.0.1:12345/schemas/document/mock_version/document.schema.json")
                .unwrap()
        )
        .unwrap()
    );
}

impl Schema {
    pub fn new(
        _header_schema_url: &str,
        _document_schema_url: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let headerschema_compiled = JSONSchema::compile(HEADERSCHEMA_VALUE_ARC.as_ref())?;
        let agentschema_compiled = JSONSchema::compile(AGENTSCHEMA_VALUE_ARC.as_ref())?;

        let schema = Self {
            headerschema: headerschema_compiled,
            agentschema: agentschema_compiled,
            // Initialize other schemas with dummy data...
            signatureschema: JSONSchema::compile(&Value::Null)?,
            jacsconfigschema: JSONSchema::compile(&Value::Null)?,
            agreementschema: JSONSchema::compile(&Value::Null)?,
            serviceschema: JSONSchema::compile(&Value::Null)?,
            unitschema: JSONSchema::compile(&Value::Null)?,
            actionschema: JSONSchema::compile(&Value::Null)?,
            toolschema: JSONSchema::compile(&Value::Null)?,
            contactschema: JSONSchema::compile(&Value::Null)?,
            taskschema: JSONSchema::compile(&Value::Null)?,
            messageschema: JSONSchema::compile(&Value::Null)?,
            evalschema: JSONSchema::compile(&Value::Null)?,
        };

        Ok(schema)
    }

    pub fn create(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let instance: Value = serde_json::from_str(json)?;
        let errors: Vec<ValidationError> = self
            .agentschema
            .validate(&instance)
            .into_iter()
            .filter_map(|e| Some(ValidationError(format!("Validation error: {:?}", e))))
            .collect();
        if !errors.is_empty() {
            return Err(Box::new(ValidationError(format!(
                "Validation errors: {:?}",
                errors
            ))));
        }
        Ok(instance)
    }

    pub fn validate_header(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let header: Value = serde_json::from_str(json)?;
        let errors: Vec<ValidationError> = self
            .headerschema
            .validate(&header)
            .into_iter()
            .filter_map(|e| Some(ValidationError(format!("Validation error: {:?}", e))))
            .collect();
        if !errors.is_empty() {
            return Err(Box::new(ValidationError(format!(
                "Validation errors: {:?}",
                errors
            ))));
        }
        Ok(header)
    }

    pub fn validate_config(&self, json: &str) -> Result<(), Box<dyn Error>> {
        let config: Value = serde_json::from_str(json)?;
        let errors: Vec<ValidationError> = self
            .jacsconfigschema
            .validate(&config)
            .into_iter()
            .filter_map(|e| Some(ValidationError(format!("Validation error: {:?}", e))))
            .collect();
        if !errors.is_empty() {
            return Err(Box::new(ValidationError(format!(
                "Validation errors: {:?}",
                errors
            ))));
        }
        Ok(())
    }

    pub fn validate_signature(&self, json: &str) -> Result<(), Box<dyn Error>> {
        let signature: Value = serde_json::from_str(json)?;
        let errors: Vec<ValidationError> = self
            .signatureschema
            .validate(&signature)
            .into_iter()
            .filter_map(|e| Some(ValidationError(format!("Validation error: {:?}", e))))
            .collect();
        if !errors.is_empty() {
            return Err(Box::new(ValidationError(format!(
                "Validation errors: {:?}",
                errors
            ))));
        }
        Ok(())
    }

    pub fn validate_agent(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let agent: Value = serde_json::from_str(json)?;
        let errors: Vec<ValidationError> = self
            .agentschema
            .validate(&agent)
            .into_iter()
            .filter_map(|e| Some(ValidationError(format!("Validation error: {:?}", e))))
            .collect();
        if !errors.is_empty() {
            return Err(Box::new(ValidationError(format!(
                "Validation errors: {:?}",
                errors
            ))));
        }
        Ok(agent)
    }
}

pub use crate::schema::utils::SchemaResolverErrorWrapper;

lazy_static! {
    pub static ref DEFAULT_SCHEMA_STRINGS: HashMap<String, &'static str> = {
        let mut m = HashMap::new();
        m.insert(
            "http://127.0.0.1:12345/schemas/header/mock_version/header.schema.json".to_string(),
            r#"{
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Mock Header Schema",
                "type": "object",
                "properties": {
                    "version": {
                        "type": "string"
                    },
                    "identifier": {
                        "type": "string"
                    }
                },
                "required": ["version", "identifier"]
            }"#,
        );
        m.insert(
            "http://127.0.0.1:12345/schemas/document/mock_version/document.schema.json".to_string(),
            r#"{
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Mock Document Schema",
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string"
                    },
                    "content": {
                        "type": "string"
                    }
                },
                "required": ["title", "content"]
            }"#,
        );
        m
    };
}
