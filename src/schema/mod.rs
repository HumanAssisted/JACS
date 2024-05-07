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
    #[serde(skip)]
    pub headerschema: JSONSchema,
    #[serde(skip)]
    pub agentschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    signatureschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    jacsconfigschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    agreementschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    serviceschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    unitschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    actionschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    toolschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    contactschema: JSONSchema,
    #[serde(skip)]
    pub taskschema: JSONSchema,
    #[serde(skip)]
    #[allow(dead_code)]
    messageschema: JSONSchema,
    #[serde(skip)]
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
        println!("Compiling header schema from URL: {}", _header_schema_url);
        let headerschema_compiled = JSONSchema::compile(HEADERSCHEMA_VALUE_ARC.as_ref())?;
        println!("Header schema compiled successfully.");

        println!("Compiling agent schema from URL: {}", _document_schema_url);
        let agentschema_compiled = JSONSchema::compile(AGENTSCHEMA_VALUE_ARC.as_ref())?;
        println!("Agent schema compiled successfully.");

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
        println!("Entering validate_agent method with JSON: {}", json);
        println!("JSON data as a string before parsing: {}", json);
        let agent: Value = serde_json::from_str(json)?;
        println!("Parsed JSON Value: {:?}", agent); // Confirm the parsed JSON structure
        println!("Value before validation: {:?}", agent); // Output the value right before validation
        let validation_result = self.agentschema.validate(&agent);

        let validation_errors: Vec<ValidationError> = validation_result
            .err()
            .into_iter()
            .flat_map(|iter| iter)
            .map(|err| ValidationError(format!("Validation error: {:?}", err)))
            .collect();
        if !validation_errors.is_empty() {
            println!("Validation errors encountered: {:?}", validation_errors); // Log detailed validation errors
            Err(Box::new(ValidationError(format!(
                "Validation errors: {:?}",
                validation_errors
            ))))
        } else {
            println!("Validation successful for agent JSON."); // Log successful validation
            Ok(agent)
        }
    }
}

impl Default for Schema {
    fn default() -> Self {
        Schema {
            headerschema: JSONSchema::compile(&Value::Null).unwrap(),
            agentschema: JSONSchema::compile(&Value::Null).unwrap(),
            signatureschema: JSONSchema::compile(&Value::Null).unwrap(),
            jacsconfigschema: JSONSchema::compile(&Value::Null).unwrap(),
            agreementschema: JSONSchema::compile(&Value::Null).unwrap(),
            serviceschema: JSONSchema::compile(&Value::Null).unwrap(),
            unitschema: JSONSchema::compile(&Value::Null).unwrap(),
            actionschema: JSONSchema::compile(&Value::Null).unwrap(),
            toolschema: JSONSchema::compile(&Value::Null).unwrap(),
            contactschema: JSONSchema::compile(&Value::Null).unwrap(),
            taskschema: JSONSchema::compile(&Value::Null).unwrap(),
            messageschema: JSONSchema::compile(&Value::Null).unwrap(),
            evalschema: JSONSchema::compile(&Value::Null).unwrap(),
        }
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
                    "jacsId": {
                        "type": "string",
                        "format": "uuid"
                    },
                    "jacsVersion": {
                        "type": "string",
                        "format": "uuid"
                    },
                    "jacsVersionDate": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "jacsSignature": {
                        "$ref": "https://hai.ai/schemas/components/signature/v1/signature.schema.json"
                    },
                    "jacsRegistration": {
                        "$ref": "https://hai.ai/schemas/components/signature/v1/signature.schema.json"
                    },
                    "jacsAgreement": {
                        "$ref": "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json"
                    },
                    "jacsAgreementHash": {
                        "type": "string"
                    },
                    "jacsPreviousVersion": {
                        "type": "string",
                        "format": "uuid"
                    },
                    "jacsOriginalVersion": {
                        "type": "string",
                        "format": "uuid"
                    },
                    "jacsOriginalDate": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "jacsSha256": {
                        "type": "string"
                    },
                    "jacsFiles": {
                        "type": "array",
                        "items": {
                            "$ref": "https://hai.ai/schemas/components/files/v1/files.schema.json"
                        }
                    }
                },
                "required": [
                    "jacsId",
                    "jacsVersion",
                    "jacsVersionDate",
                    "jacsOriginalVersion",
                    "jacsOriginalDate",
                    "$schema"
                ]
            }"#,
        );
        m.insert(
            "http://127.0.0.1:12345/schemas/document/mock_version/document.schema.json".to_string(),
            r#"{
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Agent",
                "type": "object",
                "properties": {
                    "jacsId": {
                        "type": "string",
                        "format": "uuid"
                    },
                    "jacsVersion": {
                        "type": "string"
                    },
                    "jacsVersionDate": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "jacsOriginalVersion": {
                        "type": "string"
                    },
                    "jacsOriginalDate": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "jacsAgentType": {
                        "type": "string"
                    },
                    "jacsServices": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "serviceId": {
                                    "type": "string"
                                },
                                "serviceName": {
                                    "type": "string"
                                },
                                "serviceDescription": {
                                    "type": "string"
                                }
                            },
                            "required": ["serviceId", "serviceName", "serviceDescription"]
                        }
                    },
                    "jacsContacts": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "contactId": {
                                    "type": "string"
                                },
                                "contactType": {
                                    "type": "string"
                                },
                                "contactDetails": {
                                    "type": "string"
                                }
                            },
                            "required": ["contactId", "contactType", "contactDetails"]
                        }
                    }
                },
                "required": [
                    "jacsId",
                    "jacsVersion",
                    "jacsVersionDate",
                    "jacsOriginalVersion",
                    "jacsOriginalDate",
                    "jacsAgentType",
                    "jacsServices",
                    "jacsContacts"
                ]
            }"#,
        );
        m
    };
}
