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

// Custom error type to wrap jsonschema::ValidationError
#[derive(Debug)]
struct ValidationError {
    errors: Vec<String>,
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

#[allow(dead_code)]
#[derive(Debug)]
pub struct Schema {
    pub headerschema: JSONSchema,
    pub agentschema: JSONSchema,
    // Removed the redundant fields headerschema_value and agentschema_value
    signatureschema: JSONSchema,
    jacsconfigschema: JSONSchema,
    agreementschema: JSONSchema,
    serviceschema: JSONSchema,
    unitschema: JSONSchema,
    actionschema: JSONSchema,
    toolschema: JSONSchema,
    contactschema: JSONSchema,
    pub taskschema: JSONSchema,
    messageschema: JSONSchema,
    evalschema: JSONSchema,
}

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
    pub fn new(header_schema_url: &str, document_schema_url: &str) -> Result<Self, Box<dyn Error>> {
        // Fetch the header schema from the provided URL and parse it into a Value
        let headerschema_response = reqwest::blocking::get(header_schema_url)?.text()?;
        let agentschema_response = reqwest::blocking::get(document_schema_url)?.text()?;

        // Parse the fetched schema strings into Value
        let headerschema_value: Value = serde_json::from_str(&headerschema_response)?;
        let agentschema_value: Value = serde_json::from_str(&agentschema_response)?;

        // Store the parsed Values in the Schema struct to ensure they are owned by the Schema instance
        let schema = Self {
            headerschema: JSONSchema::compile(&HEADERSCHEMA_VALUE_ARC)?,
            agentschema: JSONSchema::compile(&AGENTSCHEMA_VALUE_ARC)?,
            // The rest of the fields remain unchanged...
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
        let instance = serde_json::from_str(json)?;
        let validation = self.agentschema.validate(&instance);
        match validation {
            Ok(()) => Ok(instance.clone()), // Clone the instance before returning
            Err(e) => {
                let errors: Vec<String> = e.into_iter().map(|err| err.to_string()).collect();
                Err(Box::new(ValidationError { errors }))
            }
        }
    }

    pub fn validate_header(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let header = serde_json::from_str(json)?;
        let validation = self.headerschema.validate(&header);
        match validation {
            Ok(()) => Ok(header.clone()), // Clone the header before returning
            Err(e) => {
                let errors: Vec<String> = e.into_iter().map(|err| err.to_string()).collect();
                Err(Box::new(ValidationError { errors }))
            }
        }
    }

    pub fn validate_config(&self, json: &str) -> Result<(), Box<dyn Error>> {
        let config = serde_json::from_str(json)?;
        let validation = self.jacsconfigschema.validate(&config);
        match validation {
            Ok(()) => Ok(()),
            Err(e) => {
                let errors: Vec<String> = e.into_iter().map(|err| err.to_string()).collect();
                Err(Box::new(ValidationError { errors }))
            }
        }
    }

    pub fn validate_signature(&self, json: &str) -> Result<(), Box<dyn Error>> {
        let signature = serde_json::from_str(json)?;
        let validation = self.signatureschema.validate(&signature);
        match validation {
            Ok(()) => Ok(()),
            Err(e) => {
                let errors: Vec<String> = e.into_iter().map(|err| err.to_string()).collect();
                Err(Box::new(ValidationError { errors }))
            }
        }
    }

    pub fn validate_agent(&self, json: &str) -> Result<Value, Box<dyn Error>> {
        let agent = serde_json::from_str(json)?;
        let validation = self.agentschema.validate(&agent);
        match validation {
            Ok(()) => Ok(agent.clone()), // Clone the agent before returning
            Err(e) => {
                let errors: Vec<String> = e.into_iter().map(|err| err.to_string()).collect();
                Err(Box::new(ValidationError { errors }))
            }
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
