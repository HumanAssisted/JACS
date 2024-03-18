use crate::schema::utils::ValueExt;
use chrono::prelude::*;
use jsonschema::{Draft, JSONSchema};
use log::{debug, error, warn};
use serde_json::Value;
use std::io::{Error, ErrorKind};
use url::Url;
use uuid::Uuid;

pub mod signature;
pub mod utils;
use jsonschema::SchemaResolverError;
use signature::SignatureVerifiers;
use utils::{EmbeddedSchemaResolver, DEFAULT_SCHEMA_STRINGS};

pub struct Schema {
    /// used to validate any JACS document
    headerschema: JSONSchema,
    /// used to validate any JACS agent
    agentschema: JSONSchema,
    // schemas: HashMap<String, JSONSchema>
}

impl Schema {
    pub fn new(agentversion: &String, headerversion: &String) -> Result<Self, Error> {
        // let current_dir = env::current_dir()?;
        //let mut schemas: HashMap<String, JSONSchema> = HashMap::new();
        let headerkey = format!("schemas/header/{}/header.schema.json", headerversion);
        let headerdata = DEFAULT_SCHEMA_STRINGS.get(&headerkey).unwrap();
        let agentversion = format!("schemas/agent/{}/agent.schema.json", agentversion);
        let agentdata = DEFAULT_SCHEMA_STRINGS.get(&agentversion).unwrap();
        let agentschema_result: Value = serde_json::from_str(&agentdata)?;
        let headerchema_result: Value = serde_json::from_str(&headerdata)?;

        let agentschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new()) // current_dir.clone()
            .compile(&agentschema_result)
            .expect("A valid schema");

        let headerschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&headerchema_result)
            .expect("A valid schema");

        Ok(Self {
            headerschema,
            agentschema,
        })
    }

    pub fn validate_header(&self, json: &str) -> Result<Value, String> {
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

        let validation_result = self.headerschema.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages.first().cloned().unwrap_or_else(|| {
                    "Unexpected error during validation: no error messages found".to_string()
                }))
            }
        }
    }

    pub fn validate_agent(&self, json: &str) -> Result<Value, String> {
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON for agent: {}", e);
                warn!("validate error {:?}", error_message);
                return Err(error_message);
            }
        };

        let validation_result = self.agentschema.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages.first().cloned().unwrap_or_else(|| {
                    "Unexpected error during validation: no error messages found".to_string()
                }))
            }
        }
    }

    /// utilty function to retrieve the list of fields
    /// this is especially useful for signatures
    pub fn get_array_of_values(&self, signature: serde_json::Value, fieldname: &String) -> String {
        if let Some(array_field) = signature.get(fieldname).and_then(Value::as_array) {
            let mut result_strings = Vec::new();
            for value in array_field {
                if let Some(string_value) = value.as_str() {
                    result_strings.push(string_value.to_string());
                }
            }
            return format!("Result Strings: {:?}", result_strings);
        }
        "".to_string()
    }

    pub fn create_signature(&self) {}

    /// give a signature field
    pub fn check_signature(&self, fieldname: &String) {}

    /// load a document that has data but no id or version
    /// an id and version is assigned
    /// header is validated
    /// document is reeturned
    pub fn create(&self, json: &str) -> Result<Value, Error> {
        // create json string
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON: {}", e);
                error!("validate error {:?}", error_message);
                return Err(e.into());
            }
        };

        // make sure there is no id or version field
        if instance.get_str("id").is_some() || instance.get_str("version").is_some() {
            let error_message = "New JACs documents should have no id or version";
            error!("{}", error_message);
            return Err(Error::new(ErrorKind::NotFound, error_message));
        }

        // assign id and version
        let id = Uuid::new_v4();
        let version = Uuid::new_v4();
        let now: DateTime<Utc> = Utc::now();
        let versioncreated = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let validation_result = self.headerschema.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages.first().cloned().unwrap_or_else(|| {
                    "Unexpected error during validation: no error messages found".to_string()
                }))
            }
        };

        // validate schema json string
        // make sure id and version are empty

        // generate keys

        // create keys
        // self-sign as owner
        // validate signature
        // save
        // updatekey is the except we increment version and preserve id
        // update actions produces signatures
        // self.validate();

        Ok(instance.clone())
    }

    // pub fn create_document(&self, json: &str) -> Result<Value, String> {
    //     /// use the schema's create function

    //     // write file to disk at [jacs]/agents/
    //     // run as agent

    //     Ok()
    // }
}
