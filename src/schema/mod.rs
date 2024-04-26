use crate::schema::utils::ValueExt;
use crate::schema::utils::CONFIG_SCHEMA_STRING;
use chrono::prelude::*;
use jsonschema::{Draft, JSONSchema};
use log::{debug, error, warn};
use serde_json::json;
use serde_json::Value;

use url::Url;
use uuid::Uuid;

pub mod agent_crud;
pub mod signature;
pub mod utils;

use utils::{EmbeddedSchemaResolver, DEFAULT_SCHEMA_STRINGS};

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
    /// used to validate any JACS document
    headerschema: JSONSchema,
    headerversion: String,
    /// used to validate any JACS agent
    agentschema: JSONSchema,
    signatureschema: JSONSchema,
    jacsconfigschema: JSONSchema,
    agreementschema: JSONSchema,
    serviceschema: JSONSchema,
    unitschema: JSONSchema,
    actionschema: JSONSchema,
    toolschema: JSONSchema,
    contactschema: JSONSchema,
    taskschema: JSONSchema,
    messageschema: JSONSchema,
}

impl Schema {
    pub fn new(
        agentversion: &String,
        headerversion: &String,
        signatureversion: &String,
    ) -> Result<Self, Box<dyn std::error::Error + 'static>> {
        // let current_dir = env::current_dir()?;
        // TODO let the agent, header, and signature versions for verifying being flexible
        let default_version = "v1";
        let header_path = format!("schemas/header/{}/header.schema.json", headerversion);
        let agentversion_path = format!("schemas/agent/{}/agent.schema.json", agentversion);
        let agreementversion_path = format!(
            "schemas/components/agreement/{}/agreement.schema.json",
            agentversion
        );
        let signatureversion_path = format!(
            "schemas/components/signature/{}/signature.schema.json",
            signatureversion
        );

        let unit_path = format!(
            "schemas/components/unit/{}/unit.schema.json",
            default_version
        );

        let service_path = format!(
            "schemas/components/service/{}/service.schema.json",
            default_version
        );

        let action_path = format!(
            "schemas/components/action/{}/action.schema.json",
            default_version
        );

        let tool_path = format!(
            "schemas/components/tool/{}/tool.schema.json",
            default_version
        );

        let contact_path = format!(
            "schemas/components/contact/{}/contact.schema.json",
            default_version
        );

        let task_path = format!("schemas/task/{}/task.schema.json", default_version);

        let message_path = format!(
            "schemas/components/message/{}/message.schema.json",
            default_version
        );

        let headerdata = DEFAULT_SCHEMA_STRINGS.get(&header_path).unwrap();
        let agentdata = DEFAULT_SCHEMA_STRINGS.get(&agentversion_path).unwrap();
        let agreementdata = DEFAULT_SCHEMA_STRINGS.get(&agreementversion_path).unwrap();
        let signaturedata = DEFAULT_SCHEMA_STRINGS.get(&signatureversion_path).unwrap();
        let servicedata = DEFAULT_SCHEMA_STRINGS.get(&service_path).unwrap();
        let unitdata = DEFAULT_SCHEMA_STRINGS.get(&unit_path).unwrap();
        let actiondata = DEFAULT_SCHEMA_STRINGS.get(&action_path).unwrap();
        let tooldata = DEFAULT_SCHEMA_STRINGS.get(&tool_path).unwrap();
        let contactdata = DEFAULT_SCHEMA_STRINGS.get(&contact_path).unwrap();
        let taskdata = DEFAULT_SCHEMA_STRINGS.get(&task_path).unwrap();
        let messagedata = DEFAULT_SCHEMA_STRINGS.get(&message_path).unwrap();

        let agentschema_result: Value = serde_json::from_str(&agentdata)?;
        let headerchema_result: Value = serde_json::from_str(&headerdata)?;
        let agreementschema_result: Value = serde_json::from_str(&agreementdata)?;
        let signatureschema_result: Value = serde_json::from_str(&signaturedata)?;
        let jacsconfigschema_result: Value = serde_json::from_str(&CONFIG_SCHEMA_STRING)?;
        let serviceschema_result: Value = serde_json::from_str(&servicedata)?;
        let unitschema_result: Value = serde_json::from_str(&unitdata)?;
        let actionschema_result: Value = serde_json::from_str(&actiondata)?;
        let toolschema_result: Value = serde_json::from_str(&tooldata)?;
        let contactschema_result: Value = serde_json::from_str(&contactdata)?;
        let taskschema_result: Value = serde_json::from_str(&taskdata)?;
        let messageschema_result: Value = serde_json::from_str(&messagedata)?;

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

        let signatureschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&signatureschema_result)
            .expect("A valid schema");

        let agreementschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&agreementschema_result)
            .expect("A valid schema");

        let serviceschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&serviceschema_result)
            .expect("A valid schema");

        let unitschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&unitschema_result)
            .expect("A valid schema");

        let actionschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&actionschema_result)
            .expect("A valid schema");

        let toolschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&toolschema_result)
            .expect("A valid schema");

        let jacsconfigschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&jacsconfigschema_result)
            .expect("A valid schema");

        let contactschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&contactschema_result)
            .expect("A valid schema");

        let messageschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&messageschema_result)
            .expect("A valid schema");

        let taskschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&taskschema_result)
            .expect("A valid schema");

        Ok(Self {
            headerschema,
            headerversion: headerversion.to_string(),
            agentschema,
            signatureschema,
            jacsconfigschema,
            agreementschema,
            serviceschema,
            unitschema,
            actionschema,
            toolschema,
            contactschema,
            taskschema,
            messageschema,
        })
    }

    pub fn validate_config(
        &self,
        json: &str,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON: {}", e);
                error!("validate error {:?}", error_message);
                return Err(error_message.into());
            }
        };

        let validation_result = self.jacsconfigschema.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(errors) => {
                error!("error validating config file");
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages
                    .first()
                    .cloned()
                    .unwrap_or_else(|| {
                        "Unexpected error during validation: no error messages found".to_string()
                    })
                    .into())
            }
        }
    }

    /// basic check this conforms to a schema
    /// validate header does not check hashes or signature
    pub fn validate_header(
        &self,
        json: &str,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON: {}", e);
                warn!("validate error {:?}", error_message);
                return Err(error_message.into());
            }
        };

        let validation_result = self.headerschema.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(errors) => {
                error!("error validating header schema");
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages
                    .first()
                    .cloned()
                    .unwrap_or_else(|| {
                        "Unexpected error during validation: no error messages found".to_string()
                    })
                    .into())
            }
        }
    }

    /// basic check this conforms to a schema
    /// validate header does not check hashes or signature
    pub fn validate_signature(
        &self,
        signature: &Value,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let validation_result = self.signatureschema.validate(&signature);

        match validation_result {
            Ok(_) => Ok(()),
            Err(errors) => {
                error!("error validating signature schema");
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages
                    .first()
                    .cloned()
                    .unwrap_or_else(|| {
                        "Unexpected error during validation: no error messages found".to_string()
                    })
                    .into())
            }
        }
    }

    pub fn validate_agent(
        &self,
        json: &str,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON for agent: {}", e);
                warn!("validate error {:?}", error_message);
                return Err(error_message.into());
            }
        };

        let validation_result = self.agentschema.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(errors) => {
                error!("error validating agent schema");
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages
                    .first()
                    .cloned()
                    .unwrap_or_else(|| {
                        "Unexpected error during validation: no error messages found".to_string()
                    })
                    .into())
            }
        }
    }

    // TODO get from member var  self.headerschema.to_string())
    pub fn get_header_schema_url(&self) -> String {
        format!(
            "https://hai.ai/schemas/header/{}/header.schema.json",
            self.headerversion
        )
    }

    /// load a document that has data but no id or version
    /// an id and version is assigned
    /// header is validated
    /// document is reeturned
    pub fn create(&self, json: &str) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        // create json string
        let mut instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON: {}", e);
                error!("loading error {:?}", error_message);
                return Err(e.into());
            }
        };

        // make sure there is no id or version field
        if instance.get_str("jacsId").is_some() || instance.get_str("jacsVersion").is_some() {
            let error_message = "New JACs documents should have no id or version";
            error!("{}", error_message);
            return Err(error_message.into());
        }

        // assign id and version
        let id = Uuid::new_v4().to_string();
        let version = Uuid::new_v4().to_string();
        let original_version = version.clone();
        // let now: DateTime<Utc> = Utc::now();
        let versioncreated = Utc::now().to_rfc3339();

        instance["jacsId"] = json!(format!("{}", id));
        instance["jacsVersion"] = json!(format!("{}", version));
        instance["jacsVersionDate"] = json!(format!("{}", versioncreated));
        instance["jacsOriginalVersion"] = json!(format!("{}", original_version));
        instance["jacsOriginalDate"] = json!(format!("{}", versioncreated));

        // if no schema is present insert standard header version
        if !instance.get_str("$schema").is_some() {
            instance["$schema"] = json!(format!("{}", self.get_header_schema_url()));
        }

        let validation_result = self.headerschema.validate(&instance);

        match validation_result {
            Ok(instance) => instance,
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                let error_message = error_messages.first().cloned().unwrap_or_else(|| {
                    "Unexpected error during validation: no error messages found".to_string()
                });
                error!("{}", error_message);
                return Err(Box::new(ValidationError(error_message))
                    as Box<dyn std::error::Error + 'static>);
            }
        };

        Ok(instance.clone())
    }

    // pub fn create_document(&self, json: &str) -> Result<Value, String> {
    //     /// use the schema's create function

    //     // write file to disk at [jacs]/agents/
    //     // run as agent

    //     Ok()
    // }
}
