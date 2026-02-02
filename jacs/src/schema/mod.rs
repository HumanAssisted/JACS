use crate::error::JacsError;
use crate::schema::utils::CONFIG_SCHEMA_STRING;
use crate::schema::utils::ValueExt;
use crate::time_utils;
use jsonschema::{Draft, Retrieve, Validator};
use referencing::Uri;
use tracing::{debug, error, warn};

use regex::Regex;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

pub mod action_crud;
pub mod agent_crud;
pub mod contact_crud;
pub mod message_crud;
pub mod service_crud;
pub mod signature;
pub mod task_crud;
pub mod tools_crud;
pub mod utils;

use crate::agent::document::DEFAULT_JACS_DOC_LEVEL;
use utils::{DEFAULT_SCHEMA_STRINGS, EmbeddedSchemaResolver};

use std::error::Error;
use std::fmt;

/// Builds a JSON Schema validator with standard JACS configuration.
///
/// This helper consolidates the repeated pattern of creating validators with
/// Draft7 and the embedded schema resolver.
///
/// # Arguments
/// * `schema` - The parsed JSON schema value to compile
/// * `schema_name` - A descriptive name for error messages (e.g., "agentschema", "taskschema")
///
/// # Returns
/// * `Ok(Validator)` - The compiled validator ready for use
/// * `Err(JacsError)` - If schema compilation fails
fn build_validator(schema: &Value, schema_name: &str) -> Result<Validator, JacsError> {
    Validator::options()
        .with_draft(Draft::Draft7)
        .with_retriever(EmbeddedSchemaResolver::new())
        .build(schema)
        .map_err(|e| JacsError::SchemaError(format!("Failed to compile {}: {}", schema_name, e)))
}

/// Formats a schema validation error with detailed, actionable information.
///
/// This function extracts the field path, expected type/value, and actual value
/// from a jsonschema validation error to produce human-readable error messages.
///
/// # Arguments
/// * `error` - The jsonschema validation error
/// * `schema_name` - The name of the schema that failed (e.g., "agent.schema.json")
/// * `instance` - The JSON value that was being validated
///
/// # Returns
/// A formatted error string with field path, expected vs actual values
///
/// # Example output
/// ```text
/// Schema validation failed for 'agent.schema.json' at field 'jacsServices.0.name': "name" is not of type "string" [expected string, got number (42)]
/// ```
pub fn format_schema_validation_error(
    error: &jsonschema::ValidationError,
    schema_name: &str,
    instance: &Value,
) -> String {
    let path = error.instance_path.to_string();
    let field_path = if path.is_empty() || path == "/" {
        "root".to_string()
    } else {
        path.trim_start_matches('/').replace('/', ".").to_string()
    };

    // Extract the actual invalid value from the instance using the path
    let actual_value: Option<String> = if !path.is_empty() && path != "/" {
        let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let mut current = instance;
        for part in &path_parts {
            match current {
                Value::Object(obj) => {
                    if let Some(val) = obj.get(*part) {
                        current = val;
                    } else {
                        break;
                    }
                }
                Value::Array(arr) => {
                    if let Ok(idx) = part.parse::<usize>() {
                        if let Some(val) = arr.get(idx) {
                            current = val;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        if current != instance {
            let type_name = match current {
                Value::Null => "null".to_string(),
                Value::Bool(_) => "boolean".to_string(),
                Value::Number(_) => "number".to_string(),
                Value::String(_) => "string".to_string(),
                Value::Array(_) => "array".to_string(),
                Value::Object(_) => "object".to_string(),
            };
            let value_str = current.to_string();
            let truncated = if value_str.len() > 50 {
                format!("{}...", &value_str[..47])
            } else {
                value_str
            };
            Some(format!("{} ({})", type_name, truncated))
        } else {
            None
        }
    } else {
        None
    };

    // Parse the error message to extract expected type information
    let error_str = error.to_string();
    let expected = extract_expected_type(&error_str);

    // Build the detailed error message
    let mut msg = format!(
        "Schema validation failed for '{}' at field '{}': {}",
        schema_name, field_path, error
    );

    // Add expected vs actual comparison if we have the information
    if let Some(exp) = expected {
        if let Some(ref actual) = actual_value {
            msg.push_str(&format!(" [expected {}, got {}]", exp, actual));
        } else {
            msg.push_str(&format!(" [expected {}]", exp));
        }
    } else if let Some(ref actual) = actual_value {
        msg.push_str(&format!(" [got {}]", actual));
    }

    msg
}

/// Extracts the expected type or value pattern from a validation error message.
fn extract_expected_type(error_msg: &str) -> Option<String> {
    // Handle "is not of type X" errors
    if let Some(pos) = error_msg.find("is not of type ") {
        let rest = &error_msg[pos + 15..];
        if let Some(end) = rest.find([',', ')', ']']) {
            return Some(rest[..end].trim_matches('"').to_string());
        }
        return Some(rest.trim_matches('"').to_string());
    }

    // Handle "is not one of" enum errors
    if let Some(pos) = error_msg.find("is not one of ") {
        let rest = &error_msg[pos + 14..];
        return Some(format!("one of {}", rest));
    }

    // Handle "is a required property" errors
    if error_msg.contains("is a required property") {
        return Some("required property".to_string());
    }

    // Handle "is missing" errors
    if error_msg.contains("is missing") {
        return Some("required field".to_string());
    }

    // Handle pattern/format errors
    if error_msg.contains("does not match") {
        return Some("matching pattern".to_string());
    }

    None
}

// Custom error type
#[derive(Debug)]
pub struct ValidationError(pub String);

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Validation error: {}", self.0)
    }
}

impl Error for ValidationError {}

// Schema validators are pre-compiled for future document types
// They will be exposed as validation methods are added
#[derive(Debug)]
#[allow(dead_code)]
pub struct Schema {
    /// used to validate any JACS document
    pub headerschema: Validator,
    headerversion: String,
    /// used to validate any JACS agent
    pub agentschema: Validator,
    signatureschema: Validator,
    jacsconfigschema: Validator,
    agreementschema: Validator,
    serviceschema: Validator,
    unitschema: Validator,
    actionschema: Validator,
    toolschema: Validator,
    contactschema: Validator,
    pub taskschema: Validator,
    messageschema: Validator,
    evalschema: Validator,
    nodeschema: Validator,
    programschema: Validator,
    embeddingschema: Validator,
}

static EXCLUDE_FIELDS: [&str; 2] = ["$schema", "$id"];

impl Schema {
    ///  we extract only fields that the schema identitifies has useful to humans
    /// logs store the complete valid file, but for databases or applications we may want
    /// only certain fields
    /// if fieldnames are tagged with "hai" in the schema, they are excluded from here
    pub fn extract_hai_fields(
        &self,
        document: &Value,
        level: &str,
    ) -> Result<Value, Box<dyn Error>> {
        let schema_url = document["$schema"]
            .as_str()
            .unwrap_or("schemas/header/v1/header.schema.json");
        let mut processed_fields: Vec<String> = Vec::new();
        self._extract_hai_fields(document, schema_url, level, &mut processed_fields)
    }

    fn _extract_hai_fields(
        &self,
        document: &Value,
        schema_url: &str,
        level: &str,
        processed_fields: &mut Vec<String>,
    ) -> Result<Value, Box<dyn Error>> {
        let mut result = json!({});

        // Load the schema using the EmbeddedSchemaResolver
        let schema_resolver = EmbeddedSchemaResolver::new();
        let base_url = Url::parse("https://hai.ai")?;
        let url = base_url.join(schema_url)?;
        let schema_value_result =
            schema_resolver.retrieve(&Uri::try_from(url.as_str().to_string())?);
        let schema_value: Arc<Value> = match schema_value_result {
            Err(_) => {
                let default_url =
                    Url::parse("https://hai.ai/schemas/header/v1/header.schema.json")?;
                let result = match schema_resolver
                    .retrieve(&Uri::try_from(default_url.as_str().to_string())?)
                {
                    Ok(value) => value,
                    Err(e) => return Err(e.to_string().into()),
                };
                Arc::new(result)
            }
            Ok(value) => Arc::new(value),
        };

        match schema_value.as_ref() {
            Value::Object(schema_map) => {
                if let Some(all_of) = schema_map.get("allOf") {
                    // only in the case of allOf, we Share processed_fields

                    if let Value::Array(all_of_array) = all_of {
                        for item in all_of_array {
                            if let Some(ref_url) = item.get("$ref")
                                && let Some(ref_schema_url) = ref_url.as_str()
                            {
                                let child_result = self._extract_hai_fields(
                                    document,
                                    ref_schema_url,
                                    level,
                                    processed_fields,
                                )?;
                                if let (Some(result_obj), Some(child_obj)) =
                                    (result.as_object_mut(), child_result.as_object())
                                {
                                    result_obj.extend(child_obj.clone());
                                }
                            }

                            if let Some(properties) = item.get("properties") {
                                self.process_properties(
                                    level,
                                    document,
                                    processed_fields,
                                    &mut result,
                                    properties,
                                )?;
                            }
                        }
                    }
                } else if let Some(properties) = schema_map.get("properties") {
                    // Handle the case when "properties" is directly under the schema object
                    self.process_properties(
                        level,
                        document,
                        processed_fields,
                        &mut result,
                        properties,
                    )?;
                }
            }
            _ => return Err("Invalid schema format".into()),
        }

        // Extract fields from the document that are not present in the schema
        if let Some(document_object) = document.as_object() {
            for (field_name, field_value) in document_object {
                if !processed_fields.contains(field_name)
                    && (!EXCLUDE_FIELDS.contains(&field_name.as_str()) || level == "base")
                {
                    result[field_name] = field_value.clone();
                }
            }
        }

        Ok(result)
    }

    fn process_properties(
        &self,
        level: &str,
        document: &Value,
        processed_fields: &mut Vec<String>,
        result: &mut Value,
        properties: &Value,
    ) -> Result<(), Box<dyn Error>> {
        if let Value::Object(properties_map) = properties {
            for (field_name, field_schema) in properties_map {
                if field_name == "jacsTaskMessages" || field_name == "attachments" {
                    debug!(
                        "\n\n attachments field_name  in items {} {:?}\n\n\n\n",
                        field_name, field_schema
                    );
                }

                Self::process_field_value(
                    level,
                    result,
                    field_name,
                    field_schema.clone(),
                    document.clone(),
                );

                processed_fields.push(field_name.clone());

                if let Some(ref_url) = field_schema.get("$ref") {
                    if let Some(ref_schema_url) = ref_url.as_str()
                        && let Some(field_value) = document.get(field_name.clone())
                    {
                        let mut new_processed_fields = Vec::new();
                        let child_result = self._extract_hai_fields(
                            field_value,
                            ref_schema_url,
                            level,
                            &mut new_processed_fields,
                        )?;
                        if !child_result.is_null() {
                            result[field_name] = child_result;
                        }
                    }
                } else if let Some(items) = field_schema.get("items")
                    && let Some(ref_url) = items.get("$ref")
                    && let Some(ref_schema_url) = ref_url.as_str()
                    && let Some(Value::Array(field_value_array)) = document.get(field_name)
                {
                    let mut items_result = Vec::new();
                    for item_value in field_value_array {
                        let mut new_processed_fields = Vec::new();
                        let child_result = self._extract_hai_fields(
                            item_value,
                            ref_schema_url,
                            level,
                            &mut new_processed_fields,
                        )?;
                        items_result.push(child_result);
                    }
                    result[field_name] = Value::Array(items_result);
                }
            }

            return Ok(());
        }

        Err("Properties map failed: could not extract from schema".into())
    }

    fn process_field_value(
        level: &str,
        result: &mut Value,
        field_name: &str,
        field_schema: Value,
        document: Value,
    ) {
        let hai_level = field_schema
            .get("hai")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        debug!("properties hai_level {} {}", hai_level, field_name);
        match level {
            "agent" => {
                if hai_level == "agent"
                    && let Some(field_value) = document.get(field_name)
                {
                    result[field_name] = field_value.clone();
                }
            }
            "meta" => {
                if (hai_level == "agent" || hai_level == "meta")
                    && let Some(field_value) = document.get(field_name)
                {
                    result[field_name] = field_value.clone();
                }
            }
            "base" => {
                if let Some(field_value) = document.get(field_name) {
                    result[field_name] = field_value.clone();
                }
            }
            _ => {
                if let Some(field_value) = document.get(field_name) {
                    result[field_name] = field_value.clone();
                }
            }
        }
    }

    pub fn new(
        agentversion: &str,
        headerversion: &str,
        signatureversion: &str,
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
        let node_path = format!("schemas/node/{}/node.schema.json", default_version);
        let program_path = format!("schemas/program/{}/program.schema.json", default_version);

        let message_path = format!("schemas/message/{}/message.schema.json", default_version);
        let eval_path = format!("schemas/eval/{}/eval.schema.json", default_version);
        let embedding_path = format!(
            "schemas/components/embedding/{}/embedding.schema.json",
            default_version
        );

        // Helper to get schema with better error messages
        let get_schema = |path: &str| -> Result<&str, Box<dyn std::error::Error>> {
            DEFAULT_SCHEMA_STRINGS.get(path)
                .copied()
                .ok_or_else(|| format!("Schema not found: {}", path).into())
        };

        let headerdata = get_schema(&header_path)?;
        let agentdata = get_schema(&agentversion_path)?;
        let agreementdata = get_schema(&agreementversion_path)?;
        let signaturedata = get_schema(&signatureversion_path)?;
        let servicedata = get_schema(&service_path)?;
        let unitdata = get_schema(&unit_path)?;
        let actiondata = get_schema(&action_path)?;
        let tooldata = get_schema(&tool_path)?;
        let contactdata = get_schema(&contact_path)?;
        let taskdata = get_schema(&task_path)?;
        let messagedata = get_schema(&message_path)?;
        let evaldata = get_schema(&eval_path)?;
        let programdata = get_schema(&program_path)?;
        let nodedata = get_schema(&node_path)?;
        let embeddingdata = get_schema(&embedding_path)?;

        let agentschema_result: Value = serde_json::from_str(agentdata)?;
        let headerchema_result: Value = serde_json::from_str(headerdata)?;
        let agreementschema_result: Value = serde_json::from_str(agreementdata)?;
        let signatureschema_result: Value = serde_json::from_str(signaturedata)?;
        let jacsconfigschema_result: Value = serde_json::from_str(CONFIG_SCHEMA_STRING)?;
        let serviceschema_result: Value = serde_json::from_str(servicedata)?;
        let unitschema_result: Value = serde_json::from_str(unitdata)?;
        let actionschema_result: Value = serde_json::from_str(actiondata)?;
        let toolschema_result: Value = serde_json::from_str(tooldata)?;
        let contactschema_result: Value = serde_json::from_str(contactdata)?;
        let taskschema_result: Value = serde_json::from_str(taskdata)?;
        let messageschema_result: Value = serde_json::from_str(messagedata)?;
        let evalschema_result: Value = serde_json::from_str(evaldata)?;
        let nodeschema_result: Value = serde_json::from_str(nodedata)?;
        let programschema_result: Value = serde_json::from_str(programdata)?;
        let embeddingschema_result: Value = serde_json::from_str(embeddingdata)?;

        let agentschema = build_validator(&agentschema_result, &agentversion_path)?;
        let headerschema = build_validator(&headerchema_result, &header_path)?;
        let signatureschema = build_validator(&signatureschema_result, &signatureversion_path)?;
        let jacsconfigschema = build_validator(&jacsconfigschema_result, "jacsconfigschema")?;
        let serviceschema = build_validator(&serviceschema_result, &service_path)?;
        let unitschema = build_validator(&unitschema_result, &unit_path)?;
        let actionschema = build_validator(&actionschema_result, &action_path)?;
        let toolschema = build_validator(&toolschema_result, &tool_path)?;
        let agreementschema = build_validator(&agreementschema_result, &agreementversion_path)?;
        let evalschema = build_validator(&evalschema_result, &eval_path)?;
        let nodeschema = build_validator(&nodeschema_result, &node_path)?;
        let programschema = build_validator(&programschema_result, &program_path)?;
        let embeddingschema = build_validator(&embeddingschema_result, &embedding_path)?;
        let contactschema = build_validator(&contactschema_result, &contact_path)?;
        let taskschema = build_validator(&taskschema_result, &task_path)?;
        let messageschema = build_validator(&messageschema_result, &message_path)?;

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
            evalschema,
            nodeschema,
            programschema,
            embeddingschema,
        })
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
            Err(error) => {
                let schema_name = instance
                    .get("$schema")
                    .and_then(|v| v.as_str())
                    .unwrap_or("header.schema.json");
                let error_message = format_schema_validation_error(&error, schema_name, &instance);
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    /// basic check this conforms to a schema
    /// validate header does not check hashes or signature
    pub fn validate_task(&self, json: &str) -> Result<Value, Box<dyn std::error::Error + 'static>> {
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

        let validation_result = self.taskschema.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(error) => {
                let schema_name = instance
                    .get("$schema")
                    .and_then(|v| v.as_str())
                    .unwrap_or("task.schema.json");
                let error_message = format_schema_validation_error(&error, schema_name, &instance);
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    /// basic check this conforms to a schema
    /// validate header does not check hashes or signature
    pub fn validate_signature(
        &self,
        signature: &Value,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let validation_result = self.signatureschema.validate(signature);

        match validation_result {
            Ok(_) => Ok(()),
            Err(error) => {
                let error_message =
                    format_schema_validation_error(&error, "signature.schema.json", signature);
                error!("{}", error_message);
                Err(error_message.into())
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
            Err(error) => {
                let schema_name = instance
                    .get("$schema")
                    .and_then(|v| v.as_str())
                    .unwrap_or("agent.schema.json");
                let error_message = format_schema_validation_error(&error, schema_name, &instance);
                error!("{}", error_message);
                Err(error_message.into())
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

    pub fn getschema(&self, value: Value) -> Result<String, Box<dyn Error>> {
        let schemafield = "$schema";
        if let Some(schema) = value.get(schemafield)
            && let Some(schema_str) = schema.as_str()
        {
            return Ok(schema_str.to_string());
        }
        Err("Schema extraction failed: no schema in doc or schema is not a string".into())
    }

    /// use this to get the name of the
    pub fn getshortschema(&self, value: Value) -> Result<String, Box<dyn Error>> {
        let longschema = self.getschema(value)?;
        let re = Regex::new(r"/([^/]+)\.schema\.json$")
            .map_err(|e| format!("Invalid regex pattern: {}", e))?;

        if let Some(caps) = re.captures(&longschema)
            && let Some(matched) = caps.get(1)
        {
            return Ok(matched.as_str().to_string());
        }
        Err("Failed to extract schema name from URL".into())
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
        let versioncreated = time_utils::now_rfc3339();

        instance["jacsId"] = json!(format!("{}", id));
        instance["jacsVersion"] = json!(format!("{}", version));
        instance["jacsVersionDate"] = json!(format!("{}", versioncreated));
        instance["jacsOriginalVersion"] = json!(format!("{}", original_version));
        instance["jacsOriginalDate"] = json!(format!("{}", versioncreated));
        instance["jacsLevel"] = json!(
            instance
                .get_str("jacsLevel")
                .unwrap_or(DEFAULT_JACS_DOC_LEVEL.to_string())
        );
        // if no schema is present insert standard header version
        if instance.get_str("$schema").is_none() {
            instance["$schema"] = json!(format!("{}", self.get_header_schema_url()));
        }

        // if no type is present look for $schema and extract the name
        if instance.get_str("jacsType").is_none() {
            let cloned_instance = instance.clone();
            instance["jacsType"] = match self.getshortschema(cloned_instance) {
                Ok(schema) => json!(schema),
                Err(_) => json!("document"),
            };
        }

        let validation_result = self.headerschema.validate(&instance);

        match validation_result {
            Ok(instance) => instance,
            Err(error) => {
                let schema_name = instance
                    .get("$schema")
                    .and_then(|v| v.as_str())
                    .unwrap_or("header.schema.json");
                let error_message = format!(
                    "Document creation failed: {}",
                    format_schema_validation_error(&error, schema_name, &instance)
                );
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
