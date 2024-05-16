use crate::agent::agreement::subtract_vecs;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::loaders::FileLoader;
use crate::agent::security::check_data_directory;
use crate::agent::Agent;
use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use crate::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use crate::agent::SHA256_FIELDNAME;
use crate::crypt::hash::hash_string;
use crate::schema::utils::ValueExt;
use base64::prelude::*;
use chrono::{Local, Utc};
use difference::{Changeset, Difference};
use flate2::read::GzDecoder;
use log::error;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct JACSDocument {
    pub id: String,
    pub version: String,
    pub value: Value,
}

// extend with functions for types
impl JACSDocument {
    pub fn getkey(&self) -> String {
        // No need to clone, as format! macro does not take ownership
        format!("{}:{}", &self.id, &self.version)
    }

    pub fn getvalue(&self) -> &Value {
        // Return a reference to the value
        &self.value
    }

    pub fn getschema(&self) -> Result<String, Box<dyn Error>> {
        let schemafield = "$schema";
        if let Some(schema) = self.value.get(schemafield) {
            match schema.as_str() {
                Some(schema_str) => Ok(schema_str.to_owned()),
                None => Err(Box::<dyn Error>::from("Schema is not a string")),
            }
        } else {
            Err(Box::<dyn Error>::from("No schema in document"))
        }
    }

    pub fn getshortschema(&self) -> Result<String, Box<dyn Error>> {
        let longschema = self.getschema()?;
        let re =
            Regex::new(r"/([^/]+)\.schema\.json$").map_err(|e| format!("Regex error: {}", e))?;

        if let Some(caps) = re.captures(&longschema) {
            if let Some(matched) = caps.get(1) {
                return Ok(matched.as_str().to_string());
            }
        }
        Err(Box::<dyn Error>::from(
            "Failed to extract schema name from URL",
        ))
    }

    pub fn agreement_unsigned_agents(
        &self,
        agreement_fieldname: Option<String>,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let all_requested_agents = self.agreement_requested_agents(agreement_fieldname.clone())?;
        let all_agreement_signed_agents = self.agreement_signed_agents(agreement_fieldname)?;

        Ok(subtract_vecs(
            &all_requested_agents,
            &all_agreement_signed_agents,
        ))
    }

    pub fn agreement_requested_agents(
        &self,
        agreement_fieldname: Option<String>,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };
        let value: &serde_json::Value = &self.value;
        if let Some(jacs_agreement) = value.get(agreement_fieldname_key) {
            if let Some(agents) = jacs_agreement.get("agentIDs") {
                if let Some(agents_array) = agents.as_array() {
                    return Ok(agents_array
                        .iter()
                        .map(|v| match v.as_str() {
                            Some(agent_str) => Ok(agent_str.to_string()),
                            None => Err(Box::<dyn Error>::from("Expected a string for agent ID")),
                        })
                        .collect::<Result<Vec<_>, _>>()?);
                }
            }
        }
        Err(Box::<dyn Error>::from(
            "no agreement or agents in agreement",
        ))
    }

    pub fn signing_agent(&self) -> Result<String, Box<dyn Error>> {
        let value: &serde_json::Value = &self.value;
        if let Some(jacs_signature) = value.get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME) {
            if let Some(agent_id) = jacs_signature.get("agentID").and_then(|id| id.as_str()) {
                Ok(agent_id.to_string())
            } else {
                Err(Box::<dyn Error>::from("Agent ID not found in signature"))
            }
        } else {
            Err(Box::<dyn Error>::from("Signature field is missing"))
        }
    }

    pub fn agreement_signed_agents(
        &self,
        agreement_fieldname: Option<String>,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };
        let value: &serde_json::Value = &self.value;
        if let Some(jacs_agreement) = value.get(agreement_fieldname_key) {
            if let Some(signatures) = jacs_agreement.get("signatures") {
                if let Some(signatures_array) = signatures.as_array() {
                    let mut signed_agents: Vec<String> = Vec::<String>::new();
                    for signature in signatures_array {
                        let agentid: String = match signature["agentID"].as_str() {
                            Some(agent_id_str) => agent_id_str.to_string(),
                            None => {
                                return Err(Box::<dyn Error>::from(
                                    "Expected a string for agent ID in signatures",
                                ))
                            }
                        };
                        signed_agents.push(agentid);
                    }
                    return Ok(signed_agents);
                }
            }
        }
        Err(Box::<dyn Error>::from(
            "no agreement or signatures in agreement",
        ))
    }
}

impl fmt::Display for JACSDocument {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let json_string = serde_json::to_string_pretty(&self.value).map_err(|_| fmt::Error)?;
        write!(f, "{}", json_string)
    }
}

pub trait Document {
    fn verify_document_signature(
        &mut self,
        _document_key: &String,
        signature_key_from: Option<&String>,
        _fields: Option<&Vec<String>>,
        public_key: Option<Vec<u8>>,
        _public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn Error>>;

    fn validate_document_with_custom_schema(
        &self,
        schema_path: &str,
        json: &Value,
    ) -> Result<(), Box<dyn Error>>;
    fn create_document_and_load(
        &mut self,
        json: &String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<JACSDocument, Box<dyn std::error::Error + '_>>;

    fn load_document(&mut self, document_string: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn remove_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn copy_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn store_jacs_document(&mut self, value: &Value) -> Result<JACSDocument, Box<dyn Error>>;
    fn hash_doc(&self, doc: &Value) -> Result<String, Box<dyn Error>>;
    fn get_document(&self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    // This function is implemented in the Agent struct where the documents field exists.
    fn diff_json_strings(
        &self,
        json1: &str,
        json2: &str,
    ) -> Result<(String, String), Box<dyn Error>>;
    /// export_embedded if there is embedded files recreate them, default false
    fn save_document(
        &mut self,
        document_key: &String,
        output_filename: Option<String>,
        export_embedded: Option<bool>,
        extract_only: Option<bool>,
    ) -> Result<(), Box<dyn Error>>;
    fn update_document(
        &mut self,
        document_key: &String,
        new_document_string: &String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    fn create_file_json(
        &mut self,
        filepath: &String,
        embed: bool,
    ) -> Result<serde_json::Value, Box<dyn Error>>;
    fn verify_document_files(&mut self, document: &Value) -> Result<(), Box<dyn Error>>;
    /// util function for parsing arguments for attachments
    fn parse_attachement_arg(&mut self, attachments: Option<&String>) -> Option<Vec<String>>;
    fn diff_strings(&self, string_one: &str, string_two: &str) -> (String, String, String);
    fn get_document_keys(&self) -> Result<Vec<String>, Box<dyn Error>>;
}

impl Document for Agent {
    // todo change this to use stored documents only
    fn validate_document_with_custom_schema(
        &self,
        schema_path: &str,
        json: &Value,
    ) -> Result<(), Box<dyn Error>> {
        let schemas = self
            .document_schemas
            .lock()
            .map_err(|_| Box::<dyn Error>::from("Failed to lock document schemas"))?;
        let validator = schemas.get(schema_path).ok_or_else(|| {
            Box::<dyn Error>::from(format!("Validator not found for path: {}", schema_path))
        })?;

        let validation_result = validator.validate(json);
        let result = match validation_result {
            Ok(()) => Ok(()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(Box::<dyn Error>::from(error_messages.join(", ")))
            }
        };
        result
    }

    fn create_file_json(
        &mut self,
        filepath: &String,
        embed: bool,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        // Get the file contents as base64
        let base64_contents = self.fs_get_document_content(filepath.clone())?;

        // Determine the MIME type using a Rust library (e.g., mime_guess)
        let mime_type = mime_guess::from_path(filepath)
            .first_or_octet_stream()
            .to_string();

        // Calculate the SHA256 hash of the contents
        let mut hasher = Sha256::new();
        hasher.update(&base64_contents);
        let sha256_hash = format!("{:x}", hasher.finalize());

        // Create the JSON object
        let file_json = json!({
            "mimetype": mime_type,
            "path": filepath,
            "embed": embed,
            "sha256": sha256_hash
        });

        // Add the contents field if embed is true
        let file_json = if embed {
            file_json
                .as_object()
                .ok_or_else(|| Box::<dyn Error>::from("Failed to convert Value to Object"))?
                .clone()
                .into_iter()
                .chain(vec![("contents".to_string(), json!(base64_contents))])
                .collect()
        } else {
            file_json
        };

        Ok(file_json)
    }

    fn verify_document_files(&mut self, document: &Value) -> Result<(), Box<dyn Error>> {
        // Check if the "files" field exists
        if let Some(files_array) = document.get("jacsFiles").and_then(|files| files.as_array()) {
            // Iterate over each file object
            for file_obj in files_array {
                // Get the file path and sha256 hash from the file object
                let file_path = file_obj
                    .get("path")
                    .and_then(|path| path.as_str())
                    .ok_or_else(|| Box::<dyn Error>::from("Missing file path"))?;
                let expected_hash = file_obj
                    .get("sha256")
                    .and_then(|hash| hash.as_str())
                    .ok_or_else(|| Box::<dyn Error>::from("Missing SHA256 hash"))?;

                // Load the file contents and encode as base64
                let base64_contents = self.fs_get_document_content(file_path.to_string())?;

                // Calculate the SHA256 hash of the loaded contents
                let mut hasher = Sha256::new();
                hasher.update(&base64_contents);
                let actual_hash = format!("{:x}", hasher.finalize());

                // Compare the actual hash with the expected hash
                if actual_hash != expected_hash {
                    return Err(format!("Hash mismatch for file: {}", file_path).into());
                }
            }
        }

        Ok(())
    }

    /// create an document, and provde id and version as a result
    /// filepaths:
    fn create_document_and_load(
        &mut self,
        json: &String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<JACSDocument, Box<dyn std::error::Error + '_>> {
        // Perform schema validation first, which is an immutable operation
        let instance_result = self.schema.create(json)?;
        let mut instance_to_store = instance_result;

        // Immutable borrow of self is completed here
        let files_array = attachments
            .as_ref()
            .map(|attachment_list| {
                attachment_list
                    .iter()
                    .map(|attachment_path| {
                        let final_embed = embed.unwrap_or(false);
                        self.create_file_json(attachment_path, final_embed)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        if let Some(files) = files_array {
            if let Some(instance_map) = instance_to_store.value.as_object_mut() {
                instance_map.insert("jacsFiles".to_string(), Value::Array(files));
            }
        }

        self.signing_procedure()?;

        let document_hash = self.hash_doc(&instance_to_store.value)?;
        instance_to_store.value[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        self.store_jacs_document(&instance_to_store.value)
    }

    fn load_document(&mut self, document_string: &String) -> Result<JACSDocument, Box<dyn Error>> {
        // Perform validation first, which is an immutable operation
        let validation_result = self.schema.validate_header(document_string)?;

        // Validation is successful, proceed with mutable operations
        self.store_jacs_document(&validation_result)
    }

    fn hash_doc(&self, doc: &Value) -> Result<String, Box<dyn Error>> {
        let mut doc_copy = doc.clone();
        doc_copy
            .as_object_mut()
            .map(|obj| obj.remove(SHA256_FIELDNAME));
        let doc_string = serde_json::to_string(&doc_copy)?;
        Ok(hash_string(&doc_string))
    }

    fn store_jacs_document(&mut self, value: &Value) -> Result<JACSDocument, Box<dyn Error>> {
        let mut documents = self
            .documents
            .lock()
            .map_err(|_| Box::<dyn Error>::from("Failed to lock documents"))?;
        let doc = JACSDocument {
            id: value
                .get_str("jacsId")
                .ok_or::<Box<dyn Error>>(From::from("Missing 'jacsId' field in value"))?
                .to_string(),
            version: value
                .get_str("jacsVersion")
                .ok_or::<Box<dyn Error>>(From::from("Missing 'jacsVersion' field in value"))?
                .to_string(),
            value: Some(value.clone()).into(),
        };
        let key = doc.getkey();
        documents.insert(key.clone(), doc.clone());
        Ok(doc)
    }

    fn get_document(&self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let documents = self
            .documents
            .lock()
            .map_err(|_| Box::<dyn Error>::from("Failed to lock documents"))?;
        match documents.get(document_key) {
            Some(document) => Ok(document.clone()),
            None => Err(format!("Document not found for key: {}", document_key).into()),
        }
    }

    fn remove_document(&mut self, _document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let mut documents = self
            .documents
            .lock()
            .map_err(|_| "Failed to lock documents")?;
        match documents.remove(_document_key) {
            Some(document) => Ok(document),
            None => Err(Box::<dyn Error>::from(format!(
                "Document not found for key: {}",
                _document_key
            ))),
        }
    }

    /// pass in modified doc
    /// TODO validate that the new document is owned by editor
    fn update_document(
        &mut self,
        _document_key: &String,
        new_document_string: &String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        // Perform validation first, which is an immutable operation
        let validation_result = self.schema.validate_header(new_document_string)?;
        let mut new_document = validation_result;

        // Process attachments if any, before any mutable operations on `self`
        let files_array = if let Some(attachment_list) = attachments {
            let final_embed = embed.unwrap_or(false);
            attachment_list
                .iter()
                .map(|attachment_path| self.create_file_json(attachment_path, final_embed))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };

        // Now we can proceed with mutable borrows of self
        // Add the files to the new document
        if !files_array.is_empty() {
            if let Some(instance_map) = new_document.as_object_mut() {
                instance_map.insert("jacsFiles".to_string(), Value::Array(files_array));
            }
        }

        // Store the updated document
        self.store_jacs_document(&new_document)
    }

    /// copys document without modifications
    fn copy_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let original_document = self.get_document(document_key)?;
        let mut value = original_document.value;
        let new_version = Uuid::new_v4().to_string();
        let last_version = &value["jacsVersion"];
        let versioncreated = Utc::now().to_rfc3339();

        value["jacsLastVersion"] = last_version.clone();
        value["jacsVersion"] = json!(format!("{}", new_version));
        value["jacsVersionDate"] = json!(format!("{}", versioncreated));
        // sign new version
        self.signing_procedure()?;
        // hash new version
        let document_hash = self.hash_doc(&value)?;
        value[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        Ok(self.store_jacs_document(&value)?)
    }

    fn save_document(
        &mut self,
        document_key: &String,
        output_filename: Option<String>,
        export_embedded: Option<bool>,
        extract_only: Option<bool>,
    ) -> Result<(), Box<dyn Error>> {
        let original_document = self.get_document(document_key)?;
        let document_string: String = serde_json::to_string_pretty(&original_document.value)?;

        let is_extract_only = match extract_only {
            Some(extract_only) => extract_only,
            None => false,
        };

        if !is_extract_only {
            let _ = self.fs_document_save(&document_key, &document_string, output_filename)?;
        }

        let do_export = match export_embedded {
            Some(export_embedded) => export_embedded,
            None => false,
        };

        if do_export {
            if let Some(jacs_files) = original_document.value["jacsFiles"].as_array() {
                if let Err(e) = check_data_directory() {
                    error!("Failed to check data directory: {}", e);
                }
                for item in jacs_files {
                    if item["embed"].as_bool().unwrap_or(false) {
                        let contents = item["contents"].as_str().ok_or("Contents not found")?;
                        let path = item["path"].as_str().ok_or("Path not found")?;

                        let decoded_contents = BASE64_STANDARD.decode(contents.as_bytes())?;

                        // Inflate the gzip-compressed contents
                        let mut gz_decoder = GzDecoder::new(std::io::Cursor::new(decoded_contents));
                        let mut inflated_contents = Vec::new();
                        gz_decoder.read_to_end(&mut inflated_contents)?;

                        // TODO move this portion of code out of document as it's filesystem dependent
                        // Backup the existing file if it exists
                        let file_path = Path::new(path);
                        if file_path.exists() {
                            let backup_path =
                                format!("{}.{}.bkp", path, Local::now().format("%Y%m%d_%H%M%S"));
                            fs::rename(file_path, &backup_path)?;
                        }

                        // Save the inflated contents to the file
                        let mut file = File::create(file_path)?;
                        file.write_all(&inflated_contents)?;

                        // Mark the file as not executable
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let mut permissions = file.metadata()?.permissions();
                            permissions.set_mode(0o644);
                            file.set_permissions(permissions)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn verify_document_signature(
        &mut self,
        _document_key: &String,
        signature_key_from: Option<&String>,
        _fields: Option<&Vec<String>>,
        public_key: Option<Vec<u8>>,
        _public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        // check that public key exists
        let document = self.get_document(_document_key)?;
        let document_value = document.getvalue();
        self.verify_document_files(&document_value)?;
        // this is innefficient since I generate a whole document
        let _used_public_key = match public_key {
            Some(public_key) => public_key,
            None => self.get_public_key()?,
        };

        let binding = &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string();
        let _signature_key_from_final = match signature_key_from {
            Some(signature_key_from) => signature_key_from,
            None => binding,
        };

        self.signature_verification_procedure()?;
        Ok(())
    }

    fn parse_attachement_arg(&mut self, attachments: Option<&String>) -> Option<Vec<String>> {
        match attachments {
            Some(path_str) => {
                let path = Path::new(path_str);
                if path.is_dir() {
                    // If the path is a directory, read the directory and collect file paths
                    match fs::read_dir(path) {
                        Ok(entries) => {
                            let file_paths: Vec<String> = entries
                                .filter_map(|entry| {
                                    entry
                                        .ok()
                                        .and_then(|e| e.path().to_str().map(|s| s.to_string()))
                                })
                                .collect();
                            Some(file_paths)
                        }
                        Err(_) => {
                            eprintln!("Failed to read directory: {}", path_str);
                            None
                        }
                    }
                } else if path.is_file() {
                    // If the path is a file, create a vector with the single file path
                    Some(vec![path_str.to_string()])
                } else {
                    eprintln!("Invalid path: {}", path_str);
                    None
                }
            }
            None => None,
        }
    }

    /// Function to diff two JSON strings and print the differences.
    fn diff_json_strings(
        &self,
        json1: &str,
        json2: &str,
    ) -> Result<(String, String), Box<dyn Error>> {
        let changeset = Changeset::new(json1, json2, "\n");
        let mut same = String::new();
        let mut diffs = String::new();

        for diff in changeset.diffs {
            match diff {
                Difference::Same(ref x) => same.push_str(format!(" {}", x).as_str()),
                Difference::Add(ref x) => diffs.push_str(format!("+{}", x).as_str()),
                Difference::Rem(ref x) => diffs.push_str(format!("-{}", x).as_str()),
            }
        }

        return Ok((same, diffs));
    }

    fn diff_strings(&self, string_one: &str, string_two: &str) -> (String, String, String) {
        let changeset = Changeset::new(string_one, string_two, " ");
        let mut same = String::new();
        let mut add = String::new();
        let mut rem = String::new();

        // Collect detailed differences
        for diff in &changeset.diffs {
            match diff {
                Difference::Same(ref x) => same.push_str(x),
                Difference::Add(ref x) => add.push_str(x),
                Difference::Rem(ref x) => rem.push_str(x),
            }
        }

        (same, add, rem)
    }

    fn get_document_keys(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let documents = self
            .documents
            .lock()
            .map_err(|_| "Failed to lock documents")?;
        Ok(documents.keys().map(|k| k.to_string()).collect())
    }
}
