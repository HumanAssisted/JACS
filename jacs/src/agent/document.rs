use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use crate::agent::Agent;
use crate::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use crate::agent::SHA256_FIELDNAME;
use crate::agent::agreement::subtract_vecs;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::loaders::FileLoader;
use crate::agent::security::SecurityTraits;
use crate::crypt::hash::hash_string;
use crate::schema::utils::ValueExt;
use crate::storage::MultiStorage;
use chrono::{DateTime, Local, Utc};
use difference::{Changeset, Difference};
use flate2::read::GzDecoder;
use log::error;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JACSDocument {
    pub id: String,
    pub version: String,
    pub value: Value,
    pub jacs_type: String,
}

pub const EDITABLE_JACS_DOCS: &'static [&'static str] = &["config", "artifact"];
pub const DEFAULT_JACS_DOC_LEVEL: &str = "raw";
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
            if let Some(schema_str) = schema.as_str() {
                return Ok(schema_str.to_string());
            }
        }
        return Err("no schema in doc or schema is not a string".into());
    }

    /// use this to get the name of the
    pub fn getshortschema(&self) -> Result<String, Box<dyn Error>> {
        let longschema = self.getschema()?;
        let re = Regex::new(r"/([^/]+)\.schema\.json$").unwrap();

        if let Some(caps) = re.captures(&longschema) {
            if let Some(matched) = caps.get(1) {
                return Ok(matched.as_str().to_string());
            }
        }
        Err("Failed to extract schema name from URL".into())
    }

    pub fn agreement_unsigned_agents(
        &self,
        agreement_fieldname: Option<String>,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let all_requested_agents = self.agreement_requested_agents(agreement_fieldname.clone())?;
        let all_agreement_signed_agents = self.agreement_signed_agents(agreement_fieldname)?;

        // Normalize both lists of agent IDs before comparison
        let normalized_requested_agents: Vec<String> = all_requested_agents
            .iter()
            .map(|id| {
                if let Some(pos) = id.find(':') {
                    id[0..pos].to_string()
                } else {
                    id.clone()
                }
            })
            .collect();

        let normalized_signed_agents: Vec<String> = all_agreement_signed_agents
            .iter()
            .map(|id| {
                if let Some(pos) = id.find(':') {
                    id[0..pos].to_string()
                } else {
                    id.clone()
                }
            })
            .collect();

        return Ok(subtract_vecs(
            &normalized_requested_agents,
            &normalized_signed_agents,
        ));
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
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect());
                }
            }
        }
        return Err("no agreement or agents in agreement".into());
    }

    pub fn signing_agent(&self) -> Result<String, Box<dyn Error>> {
        let value: &serde_json::Value = &self.value;
        if let Some(jacs_signature) = value.get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME) {
            return Ok(jacs_signature.get("agentID").expect("REASON").to_string());
        }
        return Err("no agreement or signatures in agreement".into());
    }

    pub fn signing_agent_str(&self) -> Result<&str, Box<dyn Error>> {
        let value: &serde_json::Value = &self.value;
        if let Some(jacs_signature) = value.get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME) {
            return Ok(jacs_signature
                .get("agentID")
                .expect("REASON")
                .as_str()
                .unwrap());
        }
        return Err("no agreement or signatures in agreement".into());
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
                        let agentid: String =
                            signature["agentID"].as_str().expect("REASON").to_string();
                        signed_agents.push(agentid);
                    }
                    return Ok(signed_agents);
                }
            }
        }
        return Err("no agreement or signatures in agreement".into());
    }
}

impl fmt::Display for JACSDocument {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let json_string = serde_json::to_string_pretty(&self.value).map_err(|_| fmt::Error)?;
        write!(f, "{}", json_string)
    }
}

pub trait DocumentTraits {
    fn verify_document_signature(
        &mut self,
        document_key: &String,
        signature_key_from: Option<&String>,
        fields: Option<&Vec<String>>,
        public_key: Option<Vec<u8>>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn Error>>;
    fn archive_old_version(
        &mut self,
        original_document: &JACSDocument,
    ) -> Result<(), Box<dyn Error>>;
    fn validate_document_with_custom_schema(
        &self,
        schema_path: &str,
        json: &Value,
    ) -> Result<(), String>;
    fn create_document_and_load(
        &mut self,
        json: &String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<JACSDocument, Box<dyn std::error::Error + 'static>>;
    fn load_all(
        &mut self,
        store: bool,
        load_only_recent: bool,
    ) -> Result<Vec<JACSDocument>, Vec<Box<dyn Error>>>;
    fn load_document(&mut self, document_string: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn remove_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn copy_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn store_jacs_document(&mut self, value: &Value) -> Result<JACSDocument, Box<dyn Error>>;
    fn hash_doc(&self, doc: &Value) -> Result<String, Box<dyn Error>>;
    fn get_document(&self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn get_document_keys(&mut self) -> Vec<String>;
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
}

impl DocumentTraits for Agent {
    // todo change this to use stored documents only
    fn validate_document_with_custom_schema(
        &self,
        schema_path: &str,
        json: &Value,
    ) -> Result<(), String> {
        let schemas = self.document_schemas.lock().unwrap();
        let validator = schemas
            .get(schema_path)
            .ok_or_else(|| format!("Validator not found for path: {}", schema_path))?;

        let validation_result = validator.validate(json);
        validation_result.map_err(|error| error.to_string())?;

        Ok(())
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
                .unwrap()
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
                    .ok_or("Missing file path")?;
                let expected_hash = file_obj
                    .get("sha256")
                    .and_then(|hash| hash.as_str())
                    .ok_or("Missing SHA256 hash")?;

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
    ) -> Result<JACSDocument, Box<dyn std::error::Error + 'static>> {
        let mut instance = self.schema.create(json)?;

        if let Some(attachment_list) = attachments {
            let mut files_array: Vec<Value> = Vec::new();

            // Iterate over each attachment
            for attachment_path in attachment_list {
                let final_embed = embed.unwrap_or(false);
                let file_json = self
                    .create_file_json(&attachment_path, final_embed)
                    .unwrap();

                // Add the file JSON to the files array
                files_array.push(file_json);
            }

            // Create a new "files" field in the document
            let instance_map = instance.as_object_mut().unwrap();
            instance_map.insert("jacsFiles".to_string(), Value::Array(files_array));
        }

        // sign document
        instance[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = self.signing_procedure(
            &instance,
            None,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
        )?;
        // hash document
        let document_hash = self.hash_doc(&instance)?;
        instance[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        Ok(self.store_jacs_document(&instance)?)
    }

    fn load_document(&mut self, document_string: &String) -> Result<JACSDocument, Box<dyn Error>> {
        match &self.validate_header(&document_string) {
            Ok(value) => {
                return self.store_jacs_document(&value);
            }
            Err(e) => {
                error!("ERROR document ERROR {}", e);
                return Err(e.to_string().into());
            }
        }
    }

    fn load_all(
        &mut self,
        store: bool,
        load_only_recent: bool,
    ) -> Result<Vec<JACSDocument>, Vec<Box<dyn Error>>> {
        let mut errors: Vec<Box<dyn Error>> = Vec::new();
        let mut documents: Vec<JACSDocument> = Vec::new();
        let mut doc_strings = self.fs_docs_load_all()?;
        let mut most_recent_docs = HashMap::new();
        // iterate over doc_strings,
        // convert to Json Value and extract the jacsId, jacsVersion, and jacsVersionDate keys.
        // create a data structure that only keeps the max jacsVersionDate (which needs to be converted to int64 from datetime string)
        // for each jacsId check if it is the most recent version
        // keep only the most recent version  this in a create a new docstrings vector of strings
        if load_only_recent {
            for doc_string in &doc_strings {
                if let Ok(doc) = serde_json::from_str::<Value>(&doc_string) {
                    if let (Some(jacs_id), Some(jacs_version_date)) =
                        (doc["jacsId"].as_str(), doc["jacsVersionDate"].as_str())
                    {
                        // Convert jacsVersionDate to timestamp (i64)
                        let timestamp = match DateTime::parse_from_rfc3339(jacs_version_date) {
                            Ok(dt) => dt.with_timezone(&Utc).timestamp(),
                            Err(e) => {
                                println!("Failed to parse timestamp: {}", e);
                                Utc::now().timestamp()
                            }
                        };

                        let entry = most_recent_docs
                            .entry(jacs_id.to_string())
                            .or_insert_with(|| (timestamp, doc_string));
                        if timestamp > entry.0 {
                            *entry = (timestamp, doc_string);
                        }
                    }
                }
            }
            doc_strings = most_recent_docs
                .values()
                .map(|&(_, doc)| doc.clone())
                .collect();
        }

        for doc_string in doc_strings {
            match self.validate_header(&doc_string) {
                Ok(doc) => {
                    let document = self.store_jacs_document(&doc);
                    match document {
                        Ok(document) => {
                            if store {
                                documents.push(document);
                            }
                        }
                        Err(e) => {
                            errors.push(e.into());
                        }
                    }
                }
                Err(e) => {
                    errors.push(e.into());
                }
            }
        }
        if errors.len() > 0 {
            error!("errors loading documents {:?}", errors);
        }
        Ok(documents)
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
        let mut documents = self.documents.lock().expect("JACSDocument lock");
        let doc = JACSDocument {
            id: value.get_str("jacsId").expect("REASON").to_string(),
            version: value.get_str("jacsVersion").expect("REASON").to_string(),
            value: Some(value.clone()).into(),
            jacs_type: value.get_str("jacsType").expect("REASON").to_string(),
        };
        let key = doc.getkey();
        documents.insert(key.clone(), doc.clone());
        Ok(doc)
    }

    fn get_document(&self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let documents = self.documents.lock().expect("JACSDocument lock");
        match documents.get(document_key) {
            Some(document) => Ok(document.clone()),
            None => Err(format!("Document not found for key: {}", document_key).into()),
        }
    }

    fn remove_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let mut documents = self.documents.lock().expect("JACSDocument lock");
        match documents.remove(document_key) {
            Some(document) => Ok(document),
            None => Err(format!("Document not found for key: {}", document_key).into()),
        }
    }

    // used to see if key is already in index
    fn get_document_keys(&mut self) -> Vec<String> {
        let documents = self.documents.lock().expect("documents lock");
        return documents.keys().map(|k| k.to_string()).collect();
    }

    /// pass in modified doc
    /// the original document needs to be marked as obsolete
    /// but this means not a deletion, but a move of the file
    /// TODO validate that the new document is owned by editor
    fn update_document(
        &mut self,
        document_key: &String,
        new_document_string: &String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        // check that old document is found
        let mut new_document: Value = self.schema.validate_header(new_document_string)?;
        let error_message = format!("original document {} not found", document_key);
        let original_document = self.get_document(document_key).expect(&error_message);
        let value = original_document.value.clone();
        let jacs_level = new_document
            .get_str("jacsLevel")
            .unwrap_or(DEFAULT_JACS_DOC_LEVEL.to_string());
        if (!EDITABLE_JACS_DOCS.contains(&jacs_level.as_str())) {
            return Err(format!("JACS docs of type {} are not editable", jacs_level).into());
        };

        let mut files_array: Vec<Value> = new_document
            .get("jacsFiles")
            .and_then(|files| files.as_array())
            .cloned()
            .unwrap_or_else(Vec::new);

        // now re-verify these files

        let _ = self
            .verify_document_files(&new_document)
            .expect("file verification");
        if let Some(attachment_list) = attachments {
            // Iterate over each attachment
            for attachment_path in attachment_list {
                // Call create_file_json with embed set to false
                let final_embed = embed.unwrap_or(false);
                let file_json = self
                    .create_file_json(&attachment_path, final_embed)
                    .unwrap();

                // Add the file JSON to the files array
                files_array.push(file_json);
            }
        }

        // Create a new "files" field in the document
        if let Some(instance_map) = new_document.as_object_mut() {
            instance_map.insert("jacsFiles".to_string(), Value::Array(files_array));
        }

        // check that new document has same id, value, hash as old
        let orginal_id = &value.get_str("jacsId");
        let orginal_version = &value.get_str("jacsVersion");
        // check which fields are different
        let new_doc_orginal_id = &new_document.get_str("jacsId");
        let new_doc_orginal_version = &new_document.get_str("jacsVersion");
        if (orginal_id != new_doc_orginal_id) || (orginal_version != new_doc_orginal_version) {
            return Err(format!(
                "The id/versions do not match found for key: {}. {:?}{:?}",
                document_key, new_doc_orginal_id, new_doc_orginal_version
            )
            .into());
        }

        //TODO  show diff

        // validate schema
        let new_version = Uuid::new_v4().to_string();
        let last_version = &value["jacsVersion"];
        let versioncreated = Utc::now().to_rfc3339();

        new_document["jacsPreviousVersion"] = last_version.clone();
        new_document["jacsVersion"] = json!(format!("{}", new_version));
        new_document["jacsVersionDate"] = json!(format!("{}", versioncreated));
        // get all fields but reserved
        new_document[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = self.signing_procedure(
            &new_document,
            None,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
        )?;

        // hash new version
        let document_hash = self.hash_doc(&new_document)?;
        new_document[SHA256_FIELDNAME] = json!(format!("{}", document_hash));

        // archive old version
        // let result = self.archive_old_version(&original_document);
        // if let Err(e) = result {
        //     println!("Failed to archive old version: {}", e);
        // }

        Ok(self.store_jacs_document(&new_document)?)
    }

    fn archive_old_version(
        &mut self,
        original_document: &JACSDocument,
    ) -> Result<(), Box<dyn Error>> {
        let lookup_key = original_document.getkey();
        // remove from hashmap
        let mut documents = self.documents.lock().expect("JACSDocument lock");
        documents.remove(&lookup_key);
        // move file to archive
        let _ = self.fs_document_archive(&lookup_key)?;
        Ok(())
    }

    /// copys document without modifications
    fn copy_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let original_document = self.get_document(document_key).unwrap();
        let mut value = original_document.value;
        let new_version = Uuid::new_v4().to_string();
        let last_version = &value["jacsVersion"];
        let versioncreated = Utc::now().to_rfc3339();

        value["jacsPreviousVersion"] = last_version.clone();
        value["jacsVersion"] = json!(format!("{}", new_version));
        value["jacsVersionDate"] = json!(format!("{}", versioncreated));
        // sign new version
        value[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = self.signing_procedure(
            &value,
            None,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
        )?;
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
        let original_document = self.get_document(document_key).unwrap();
        let document_directory: String = "documents".to_string(); // get_short_name(&original_document.value)?;
        let document_string: String = serde_json::to_string_pretty(&original_document.value)?;

        let is_extract_only = match extract_only {
            Some(extract_only) => extract_only,
            None => false,
        };

        if !is_extract_only {
            let _ = self.fs_document_save(
                &document_key,
                &document_string,
                &document_directory,
                output_filename,
            )?;
        }

        let do_export = match export_embedded {
            Some(export_embedded) => export_embedded,
            None => false,
        };

        if do_export {
            if let Some(jacs_files) = original_document.value["jacsFiles"].as_array() {
                if let Err(e) = self.check_data_directory() {
                    error!("Failed to check data directory: {}", e);
                }
                for item in jacs_files {
                    if item["embed"].as_bool().unwrap_or(false) {
                        let contents = item["contents"].as_str().ok_or("Contents not found")?;
                        let path = item["path"].as_str().ok_or("Path not found")?;

                        let decoded_contents = base64::decode(contents)?;

                        // Inflate the gzip-compressed contents
                        let mut gz_decoder = GzDecoder::new(std::io::Cursor::new(decoded_contents));
                        let mut inflated_contents = Vec::new();
                        gz_decoder.read_to_end(&mut inflated_contents)?;

                        // TODO move this portion of code out of document as it's filesystem dependent
                        // Backup the existing file if it exists
                        let storage = MultiStorage::new(None)?;
                        if storage.file_exists(path, None)? {
                            let backup_path =
                                format!("{}.{}.bkp", path, Local::now().format("%Y%m%d_%H%M%S"));
                            storage.rename_file(path, &backup_path)?;
                        }

                        // Save the inflated contents to the file
                        let storage = MultiStorage::new(None)?;
                        storage.save_file(path, &inflated_contents)?;

                        // Mark the file as not executable
                        #[cfg(not(target_arch = "wasm32"))]
                        if !self.use_filesystem() {
                            self.mark_file_not_executable(Path::new(path))?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn verify_document_signature(
        &mut self,
        document_key: &String,
        signature_key_from: Option<&String>,
        fields: Option<&Vec<String>>,
        public_key: Option<Vec<u8>>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        // check that public key exists
        let document = self.get_document(document_key).expect("Reason");
        let document_value = document.getvalue();
        let _ = self
            .verify_document_files(&document_value)
            .expect("file verification");
        // this is innefficient since I generate a whole document
        let used_public_key = match public_key {
            Some(public_key) => public_key,
            None => self.get_public_key()?,
        };

        let binding = &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string();
        let signature_key_from_final = match signature_key_from {
            Some(signature_key_from) => signature_key_from,
            None => binding,
        };

        let result = self.signature_verification_procedure(
            &document_value,
            fields,
            signature_key_from_final,
            used_public_key,
            public_key_enc_type,
            None,
            None,
        );
        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                let error_message =
                    format!("Signatures not verifiable {} {:?}! ", document_key, err);
                error!("{}", error_message);
                return Err(error_message.into());
            }
        }
    }

    fn parse_attachement_arg(&mut self, attachments: Option<&String>) -> Option<Vec<String>> {
        match attachments {
            Some(path_str) => {
                let storage = MultiStorage::new(None).ok()?;

                // First try to list files in case it's a directory
                match storage.list(path_str, None) {
                    Ok(file_paths) => {
                        if !file_paths.is_empty() {
                            // Path is a directory, return list of files
                            Some(file_paths)
                        } else {
                            // Check if path is a single file
                            match storage.file_exists(path_str, None) {
                                Ok(true) => Some(vec![path_str.to_string()]),
                                _ => {
                                    eprintln!("Invalid path: {}", path_str);
                                    None
                                }
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("Failed to read path: {}", path_str);
                        None
                    }
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
                Difference::Same(x) => same.push_str(x),
                Difference::Add(x) => add.push_str(x),
                Difference::Rem(x) => rem.push_str(x),
            }
        }

        (same, add, rem)
    }
}
