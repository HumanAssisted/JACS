use crate::agent::boilerplate::BoilerPlate;
use crate::agent::loaders::FileLoader;
use crate::agent::Agent;
use crate::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use crate::agent::SHA256_FIELDNAME;
use crate::crypt::hash::hash_string;
use crate::schema::utils::ValueExt;
use chrono::Utc;
use log::error;
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct JACSDocument {
    pub id: String,
    pub version: String,
    pub value: Value,
}

impl JACSDocument {
    pub fn getkey(&self) -> String {
        // return the id and version
        let id = self.id.clone();
        let version = self.version.clone();
        return format!("{}:{}", id, version);
    }

    pub fn getvalue(&self) -> Value {
        self.value.clone()
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
        document_key: &String,
        signature_key_from: Option<&String>,
        fields: Option<&Vec<String>>,
        public_key: Option<Vec<u8>>,
        public_key_enc_type: Option<String>,
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
    ) -> Result<JACSDocument, Box<dyn std::error::Error + 'static>>;

    fn load_document(&mut self, document_string: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn remove_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn copy_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn store_jacs_document(&mut self, value: &Value) -> Result<JACSDocument, Box<dyn Error>>;
    fn hash_doc(&self, doc: &Value) -> Result<String, Box<dyn Error>>;
    fn get_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    fn get_document_keys(&mut self) -> Vec<String>;
    fn save_document(
        &mut self,
        document_key: &String,
        output_filename: Option<String>,
    ) -> Result<(), Box<dyn Error>>;
    fn update_document(
        &mut self,
        document_key: &String,
        new_document_string: &String,
        attachments: Option<Vec<String>>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    fn create_file_json(
        &mut self,
        filepath: &String,
        embed: bool,
    ) -> Result<serde_json::Value, Box<dyn Error>>;
    fn verify_document_files(&mut self, document: &Value) -> Result<(), Box<dyn Error>>;
}

impl Document for Agent {
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
        //.map(|schema| Arc::new(schema))
        //.expect("REASON");

        let x = match validator.validate(json) {
            Ok(()) => Ok(()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages.join(", "))
            }
        };
        x
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
        if let Some(files_array) = document.get("files").and_then(|files| files.as_array()) {
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
    ) -> Result<JACSDocument, Box<dyn std::error::Error + 'static>> {
        let mut instance = self.schema.create(json)?;

        if let Some(attachment_list) = attachments {
            let mut files_array: Vec<Value> = Vec::new();

            // Iterate over each attachment
            for attachment_path in attachment_list {
                // Call create_file_json with embed set to false
                let file_json = self.create_file_json(&attachment_path, false).unwrap();

                // Add the file JSON to the files array
                files_array.push(file_json);
            }

            // Create a new "files" field in the document
            let instance_map = instance.as_object_mut().unwrap();
            instance_map.insert("files".to_string(), Value::Array(files_array));
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
            id: value.get_str("id").expect("REASON").to_string(),
            version: value.get_str("version").expect("REASON").to_string(),
            value: Some(value.clone()).into(),
        };
        let key = doc.getkey();
        documents.insert(key.clone(), doc.clone());
        Ok(doc)
    }

    fn get_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
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

    fn get_document_keys(&mut self) -> Vec<String> {
        let documents = self.documents.lock().expect("documents lock");
        return documents.keys().map(|k| k.to_string()).collect();
    }

    /// pass in modified doc
    /// TODO validate that the new document is owned by editor
    fn update_document(
        &mut self,
        document_key: &String,
        new_document_string: &String,
        attachments: Option<Vec<String>>,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        // check that old document is found
        let mut new_document: Value = self.schema.validate_header(new_document_string)?;
        let error_message = format!("original document {} not found", document_key);
        let original_document = self.get_document(document_key).expect(&error_message);
        let value = original_document.value;

        let files_array: &mut Vec<Value> = new_document
            .as_object_mut()
            .and_then(|obj| obj.get_mut("files"))
            .and_then(|files| files.as_array_mut())
            .unwrap_or_else(|| {
                new_document
                    .as_object_mut()
                    .unwrap()
                    .insert("files".to_string(), Value::Array(Vec::new()));
                new_document["files"].as_array_mut().unwrap()
            });

        // now re-verify these files
        let _ = self
            .verify_document_files(&new_document)
            .expect("file verification");
        if let Some(attachment_list) = attachments {
            // Iterate over each attachment
            for attachment_path in attachment_list {
                // Call create_file_json with embed set to false
                let file_json = self.create_file_json(&attachment_path, false).unwrap();

                // Add the file JSON to the files array
                files_array.push(file_json);
            }

            // Create a new "files" field in the document
            let instance_map = new_document.as_object_mut().unwrap();
            instance_map.insert("files".to_string(), Value::Array(files_array));
        }

        // check that new document has same id, value, hash as old
        let orginal_id = &value.get_str("id");
        let orginal_version = &value.get_str("version");
        // check which fields are different
        let new_doc_orginal_id = &new_document.get_str("id");
        let new_doc_orginal_version = &new_document.get_str("version");
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
        let last_version = &value["version"];
        let versioncreated = Utc::now().to_rfc3339();

        new_document["lastVersion"] = last_version.clone();
        new_document["version"] = json!(format!("{}", new_version));
        new_document["versionDate"] = json!(format!("{}", versioncreated));
        // get all fields but reserved
        new_document[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = self.signing_procedure(
            &new_document,
            None,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
        )?;

        // hash new version
        let document_hash = self.hash_doc(&new_document)?;
        new_document[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        Ok(self.store_jacs_document(&new_document)?)
    }

    /// copys document without modifications
    fn copy_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let original_document = self.get_document(document_key).unwrap();
        let mut value = original_document.value;
        let new_version = Uuid::new_v4().to_string();
        let last_version = &value["version"];
        let versioncreated = Utc::now().to_rfc3339();

        value["lastVersion"] = last_version.clone();
        value["version"] = json!(format!("{}", new_version));
        value["versionDate"] = json!(format!("{}", versioncreated));
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
    ) -> Result<(), Box<dyn Error>> {
        let original_document = self.get_document(document_key).unwrap();
        let document_string: String = serde_json::to_string_pretty(&original_document.value)?;
        let _ = self.fs_document_save(&document_key, &document_string, output_filename);
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
}
