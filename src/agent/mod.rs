// pub mod document;

pub mod boilerplate;
pub mod loaders;

use crate::agent::boilerplate::BoilerPlate;

use crate::crypt::hash::hash_string;
use crate::crypt::KeyManager;
use crate::crypt::{rsawrapper, JACS_AGENT_KEY_ALGORITHM};
use crate::document::JACSDocument;
use crate::schema::utils::ValueExt;
use crate::schema::Schema;

use chrono::prelude::*;
use jsonschema::{Draft, JSONSchema};
use loaders::FileLoader;
use log::{debug, error, warn};
use reqwest;
use serde_json::{json, to_value, Value};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const SHA256_FIELDNAME: &str = "sha256";
pub const AGENT_SIGNATURE_FIELDNAME: &str = "self-signature";
pub const DOCUMENT_AGENT_SIGNATURE_FIELDNAME: &str = "agent-signature";
const DEFAULT_DIRECTORY_ENV_VAR: &str = "JACS_AGENT_DEFAULT_DIRECTORY";

pub struct Agent {
    /// the JSONSchema used
    schema: Schema,
    /// the agent JSON Struct
    /// TODO make this threadsafe
    value: Option<Value>,
    /// custom schemas that can be loaded to check documents
    /// the resolver might ahve trouble TEST
    document_schemas: Arc<Mutex<HashMap<String, JSONSchema>>>,
    documents: Arc<Mutex<HashMap<String, JACSDocument>>>,
    public_keys: HashMap<String, String>,
    default_directory: PathBuf,
    /// everything needed for the agent to sign things
    id: Option<String>,
    version: Option<String>,
    public_key: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    key_algorithm: Option<String>,
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.value {
            Some(value) => {
                let json_string = serde_json::to_string_pretty(value).map_err(|_| fmt::Error)?;
                write!(f, "{}", json_string)
            }
            None => write!(f, "No Agent Loaded"),
        }
    }
}

impl Agent {
    pub fn new(
        agentversion: &String,
        headerversion: &String,
        signature_version: &String,
    ) -> Result<Self, Box<dyn Error>> {
        let schema = Schema::new(agentversion, headerversion, signature_version)?;
        let mut document_schemas_map = Arc::new(Mutex::new(HashMap::new()));
        let mut document_map = Arc::new(Mutex::new(HashMap::new()));
        let mut public_keys: HashMap<String, String> = HashMap::new();
        let default_directory = env::var(DEFAULT_DIRECTORY_ENV_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| env::current_dir().unwrap());
        Ok(Self {
            schema,
            value: None,
            document_schemas: document_schemas_map,
            documents: document_map,
            public_keys: public_keys,
            default_directory: default_directory,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
        })
    }

    // loads and validates agent
    pub fn load_by_id(
        &mut self,
        id: String,
        _version: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let agent_string = self.load_local_agent_by_id(&id)?;
        return self.load(&agent_string);
    }

    pub fn ready(&mut self) -> bool {
        true
    }

    pub fn set_keys(
        &mut self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        key_algorithm: &String,
    ) -> Result<(), Box<dyn Error>> {
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        //TODO check algo
        self.key_algorithm = Some(key_algorithm.to_string());
        Ok(())
    }

    // todo keep this as private
    pub fn get_private_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match &self.private_key {
            Some(private_key) => Ok(private_key.clone()),
            None => Err("private_key is None".into()),
        }
    }

    pub fn get_default_dir(&self) -> PathBuf {
        self.default_directory.clone()
    }

    pub fn load(&mut self, agent_string: &String) -> Result<(), Box<dyn Error>> {
        match &self.validate_agent(&agent_string) {
            Ok(value) => {
                self.value = Some(value.clone());
                if let Some(ref value) = self.value {
                    self.id = value.get_str("id");
                    self.version = value.get_str("version");
                }
            }
            Err(e) => {
                error!("ERROR document ERROR {}", e);
                return Err(e.to_string().into());
            }
        }

        if self.id.is_some() {
            let id_string = self.id.clone().expect("string expected").to_string();
            self.load_keys()?;
            debug!("loaded keys for agent")
        }

        return Ok(());
    }

    pub fn load_document(
        &mut self,
        document_string: &String,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        match &self.validate_header(&document_string) {
            Ok(value) => {
                return self.storeJACSDocument(&value);
            }
            Err(e) => {
                error!("ERROR document ERROR {}", e);
                return Err(e.to_string().into());
            }
        }
    }

    // // hashing
    // fn hash_self(&self) -> Result<String, Box<dyn Error>> {
    //     match &self.value {
    //         Some(embedded_value) => self.hash_doc(embedded_value),
    //         None => {
    //             let error_message = "Value is None";
    //             error!("{}", error_message);
    //             Err(error_message.into())
    //         }
    //     }
    // }

    // get docs by prrefix
    // let user_values: HashMap<&String, &Value> = map
    //     .iter()
    //     .filter(|(key, _)| key.starts_with(prefix))
    //     .collect();

    pub fn verify_document_signature(
        &mut self,
        document_key: &String,
        signature_key_from: &String,
        fields: Option<&Vec<String>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        // check that public key exists
        let document = self.get_document(document_key).expect("Reason");
        let document_value = document.getvalue();
        // this is innefficient since I generate a whole document
        let used_public_key = match public_key {
            Some(public_key) => public_key,
            None => self.get_public_key()?,
        };
        let result = self.signature_verification_procedure(
            &document_value,
            fields,
            signature_key_from,
            used_public_key,
        );
        match result {
            Ok(result) => Ok(()),
            Err(err) => {
                let error_message =
                    format!("Signatures not verifiable {} {:?}! ", document_key, err);
                error!("{}", error_message);
                return Err(error_message.into());
            }
        }
    }

    pub fn verify_self_signature(&mut self) -> Result<(), Box<dyn Error>> {
        let public_key = self.get_public_key()?;
        // validate header
        let signature_key_from = &AGENT_SIGNATURE_FIELDNAME.to_string();
        match &self.value {
            Some(embedded_value) => {
                let (document_values_string, _) =
                    Agent::get_values_as_string(&embedded_value, None, signature_key_from)?;
                let signature_base64 = embedded_value[signature_key_from]["signature"]
                    .as_str()
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_string();
                self.verify_string(&document_values_string, &signature_base64, public_key)
            }
            None => {
                let error_message = "Value is None";
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    fn signature_verification_procedure(
        &mut self,
        json_value: &Value,
        fields: Option<&Vec<String>>,
        signature_key_from: &String,
        public_key: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        let (document_values_string, _) =
            Agent::get_values_as_string(&json_value, fields.cloned(), signature_key_from)?;
        debug!(
            "signing_procedure document_values_string:\n{}",
            document_values_string
        );
        let signature_base64 = json_value[signature_key_from]["signature"]
            .as_str()
            .unwrap_or("")
            .trim_matches('"')
            .to_string();
        self.verify_string(&document_values_string, &signature_base64, public_key)
    }

    /// re-used function to generate a signature json fragment
    /// if no fields are provided get_values_as_string() will choose system defaults
    /// NOTE: system default fields if they change could cause problems
    fn signing_procedure(
        &mut self,
        json_value: &Value,
        fields: Option<&Vec<String>>,
        placement_key: &String,
    ) -> Result<Value, Box<dyn Error>> {
        debug!("placement_key:\n{}", placement_key);
        let (document_values_string, accepted_fields) =
            Agent::get_values_as_string(&json_value, fields.cloned(), placement_key)?;
        debug!(
            "signing_procedure document_values_string:\n{}",
            document_values_string
        );
        let signature = self.sign_string(&document_values_string)?;
        debug!("signing_procedure created signature :\n{}", signature);
        let binding = String::new();
        let agent_id = self.id.as_ref().unwrap_or(&binding);
        let agent_version = self.version.as_ref().unwrap_or(&binding);
        let date = Utc::now().to_rfc3339();

        let signing_algorithm = env::var(JACS_AGENT_KEY_ALGORITHM)?;

        let serialized_fields = match to_value(accepted_fields) {
            Ok(value) => value,
            Err(err) => return Err(Box::new(err)),
        };
        let public_key = self.get_public_key()?;
        let public_key_hash = hash_string(&String::from_utf8(public_key)?);
        //TODO fields must never include sha256 at top level
        // error
        let signature_document = json!({
            // based on v1
            "agentid": agent_id,
            "agentversion": agent_version,
            "date": date,
            "signature":signature,
            "signing_algorithm":signing_algorithm,
            "public-key-hash": public_key_hash,
            "fields": serialized_fields
        });
        // TODO add sha256 of public key
        // validate signature schema
        let _ = self.schema.validate_signature(&signature_document)?;

        return Ok(signature_document);
    }

    /// given a set of fields, return a single string
    /// this function critical to all signatures
    /// placement_key is where this signature will go, so it should not be using itself
    /// TODO warn on missing keys
    fn get_values_as_string(
        json_value: &Value,
        keys: Option<Vec<String>>,
        placement_key: &String,
    ) -> Result<(String, Vec<String>), Box<dyn Error>> {
        let mut result = String::new();
        debug!("get_values_as_string keys:\n{:?}", keys);
        let accepted_fields = match keys {
            Some(keys) => keys,
            None => {
                // Choose default field names
                let default_keys: Vec<String> = json_value
                    .as_object()
                    .unwrap_or(&serde_json::Map::new())
                    .keys()
                    .filter(|&key| {
                        key != placement_key
                            && key != SHA256_FIELDNAME
                            && key != AGENT_SIGNATURE_FIELDNAME
                            && key != DOCUMENT_AGENT_SIGNATURE_FIELDNAME
                    })
                    .map(|key| key.to_string())
                    .collect();
                default_keys
            }
        };

        for key in &accepted_fields {
            if let Some(value) = json_value.get(&key) {
                if let Some(str_value) = value.as_str() {
                    if str_value == placement_key
                        || str_value == SHA256_FIELDNAME
                        || str_value == AGENT_SIGNATURE_FIELDNAME
                        || str_value == DOCUMENT_AGENT_SIGNATURE_FIELDNAME
                    {
                        let error_message = format!(
                            "Field names for signature must not include itself or hashing
                              - these are reserved for this signature {}: see {} {} {}",
                            placement_key,
                            SHA256_FIELDNAME,
                            AGENT_SIGNATURE_FIELDNAME,
                            DOCUMENT_AGENT_SIGNATURE_FIELDNAME
                        );
                        error!("{}", error_message);
                        return Err(error_message.into());
                    }
                    result.push_str(str_value);
                    result.push_str(" ");
                }
            }
        }
        debug!(
            "get_values_as_string result: {:?} fields {:?}",
            result.trim().to_string(),
            accepted_fields
        );
        Ok((result.trim().to_string(), accepted_fields))
    }

    /// verify the hash of a complete document that has SHA256_FIELDNAME
    pub fn verify_hash(&self, doc: &Value) -> Result<bool, Box<dyn Error>> {
        let original_hash_string = doc[SHA256_FIELDNAME].as_str().unwrap_or("").to_string();
        let new_hash_string = self.hash_doc(doc)?;

        if original_hash_string != new_hash_string {
            let error_message = format!(
                "Hashes don't match for doc {:?} {:?}! {:?} != {:?}",
                doc.get_str("id").expect("REASON"),
                doc.get_str("version").expect("REASON"),
                original_hash_string,
                new_hash_string
            );
            error!("{}", error_message);
            return Err(error_message.into());
        }
        Ok(true)
    }

    /// verify the hash where the document is the agent itself.
    pub fn verify_self_hash(&self) -> Result<bool, Box<dyn Error>> {
        match &self.value {
            Some(embedded_value) => self.verify_hash(embedded_value),
            None => {
                let error_message = "Value is None";
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    pub fn hash_doc(&self, doc: &Value) -> Result<String, Box<dyn Error>> {
        let mut doc_copy = doc.clone();
        doc_copy
            .as_object_mut()
            .map(|obj| obj.remove(SHA256_FIELDNAME));
        let doc_string = serde_json::to_string(&doc_copy)?;
        Ok(hash_string(&doc_string))
    }

    fn storeJACSDocument(&mut self, value: &Value) -> Result<JACSDocument, Box<dyn Error>> {
        let mut documents = self.documents.lock().unwrap();
        let doc = JACSDocument {
            id: value.get_str("id").expect("REASON").to_string(),
            version: value.get_str("version").expect("REASON").to_string(),
            value: Some(value.clone()).into(),
        };
        let key = doc.getkey();
        documents.insert(key.clone(), doc.clone());
        Ok(doc)
    }

    pub fn get_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
        let documents = self.documents.lock().unwrap();
        match documents.get(document_key) {
            Some(document) => Ok(document.clone()),
            None => Err(format!("Document not found for key: {}", document_key).into()),
        }
    }

    pub fn remove_document(
        &mut self,
        document_key: &String,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        let mut documents = self.documents.lock().unwrap();
        match documents.remove(document_key) {
            Some(document) => Ok(document),
            None => Err(format!("Document not found for key: {}", document_key).into()),
        }
    }

    pub fn get_document_keys(&mut self) -> Vec<String> {
        let documents = self.documents.lock().unwrap();
        return documents.keys().map(|k| k.to_string()).collect();
    }

    pub fn get_schema_keys(&mut self) -> Vec<String> {
        let document_schemas = self.document_schemas.lock().unwrap();
        return document_schemas.keys().map(|k| k.to_string()).collect();
    }

    /// pass in modified agent's JSON
    /// the function will replace it's internal value after:
    /// versioning
    /// resigning
    /// rehashing
    pub fn update_self(&mut self, new_agent_string: &String) -> Result<String, Box<dyn Error>> {
        let mut new_self: Value = self.schema.validate_agent(new_agent_string)?;
        let original_self = self.value.as_ref().expect("REASON");
        let orginal_id = &original_self.get_str("id");
        let orginal_version = &original_self.get_str("version");
        // check which fields are different
        let new_doc_orginal_id = &new_self.get_str("id");
        let new_doc_orginal_version = &new_self.get_str("version");
        if (orginal_id != new_doc_orginal_id) || (orginal_version != new_doc_orginal_version) {
            return Err(format!(
                "The id/versions do not match for old and new agent:  . {:?}{:?}",
                new_doc_orginal_id, new_doc_orginal_version
            )
            .into());
        }

        // validate schema
        let new_version = Uuid::new_v4().to_string();
        let last_version = &original_self["version"];
        let versioncreated = Utc::now().to_rfc3339();

        new_self["lastVersion"] = last_version.clone();
        new_self["version"] = json!(format!("{}", new_version));
        new_self["versionDate"] = json!(format!("{}", versioncreated));

        // generate new keys?
        // sign new version
        new_self[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&new_self, None, &AGENT_SIGNATURE_FIELDNAME.to_string())?;
        // hash new version
        let document_hash = self.hash_doc(&new_self)?;
        new_self[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        //replace ones self
        self.version = Some(new_self["version"].to_string());
        self.value = Some(new_self.clone());
        Ok(new_self.to_string())
    }

    /// pass in modified doc
    pub fn update_document(
        &mut self,
        document_key: &String,
        new_document_string: &String,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        // check that old document is found
        let new_document: Value = self.schema.validate_header(new_document_string)?;
        let original_document = self.get_document(document_key).unwrap();
        let mut value = original_document.value;
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

        value["lastVersion"] = last_version.clone();
        value["version"] = json!(format!("{}", new_version));
        value["versionDate"] = json!(format!("{}", versioncreated));
        // get all fields but reserved
        value[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = self.signing_procedure(
            &value,
            None,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
        )?;

        // hash new version
        let document_hash = self.hash_doc(&value)?;
        value[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        Ok(self.storeJACSDocument(&value)?)
    }

    /// copys document without modifications
    pub fn copy_document(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>> {
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
        Ok(self.storeJACSDocument(&value)?)
    }

    pub fn validate_header(
        &mut self,
        json: &str,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let value = self.schema.validate_header(json)?;

        // additional validation

        // check hash
        let _ = self.verify_hash(&value)?;
        // check signature
        return Ok(value);
    }

    pub fn validate_agent(
        &mut self,
        json: &str,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let value = self.schema.validate_agent(json)?;

        // additional validation
        // check hash
        let _ = self.verify_hash(&value)?;
        // check signature
        return Ok(value);
    }

    //// accepts local file system path or Urls
    pub fn load_custom_schemas(&mut self, schema_paths: &[String]) {
        let mut schemas = self.document_schemas.lock().unwrap();
        for path in schema_paths {
            let schema = if path.starts_with("http://") || path.starts_with("https://") {
                // Load schema from URL
                let schema_json = reqwest::blocking::get(path).unwrap().json().unwrap();
                JSONSchema::options()
                    .with_draft(Draft::Draft7)
                    .compile(&schema_json)
                    .unwrap()
            } else {
                // Load schema from local file
                let schema_json = std::fs::read_to_string(path).unwrap();
                let schema_value: Value = serde_json::from_str(&schema_json).unwrap();
                JSONSchema::options()
                    .with_draft(Draft::Draft7)
                    .compile(&schema_value)
                    .unwrap()
            };
            schemas.insert(path.clone(), schema);
        }
    }

    // todo change this to use stored documents only
    pub fn validate_document_with_custom_schema(
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

    /// create an document, and provde id and version as a result
    pub fn create_document_and_load(
        &mut self,
        json: &String,
    ) -> Result<JACSDocument, Box<dyn std::error::Error + 'static>> {
        let mut instance = self.schema.create(json)?;
        // sign document
        instance[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = self.signing_procedure(
            &instance,
            None,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
        )?;
        // hash document
        let document_hash = self.hash_doc(&instance)?;
        instance[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        Ok(self.storeJACSDocument(&instance)?)
    }

    /// returns ID and version separated by a colon
    fn getagentkey(&self) -> String {
        // return the id and version
        let binding = String::new();
        let id = self.id.as_ref().unwrap_or(&binding);
        let version = self.version.as_ref().unwrap_or(&binding);
        return format!("{}:{}", id, version);
    }

    /// create an agent, and provde id and version as a result
    pub fn create_agent_and_load(
        &mut self,
        json: &String,
        create_keys: bool,
        _create_keys_algorithm: Option<&String>,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        // validate schema json string
        // make sure id and version are empty
        let mut instance = self.schema.create(json)?;

        if let Some(ref value) = self.value {
            self.id = value.get_str("id");
            self.version = value.get_str("version");
        }
        if create_keys {
            self.generate_keys()?;
        }
        let _ = self.load_keys();

        // generate keys

        // create keys
        // self-sign as owner
        // validate signature
        // save
        // updatekey is the except we increment version and preserve id
        // update actions produces signatures
        // hash agent
        // self.validate();
        // sign agent
        instance[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&instance, None, &AGENT_SIGNATURE_FIELDNAME.to_string())?;
        // write  file to disk at [jacs]/agents/
        // run as agent
        // validate the agent schema now
        let document_hash = self.hash_doc(&instance)?;
        instance[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        self.value = Some(instance.clone());
        return Ok(instance);
    }
}

/*

todo

 - load actor and sign and act on other things
 - which requires a private key
 - also a verifier
 - remote public key or embeeded?


EVERY resource(actor) and task has

1. hash/checksum based on
  - previous hash, id, version
2. signature based on hash



*/
