// pub mod document;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::Document;
use crate::agent::document::JACSDocument;

use crate::agent::security::check_data_directory;
use crate::config::get_default_dir;
pub mod boilerplate;
pub mod document;
pub mod loaders;
pub mod security;

use crate::crypt::hash::hash_string;
use crate::crypt::KeyManager;
use crate::crypt::{rsawrapper, JACS_AGENT_KEY_ALGORITHM};

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

        check_data_directory();
        let default_directory = get_default_dir();

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
        let agent_string = self.fs_agent_load(&id)?;
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
        // validate schema
        // then load
        // then load keys
        // then validate signatures
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
            self.fs_load_keys()?;
            debug!("loaded keys for agent");
            self.verify_self_signature()?;
        }

        return Ok(());
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
                match self.verify_string(&document_values_string, &signature_base64, public_key) {
                    Ok(()) => Ok(()),
                    error => {
                        self.unset_self();
                        return error.into();
                    }
                }
            }
            None => {
                let error_message = "Value is None";
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    fn unset_self(&mut self) {
        self.id = None;
        self.version = None;
        self.value = None;
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

    pub fn get_schema_keys(&mut self) -> Vec<String> {
        let document_schemas = self.document_schemas.lock().expect("document_schemas lock");
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
        self.validate_agent(&self.to_string())?;
        self.verify_self_signature()?;
        Ok(new_self.to_string())
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
        //
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

    /// returns ID and version separated by a colon
    fn getagentkey(&self) -> String {
        // return the id and version
        let binding = String::new();
        let id = self.id.as_ref().unwrap_or(&binding);
        let version = self.version.as_ref().unwrap_or(&binding);
        return format!("{}:{}", id, version);
    }

    pub fn save(&self) -> Result<String, Box<dyn Error>> {
        let agent_string = self.as_string()?;
        let lookup_id = self.get_lookup_id()?;
        self.fs_agent_save(&lookup_id, &agent_string)
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

        self.id = instance.get_str("id");
        self.version = instance.get_str("version");

        if create_keys {
            self.generate_keys()?;
        }
        let _ = self.fs_load_keys();

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
        self.verify_self_signature()?;
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
