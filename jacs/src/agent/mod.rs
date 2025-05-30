pub mod agreement;
pub mod boilerplate;
pub mod document;
pub mod loaders;
pub mod payloads;
pub mod security;

use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::crypt::hash::hash_public_key;
use crate::storage::MultiStorage;

use crate::config::{Config, find_config, load_config};

use crate::crypt::aes_encrypt::{decrypt_private_key, encrypt_private_key};

use crate::crypt::KeyManager;

use crate::observability::convenience::{record_agent_operation, record_signature_verification};
use crate::schema::Schema;
use crate::schema::utils::{EmbeddedSchemaResolver, ValueExt, resolve_schema};
use chrono::prelude::*;
use jsonschema::{Draft, Validator};
use loaders::FileLoader;
use serde_json::{Value, json, to_value};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use secrecy::SecretBox;

/// this field is only ignored by itself, but other
/// document signatures and hashes include this to detect tampering
pub const DOCUMENT_AGREEMENT_HASH_FIELDNAME: &str = "jacsAgreementHash";

// these fields generally exclude themselves when hashing
pub const SHA256_FIELDNAME: &str = "jacsSha256";
pub const AGENT_SIGNATURE_FIELDNAME: &str = "jacsSignature";
pub const AGENT_REGISTRATION_SIGNATURE_FIELDNAME: &str = "jacsRegistration";
pub const AGENT_AGREEMENT_FIELDNAME: &str = "jacsAgreement";
pub const TASK_START_AGREEMENT_FIELDNAME: &str = "jacsStartAgreement";
pub const TASK_END_AGREEMENT_FIELDNAME: &str = "jacsEndAgreement";
pub const DOCUMENT_AGENT_SIGNATURE_FIELDNAME: &str = "jacsSignature";
pub const JACS_VERSION_FIELDNAME: &str = "jacsVersion";
pub const JACS_VERSION_DATE_FIELDNAME: &str = "jacsVersionDate";
pub const JACS_PREVIOUS_VERSION_FIELDNAME: &str = "jacsPreviousVersion";

// these fields are ignored when hashing
pub const JACS_IGNORE_FIELDS: [&str; 7] = [
    SHA256_FIELDNAME,
    AGENT_SIGNATURE_FIELDNAME,
    DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
    AGENT_AGREEMENT_FIELDNAME,
    AGENT_REGISTRATION_SIGNATURE_FIELDNAME,
    TASK_START_AGREEMENT_FIELDNAME,
    TASK_END_AGREEMENT_FIELDNAME,
];

// Just use Vec<u8> directly since it already implements the needed traits
pub type PrivateKey = Vec<u8>;
pub type SecretPrivateKey = SecretBox<Vec<u8>>;

// If we need any specific methods for private key operations:
pub fn use_secret(key: &[u8]) -> Vec<u8> {
    decrypt_private_key(key).expect("use_secret decrypt failed")
}

#[derive(Debug)]
pub struct Agent {
    /// the JSONSchema used
    /// todo use getter
    pub schema: Schema,
    /// the agent JSON Struct
    /// TODO make this threadsafe
    value: Option<Value>,
    /// use getter
    pub config: Option<Config>,
    //  todo make read commands public but not write commands
    storage: MultiStorage,
    /// custom schemas that can be loaded to check documents
    /// the resolver might ahve trouble TEST
    document_schemas: Arc<Mutex<HashMap<String, Validator>>>,
    documents: Arc<Mutex<HashMap<String, JACSDocument>>>,
    /// everything needed for the agent to sign things
    id: Option<String>,
    version: Option<String>,
    public_key: Option<Vec<u8>>,
    private_key: Option<SecretPrivateKey>,
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
        let document_schemas_map = Arc::new(Mutex::new(HashMap::new()));
        let document_map = Arc::new(Mutex::new(HashMap::new()));
        let config = Some(find_config("./".to_string())?);
        Ok(Self {
            schema,
            value: None,
            config: config,
            storage: MultiStorage::default_new()?,
            document_schemas: document_schemas_map,
            documents: document_map,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
        })
    }

    pub fn load_by_id(&mut self, lookup_id: String) -> Result<(), Box<dyn Error>> {
        let start_time = std::time::Instant::now();

        self.config = Some(find_config("./".to_string())?);
        debug!("load_by_id config {:?}", self.config);

        let agent_string = self.fs_agent_load(&lookup_id)?;
        let result = self.load(&agent_string);

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let success = result.is_ok();

        // Record the agent operation
        record_agent_operation("load_by_id", &lookup_id, success, duration_ms);

        if success {
            info!("Successfully loaded agent by ID: {}", lookup_id);
        } else {
            error!("Failed to load agent by ID: {}", lookup_id);
        }

        result
    }

    pub fn load_by_config(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        // load config string
        self.config = Some(load_config(&path)?);
        let lookup_id: &str = self
            .config
            .as_ref()
            .unwrap()
            .jacs_agent_id_and_version()
            .as_deref()
            .unwrap_or("");
        let storage_type = self
            .config
            .as_ref()
            .unwrap()
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("");
        self.storage = MultiStorage::new(storage_type.to_string())?;
        if !lookup_id.is_empty() {
            let agent_string = self.fs_agent_load(&lookup_id.to_string())?;
            return self.load(&agent_string);
        } else {
            return Ok(());
        }
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
        let private_key_encrypted = encrypt_private_key(&private_key)?;
        // Box the Vec<u8> before creating SecretBox
        self.private_key = Some(SecretBox::new(Box::new(private_key_encrypted)));
        self.public_key = Some(public_key);
        self.key_algorithm = Some(key_algorithm.to_string());
        Ok(())
    }

    pub fn get_private_key(&self) -> Result<&SecretPrivateKey, Box<dyn Error>> {
        match &self.private_key {
            Some(private_key) => Ok(private_key),
            None => Err("private_key is None".into()),
        }
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
                    self.id = value.get_str("jacsId");
                    self.version = value.get_str("jacsVersion");
                }

                if !Uuid::parse_str(&self.id.clone().expect("string expected").to_string()).is_ok()
                    || !Uuid::parse_str(&self.version.clone().expect("string expected").to_string())
                        .is_ok()
                {
                    warn!("ID and Version must be UUID");
                }
            }
            Err(e) => {
                error!("Agent validation failed: {}", e);
                return Err(e.to_string().into());
            }
        }

        if self.id.is_some() {
            let _id_string = self.id.clone().expect("string expected").to_string();
            // check if keys are already loaded
            if self.public_key.is_none() || self.private_key.is_none() {
                self.fs_load_keys()?;
            } else {
                info!("Keys already loaded for agent");
            }

            self.verify_self_signature()?;
        }

        return Ok(());
    }

    pub fn verify_self_signature(&mut self) -> Result<(), Box<dyn Error>> {
        let public_key = self.get_public_key()?;
        // validate header
        let signature_key_from = &AGENT_SIGNATURE_FIELDNAME.to_string();
        match &self.value.clone() {
            Some(embedded_value) => {
                return self.signature_verification_procedure(
                    embedded_value,
                    None,
                    signature_key_from,
                    public_key,
                    None,
                    None,
                    None,
                );
            }
            None => {
                let error_message = "Value is None";
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    // fn unset_self(&mut self) {
    //     self.id = None;
    //     self.version = None;
    //     self.value = None;
    // }

    pub fn get_agent_for_doc(
        &mut self,
        document_key: String,
        signature_key_from: Option<&String>,
    ) -> Result<String, Box<dyn Error>> {
        let document = self.get_document(&document_key).expect("Reason");
        let document_value = document.getvalue();
        let binding = &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string();
        let signature_key_from_final = match signature_key_from {
            Some(signature_key_from) => signature_key_from,
            None => binding,
        };
        return self.get_signature_agent_id_and_version(&document_value, signature_key_from_final);
    }

    fn get_signature_agent_id_and_version(
        &self,
        json_value: &Value,
        signature_key_from: &String,
    ) -> Result<String, Box<dyn Error>> {
        let agentid = json_value[signature_key_from]["agentID"]
            .as_str()
            .unwrap_or("")
            .trim_matches('"')
            .to_string();
        let agentversion = json_value[signature_key_from]["agentVersion"]
            .as_str()
            .unwrap_or("")
            .trim_matches('"')
            .to_string();
        return Ok(format!("{}:{}", agentid, agentversion));
    }

    pub fn signature_verification_procedure(
        &self,
        json_value: &Value,
        fields: Option<&Vec<String>>,
        signature_key_from: &String,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
        original_public_key_hash: Option<String>,
        signature: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let start_time = std::time::Instant::now();

        let (document_values_string, _) =
            Agent::get_values_as_string(&json_value, fields.cloned(), signature_key_from)?;
        debug!(
            "signature_verification_procedure document_values_string:\n{}",
            document_values_string
        );

        debug!(
            "signature_verification_procedure placement_key:\n{}",
            signature_key_from
        );

        let public_key_hash: String = match original_public_key_hash {
            Some(orig) => orig,
            _ => json_value[signature_key_from]["publicKeyHash"]
                .as_str()
                .unwrap_or("")
                .trim_matches('"')
                .to_string(),
        };

        let public_key_rehash = hash_public_key(public_key.clone());

        if public_key_rehash != public_key_hash {
            let error_message = format!(
                "Incorrect public key used to verify signature public_key_rehash {} public_key_hash {} ",
                public_key_rehash, public_key_hash
            );
            error!("{}", error_message);

            let duration_ms = start_time.elapsed().as_millis() as u64;
            let algorithm = public_key_enc_type.as_deref().unwrap_or("unknown");
            record_signature_verification("unknown_agent", false, algorithm);

            return Err(error_message.into());
        }

        let signature_base64 = match signature.clone() {
            Some(sig) => sig,
            _ => json_value[signature_key_from]["signature"]
                .as_str()
                .unwrap_or("")
                .trim_matches('"')
                .to_string(),
        };

        debug!(
            "\n\n\n standard sig {}  \n agreement special sig \n{:?} \nchosen signature_base64\n {} \n\n\n",
            json_value[signature_key_from]["signature"]
                .as_str()
                .unwrap_or("")
                .trim_matches('"')
                .to_string(),
            signature,
            signature_base64
        );

        let result = self.verify_string(
            &document_values_string,
            &signature_base64,
            public_key,
            public_key_enc_type.clone(),
        );

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let success = result.is_ok();
        let algorithm = public_key_enc_type.as_deref().unwrap_or("unknown");
        let agent_id = json_value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_agent");

        record_signature_verification(agent_id, success, algorithm);

        if success {
            info!("Signature verification successful for agent: {}", agent_id);
        } else {
            error!("Signature verification failed for agent: {}", agent_id);
        }

        result
    }

    /// Generates a signature JSON fragment for the specified JSON value.
    ///
    /// This function takes a JSON value, an optional list of fields to include in the signature,
    /// and a placement key. It retrieves the values of the specified fields from the JSON value,
    /// signs them using the agent's signing key, and returns a new JSON value containing the
    /// signature and related metadata.
    ///
    /// If no fields are provided, the function will choose system default fields. Note that if
    /// the system default fields change, it could cause problems with signature verification.
    ///
    /// # Arguments
    ///
    /// * `json_value` - A reference to the JSON value to be signed.
    /// * `fields` - An optional reference to a vector of field names to include in the signature.
    ///              If `None`, system default fields will be used.
    /// * `placement_key` - A reference to a string representing the key where the signature
    ///                     should be placed in the resulting JSON value.
    ///
    /// # Returns
    ///
    /// * `Ok(Value)` - A new JSON value containing the signature and related metadata.
    /// * `Err(Box<dyn Error>)` - An error occurred while generating the signature.
    ///
    ///
    /// # Errors
    ///
    /// This function may return an error in the following cases:
    ///
    /// * If the specified fields are not found in the JSON value.
    /// * If an error occurs while signing the values.
    /// * If an error occurs while serializing the accepted fields.
    /// * If an error occurs while retrieving the agent's public key.
    /// * If an error occurs while validating the generated signature against the schema.
    pub fn signing_procedure(
        &mut self,
        json_value: &Value,
        fields: Option<&Vec<String>>,
        placement_key: &String,
    ) -> Result<Value, Box<dyn Error>> {
        debug!("placement_key:\n{}", placement_key);
        let (document_values_string, accepted_fields) =
            Agent::get_values_as_string(&json_value, fields.cloned(), placement_key)?;
        debug!(
            "signing_procedure document_values_string:\n\n{}\n\n",
            document_values_string
        );
        let signature = self.sign_string(&document_values_string)?;
        debug!("signing_procedure created signature :\n{}", signature);
        let binding = String::new();
        let agent_id = self.id.as_ref().unwrap_or(&binding);
        let agent_version = self.version.as_ref().unwrap_or(&binding);
        let date = Utc::now().to_rfc3339();

        let signing_algorithm = self.config.as_ref().unwrap().get_key_algorithm()?;

        let serialized_fields = match to_value(accepted_fields) {
            Ok(value) => value,
            Err(err) => return Err(Box::new(err)),
        };
        let public_key = self.get_public_key()?;
        let public_key_hash = hash_public_key(public_key);
        debug!("hash {:?} ", public_key_hash);
        //TODO fields must never include sha256 at top level
        // error
        let signature_document = json!({
            // based on v1
            "agentID": agent_id,
            "agentVersion": agent_version,
            "date": date,
            "signature":signature,
            "signingAlgorithm":signing_algorithm,
            "publicKeyHash": public_key_hash,
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
                        key != placement_key && !JACS_IGNORE_FIELDS.contains(&key.as_str())
                    })
                    .map(|key| key.to_string())
                    .collect();
                default_keys
            }
        };

        for key in &accepted_fields {
            if let Some(value) = json_value.get(&key) {
                if let Some(str_value) = value.as_str() {
                    if str_value == placement_key || JACS_IGNORE_FIELDS.contains(&str_value) {
                        let error_message = format!(
                            "Field names for signature must not include itself or hashing
                              - these are reserved for this signature {}: see {:?}",
                            placement_key, JACS_IGNORE_FIELDS
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
                doc.get_str("jacsId").expect("REASON"),
                doc.get_str("jacsVersion").expect("REASON"),
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
        let orginal_id = &original_self.get_str("jacsId");
        let orginal_version = &original_self.get_str("jacsVersion");
        // check which fields are different
        let new_doc_orginal_id = &new_self.get_str("jacsId");
        let new_doc_orginal_version = &new_self.get_str("jacsVersion");
        if (orginal_id != new_doc_orginal_id) || (orginal_version != new_doc_orginal_version) {
            return Err(format!(
                "The id/versions do not match for old and new agent:  . {:?}{:?}",
                new_doc_orginal_id, new_doc_orginal_version
            )
            .into());
        }

        // validate schema
        let new_version = Uuid::new_v4().to_string();
        let last_version = &original_self["jacsVersion"];
        let versioncreated = Utc::now().to_rfc3339();

        new_self["jacsPreviousVersion"] = last_version.clone();
        new_self["jacsVersion"] = json!(format!("{}", new_version));
        new_self["jacsVersionDate"] = json!(format!("{}", versioncreated));

        // generate new keys?
        // sign new version
        new_self[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&new_self, None, &AGENT_SIGNATURE_FIELDNAME.to_string())?;
        // hash new version
        let document_hash = self.hash_doc(&new_self)?;
        new_self[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        //replace ones self
        self.version = Some(new_self["jacsVersion"].to_string());
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
    pub fn load_custom_schemas(&mut self, schema_paths: &[String]) -> Result<(), String> {
        let mut schemas = self.document_schemas.lock().map_err(|e| e.to_string())?;
        for path in schema_paths {
            let schema_value = resolve_schema(path).map_err(|e| e.to_string())?;
            let schema = Validator::options()
                .with_draft(Draft::Draft7)
                .with_retriever(EmbeddedSchemaResolver::new())
                .build(&schema_value)
                .map_err(|e| e.to_string())?;
            schemas.insert(path.clone(), schema);
        }
        Ok(())
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

        self.id = instance.get_str("jacsId");
        self.version = instance.get_str("jacsVersion");

        if create_keys {
            self.generate_keys()?;
        }
        if self.public_key.is_none() || self.private_key.is_none() {
            let _ = self.fs_load_keys()?;
        }

        // Instead of using ID:version as the filename, we should use the public key hash
        if self.public_key.is_some() && self.key_algorithm.is_some() {
            let public_key = self.public_key.as_ref().unwrap();
            let key_algorithm = self.key_algorithm.as_ref().unwrap();

            // Calculate hash of public key to use as filename
            let public_key_hash = hash_public_key(public_key.clone());

            // Save public key using its hash as the identifier
            let _ = self.fs_save_remote_public_key(
                &public_key_hash,
                public_key,
                key_algorithm.as_bytes(),
            );
        }

        // schema.create will call this "document" otherwise
        instance["jacsType"] = json!("agent");
        instance["jacsLevel"] = json!("config");
        instance["$schema"] = json!("https://hai.ai/schemas/agent/v1/agent.schema.json");
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
