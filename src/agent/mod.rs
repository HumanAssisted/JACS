pub mod agreement;
pub mod boilerplate;
pub mod document;
pub mod loaders;
pub mod security;

use crate::agent::document::JACSDocument;
use crate::config::{get_default_dir, set_env_vars};
use crate::crypt::aes_encrypt::{decrypt_private_key, encrypt_private_key};
use crate::schema::utils::ValueExt;
use crate::schema::Schema;
use jsonschema::JSONSchema;
use loaders::FileLoader;
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

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
pub const JACS_PREVIOUS_VERSION_FIELDNAME: &str = "jacsLastVersion";

pub const JACS_IGNORE_FIELDS: [&str; 7] = [
    SHA256_FIELDNAME,
    AGENT_SIGNATURE_FIELDNAME,
    DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
    AGENT_AGREEMENT_FIELDNAME,
    AGENT_REGISTRATION_SIGNATURE_FIELDNAME,
    TASK_START_AGREEMENT_FIELDNAME,
    TASK_END_AGREEMENT_FIELDNAME,
];

use secrecy::{CloneableSecret, DebugSecret, Secret, Zeroize};

#[derive(Clone)]
pub struct PrivateKey(Vec<u8>);

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Permits cloning
impl CloneableSecret for PrivateKey {}

/// Provides a `Debug` impl (by default `[[REDACTED]]`)
impl DebugSecret for PrivateKey {}

impl PrivateKey {
    /// A method that operates on the private key.
    /// This method is just an example; it prints the length of the private key.
    /// Replace this with your actual cryptographic operation.
    pub fn use_secret(&self) -> Vec<u8> {
        decrypt_private_key(&self.0).expect("use_secret decrypt failed")
    }
}

// impl PrivateKey {
//     pub fn with_secret<F, R>(&self, f: F) -> R
//     where
//         F: FnOnce(&[u8]) -> R,
//     {
//         let decrypted_key = decrypt_private_key(&self.0).expect("use_secret decrypt failed");
//         f(&decrypted_key)
//     }
// }

/// Use this alias when storing secret values
pub type SecretPrivateKey = Secret<PrivateKey>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Agent {
    #[serde(skip_serializing, skip_deserializing)]
    /// the JSONSchema used
    pub schema: Schema,
    /// the agent JSON Struct
    /// TODO make this threadsafe
    value: Option<Value>,
    #[serde(skip_serializing, skip_deserializing)]
    /// custom schemas that can be loaded to check documents
    /// the resolver might ahve trouble TEST
    document_schemas: Arc<Mutex<HashMap<String, Arc<JSONSchema>>>>,
    #[serde(skip_serializing, skip_deserializing)]
    documents: Arc<Mutex<HashMap<String, JACSDocument>>>,
    default_directory: PathBuf,
    /// everything needed for the agent to sign things
    id: Option<String>,
    version: Option<String>,
    public_key: Option<Vec<u8>>,
    #[serde(skip_serializing, skip_deserializing)]
    private_key: Option<SecretPrivateKey>,
    key_algorithm: Option<String>,

    /// URL for the header schema used for validation.
    header_schema_url: Option<String>,

    /// URL for the document schema used for validation.
    document_schema_url: Option<String>,
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
        _agentversion: &String,
        _headerversion: &String,
        header_schema_url: String,
        document_schema_url: String,
    ) -> Result<Self, Box<dyn Error>> {
        set_env_vars();
        println!("Header schema URL: {}", header_schema_url);
        println!("Document schema URL: {}", document_schema_url);
        let schema = Schema::new(&header_schema_url, &document_schema_url)?;
        let document_schemas_map = Arc::new(Mutex::new(HashMap::new()));
        let document_map = Arc::new(Mutex::new(HashMap::new()));

        let default_directory = get_default_dir();

        let config = fs::read_to_string("jacs.config.json").expect("config file missing");
        schema.validate_config(&config).expect("config validation");

        Ok(Self {
            schema,
            value: None,
            document_schemas: document_schemas_map,
            documents: document_map,
            default_directory,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
            header_schema_url: Some(header_schema_url),
            document_schema_url: Some(document_schema_url),
        })
    }

    pub fn create_agent_and_load(
        agent_version: &String,
        headerversion: &String,
        header_schema_url: String,
        document_schema_url: String,
        agent_string: &String,
    ) -> Result<Self, Box<dyn Error>> {
        let mut agent = Agent::new(
            agent_version,
            headerversion,
            header_schema_url,
            document_schema_url,
        )?;
        agent.load(agent_string)?;
        Ok(agent)
    }

    pub fn load(&mut self, agent_string: &String) -> Result<(), Box<dyn Error>> {
        println!("Agent::load - Received JSON string: {}", agent_string);
        println!(
            "Agent::load - About to validate JSON string: {:?}",
            agent_string
        );
        if agent_string.is_empty() {
            println!("Agent::load - Error: JSON string is empty");
        } else {
            println!("Agent::load - JSON string is not empty");
        }
        let validation_result = self.schema.validate_agent(agent_string);
        println!("Agent::load - Validation result: {:?}", validation_result);
        match validation_result {
            Ok(value) => {
                println!("Agent::load - Validation successful. Value: {:?}", value);
                self.value = Some(value);
                if let Some(ref value) = self.value {
                    self.id = value.get_str("id");
                    self.version = value.get_str("version");
                }

                if !Uuid::parse_str(&self.id.clone().unwrap_or_default()).is_ok()
                    || !Uuid::parse_str(&self.version.clone().unwrap_or_default()).is_ok()
                {
                    println!("ID and Version must be UUID");
                }
            }
            Err(e) => {
                error!("ERROR document ERROR {}", e);
                return Err(e.into());
            }
        }

        if self.id.is_some() {
            // check if keys are already loaded
            if self.public_key.is_none() || self.private_key.is_none() {
                self.fs_load_keys()?;
            } else {
                println!("keys already loaded for agent");
            }

            self.verify_self_signature()?;
        }
        println!("Exiting Agent::load function");
        Ok(())
    }

    // loads and validates agent
    pub fn load_by_id(
        &mut self,
        id: Option<String>,
        _version: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let lookup_id = id
            .or_else(|| env::var("JACS_AGENT_ID_AND_VERSION").ok())
            .ok_or_else(|| "need to set JACS_AGENT_ID_AND_VERSION")?;

        println!("Loading agent with ID: {}", lookup_id);
        let agent_string = self.fs_agent_load(&lookup_id)?;
        println!("Loaded agent string: {}", agent_string); // Added print statement
        println!("Agent string to be loaded: {}", agent_string);
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
        let private_key_encrypted = encrypt_private_key(&private_key)?;
        self.private_key = Some(Secret::new(PrivateKey(private_key_encrypted))); //Some(private_key);
        self.public_key = Some(public_key);
        //TODO check algo
        self.key_algorithm = Some(key_algorithm.to_string());
        Ok(())
    }

    // todo keep this as private
    pub fn get_private_key(&self) -> Result<Secret<PrivateKey>, Box<dyn Error>> {
        match &self.private_key {
            Some(private_key) => {
                // Ok(self.private_key.map(|secret| secret.into()).expect("REASON"))
                Ok(private_key.clone())
            }
            None => Err("private_key is None".into()),
        }
    }

    pub fn get_default_dir(&self) -> PathBuf {
        self.default_directory.clone()
    }

    pub fn set_header_schema_url(&mut self, url: String) {
        self.header_schema_url = Some(url);
    }

    pub fn set_document_schema_url(&mut self, url: String) {
        self.document_schema_url = Some(url);
    }

    // Placeholder method for getting values as a string
    pub fn get_values_as_string(&self) -> Result<(String, Vec<String>), Box<dyn Error>> {
        // TODO: Implement the actual logic
        Ok(("".to_string(), Vec::new()))
    }

    // Placeholder method for the signing procedure
    pub fn signing_procedure(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Implement the actual logic
        Ok(())
    }

    // Placeholder method for the signature verification procedure
    pub fn signature_verification_procedure(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Implement the actual logic
        Ok(())
    }

    // Placeholder method for verifying self signature
    pub fn verify_self_signature(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Implement the actual logic
        Ok(())
    }

    pub fn load_custom_schemas(&mut self) -> Result<(), Box<dyn Error>> {
        let schemas_dir = self.default_directory.join("schemas");
        let schema_files = fs::read_dir(schemas_dir)?;

        for entry in schema_files {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let schema_json = fs::read_to_string(path)?;
                let schema_value_owned: serde_json::Value = serde_json::from_str(&schema_json)?;
                let compiled_schema =
                    JSONSchema::compile(&schema_value_owned).expect("A valid schema");
                let schema_arc = Arc::new(compiled_schema);
                let schema_key = entry.file_name().to_string_lossy().into_owned();
                self.document_schemas
                    .lock()
                    .unwrap()
                    .insert(schema_key, schema_arc);
            }
        }

        Ok(())
    }

    pub fn validate_document(&self, document: &Value) -> Result<(), Box<dyn Error>> {
        let schema_key = "default"; // This should be determined based on the document
        let schemas_lock = self.document_schemas.lock().unwrap();
        let schema = schemas_lock.get(schema_key).ok_or("Schema not found")?;
        let validation_result = schema.validate(document);
        match validation_result {
            Ok(_) => Ok(()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(format!("Document validation errors: {:?}", error_messages).into())
            }
        }
    }
}
