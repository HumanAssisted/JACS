// Allow deprecated config functions during 12-Factor migration (see task ARCH-005)
#![allow(deprecated)]

pub mod agreement;
pub mod boilerplate;
pub mod document;
pub mod loaders;
pub mod payloads;
pub mod security;

use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::crypt::hash::hash_public_key;
use crate::error::JacsError;
use crate::storage::MultiStorage;

use crate::config::{Config, find_config, load_config, load_config_12factor};

use crate::crypt::aes_encrypt::{decrypt_private_key_secure, encrypt_private_key};
use crate::crypt::private_key::ZeroizingVec;

use crate::crypt::KeyManager;

use crate::dns::bootstrap::verify_pubkey_via_dns_or_embedded;
#[cfg(feature = "observability-convenience")]
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

use crate::validation::are_valid_uuid_parts;
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

/// Decrypt a private key with automatic memory zeroization.
///
/// # Security
/// Returns a `ZeroizingVec` that will securely erase the decrypted key
/// from memory when it goes out of scope.
///
/// # Errors
/// Returns an error if decryption fails (wrong password or corrupted data).
pub fn use_secret(key: &[u8]) -> Result<ZeroizingVec, Box<dyn std::error::Error>> {
    decrypt_private_key_secure(key)
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
    /// everything needed for the agent to sign things
    id: Option<String>,
    version: Option<String>,
    public_key: Option<Vec<u8>>,
    private_key: Option<SecretPrivateKey>,
    key_algorithm: Option<String>,
    /// control DNS strictness for public key verification
    dns_strict: bool,
    /// whether DNS validation is enabled (None means derive from config/domain presence)
    dns_validate_enabled: Option<bool>,
    /// whether DNS validation is required (must have domain and successful DNS check)
    dns_required: Option<bool>,
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
        agentversion: &str,
        headerversion: &str,
        signature_version: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let schema = Schema::new(agentversion, headerversion, signature_version)?;
        let document_schemas_map = Arc::new(Mutex::new(HashMap::new()));
        let config = Some(find_config("./".to_string())?);
        Ok(Self {
            schema,
            value: None,
            config,
            storage: MultiStorage::default_new()?,
            document_schemas: document_schemas_map,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
            dns_strict: false,
            dns_validate_enabled: None,
            dns_required: None,
        })
    }

    pub fn set_dns_strict(&mut self, strict: bool) {
        self.dns_strict = strict;
    }

    pub fn set_dns_validate(&mut self, enabled: bool) {
        self.dns_validate_enabled = Some(enabled);
        if !enabled {
            self.dns_strict = false;
        }
    }
    pub fn set_dns_required(&mut self, required: bool) {
        self.dns_required = Some(required);
    }

    #[must_use = "agent loading result must be checked for errors"]
    pub fn load_by_id(&mut self, lookup_id: String) -> Result<(), Box<dyn Error>> {
        let start_time = std::time::Instant::now();

        self.config = Some(find_config("./".to_string()).map_err(|e| {
            format!(
                "load_by_id failed for agent '{}': Could not find or load configuration: {}",
                lookup_id, e
            )
        })?);
        debug!("load_by_id config {:?}", self.config);

        let agent_string = self.fs_agent_load(&lookup_id).map_err(|e| {
            format!(
                "load_by_id failed for agent '{}': Could not load agent file: {}",
                lookup_id, e
            )
        })?;
        let result: Result<(), Box<dyn Error>> = self.load(&agent_string).map_err(|e| {
            format!(
                "load_by_id failed for agent '{}': Agent validation or key loading failed: {}",
                lookup_id, e
            ).into()
        });

        let _duration_ms = start_time.elapsed().as_millis() as u64;
        let success = result.is_ok();

        #[cfg(feature = "observability-convenience")]
        {
            // Record the agent operation
            record_agent_operation("load_by_id", &lookup_id, success, duration_ms);
        }

        if success {
            info!("Successfully loaded agent by ID: {}", lookup_id);
        } else {
            error!("Failed to load agent by ID: {}", lookup_id);
        }

        result
    }

    #[must_use = "agent loading result must be checked for errors"]
    pub fn load_by_config(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        // load config string
        self.config = Some(load_config(&path).map_err(|e| {
            format!(
                "load_by_config failed: Could not load configuration from '{}': {}",
                path, e
            )
        })?);
        let config = self.config.as_ref().ok_or_else(|| {
            format!(
                "load_by_config failed: Configuration object is unexpectedly None after loading from '{}'",
                path
            )
        })?;
        // Clone values needed for error messages to avoid borrow conflicts
        let lookup_id: String = config
            .jacs_agent_id_and_version()
            .as_deref()
            .unwrap_or("")
            .to_string();
        let storage_type: String = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("")
            .to_string();
        self.storage = MultiStorage::new(storage_type.clone()).map_err(|e| {
            format!(
                "load_by_config failed: Could not initialize storage type '{}' (from config '{}'): {}",
                storage_type, path, e
            )
        })?;
        if !lookup_id.is_empty() {
            let agent_string = self.fs_agent_load(&lookup_id).map_err(|e| {
                format!(
                    "load_by_config failed: Could not load agent '{}' (specified in config '{}'): {}",
                    lookup_id, path, e
                )
            })?;
            self.load(&agent_string).map_err(|e| {
                let err_msg = format!(
                    "load_by_config failed: Agent '{}' validation or key loading failed (config '{}'): {}",
                    lookup_id, path, e
                );
                Box::<dyn Error>::from(err_msg)
            })
        } else {
            Ok(())
        }
    }

    pub fn ready(&mut self) -> bool {
        true
    }

    /// Get the agent's JSON value
    pub fn get_value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    /// Get the agent's key algorithm
    pub fn get_key_algorithm(&self) -> Option<&String> {
        self.key_algorithm.as_ref()
    }

    pub fn set_keys(
        &mut self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        key_algorithm: &str,
    ) -> Result<(), Box<dyn Error>> {
        let private_key_encrypted = encrypt_private_key(&private_key)?;
        // Box the Vec<u8> before creating SecretBox
        self.private_key = Some(SecretBox::new(Box::new(private_key_encrypted)));
        self.public_key = Some(public_key);
        self.key_algorithm = Some(key_algorithm.to_string());
        Ok(())
    }

    #[must_use = "private key must be used for signing operations"]
    pub fn get_private_key(&self) -> Result<&SecretPrivateKey, Box<dyn Error>> {
        match &self.private_key {
            Some(private_key) => Ok(private_key),
            None => {
                let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
                Err(JacsError::KeyNotFound {
                    path: format!(
                        "Private key for agent '{}': Call fs_load_keys() or fs_preload_keys() first, or ensure keys are generated during agent creation.",
                        agent_id
                    ),
                }.into())
            }
        }
    }

    #[must_use = "agent loading result must be checked for errors"]
    pub fn load(&mut self, agent_string: &str) -> Result<(), Box<dyn Error>> {
        // validate schema
        // then load
        // then load keys
        // then validate signatures
        match &self.validate_agent(agent_string) {
            Ok(value) => {
                self.value = Some(value.clone());
                if let Some(ref value) = self.value {
                    self.id = value.get_str("jacsId");
                    self.version = value.get_str("jacsVersion");
                }

                // Validate that ID and Version are valid UUIDs
                if let (Some(id), Some(version)) = (&self.id, &self.version)
                    && !are_valid_uuid_parts(id, version)
                {
                    warn!("ID and Version must be UUID");
                }
            }
            Err(e) => {
                error!("Agent validation failed: {}", e);
                return Err(JacsError::AgentError(format!(
                    "Agent load failed at schema validation step: {}. \
                    Ensure the agent JSON conforms to the JACS agent schema.",
                    e
                )).into());
            }
        }

        let agent_id_for_errors = self.id.clone().unwrap_or_else(|| "<unknown>".to_string());

        if self.id.is_some() {
            // check if keys are already loaded
            if self.public_key.is_none() || self.private_key.is_none() {
                self.fs_load_keys().map_err(|e| {
                    format!(
                        "Agent load failed for '{}' at key loading step: {}",
                        agent_id_for_errors, e
                    )
                })?;
            } else {
                info!("Keys already loaded for agent");
            }

            self.verify_self_signature().map_err(|e| {
                format!(
                    "Agent load failed for '{}' at signature verification step: {}. \
                    The agent's signature may be invalid or the keys may not match.",
                    agent_id_for_errors, e
                )
            })?;
        }

        Ok(())
    }

    #[must_use = "signature verification result must be checked"]
    pub fn verify_self_signature(&mut self) -> Result<(), Box<dyn Error>> {
        let agent_id = self.id.clone().unwrap_or_else(|| "<unknown>".to_string());
        let public_key = self.get_public_key().map_err(|e| {
            format!(
                "verify_self_signature failed for agent '{}': Could not retrieve public key: {}",
                agent_id, e
            )
        })?;
        // validate header
        let signature_key_from = &AGENT_SIGNATURE_FIELDNAME.to_string();
        match &self.value.clone() {
            Some(embedded_value) => self.signature_verification_procedure(
                embedded_value,
                None,
                signature_key_from,
                public_key,
                None,
                None,
                None,
            ).map_err(|e| {
                format!(
                    "verify_self_signature failed for agent '{}': Signature verification failed: {}",
                    agent_id, e
                ).into()
            }),
            None => {
                let error_message = format!(
                    "verify_self_signature failed for agent '{}': Agent value is not loaded. \
                    Ensure the agent is properly initialized before verifying signature.",
                    agent_id
                );
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
        signature_key_from: Option<&str>,
    ) -> Result<String, Box<dyn Error>> {
        let document = self.get_document(&document_key)?;
        let document_value = document.getvalue();
        let binding = &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string();
        let signature_key_from_final = match signature_key_from {
            Some(signature_key_from) => signature_key_from,
            None => binding,
        };
        self.get_signature_agent_id_and_version(document_value, signature_key_from_final)
    }

    fn get_signature_agent_id_and_version(
        &self,
        json_value: &Value,
        signature_key_from: &str,
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
        Ok(format!("{}:{}", agentid, agentversion))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signature_verification_procedure(
        &self,
        json_value: &Value,
        fields: Option<&[String]>,
        signature_key_from: &str,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
        original_public_key_hash: Option<String>,
        signature: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let start_time = std::time::Instant::now();

        let (document_values_string, _) = Agent::get_values_as_string(
            json_value,
            fields.map(|s| s.to_vec()),
            signature_key_from,
        )?;
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

        // DNS policy resolution
        let maybe_domain = self
            .value
            .as_ref()
            .and_then(|v| v.get("jacsAgentDomain").and_then(|x| x.as_str()))
            .map(|s| s.to_string())
            .or_else(|| {
                self.config
                    .as_ref()
                    .and_then(|c| c.jacs_agent_domain().clone())
            });

        let maybe_agent_id = json_value
            .get(signature_key_from)
            .and_then(|sig| sig.get("agentID"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Effective policy
        let domain_present = maybe_domain.is_some();
        let validate = self.dns_validate_enabled.unwrap_or(domain_present);
        let strict = self.dns_strict;
        let required = self.dns_required.unwrap_or(domain_present);

        if validate && domain_present {
            if let (Some(domain), Some(agent_id_for_dns)) =
                (maybe_domain.clone(), maybe_agent_id.clone())
            {
                // Allow embedded fallback only if not required
                let embedded = if required {
                    None
                } else {
                    Some(&public_key_hash)
                };
                if let Err(e) = verify_pubkey_via_dns_or_embedded(
                    &public_key,
                    &agent_id_for_dns,
                    Some(&domain),
                    embedded.map(|s| s.as_str()),
                    strict,
                ) {
                    error!("public key identity check failed: {}", e);
                    return Err(e.into());
                }
            } else if required {
                return Err("DNS validation failed: domain required but not configured".into());
            }
        } else {
            // DNS not validated -> rely on embedded fingerprint
            let public_key_rehash = hash_public_key(public_key.clone());
            if public_key_rehash != public_key_hash {
                let error_message = format!(
                    "Incorrect public key used to verify signature public_key_rehash {} public_key_hash {} ",
                    public_key_rehash, public_key_hash
                );
                error!("{}", error_message);

                let _duration_ms = start_time.elapsed().as_millis() as u64;
                let _algorithm = public_key_enc_type.as_deref().unwrap_or("unknown");
                #[cfg(feature = "observability-convenience")]
                {
                    record_signature_verification("unknown_agent", false, algorithm);
                }

                return Err(error_message.into());
            }
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

        let _duration_ms = start_time.elapsed().as_millis() as u64;
        let success = result.is_ok();
        let _algorithm = public_key_enc_type.as_deref().unwrap_or("unknown");
        let agent_id = json_value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_agent");

        #[cfg(feature = "observability-convenience")]
        {
            record_signature_verification(agent_id, success, algorithm);
        }

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
    ///   If `None`, system default fields will be used.
    /// * `placement_key` - A reference to a string representing the key where the signature
    ///   should be placed in the resulting JSON value.
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
        fields: Option<&[String]>,
        placement_key: &str,
    ) -> Result<Value, Box<dyn Error>> {
        debug!("placement_key:\n{}", placement_key);
        let (document_values_string, accepted_fields) =
            Agent::get_values_as_string(json_value, fields.map(|s| s.to_vec()), placement_key)?;
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

        let config = self.config.as_ref().ok_or_else(|| {
            let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
            format!(
                "signing_procedure failed for agent '{}': Agent config is not initialized. \
                Ensure the agent is properly loaded with a valid configuration.",
                agent_id
            )
        })?;
        let signing_algorithm = config.get_key_algorithm()?;

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
        self.schema.validate_signature(&signature_document)?;

        Ok(signature_document)
    }

    /// given a set of fields, return a single string
    /// this function critical to all signatures
    /// placement_key is where this signature will go, so it should not be using itself
    /// TODO warn on missing keys
    fn get_values_as_string(
        json_value: &Value,
        keys: Option<Vec<String>>,
        placement_key: &str,
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
            if let Some(value) = json_value.get(key)
                && let Some(str_value) = value.as_str()
            {
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
                result.push(' ');
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
    #[must_use = "hash verification result must be checked"]
    pub fn verify_hash(&self, doc: &Value) -> Result<bool, Box<dyn Error>> {
        let original_hash_string = doc[SHA256_FIELDNAME].as_str().unwrap_or("").to_string();
        let new_hash_string = self.hash_doc(doc)?;

        if original_hash_string != new_hash_string {
            let error_message = format!(
                "Hashes don't match for doc {:?} {:?}! {:?} != {:?}",
                doc.get_str("jacsId").unwrap_or_else(|| "unknown".to_string()),
                doc.get_str("jacsVersion").unwrap_or_else(|| "unknown".to_string()),
                original_hash_string,
                new_hash_string
            );
            error!("{}", error_message);
            return Err(error_message.into());
        }
        Ok(true)
    }

    /// verify the hash where the document is the agent itself.
    #[must_use = "hash verification result must be checked"]
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
        match self.document_schemas.lock() {
            Ok(document_schemas) => document_schemas.keys().map(|k| k.to_string()).collect(),
            Err(_) => Vec::new(), // Return empty vec if lock is poisoned
        }
    }

    /// pass in modified agent's JSON
    /// the function will replace it's internal value after:
    /// versioning
    /// resigning
    /// rehashing
    #[must_use = "updated agent JSON must be used or stored"]
    pub fn update_self(&mut self, new_agent_string: &str) -> Result<String, Box<dyn Error>> {
        let mut new_self: Value = self.schema.validate_agent(new_agent_string)?;
        let original_self = self.value.as_ref().ok_or_else(|| {
            let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
            format!(
                "update_self failed for agent '{}': Agent value is not loaded. \
                Load the agent first before attempting to update it.",
                agent_id
            )
        })?;
        let orginal_id = &original_self.get_str("jacsId");
        let orginal_version = &original_self.get_str("jacsVersion");
        // check which fields are different
        let new_doc_orginal_id = &new_self.get_str("jacsId");
        let new_doc_orginal_version = &new_self.get_str("jacsVersion");
        if (orginal_id != new_doc_orginal_id) || (orginal_version != new_doc_orginal_version) {
            return Err(JacsError::AgentError(format!(
                "The id/versions do not match for old and new agent:  . {:?}{:?}",
                new_doc_orginal_id, new_doc_orginal_version
            ))
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
            self.signing_procedure(&new_self, None, AGENT_SIGNATURE_FIELDNAME)?;
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

        Ok(value)
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

        Ok(value)
    }

    //// accepts local file system path or Urls
    #[must_use = "schema loading result must be checked for errors"]
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

    #[must_use = "save result must be checked for errors"]
    pub fn save(&self) -> Result<String, Box<dyn Error>> {
        let agent_string = self.as_string()?;
        let lookup_id = self.get_lookup_id()?;
        self.fs_agent_save(&lookup_id, &agent_string)
    }

    /// create an agent, and provde id and version as a result
    #[must_use = "created agent value must be used"]
    pub fn create_agent_and_load(
        &mut self,
        json: &str,
        create_keys: bool,
        _create_keys_algorithm: Option<&str>,
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
            self.fs_load_keys()?;
        }

        // Instead of using ID:version as the filename, we should use the public key hash
        if let (Some(public_key), Some(key_algorithm)) =
            (&self.public_key, &self.key_algorithm)
        {
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
            self.signing_procedure(&instance, None, AGENT_SIGNATURE_FIELDNAME)?;
        // write  file to disk at [jacs]/agents/
        // run as agent
        // validate the agent schema now
        let document_hash = self.hash_doc(&instance)?;
        instance[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        self.value = Some(instance.clone());
        self.verify_self_signature()?;
        Ok(instance)
    }

    /// Returns an `AgentBuilder` for constructing an `Agent` with a fluent API.
    ///
    /// # Example
    /// ```rust,ignore
    /// use jacs::agent::Agent;
    ///
    /// // Build an agent with default v1 versions
    /// let agent = Agent::builder().build()?;
    ///
    /// // Build an agent with custom configuration
    /// let agent = Agent::builder()
    ///     .config_path("path/to/jacs.config.json")
    ///     .dns_strict(true)
    ///     .build()?;
    ///
    /// // Build an agent with explicit versions
    /// let agent = Agent::builder()
    ///     .agent_version("v1")
    ///     .header_version("v1")
    ///     .signature_version("v1")
    ///     .build()?;
    /// ```
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    /// Verifies multiple signatures in a batch operation.
    ///
    /// This method processes each verification sequentially. For CPU-bound signature
    /// verification, this is often efficient due to the cryptographic operations
    /// being compute-intensive. If parallel verification is needed, consider using
    /// rayon's `par_iter()` on the input slice externally.
    ///
    /// # Arguments
    ///
    /// * `items` - A slice of tuples containing:
    ///   - `data`: The string data that was signed
    ///   - `signature`: The base64-encoded signature
    ///   - `public_key`: The public key bytes for verification
    ///   - `algorithm`: Optional algorithm hint (e.g., "ring-Ed25519", "RSA-PSS")
    ///
    /// # Returns
    ///
    /// A vector of `Result<(), JacsError>` in the same order as the input items.
    /// - `Ok(())` indicates the signature is valid
    /// - `Err(JacsError)` indicates verification failed with a specific reason
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::agent::Agent;
    ///
    /// let agent = Agent::builder().build()?;
    ///
    /// let items = vec![
    ///     ("message1".to_string(), sig1, pk1.clone(), None),
    ///     ("message2".to_string(), sig2, pk2.clone(), Some("ring-Ed25519".to_string())),
    /// ];
    ///
    /// let results = agent.verify_batch(&items);
    /// for (i, result) in results.iter().enumerate() {
    ///     match result {
    ///         Ok(()) => println!("Item {} verified successfully", i),
    ///         Err(e) => println!("Item {} failed: {}", i, e),
    ///     }
    /// }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - Verification is sequential; for parallel verification, use rayon externally
    /// - Each verification is independent and does not short-circuit on failure
    /// - The method returns all results even if some verifications fail
    #[must_use]
    pub fn verify_batch(
        &self,
        items: &[(String, String, Vec<u8>, Option<String>)],
    ) -> Vec<Result<(), JacsError>> {
        items
            .iter()
            .map(|(data, signature, public_key, algorithm)| {
                self.verify_string(data, signature, public_key.clone(), algorithm.clone())
                    .map_err(|e| JacsError::SignatureVerificationFailed {
                        reason: e.to_string(),
                    })
            })
            .collect()
    }
}

/// A builder for constructing `Agent` instances with a fluent API.
///
/// This provides a more ergonomic way to create agents compared to calling
/// `Agent::new()` directly, with sensible defaults for common use cases.
///
/// # Defaults
/// - `agent_version`: "v1"
/// - `header_version`: "v1"
/// - `signature_version`: "v1"
/// - `dns_strict`: false
/// - `dns_validate`: None (derived from config/domain presence)
/// - `dns_required`: None (derived from config/domain presence)
///
/// # Example
/// ```rust,ignore
/// use jacs::agent::AgentBuilder;
///
/// // Simplest usage - all defaults
/// let agent = AgentBuilder::new().build()?;
///
/// // With config file
/// let agent = AgentBuilder::new()
///     .config_path("/path/to/config.json")
///     .build()?;
///
/// // With inline config
/// let config = Config::with_defaults();
/// let agent = AgentBuilder::new()
///     .config(config)
///     .build()?;
/// ```
#[derive(Debug, Default)]
pub struct AgentBuilder {
    agent_version: Option<String>,
    header_version: Option<String>,
    signature_version: Option<String>,
    config_path: Option<String>,
    config: Option<Config>,
    dns_strict: Option<bool>,
    dns_validate: Option<bool>,
    dns_required: Option<bool>,
}

impl AgentBuilder {
    /// Creates a new `AgentBuilder` with default values.
    ///
    /// Default versions are all "v1".
    pub fn new() -> Self {
        Self {
            agent_version: None,
            header_version: None,
            signature_version: None,
            config_path: None,
            config: None,
            dns_strict: None,
            dns_validate: None,
            dns_required: None,
        }
    }

    /// Sets the agent schema version (default: "v1").
    pub fn agent_version(mut self, version: &str) -> Self {
        self.agent_version = Some(version.to_string());
        self
    }

    /// Sets the header schema version (default: "v1").
    pub fn header_version(mut self, version: &str) -> Self {
        self.header_version = Some(version.to_string());
        self
    }

    /// Sets the signature schema version (default: "v1").
    pub fn signature_version(mut self, version: &str) -> Self {
        self.signature_version = Some(version.to_string());
        self
    }

    /// Sets all schema versions at once (agent, header, signature).
    ///
    /// This is a convenience method for setting all versions to the same value.
    pub fn all_versions(mut self, version: &str) -> Self {
        self.agent_version = Some(version.to_string());
        self.header_version = Some(version.to_string());
        self.signature_version = Some(version.to_string());
        self
    }

    /// Sets the path to a JACS config file to load.
    ///
    /// If set, the config will be loaded from this path during `build()`.
    /// This takes precedence over any config set via `config()`.
    ///
    /// # Example
    /// ```rust,ignore
    /// let agent = Agent::builder()
    ///     .config_path("./jacs.config.json")
    ///     .build()?;
    /// ```
    pub fn config_path(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    /// Sets a pre-built config directly.
    ///
    /// Note: If `config_path()` is also set, the path takes precedence
    /// and this config will be ignored.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = Config::with_defaults();
    /// let agent = Agent::builder()
    ///     .config(config)
    ///     .build()?;
    /// ```
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets whether DNS validation should be strict.
    ///
    /// When strict, DNS verification must succeed (no fallback to embedded fingerprint).
    pub fn dns_strict(mut self, strict: bool) -> Self {
        self.dns_strict = Some(strict);
        self
    }

    /// Sets whether DNS validation is enabled.
    ///
    /// If None, DNS validation is derived from config/domain presence.
    pub fn dns_validate(mut self, enabled: bool) -> Self {
        self.dns_validate = Some(enabled);
        self
    }

    /// Sets whether DNS validation is required.
    ///
    /// When required, the agent must have a domain and DNS validation must succeed.
    pub fn dns_required(mut self, required: bool) -> Self {
        self.dns_required = Some(required);
        self
    }

    /// Builds the `Agent` with the configured options.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Schema initialization fails
    /// - Config file loading fails (if `config_path` was set)
    /// - Storage initialization fails
    ///
    /// # Example
    /// ```rust,ignore
    /// let agent = Agent::builder()
    ///     .config_path("./jacs.config.json")
    ///     .dns_strict(true)
    ///     .build()?;
    /// ```
    #[must_use = "agent build result must be checked for errors"]
    pub fn build(self) -> Result<Agent, JacsError> {
        // Use defaults if not specified
        let agent_version = self.agent_version.unwrap_or_else(|| "v1".to_string());
        let header_version = self.header_version.unwrap_or_else(|| "v1".to_string());
        let signature_version = self.signature_version.unwrap_or_else(|| "v1".to_string());

        // Initialize schema
        let schema = Schema::new(&agent_version, &header_version, &signature_version)
            .map_err(|e| JacsError::SchemaError(format!("Failed to initialize schema: {}", e)))?;

        // Load config
        let config = if let Some(path) = self.config_path {
            // Load from path using 12-Factor compliant loading
            Some(load_config_12factor(Some(&path)).map_err(|e| {
                JacsError::ConfigError(format!("Failed to load config from '{}': {}", path, e))
            })?)
        } else if let Some(cfg) = self.config {
            // Use provided config
            Some(cfg)
        } else {
            // Use 12-Factor loading with defaults + env vars
            Some(load_config_12factor(None).map_err(|e| {
                JacsError::ConfigError(format!("Failed to load default config: {}", e))
            })?)
        };

        // Initialize storage
        let storage = MultiStorage::default_new().map_err(|e| {
            JacsError::ConfigError(format!("Failed to initialize storage: {}", e))
        })?;

        let document_schemas = Arc::new(Mutex::new(HashMap::new()));

        // Create the agent
        let mut agent = Agent {
            schema,
            value: None,
            config,
            storage,
            document_schemas,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
            dns_strict: self.dns_strict.unwrap_or(false),
            dns_validate_enabled: self.dns_validate,
            dns_required: self.dns_required,
        };

        // Apply DNS settings if specified
        if let Some(strict) = self.dns_strict {
            agent.set_dns_strict(strict);
        }
        if let Some(validate) = self.dns_validate {
            agent.set_dns_validate(validate);
        }
        if let Some(required) = self.dns_required {
            agent.set_dns_required(required);
        }

        Ok(agent)
    }

    /// Builds an `Agent` and loads it from the specified agent ID.
    ///
    /// This is a convenience method that combines `build()` with `load_by_id()`.
    ///
    /// # Arguments
    /// * `agent_id` - The agent ID in format "uuid:version_uuid"
    ///
    /// # Example
    /// ```rust,ignore
    /// let agent = Agent::builder()
    ///     .config_path("./jacs.config.json")
    ///     .build_and_load("123e4567-e89b-12d3-a456-426614174000:123e4567-e89b-12d3-a456-426614174001")?;
    /// ```
    #[must_use = "agent build and load result must be checked for errors"]
    pub fn build_and_load(self, agent_id: &str) -> Result<Agent, JacsError> {
        let mut agent = self.build()?;
        agent.load_by_id(agent_id.to_string()).map_err(|e| {
            JacsError::AgentError(format!("Failed to load agent '{}': {}", agent_id, e))
        })?;
        Ok(agent)
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;

    #[test]
    fn test_agent_builder_default_values() {
        // Build an agent with all defaults
        let agent = Agent::builder().build().expect("Should build with defaults");

        // Verify the agent was created (not loaded, so no value)
        assert!(agent.get_value().is_none());
        // Config should be loaded
        assert!(agent.config.is_some());
    }

    #[test]
    fn test_agent_builder_new_equals_default() {
        // AgentBuilder::new() and AgentBuilder::default() should produce equivalent builders
        let builder_new = AgentBuilder::new();
        let builder_default = AgentBuilder::default();

        // Both should have None for all fields
        assert!(builder_new.agent_version.is_none());
        assert!(builder_new.header_version.is_none());
        assert!(builder_new.signature_version.is_none());
        assert!(builder_new.config_path.is_none());
        assert!(builder_new.config.is_none());
        assert!(builder_new.dns_strict.is_none());
        assert!(builder_new.dns_validate.is_none());
        assert!(builder_new.dns_required.is_none());

        assert!(builder_default.agent_version.is_none());
        assert!(builder_default.header_version.is_none());
        assert!(builder_default.signature_version.is_none());
        assert!(builder_default.config_path.is_none());
        assert!(builder_default.config.is_none());
        assert!(builder_default.dns_strict.is_none());
        assert!(builder_default.dns_validate.is_none());
        assert!(builder_default.dns_required.is_none());
    }

    #[test]
    fn test_agent_builder_custom_versions() {
        // Build an agent with custom versions
        let agent = Agent::builder()
            .agent_version("v1")
            .header_version("v1")
            .signature_version("v1")
            .build()
            .expect("Should build with custom versions");

        // Verify the agent was created
        assert!(agent.config.is_some());
    }

    #[test]
    fn test_agent_builder_all_versions() {
        // Test the all_versions convenience method
        let builder = AgentBuilder::new().all_versions("v1");

        assert_eq!(builder.agent_version, Some("v1".to_string()));
        assert_eq!(builder.header_version, Some("v1".to_string()));
        assert_eq!(builder.signature_version, Some("v1".to_string()));
    }

    #[test]
    fn test_agent_builder_dns_settings() {
        // Build an agent with DNS settings
        let agent = Agent::builder()
            .dns_strict(true)
            .dns_validate(true)
            .dns_required(false)
            .build()
            .expect("Should build with DNS settings");

        // Verify DNS settings were applied
        assert!(agent.dns_strict);
        assert_eq!(agent.dns_validate_enabled, Some(true));
        assert_eq!(agent.dns_required, Some(false));
    }

    #[test]
    fn test_agent_builder_with_config() {
        // Build an agent with a direct config
        let config = Config::with_defaults();
        let agent = Agent::builder()
            .config(config)
            .build()
            .expect("Should build with config");

        // Verify config was used
        assert!(agent.config.is_some());
    }

    #[test]
    fn test_agent_builder_fluent_api() {
        // Verify the fluent API returns Self at each step
        let agent = Agent::builder()
            .agent_version("v1")
            .header_version("v1")
            .signature_version("v1")
            .dns_strict(false)
            .dns_validate(true)
            .build()
            .expect("Should build with fluent API");

        assert!(agent.config.is_some());
    }

    #[test]
    fn test_agent_builder_method_exists() {
        // Verify Agent::builder() returns an AgentBuilder
        let builder = Agent::builder();
        assert!(builder.agent_version.is_none());
    }

    #[test]
    fn test_agent_builder_config_path_invalid() {
        // Build with an invalid config path should fail
        let result = Agent::builder()
            .config_path("/nonexistent/path/to/config.json")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("config"));
    }

    #[test]
    fn test_verify_batch_empty_input() {
        // Test that verify_batch handles empty input gracefully
        let agent = Agent::builder().build().expect("Should build with defaults");
        let items: Vec<(String, String, Vec<u8>, Option<String>)> = vec![];
        let results = agent.verify_batch(&items);
        assert!(results.is_empty());
    }

    #[test]
    fn test_verify_batch_returns_correct_count() {
        // Test that verify_batch returns one result per input item
        let agent = Agent::builder().build().expect("Should build with defaults");

        // Create invalid items (they will fail verification, but we are testing the count)
        let items: Vec<(String, String, Vec<u8>, Option<String>)> = vec![
            ("data1".to_string(), "invalid_sig".to_string(), vec![1, 2, 3], None),
            ("data2".to_string(), "invalid_sig".to_string(), vec![4, 5, 6], None),
            ("data3".to_string(), "invalid_sig".to_string(), vec![7, 8, 9], None),
        ];

        let results = agent.verify_batch(&items);
        assert_eq!(results.len(), 3);

        // All should fail since these are invalid signatures
        for result in &results {
            assert!(result.is_err());
        }
    }
}
