use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::security::SecurityTraits;
use crate::crypt::aes_encrypt::{decrypt_private_key_secure, encrypt_private_key};
use crate::error::JacsError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::Compression;
use flate2::write::GzEncoder;
use secrecy::ExposeSecret;

use crate::storage::jenv::get_env_var;
use crate::time_utils;
use std::error::Error;
use std::io::Write;
use std::path::Path;
use tracing::{debug, error, info, warn};

/// This environment variable determine if files are saved to the filesystem at all
/// if you are building something that passing data through to a database, you'd set this flag to 0 or False
///
/// The goal of fileloader is to prevent fileloading into arbitrary directories
/// by centralizing all filesystem access
/// Only an initilaized agent can perform some of the functions by calling isready()
/// as an attempt to ensure actions on the filesystem requiring
/// the agent are acted out by the agent
pub trait FileLoader {
    // utils

    fn fs_docs_load_all(&mut self) -> Result<Vec<String>, Vec<Box<dyn Error>>>;
    fn fs_agent_load(&self, agentid: &str) -> Result<String, Box<dyn Error>>;
    // fn fs_agent_new(&self, filename: &String) -> Result<String, Box<dyn Error>>;
    // fn fs_document_new(&self, filename: &String) -> Result<String, Box<dyn Error>>;
    // fn fs_document_load(&self, document_id: &String) -> Result<String, Box<dyn Error>>;
    fn fs_preload_keys(
        &mut self,
        private_key_filename: &str,
        public_key_filename: &str,
        custom_key_algorithm: Option<String>,
    ) -> Result<(), Box<dyn Error>>;
    fn fs_save_keys(&mut self) -> Result<(), Box<dyn Error>>;
    fn fs_load_keys(&mut self) -> Result<(), Box<dyn Error>>;

    // save
    // fn fs_docs_save_all(&mut self) -> Result<Vec<String>, Box<dyn Error>>;
    fn fs_agent_save(&self, agentid: &str, agent_string: &str) -> Result<String, Box<dyn Error>>;
    fn fs_document_save(
        &self,
        document_id: &str,
        document_string: &str,
        output_filename: Option<String>,
    ) -> Result<String, Box<dyn Error>>;

    fn fs_document_archive(&self, lookup_key: &str) -> Result<(), Box<dyn Error>>;
    fn load_public_key_file(&self, filename: &str) -> Result<Vec<u8>, Box<dyn Error>>;
    fn load_private_key(&self, filename: &str) -> Result<Vec<u8>, Box<dyn Error>>;
    fn save_private_key(
        &self,
        filename: &str,
        private_key: &[u8],
    ) -> Result<String, Box<dyn Error>>;
    fn create_backup(&self, file_path: &str) -> Result<String, Box<dyn Error>>;
    /// used to get base64 content from a filepath
    fn fs_get_document_content(&self, document_filepath: String) -> Result<String, Box<dyn Error>>;
    fn fs_load_public_key(&self, hash: &str) -> Result<Vec<u8>, Box<dyn Error>>;
    fn use_filesystem(&self) -> bool;
    fn fs_load_public_key_type(&self, agent_id_and_version: &str)
    -> Result<String, Box<dyn Error>>;
    fn fs_save_remote_public_key(
        &self,
        agent_id_and_version: &str,
        public_key: &[u8],
        public_key_enc_type: &[u8],
    ) -> Result<(), Box<dyn Error>>;
    fn make_data_directory_path(&self, filename: &str) -> Result<String, Box<dyn Error>>;
    fn make_key_directory_path(&self, filename: &str) -> Result<String, Box<dyn Error>>;
}

#[cfg(not(target_arch = "wasm32"))]
impl FileLoader for Agent {
    fn use_filesystem(&self) -> bool {
        // Handle Option<Config> and Option<String> from getter
        self.config
            .as_ref()
            .is_some_and(|conf| conf.jacs_default_storage().as_deref() == Some("fs"))
    }

    fn fs_save_keys(&mut self) -> Result<(), Box<dyn Error>> {
        // Get private key filename: ONLY from config
        let private_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| {
                "fs_save_keys failed: Agent config is missing. Ensure the agent is initialized with a valid configuration before saving keys.".to_string()
            })?
            .jacs_agent_private_key_filename()
            .as_deref()
            .ok_or_else(|| {
                "fs_save_keys failed: 'jacs_agent_private_key_filename' not found in config. Add this field to your jacs.config.json or set JACS_AGENT_PRIVATE_KEY_FILENAME environment variable.".to_string()
            })?
            .to_string();

        // Get public key filename: ONLY from config
        let public_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| {
                "fs_save_keys failed: Agent config is missing. Ensure the agent is initialized with a valid configuration before saving keys.".to_string()
            })?
            .jacs_agent_public_key_filename()
            .as_deref()
            .ok_or_else(|| {
                "fs_save_keys failed: 'jacs_agent_public_key_filename' not found in config. Add this field to your jacs.config.json or set JACS_AGENT_PUBLIC_KEY_FILENAME environment variable.".to_string()
            })?
            .to_string();

        let absolute_public_key_path = self.make_key_directory_path(&public_key_filename)?;
        let absolute_private_key_path = self.make_key_directory_path(&private_key_filename)?;

        let binding = self.get_private_key()?;
        let borrowed_key = binding.expose_secret();
        // Use secure decryption - ZeroizingVec will be zeroized when it goes out of scope
        let key_vec = decrypt_private_key_secure(borrowed_key)?;

        self.save_private_key(&absolute_private_key_path, key_vec.as_slice())?;

        self.storage
            .save_file(&absolute_public_key_path, &self.get_public_key()?)?;

        Ok(())
    }

    fn fs_load_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let private_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| {
                "fs_load_keys failed: Agent config is missing. Ensure agent is initialized with a valid configuration before loading keys.".to_string()
            })?
            .jacs_agent_private_key_filename()
            .as_deref()
            .ok_or_else(|| {
                "fs_load_keys failed: 'jacs_agent_private_key_filename' not found in config. Add this field to your jacs.config.json or set JACS_AGENT_PRIVATE_KEY_FILENAME environment variable.".to_string()
            })?
            .to_string();

        // Get public key filename: ONLY from config
        let public_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| {
                "fs_load_keys failed: Agent config is missing during public key filename lookup.".to_string()
            })?
            .jacs_agent_public_key_filename()
            .as_deref()
            .ok_or_else(|| {
                "fs_load_keys failed: 'jacs_agent_public_key_filename' not found in config. Add this field to your jacs.config.json or set JACS_AGENT_PUBLIC_KEY_FILENAME environment variable.".to_string()
            })?
            .to_string();

        let private_key = self.load_private_key(&private_key_filename).map_err(|e| {
            format!(
                "fs_load_keys failed: Could not load private key from file '{}': {}",
                private_key_filename, e
            )
        })?;
        let agents_public_key = self.load_private_key(&public_key_filename).map_err(|e| {
            format!(
                "fs_load_keys failed: Could not load public key from file '{}': {}",
                public_key_filename, e
            )
        })?;

        let key_algorithm = self
            .config
            .as_ref()
            .ok_or_else(|| {
                "fs_load_keys failed: Agent config is missing during key algorithm lookup.".to_string()
            })?
            .jacs_agent_key_algorithm()
            .as_deref()
            .ok_or_else(|| {
                "fs_load_keys failed: 'jacs_agent_key_algorithm' not found in config. Add this field to your jacs.config.json or set JACS_AGENT_KEY_ALGORITHM environment variable.".to_string()
            })?
            .to_string();

        self.set_keys(private_key, agents_public_key, &key_algorithm).map_err(|e| {
            format!(
                "fs_load_keys failed: Could not set keys with algorithm '{}': {}",
                key_algorithm, e
            )
        })?;

        Ok(())
    }

    /// in JACS the public keys need to be added manually
    fn fs_load_public_key(&self, hash: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let public_key_path = format!("public_keys/{}.pem", hash);
        let absolute_public_key_path = self.make_data_directory_path(&public_key_path)?;
        self.storage
            .get_file(&absolute_public_key_path, None)
            .map_err(|e| {
                format!(
                    "fs_load_public_key failed: Could not load public key for hash '{}' from path '{}': {}",
                    hash, absolute_public_key_path, e
                ).into()
            })
    }

    fn fs_load_public_key_type(&self, hash: &str) -> Result<String, Box<dyn Error>> {
        let public_key_path = format!("public_keys/{}.enc_type", hash);
        let absolute_public_key_path = self.make_data_directory_path(&public_key_path)?;
        let bytes = self.storage.get_file(&absolute_public_key_path, None).map_err(|e| {
            format!(
                "fs_load_public_key_type failed: Could not load encryption type for hash '{}' from path '{}': {}",
                hash, absolute_public_key_path, e
            )
        })?;
        String::from_utf8(bytes).map_err(|e| {
            format!(
                "fs_load_public_key_type failed: Encryption type file for hash '{}' contains invalid UTF-8: {}",
                hash, e
            ).into()
        })
    }

    /// in JACS the public keys need to be added manually
    fn fs_save_remote_public_key(
        &self,
        agent_id_and_version: &str,
        public_key: &[u8],
        public_key_enc_type: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let public_key_path = format!("public_keys/{}.pem", agent_id_and_version);
        let enc_type_path = format!("public_keys/{}.enc_type", agent_id_and_version);
        let absolute_public_key_path = self.make_data_directory_path(&public_key_path)?;
        let absolute_enc_type_path = self.make_data_directory_path(&enc_type_path)?;
        self.storage
            .save_file(&absolute_public_key_path, public_key)?;
        self.storage
            .save_file(&absolute_enc_type_path, public_key_enc_type)?;

        Ok(())
    }

    /// a way to load keys that aren't default
    fn fs_preload_keys(
        &mut self,
        private_key_filename: &str,
        public_key_filename: &str,
        custom_key_algorithm: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let private_path = self.make_key_directory_path(private_key_filename).map_err(|e| {
            format!(
                "fs_preload_keys failed: Could not construct path for private key file '{}': {}",
                private_key_filename, e
            )
        })?;
        let public_path = self.make_key_directory_path(public_key_filename).map_err(|e| {
            format!(
                "fs_preload_keys failed: Could not construct path for public key file '{}': {}",
                public_key_filename, e
            )
        })?;

        let private_key = self.storage.get_file(&private_path, None).map_err(|e| {
            format!(
                "fs_preload_keys failed: Could not read private key from '{}': {}",
                private_path, e
            )
        })?;
        let public_key = self.storage.get_file(&public_path, None).map_err(|e| {
            format!(
                "fs_preload_keys failed: Could not read public key from '{}': {}",
                public_path, e
            )
        })?;

        // Determine the key algorithm with priority: custom -> config -> env var
        let key_algorithm = if let Some(algo) = custom_key_algorithm {
            // 1. Use custom_key_algorithm if provided
            algo
        } else {
            // 2. If no custom algo, try config
            self.config
                .as_ref()
                .ok_or_else(|| {
                    "fs_preload_keys failed: No custom_key_algorithm provided and agent config is missing. \
                        Provide a key algorithm or ensure the agent has a valid configuration.".to_string()
                })?
                .get_key_algorithm()
                .map_err(|e| {
                    format!(
                        "fs_preload_keys failed: Could not determine key algorithm from config: {}",
                        e
                    )
                })?
        };

        self.set_keys(private_key, public_key, &key_algorithm).map_err(|e| {
            format!(
                "fs_preload_keys failed: Could not set keys (private='{}', public='{}', algorithm='{}'): {}",
                private_key_filename, public_key_filename, key_algorithm, e
            )
        })?;

        Ok(())
    }

    /// function used to load all documents present
    fn fs_docs_load_all(&mut self) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
        let mut errors: Vec<Box<dyn Error>> = Vec::new();
        let mut documents: Vec<String> = Vec::new();

        // Handle Result from make_data_directory_path manually
        let agent_path = match self.make_data_directory_path("agent") {
            Ok(path) => path,
            Err(e) => {
                errors.push(e);
                // Cannot proceed without the agent path, return collected errors
                return Err(errors);
            }
        };
        let documents_path = match self.make_data_directory_path("documents") {
            Ok(path) => path,
            Err(e) => {
                errors.push(e);
                // Cannot proceed without the documents path, return collected errors
                return Err(errors);
            }
        };

        let paths = vec![agent_path, documents_path];

        for prefix in paths {
            match self.storage.list(&prefix, None) {
                Ok(files) => {
                    for file_path in files {
                        match self.storage.get_file(&file_path, None) {
                            Ok(contents) => match String::from_utf8(contents) {
                                Ok(doc) => documents.push(doc),
                                Err(e) => errors.push(Box::new(e)),
                            },
                            Err(e) => errors.push(Box::new(e)),
                        }
                    }
                }
                Err(e) => errors.push(Box::new(e)),
            }
        }

        if !errors.is_empty() {
            error!("errors loading documents {:?}", errors);
            Err(errors)
        } else {
            Ok(documents)
        }
    }

    fn fs_agent_load(&self, agentid: &str) -> Result<String, Box<dyn Error>> {
        // Expects logical agentid (no .json)
        info!("[fs_agent_load] Loading using agent ID: {}", agentid);

        // Construct the relative path for storage lookup
        let relative_path = format!("agent/{}.json", agentid);
        info!(
            "[fs_agent_load] Attempting to get file from relative path: {}",
            relative_path
        );

        let absolute_path = self.make_data_directory_path(&relative_path).map_err(|e| {
            format!(
                "fs_agent_load failed for agent '{}': Could not construct data directory path for '{}': {}",
                agentid, relative_path, e
            )
        })?;
        let contents = self.storage.get_file(&absolute_path, None).map_err(|e| {
            error!(
                "[fs_agent_load] Failed to get file from path '{}': {}",
                absolute_path, e
            );
            format!(
                "fs_agent_load failed for agent '{}': Could not read agent file from '{}': {}. \
                Ensure the agent file exists and the data directory is correctly configured.",
                agentid, absolute_path, e
            )
        })?;

        info!("[fs_agent_load] Successfully loaded file content.");
        String::from_utf8(contents).map_err(|e| {
            format!(
                "fs_agent_load failed for agent '{}': Agent file at '{}' contains invalid UTF-8: {}",
                agentid, absolute_path, e
            ).into()
        })
    }

    fn fs_agent_save(&self, agentid: &str, agent_string: &str) -> Result<String, Box<dyn Error>> {
        info!("[fs_agent_save] Starting save for agent ID: {}", agentid);

        // Construct the relative path for storage operations
        let relative_path_str = format!("agent/{}.json", agentid);
        let absolute_path_str = self.make_data_directory_path(&relative_path_str)?;
        info!(
            "[fs_agent_save] Calculated relative path for storage ops: {}",
            absolute_path_str
        );

        match self.storage.file_exists(&absolute_path_str, None) {
            Ok(true) => {
                // Construct relative backup path
                let relative_backup_path = format!("{}.bak", absolute_path_str);
                let absolute_backup_path = self.make_data_directory_path(&relative_backup_path)?;
                warn!(
                    "[fs_agent_save] Agent file exists (relative path), backing up to: {}",
                    absolute_backup_path
                );
                match self
                    .storage
                    .rename_file(&absolute_path_str, &absolute_backup_path)
                {
                    Ok(_) => info!("[fs_agent_save] Backup successful (using relative paths)."),
                    Err(e) => {
                        error!(
                            "[fs_agent_save] Backup rename failed (relative paths): {}. Continuing save attempt.",
                            e
                        );
                    }
                }
            }
            Ok(false) => {
                info!("[fs_agent_save] No existing file found at relative path. No backup needed.");
            }
            Err(e) => {
                error!(
                    "[fs_agent_save] Error checking file existence for backup (relative path): {}. Continuing save attempt.",
                    e
                );
            }
        }

        // Actual save operation using RELATIVE path
        info!(
            "[fs_agent_save] Calling storage.save_file with relative path: {}",
            absolute_path_str
        );
        self.storage
            .save_file(&absolute_path_str, agent_string.as_bytes())
            .map_err(|e| {
                error!(
                    "[fs_agent_save] storage.save_file failed (relative path): {}",
                    e
                );
                Box::new(e) as Box<dyn Error>
            })?;

        info!(
            "[fs_agent_save] Save successful. Returning absolute path: {}",
            absolute_path_str
        );
        Ok(absolute_path_str)
    }

    fn fs_document_archive(&self, lookup_key: &str) -> Result<(), Box<dyn Error>> {
        let document_filename = format!("{}.json", lookup_key);
        let old_path = format!("documents/{}", document_filename);
        let new_path = format!("documents/archive/{}", document_filename);
        let old_document_path = self.make_data_directory_path(&old_path)?;
        let new_document_path = self.make_data_directory_path(&new_path)?;

        let contents = self.storage.get_file(&old_document_path, None)?;
        self.storage.save_file(&new_document_path, &contents)?;
        Ok(())
    }

    fn fs_document_save(
        &self,
        document_id: &str,
        document_string: &str,
        output_filename: Option<String>,
    ) -> Result<String, Box<dyn Error>> {
        if let Err(e) = self.check_data_directory() {
            error!("Failed to check data directory: {}", e);
        }

        let documentoutput_filename = match output_filename {
            Some(filename) => filename,
            _ => document_id.to_string(),
        };

        let document_path = self.make_data_directory_path(&documentoutput_filename)?;

        // Use MultiStorage to save the file
        self.storage
            .save_file(&document_path, document_string.as_bytes())?;

        Ok(document_path)
    }

    fn fs_get_document_content(&self, document_filepath: String) -> Result<String, Box<dyn Error>> {
        let contents = self.storage.get_file(&document_filepath, None)?;

        // Compress the contents using gzip
        let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gz_encoder.write_all(&contents)?;
        let compressed_contents = gz_encoder.finish()?;

        // Encode the compressed contents using the standard base64 engine
        Ok(STANDARD.encode(&compressed_contents))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn load_public_key_file(&self, filename: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        self.storage
            .get_file(filename, None)
            .map_err(|e| {
                let suggestion = if e.to_string().contains("not found") || e.to_string().contains("NotFound") {
                    " Ensure the key file exists or run key generation first."
                } else if e.to_string().contains("permission") || e.to_string().contains("Permission") {
                    " Check file permissions - the key file may not be readable by the current user."
                } else {
                    ""
                };
                format!(
                    "Failed to read key file '{}': {}.{}",
                    filename, e, suggestion
                ).into()
            })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn load_private_key(&self, filename: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let filepath = self.make_key_directory_path(filename).map_err(|e| {
            format!(
                "load_private_key failed: Could not construct key directory path for '{}': {}",
                filename, e
            )
        })?;
        let loaded_key = self.load_public_key_file(&filepath).map_err(|e| {
            format!(
                "load_private_key failed: Could not read key file at '{}': {}",
                filepath, e
            )
        })?;
        if filename.ends_with(".enc") {
            // Use secure decryption - the ZeroizingVec will be zeroized after we extract the bytes
            let decrypted = decrypt_private_key_secure(&loaded_key).map_err(|e| {
                format!(
                    "Failed to decrypt private key from '{}': {}. \
                    Verify that JACS_PRIVATE_KEY_PASSWORD is set to the correct password used during key generation.",
                    filepath, e
                )
            })?;
            // Clone the bytes out - the ZeroizingVec will be zeroized when dropped
            // Note: The caller (set_keys) will immediately re-encrypt this
            Ok(decrypted.as_slice().to_vec())
        } else {
            Ok(loaded_key)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn save_private_key(
        &self,
        full_filepath: &str,
        private_key: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        let password = get_env_var("JACS_PRIVATE_KEY_PASSWORD", false)
            .unwrap_or(None)
            .unwrap_or_default();

        if !password.is_empty() {
            let encrypted_key = encrypt_private_key(private_key)?;
            let final_path = if !full_filepath.ends_with(".enc") {
                format!("{}.enc", full_filepath)
            } else {
                full_filepath.to_string()
            };
            self.storage.save_file(&final_path, &encrypted_key)?;
            Ok(final_path)
        } else {
            self.storage.save_file(full_filepath, private_key)?;
            Ok(full_filepath.to_string())
        }
    }
    /// private Helper function to create a backup file name based on the current timestamp
    #[cfg(not(target_arch = "wasm32"))]
    fn create_backup(&self, file_path: &str) -> Result<String, Box<dyn Error>> {
        let timestamp = time_utils::backup_timestamp_suffix();

        // Split the path into directory and filename
        let path = Path::new(file_path);
        let file_stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| Box::new(std::io::Error::other("Failed to read file stem")))?;
        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

        // Create the backup path
        let backup_filename = format!("{}.{}.{}", timestamp, file_stem, extension);
        let parent = path.parent().and_then(|p| p.to_str()).unwrap_or("");
        let backup_path = format!("{}/{}", parent, backup_filename);

        // Copy the file using MultiStorage
        let contents = self.storage.get_file(file_path, None)?;
        self.storage.save_file(&backup_path, &contents)?;
        debug!("Backup path: {}", backup_path);
        Ok(backup_path)
    }

    fn make_data_directory_path(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        info!("config!: {:?}", self.config);
        // Fail if config or specific directory is missing
        let mut data_dir = self
            .config
            .as_ref()
            .ok_or_else(|| {
                format!(
                    "make_data_directory_path failed for '{}': Agent config is missing. \
                    Ensure the agent is initialized with a valid configuration.",
                    filename
                )
            })?
            .jacs_data_directory()
            .as_deref()
            .ok_or_else(|| {
                format!(
                    "make_data_directory_path failed for '{}': 'jacs_data_directory' not found in config. \
                    Add this field to your jacs.config.json or set JACS_DATA_DIRECTORY environment variable.",
                    filename
                )
            })?;
        data_dir = data_dir.strip_prefix("./").unwrap_or(data_dir);
        debug!("data_dir {} filename {}", data_dir, filename);
        let path = format!("{}/{}", data_dir, filename);
        debug!("Data directory path: {}", path);
        Ok(path)
    }
    fn make_key_directory_path(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        // Fail if config or specific directory is missing
        let mut key_dir = self
            .config
            .as_ref()
            .ok_or_else(|| {
                format!(
                    "make_key_directory_path failed for '{}': Agent config is missing. \
                    Ensure the agent is initialized with a valid configuration.",
                    filename
                )
            })?
            .jacs_key_directory()
            .as_deref()
            .ok_or_else(|| {
                format!(
                    "make_key_directory_path failed for '{}': 'jacs_key_directory' not found in config. \
                    Add this field to your jacs.config.json or set JACS_KEY_DIRECTORY environment variable.",
                    filename
                )
            })?;
        key_dir = key_dir.strip_prefix("./").unwrap_or(key_dir);
        let path = format!("{}/{}", key_dir, filename);
        debug!("Key directory path: {}", path);
        Ok(path)
    }
}

/// Public key information retrieved from HAI key service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// The raw public key bytes.
    pub public_key: Vec<u8>,
    /// The cryptographic algorithm (e.g., "ed25519", "rsa-pss-sha256").
    pub algorithm: String,
    /// The hash of the public key for verification.
    pub hash: String,
}

/// Response structure from the HAI keys API.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, serde::Deserialize)]
struct HaiKeysApiResponse {
    /// Public key in either PEM or Base64 format.
    public_key: String,
    /// The cryptographic algorithm used.
    algorithm: String,
    /// Hash of the public key.
    public_key_hash: String,
}

/// Decodes a public key from either PEM or Base64 format.
///
/// The HAI key service may return public keys in two formats:
/// - PEM format: starts with "-----BEGIN" and contains Base64-encoded data between headers
/// - Raw Base64: direct Base64 encoding of the key bytes
///
/// This function auto-detects the format and decodes accordingly.
#[cfg(not(target_arch = "wasm32"))]
fn decode_public_key(key_data: &str) -> Result<Vec<u8>, JacsError> {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    let trimmed = key_data.trim();

    if trimmed.starts_with("-----BEGIN") {
        // PEM format - extract the Base64 content between headers
        decode_pem_public_key(trimmed)
    } else {
        // Assume raw Base64
        BASE64_STANDARD.decode(trimmed).map_err(|e| {
            JacsError::CryptoError(format!(
                "Invalid base64 encoding in public key from HAI key service: {}",
                e
            ))
        })
    }
}

/// Decodes a PEM-encoded public key.
///
/// Extracts the Base64 content between the BEGIN and END markers,
/// removes whitespace, and decodes the resulting Base64 string.
#[cfg(not(target_arch = "wasm32"))]
fn decode_pem_public_key(pem_data: &str) -> Result<Vec<u8>, JacsError> {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    // Find the end of the BEGIN header line (after "-----BEGIN ... -----")
    // We need to find the closing "-----" of the BEGIN line
    let begin_marker = "-----BEGIN";
    let begin_start = pem_data.find(begin_marker).ok_or_else(|| {
        JacsError::CryptoError("Invalid PEM format: missing BEGIN marker".to_string())
    })?;

    // Find the closing "-----" after BEGIN
    let after_begin = begin_start + begin_marker.len();
    let begin_close = pem_data[after_begin..]
        .find("-----")
        .map(|pos| after_begin + pos + 5)
        .ok_or_else(|| {
            JacsError::CryptoError("Invalid PEM format: incomplete BEGIN header".to_string())
        })?;

    // Find the END marker
    let end_start = pem_data.rfind("-----END").ok_or_else(|| {
        JacsError::CryptoError("Invalid PEM format: missing END marker".to_string())
    })?;

    if end_start <= begin_close {
        return Err(JacsError::CryptoError(
            "Invalid PEM format: no content between headers".to_string(),
        ));
    }

    // Extract the Base64 content between headers, removing all whitespace
    let base64_content: String = pem_data[begin_close..end_start]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    if base64_content.is_empty() {
        return Err(JacsError::CryptoError(
            "Invalid PEM format: no content between headers".to_string(),
        ));
    }

    BASE64_STANDARD.decode(&base64_content).map_err(|e| {
        JacsError::CryptoError(format!(
            "Invalid base64 encoding in PEM public key from HAI key service: {}",
            e
        ))
    })
}

/// Fetches a public key from the HAI key service.
///
/// This function retrieves the public key for a specific agent and version
/// from the HAI key distribution service. It is used to obtain trusted public
/// keys for verifying agent signatures without requiring local key storage.
///
/// # Arguments
///
/// * `agent_id` - The unique identifier of the agent whose key to fetch.
/// * `version` - The version of the agent's key to fetch.
///
/// # Returns
///
/// Returns `Ok(PublicKeyInfo)` containing the public key, algorithm, and hash
/// on success.
///
/// # Errors
///
/// * `JacsError::KeyNotFound` - The agent or key version was not found (404).
/// * `JacsError::NetworkError` - Connection, timeout, or other HTTP errors.
/// * `JacsError::CryptoError` - The returned key has invalid base64 encoding.
///
/// # Environment Variables
///
/// * `HAI_KEYS_BASE_URL` - Base URL for the key service. Defaults to `https://keys.hai.ai`.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::agent::loaders::{fetch_public_key_from_hai, PublicKeyInfo};
///
/// let key_info = fetch_public_key_from_hai(
///     "550e8400-e29b-41d4-a716-446655440000",
///     "1"
/// )?;
///
/// println!("Algorithm: {}", key_info.algorithm);
/// println!("Hash: {}", key_info.hash);
/// ```
///
/// # Environment Variables
///
/// * `HAI_KEYS_BASE_URL` - Base URL for the key service. Defaults to `https://keys.hai.ai`.
/// * `HAI_KEY_FETCH_RETRIES` - Number of retry attempts for network errors. Defaults to 3.
///   Set to 0 to disable retries.
#[cfg(not(target_arch = "wasm32"))]
pub fn fetch_public_key_from_hai(agent_id: &str, version: &str) -> Result<PublicKeyInfo, JacsError> {
    // Get retry count from environment or use default of 3
    let max_retries: u32 = std::env::var("HAI_KEY_FETCH_RETRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    // Get base URL from environment or use default
    let base_url =
        std::env::var("HAI_KEYS_BASE_URL").unwrap_or_else(|_| "https://keys.hai.ai".to_string());

    let url = format!("{}/jacs/v1/agents/{}/keys/{}", base_url, agent_id, version);

    info!(
        "Fetching public key from HAI: agent_id={}, version={}",
        agent_id, version
    );

    // Build blocking HTTP client with 30 second timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| JacsError::NetworkError(format!("Failed to build HTTP client: {}", e)))?;

    // Retry loop with exponential backoff
    let mut last_error: JacsError =
        JacsError::NetworkError("No attempts made to fetch public key".to_string());

    for attempt in 1..=max_retries + 1 {
        match fetch_public_key_attempt(&client, &url, agent_id, version) {
            Ok(result) => return Ok(result),
            Err(err) => {
                // Don't retry on 404 - the key doesn't exist
                if matches!(err, JacsError::KeyNotFound { .. }) {
                    return Err(err);
                }

                // Don't retry on non-retryable errors (e.g., parse errors, crypto errors)
                if !is_retryable_error(&err) {
                    return Err(err);
                }

                last_error = err;

                // Check if we've exhausted retries (attempt is 1-indexed, so max_retries+1 is the last attempt)
                if attempt > max_retries {
                    warn!(
                        "Exhausted {} retries fetching public key for agent_id={}, version={}",
                        max_retries, agent_id, version
                    );
                    break;
                }

                // Calculate exponential backoff: 1s, 2s, 4s, ...
                let backoff_secs = 1u64 << (attempt - 1);
                warn!(
                    "Retry {}/{} for agent_id={}, version={} after {}s backoff",
                    attempt, max_retries, agent_id, version, backoff_secs
                );
                std::thread::sleep(std::time::Duration::from_secs(backoff_secs));
            }
        }
    }

    // Return the last error if all retries failed
    Err(last_error)
}

/// Determines if an error is retryable (network errors) or not (parse errors, 404s).
#[cfg(not(target_arch = "wasm32"))]
fn is_retryable_error(err: &JacsError) -> bool {
    matches!(err, JacsError::NetworkError(msg) if
        msg.contains("timed out") ||
        msg.contains("connect") ||
        msg.contains("HTTP request") ||
        msg.contains("error status 5") // Retry on 5xx server errors
    )
}

/// Single attempt to fetch a public key from the HAI key service.
#[cfg(not(target_arch = "wasm32"))]
fn fetch_public_key_attempt(
    client: &reqwest::blocking::Client,
    url: &str,
    agent_id: &str,
    version: &str,
) -> Result<PublicKeyInfo, JacsError> {
    // Make request to HAI keys API
    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| {
            if e.is_timeout() {
                JacsError::NetworkError(format!(
                    "Request to HAI key service timed out after 30 seconds: {}",
                    url
                ))
            } else if e.is_connect() {
                JacsError::NetworkError(format!(
                    "Failed to connect to HAI key service at {}: {}",
                    url, e
                ))
            } else {
                JacsError::NetworkError(format!("HTTP request to HAI key service failed: {}", e))
            }
        })?;

    // Handle response status
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(JacsError::KeyNotFound {
            path: format!(
                "agent_id={}, version={} (not found in HAI key service)",
                agent_id, version
            ),
        });
    }

    if !status.is_success() {
        return Err(JacsError::NetworkError(format!(
            "HAI key service returned error status {}: failed to fetch public key for agent '{}' version '{}'",
            status, agent_id, version
        )));
    }

    // Parse JSON response
    let api_response: HaiKeysApiResponse = response.json().map_err(|e| {
        JacsError::NetworkError(format!(
            "Failed to parse HAI key service response as JSON: {}",
            e
        ))
    })?;

    // Decode public key - supports both PEM and Base64 formats
    let public_key = decode_public_key(&api_response.public_key)?;

    info!(
        "Successfully fetched public key from HAI: agent_id={}, version={}, algorithm={}",
        agent_id, version, api_response.algorithm
    );

    Ok(PublicKeyInfo {
        public_key,
        algorithm: api_response.algorithm,
        hash: api_response.public_key_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_info_struct() {
        let info = PublicKeyInfo {
            public_key: vec![1, 2, 3, 4],
            algorithm: "ed25519".to_string(),
            hash: "abc123".to_string(),
        };
        assert_eq!(info.public_key, vec![1, 2, 3, 4]);
        assert_eq!(info.algorithm, "ed25519");
        assert_eq!(info.hash, "abc123");
    }

    #[test]
    fn test_public_key_info_clone() {
        let info = PublicKeyInfo {
            public_key: vec![1, 2, 3],
            algorithm: "rsa".to_string(),
            hash: "xyz789".to_string(),
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod decode_tests {
        use super::*;

        #[test]
        fn test_decode_public_key_base64() {
            // Test raw Base64 decoding
            let key_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8];
            let base64_encoded = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

            let decoded = decode_public_key(&base64_encoded).unwrap();
            assert_eq!(decoded, key_bytes);
        }

        #[test]
        fn test_decode_public_key_base64_with_whitespace() {
            // Test Base64 with leading/trailing whitespace
            let key_bytes = vec![10, 20, 30, 40];
            let base64_encoded =
                format!("  {}  ", base64::engine::general_purpose::STANDARD.encode(&key_bytes));

            let decoded = decode_public_key(&base64_encoded).unwrap();
            assert_eq!(decoded, key_bytes);
        }

        #[test]
        fn test_decode_public_key_pem_ed25519() {
            // Test PEM-encoded public key with valid Base64
            // This is a real Ed25519 public key ASN.1 structure
            let pem = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9bTBTn3X0IA4i+S6KAHA==
-----END PUBLIC KEY-----"#;

            let result = decode_public_key(pem);
            assert!(result.is_ok(), "Failed to decode PEM: {:?}", result.err());
            let decoded = result.unwrap();
            // Just verify we got non-empty bytes back
            assert!(!decoded.is_empty());
        }

        #[test]
        fn test_decode_public_key_pem_multiline() {
            // Test PEM with multiple lines of Base64 content
            let pem = r#"-----BEGIN PUBLIC KEY-----
AQAB
CDEF
-----END PUBLIC KEY-----"#;

            let result = decode_public_key(pem);
            assert!(result.is_ok());
        }

        #[test]
        fn test_decode_public_key_invalid_pem_no_end() {
            let pem = "-----BEGIN PUBLIC KEY-----\nAQAB\n";

            let result = decode_public_key(pem);
            assert!(result.is_err());
            match result.unwrap_err() {
                JacsError::CryptoError(msg) => {
                    assert!(msg.contains("END marker"), "Error: {}", msg);
                }
                other => panic!("Expected CryptoError, got: {:?}", other),
            }
        }

        #[test]
        fn test_decode_public_key_invalid_base64() {
            let invalid = "not-valid-base64!!!";

            let result = decode_public_key(invalid);
            assert!(result.is_err());
            match result.unwrap_err() {
                JacsError::CryptoError(msg) => {
                    assert!(msg.contains("base64"), "Error: {}", msg);
                }
                other => panic!("Expected CryptoError, got: {:?}", other),
            }
        }

        #[test]
        fn test_decode_pem_public_key_empty_content() {
            let pem = "-----BEGIN PUBLIC KEY----------END PUBLIC KEY-----";

            let result = decode_pem_public_key(pem);
            assert!(result.is_err());
            match result.unwrap_err() {
                JacsError::CryptoError(msg) => {
                    assert!(msg.contains("no content"), "Error: {}", msg);
                }
                other => panic!("Expected CryptoError, got: {:?}", other),
            }
        }

        #[test]
        fn test_is_retryable_error_timeout() {
            let err = JacsError::NetworkError("Request timed out after 30s".to_string());
            assert!(is_retryable_error(&err));
        }

        #[test]
        fn test_is_retryable_error_connect() {
            let err = JacsError::NetworkError("Failed to connect to server".to_string());
            assert!(is_retryable_error(&err));
        }

        #[test]
        fn test_is_retryable_error_http_request() {
            let err = JacsError::NetworkError("HTTP request failed".to_string());
            assert!(is_retryable_error(&err));
        }

        #[test]
        fn test_is_retryable_error_5xx() {
            let err = JacsError::NetworkError("error status 503".to_string());
            assert!(is_retryable_error(&err));
        }

        #[test]
        fn test_is_retryable_error_not_retryable_parse() {
            let err = JacsError::NetworkError("Failed to parse JSON response".to_string());
            assert!(!is_retryable_error(&err));
        }

        #[test]
        fn test_is_retryable_error_not_retryable_key_not_found() {
            let err = JacsError::KeyNotFound {
                path: "test".to_string(),
            };
            assert!(!is_retryable_error(&err));
        }

        #[test]
        fn test_is_retryable_error_not_retryable_crypto() {
            let err = JacsError::CryptoError("Invalid key format".to_string());
            assert!(!is_retryable_error(&err));
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod http_tests {
        use super::*;

        #[test]
        fn test_fetch_public_key_invalid_url() {
            // Set an invalid base URL to test error handling
            // Disable retries for faster test execution
            // SAFETY: This test is run in isolation and the env var is cleaned up after
            unsafe {
                std::env::set_var("HAI_KEYS_BASE_URL", "http://localhost:1");
                std::env::set_var("HAI_KEY_FETCH_RETRIES", "0");
            }

            let result = fetch_public_key_from_hai("test-agent-id", "1");

            // Clean up first to ensure it happens even if assertions fail
            unsafe {
                std::env::remove_var("HAI_KEYS_BASE_URL");
                std::env::remove_var("HAI_KEY_FETCH_RETRIES");
            }

            // Should fail with network error (connection refused)
            assert!(result.is_err());
            let err = result.unwrap_err();
            match err {
                JacsError::NetworkError(msg) => {
                    assert!(
                        msg.contains("connect") || msg.contains("failed") || msg.contains("HTTP"),
                        "Expected connection error, got: {}",
                        msg
                    );
                }
                other => panic!("Expected NetworkError, got: {:?}", other),
            }
        }

        #[test]
        fn test_fetch_public_key_default_url() {
            // Verify default URL is used when env var is not set
            // Disable retries for faster test execution
            // SAFETY: This test is run in isolation
            unsafe {
                std::env::remove_var("HAI_KEYS_BASE_URL");
                std::env::set_var("HAI_KEY_FETCH_RETRIES", "0");
            }

            // This will fail (no server), but we can verify it attempted the right URL
            let result = fetch_public_key_from_hai("nonexistent-agent", "1");

            // Clean up
            unsafe {
                std::env::remove_var("HAI_KEY_FETCH_RETRIES");
            }

            assert!(result.is_err());
            // The error should be network-related (DNS or connection)
            match result.unwrap_err() {
                JacsError::NetworkError(_) | JacsError::KeyNotFound { .. } => {
                    // Expected - either network error or 404
                }
                other => panic!("Expected NetworkError or KeyNotFound, got: {:?}", other),
            }
        }

        #[test]
        fn test_fetch_public_key_retries_env_var() {
            // Test that HAI_KEY_FETCH_RETRIES is respected
            // SAFETY: This test is run in isolation
            unsafe {
                std::env::set_var("HAI_KEY_FETCH_RETRIES", "1");
                std::env::set_var("HAI_KEYS_BASE_URL", "http://localhost:1");
            }

            let start = std::time::Instant::now();
            let _ = fetch_public_key_from_hai("test-agent", "1");
            let elapsed = start.elapsed();

            // Clean up
            unsafe {
                std::env::remove_var("HAI_KEY_FETCH_RETRIES");
                std::env::remove_var("HAI_KEYS_BASE_URL");
            }

            // With 1 retry and 1s backoff, should take at least 1 second
            // but less than what 3 retries would take (1+2+4=7s)
            assert!(
                elapsed >= std::time::Duration::from_millis(900),
                "Expected at least ~1s for 1 retry, got {:?}",
                elapsed
            );
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "Should not take as long as 3 retries, got {:?}",
                elapsed
            );
        }
    }
}
