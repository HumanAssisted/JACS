use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::security::SecurityTraits;
use crate::crypt::aes_encrypt::decrypt_private_key;
use crate::crypt::aes_encrypt::encrypt_private_key;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::Compression;
use flate2::write::GzEncoder;
use secrecy::ExposeSecret;

use crate::storage::jenv::{get_env_var, get_required_env_var};
use chrono::Utc;
use log::{debug, error, warn};
use std::error::Error;
use std::io::Write;
use std::path::Path;

/// This environment variable determine if files are saved to the filesystem at all
/// if you are building something that passing data through to a database, you'd set this flag to 0 or False

/// The goal of fileloader is to prevent fileloading into arbitrary directories
/// by centralizing all filesystem access
/// Only an initilaized agent can perform some of the functions by calling isready()
/// as an attempt to ensure actions on the filesystem requiring
/// the agent are acted out by the agent
pub trait FileLoader {
    // utils

    fn fs_docs_load_all(&mut self) -> Result<Vec<String>, Vec<Box<dyn Error>>>;
    fn fs_agent_load(&self, agentid: &String) -> Result<String, Box<dyn Error>>;
    // fn fs_agent_new(&self, filename: &String) -> Result<String, Box<dyn Error>>;
    // fn fs_document_new(&self, filename: &String) -> Result<String, Box<dyn Error>>;
    // fn fs_document_load(&self, document_id: &String) -> Result<String, Box<dyn Error>>;
    fn fs_preload_keys(
        &mut self,
        private_key_filename: &String,
        public_key_filename: &String,
        custom_key_algorithm: Option<String>,
    ) -> Result<(), Box<dyn Error>>;
    fn fs_save_keys(&mut self) -> Result<(), Box<dyn Error>>;
    fn fs_load_keys(&mut self) -> Result<(), Box<dyn Error>>;

    // save
    // fn fs_docs_save_all(&mut self) -> Result<Vec<String>, Box<dyn Error>>;
    fn fs_agent_save(
        &self,
        agentid: &String,
        agent_string: &String,
    ) -> Result<String, Box<dyn Error>>;
    fn fs_document_save(
        &self,
        document_id: &String,
        document_string: &String,
        output_filename: Option<String>,
    ) -> Result<String, Box<dyn Error>>;

    fn fs_document_archive(&self, lookup_key: &String) -> Result<(), Box<dyn Error>>;
    fn load_public_key_file(&self, filename: &String) -> Result<Vec<u8>, Box<dyn Error>>;
    fn load_private_key(&self, filename: &String) -> Result<Vec<u8>, Box<dyn Error>>;
    fn save_private_key(
        &self,
        filename: &String,
        private_key: &[u8],
    ) -> Result<String, Box<dyn Error>>;
    fn create_backup(&self, file_path: &str) -> Result<String, Box<dyn Error>>;
    /// used to get base64 content from a filepath
    fn fs_get_document_content(&self, document_filepath: String) -> Result<String, Box<dyn Error>>;
    fn fs_load_public_key(&self, agent_id_and_version: &String) -> Result<Vec<u8>, Box<dyn Error>>;
    fn use_filesystem(&self) -> bool;
    fn fs_save_remote_public_key(
        &self,
        agent_id_and_version: &String,
        public_key: &[u8],
        public_key_enc_type: &[u8],
    ) -> Result<(), Box<dyn Error>>;
    fn make_data_directory_path(&self, filename: &String) -> Result<String, Box<dyn Error>>;
    fn make_key_directory_path(&self, filename: &String) -> Result<String, Box<dyn Error>>;
}

#[cfg(not(target_arch = "wasm32"))]
impl FileLoader for Agent {
    fn use_filesystem(&self) -> bool {
        // Handle Option<Config> and Option<String> from getter
        self.config.as_ref().map_or(false, |conf| {
            conf.jacs_default_storage().as_deref() == Some("fs")
        })
    }

    fn fs_save_keys(&mut self) -> Result<(), Box<dyn Error>> {
        // Get private key filename: ONLY from config
        let private_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| "Agent config is missing".to_string())?
            .jacs_agent_private_key_filename()
            .as_deref()
            .ok_or_else(|| "Private key filename not found in config".to_string())?
            .to_string();

        // Get public key filename: ONLY from config
        let public_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| "Agent config is missing".to_string())?
            .jacs_agent_public_key_filename()
            .as_deref()
            .ok_or_else(|| "Public key filename not found in config".to_string())?
            .to_string();

        let absolute_public_key_path = self.make_key_directory_path(&public_key_filename)?;
        let absolute_private_key_path = self.make_key_directory_path(&private_key_filename)?;

        let binding = self.get_private_key()?;
        let borrowed_key = binding.expose_secret();
        let key_vec = decrypt_private_key(borrowed_key)?;

        self.save_private_key(&absolute_private_key_path, &key_vec)?;

        self.storage
            .save_file(&absolute_public_key_path, &self.get_public_key()?)?;

        Ok(())
    }

    fn fs_load_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let private_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| "Agent config is missing".to_string())? // Error if config itself is None
            .jacs_agent_private_key_filename() // Get &Option<String>
            .as_deref() // Convert to Option<&str>
            .ok_or_else(|| "Private key filename not found in config".to_string())? // Error if Option is None
            .to_string(); // Convert &str to String

        // Get public key filename: ONLY from config
        let public_key_filename = self
            .config
            .as_ref()
            .ok_or_else(|| "Agent config is missing".to_string())? // Error if config itself is None
            .jacs_agent_public_key_filename() // Get &Option<String>
            .as_deref() // Convert to Option<&str>
            .ok_or_else(|| "Public key filename not found in config".to_string())? // Error if Option is None
            .to_string(); //
        let private_key = self.load_private_key(&private_key_filename)?;
        let agents_public_key = self.load_private_key(&public_key_filename)?;

        let key_algorithm = self
            .config
            .as_ref()
            .ok_or_else(|| "Agent config is missing".to_string())? // Error if config itself is None
            .jacs_agent_key_algorithm() // Get &Option<String>
            .as_deref() // Convert to Option<&str>
            .ok_or_else(|| "Public key filename not found in config".to_string())? // Error if Option is None
            .to_string();

        self.set_keys(private_key, agents_public_key, &key_algorithm)
    }

    /// in JACS the public keys need to be added manually
    fn fs_load_public_key(&self, agent_id_and_version: &String) -> Result<Vec<u8>, Box<dyn Error>> {
        let public_key_path = format!("public_keys/{}.pem", agent_id_and_version);
        let absolute_public_key_path = self.make_data_directory_path(&public_key_path)?;
        self.storage
            .get_file(&absolute_public_key_path, None)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    /// in JACS the public keys need to be added manually
    fn fs_save_remote_public_key(
        &self,
        agent_id_and_version: &String,
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
        private_key_filename: &String,
        public_key_filename: &String,
        custom_key_algorithm: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let private_path = self.make_key_directory_path(&private_key_filename)?;
        let public_path = self.make_key_directory_path(&public_key_filename)?;

        let private_key = self.storage.get_file(&private_path, None)?;
        let public_key = self.storage.get_file(&public_path, None)?;

        // Determine the key algorithm with priority: custom -> config -> env var
        let key_algorithm = if let Some(algo) = custom_key_algorithm {
            // 1. Use custom_key_algorithm if provided
            algo
        } else {
            // 2. If no custom algo, try config
            self.config.as_ref().unwrap().get_key_algorithm()?
        };

        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// function used to load all documents present
    fn fs_docs_load_all(&mut self) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
        let mut errors: Vec<Box<dyn Error>> = Vec::new();
        let mut documents: Vec<String> = Vec::new();

        // Handle Result from make_data_directory_path manually
        let agent_path = match self.make_data_directory_path(&"agent".to_string()) {
            Ok(path) => path,
            Err(e) => {
                errors.push(e);
                // Cannot proceed without the agent path, return collected errors
                return Err(errors);
            }
        };
        let documents_path = match self.make_data_directory_path(&"documents".to_string()) {
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

    fn fs_agent_load(&self, agentid: &String) -> Result<String, Box<dyn Error>> {
        // Expects logical agentid (no .json)
        println!("[fs_agent_load] Loading using agent ID: {}", agentid);

        // Construct the relative path for storage lookup
        let relative_path = format!("agent/{}.json", agentid);
        println!(
            "[fs_agent_load] Attempting to get file from relative path: {}",
            relative_path
        );

        let absolute_path = self.make_data_directory_path(&relative_path)?;
        let contents = self.storage.get_file(&absolute_path, None).map_err(|e| {
            error!(
                "[fs_agent_load] Failed to get file from relative path '{}': {}",
                absolute_path, e
            );
            e
        })?;

        println!("[fs_agent_load] Successfully loaded file content.");
        String::from_utf8(contents).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    fn fs_agent_save(
        &self,
        agentid: &String,
        agent_string: &String,
    ) -> Result<String, Box<dyn Error>> {
        println!("[fs_agent_save] Starting save for agent ID: {}", agentid);

        // Construct the relative path for storage operations
        let relative_path_str = format!("agent/{}.json", agentid);
        let absolute_path_str = self.make_data_directory_path(&relative_path_str)?;
        println!(
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
                    Ok(_) => println!("[fs_agent_save] Backup successful (using relative paths)."),
                    Err(e) => {
                        error!(
                            "[fs_agent_save] Backup rename failed (relative paths): {}. Continuing save attempt.",
                            e
                        );
                    }
                }
            }
            Ok(false) => {
                println!(
                    "[fs_agent_save] No existing file found at relative path. No backup needed."
                );
            }
            Err(e) => {
                error!(
                    "[fs_agent_save] Error checking file existence for backup (relative path): {}. Continuing save attempt.",
                    e
                );
            }
        }

        // Actual save operation using RELATIVE path
        println!(
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

        println!(
            "[fs_agent_save] Save successful. Returning absolute path: {}",
            absolute_path_str
        );
        Ok(absolute_path_str)
    }

    fn fs_document_archive(&self, lookup_key: &String) -> Result<(), Box<dyn Error>> {
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
        document_id: &String,
        document_string: &String,
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
    fn load_public_key_file(&self, filename: &String) -> Result<Vec<u8>, Box<dyn Error>> {
        self.storage
            .get_file(&filename, None)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn load_private_key(&self, filename: &String) -> Result<Vec<u8>, Box<dyn Error>> {
        let filepath = self.make_key_directory_path(&filename)?;
        let loaded_key = self.load_public_key_file(&filepath)?;
        if filename.ends_with(".enc") {
            Ok(decrypt_private_key(&loaded_key)?)
        } else {
            Ok(loaded_key)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn save_private_key(
        &self,
        full_filepath: &String,
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
        let timestamp = Utc::now().format("backup-%Y-%m-%d-%H-%M").to_string();

        // Split the path into directory and filename
        let path = Path::new(file_path);
        let file_stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to read file stem",
                ))
            })?;
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

    fn make_data_directory_path(&self, filename: &String) -> Result<String, Box<dyn Error>> {
        println!("config!: {:?}", self.config);
        // Fail if config or specific directory is missing
        let mut data_dir = self
            .config
            .as_ref()
            .ok_or_else(|| "Agent config is missing for data directory path".to_string())?
            .jacs_data_directory()
            .as_deref()
            .ok_or_else(|| "Config does not contain 'jacs_data_directory'".to_string())?;
        data_dir = data_dir.strip_prefix("./").unwrap_or(data_dir);
        debug!("data_dir {} filename {}", data_dir, filename);
        let path = format!("{}/{}", data_dir, filename);
        debug!("Data directory path: {}", path);
        Ok(path)
    }
    fn make_key_directory_path(&self, filename: &String) -> Result<String, Box<dyn Error>> {
        // Fail if config or specific directory is missing
        let mut key_dir = self
            .config
            .as_ref()
            .ok_or_else(|| "Agent config is missing for key directory path".to_string())?
            .jacs_key_directory()
            .as_deref()
            .ok_or_else(|| "Config does not contain 'jacs_key_directory'".to_string())?;
        key_dir = key_dir.strip_prefix("./").unwrap_or(key_dir);
        let path = format!("{}/{}", key_dir, filename);
        debug!("Key directory path: {}", path);
        Ok(path)
    }
}
