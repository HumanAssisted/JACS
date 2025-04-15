use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::security::check_data_directory;
use crate::crypt::aes_encrypt::decrypt_private_key;
use crate::crypt::aes_encrypt::encrypt_private_key;
use flate2::Compression;
use flate2::write::GzEncoder;
use secrecy::ExposeSecret;

use crate::storage::MultiStorage;
use crate::storage::StorageType;
use crate::storage::jenv::{get_env_var, get_required_env_var};
use chrono::Utc;
use log::{debug, error, info, warn};
use object_store::path::Path as ObjectPath;
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};

fn not_implemented_error() -> Box<dyn Error> {
    error!("NOT IMPLEMENTED");
    return "NOT IMPLEMENTED".into();
}

/// This environment variable determine if files are saved to the filesystem at all
/// if you are building something that passing data through to a database, you'd set this flag to 0 or False
const JACS_USE_FILESYSTEM: &str = "JACS_USE_FILESYSTEM";

pub fn use_filesystem() -> bool {
    match get_env_var(JACS_USE_FILESYSTEM, false) {
        Ok(Some(value)) => matches!(value.to_lowercase().as_str(), "true" | "1"),
        _ => false,
    }
}

/// The goal of fileloader is to prevent fileloading into arbitrary directories
/// by centralizing all filesystem access
/// Only an initilaized agent can perform some of the functions by calling isready()
/// as an attempt to ensure actions on the filesystem requiring
/// the agent are acted out by the agent
pub trait FileLoader {
    // utils
    fn build_filepath(&self, doctype: &String, docid: &String) -> Result<PathBuf, Box<dyn Error>>;
    fn build_file_directory(&self, doctype: &String) -> Result<PathBuf, Box<dyn Error>>;

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
        document_directory: &String,
        output_filename: Option<String>,
    ) -> Result<String, Box<dyn Error>>;

    fn fs_document_archive(&self, lookup_key: &String) -> Result<(), Box<dyn Error>>;

    /// used to get base64 content from a filepath
    fn fs_get_document_content(&self, document_filepath: String) -> Result<String, Box<dyn Error>>;
    fn fs_load_public_key(&self, agent_id_and_version: &String) -> Result<Vec<u8>, Box<dyn Error>>;
    fn fs_save_remote_public_key(
        &self,
        agent_id_and_version: &String,
        public_key: &[u8],
        public_key_enc_type: &[u8],
    ) -> Result<(), Box<dyn Error>>;
}

#[cfg(not(target_arch = "wasm32"))]
impl FileLoader for Agent {
    fn build_file_directory(&self, doctype: &String) -> Result<PathBuf, Box<dyn Error>> {
        if !use_filesystem() {
            let error_message = format!(
                "build_file_directory Filesystem features set to off with JACS_USE_FILESYSTEM: {}",
                doctype
            );
            error!("{}", error_message);
            return Err(error_message.into());
        }

        // Instead of building local filesystem paths, create object store paths
        let jacs_dir = get_required_env_var("JACS_DATA_DIRECTORY", true)
            .expect("JACS_DATA_DIRECTORY must be set");
        let path = format!("{}/{}", jacs_dir, doctype);

        // Still return PathBuf for compatibility with existing code
        Ok(PathBuf::from(path))
    }

    fn build_filepath(&self, doctype: &String, docid: &String) -> Result<PathBuf, Box<dyn Error>> {
        let filename = if docid.ends_with(".json") {
            docid.to_string()
        } else {
            format!("{}.json", docid)
        };

        // Use PathBuf::join for robust path construction
        let base_dir = PathBuf::from(
            get_required_env_var("JACS_DATA_DIRECTORY", true)
                .expect("JACS_DATA_DIRECTORY must be set"),
        );

        let path = base_dir.join(doctype).join(filename);

        Ok(path)
    }

    fn fs_save_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let storage = MultiStorage::new(Some(true))?;

        let private_key_filename = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let public_key_filename = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;

        let binding = self.get_private_key()?;
        let borrowed_key = binding.expose_secret();
        let key_vec = decrypt_private_key(borrowed_key)?;

        // Use save_private_key with just the filename - storage will handle paths
        save_private_key(Path::new(""), &private_key_filename, &key_vec)?;

        // Public key can be saved directly
        storage.save_file(&public_key_filename, &self.get_public_key()?)?;

        Ok(())
    }

    fn fs_load_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let private_key_filename = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let private_key = load_private_key(&private_key_filename)?;
        let public_key_filename = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;
        let public_key = load_key_file(&public_key_filename)?;

        let key_algorithm = get_required_env_var("JACS_AGENT_KEY_ALGORITHM", true)?;
        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// in JACS the public keys need to be added manually
    fn fs_load_public_key(&self, agent_id_and_version: &String) -> Result<Vec<u8>, Box<dyn Error>> {
        let storage = MultiStorage::new(Some(false))?;
        let public_key_path = format!("public_keys/{}.pem", agent_id_and_version);

        storage
            .get_file(&public_key_path, None)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    /// in JACS the public keys need to be added manually
    fn fs_save_remote_public_key(
        &self,
        agent_id_and_version: &String,
        public_key: &[u8],
        public_key_enc_type: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let storage = MultiStorage::new(Some(false))?;

        let public_key_path = format!("public_keys/{}.pem", agent_id_and_version);
        let enc_type_path = format!("public_keys/{}.enc_type", agent_id_and_version);

        storage.save_file(&public_key_path, public_key)?;
        storage.save_file(&enc_type_path, public_key_enc_type)?;

        Ok(())
    }

    /// a way to load keys that aren't default
    fn fs_preload_keys(
        &mut self,
        private_key_filename: &String,
        public_key_filename: &String,
        custom_key_algorithm: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let storage = MultiStorage::new(Some(false))?;

        let private_path = format!("{}", private_key_filename);
        let public_path = format!("{}", public_key_filename);

        let private_key = storage.get_file(&private_path, None)?;
        let public_key = storage.get_file(&public_path, None)?;

        let key_algorithm = match custom_key_algorithm {
            Some(algo) => algo,
            _ => get_required_env_var("JACS_AGENT_KEY_ALGORITHM", true)?,
        };

        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// function used to load all documents present
    fn fs_docs_load_all(&mut self) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
        let mut errors: Vec<Box<dyn Error>> = Vec::new();
        let mut documents: Vec<String> = Vec::new();
        let storage = MultiStorage::new(None).map_err(|e| vec![Box::new(e) as Box<dyn Error>])?;

        let paths = vec!["agent", "documents"];

        for prefix in paths {
            match storage.list(prefix, None) {
                Ok(files) => {
                    for file_path in files {
                        match storage.get_file(&file_path, None) {
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
        let storage = MultiStorage::new(None)?;

        // Construct the relative path for storage lookup
        let relative_path = format!("agent/{}.json", agentid);
        println!(
            "[fs_agent_load] Attempting to get file from relative path: {}",
            relative_path
        );

        let contents = storage.get_file(&relative_path, None).map_err(|e| {
            error!(
                "[fs_agent_load] Failed to get file from relative path '{}': {}",
                relative_path, e
            );
            e
        })?;

        println!("[fs_agent_load] Successfully loaded file content.");
        String::from_utf8(contents).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    // fn fs_agent_new(&self, _filename: &String) -> Result<String, Box<dyn Error>> {
    //     Err(not_implemented_error())
    // }

    // fn fs_document_new(&self, _filename: &String) -> Result<String, Box<dyn Error>> {
    //     Err(not_implemented_error())
    // }

    // fn fs_document_load(&self, _document_id: &String) -> Result<String, Box<dyn Error>> {
    //     Err(not_implemented_error())
    // }

    fn fs_agent_save(
        &self,
        agentid: &String, // Expects logical agentid (no .json)
        agent_string: &String,
    ) -> Result<String, Box<dyn Error>> {
        println!("[fs_agent_save] Starting save for agent ID: {}", agentid);

        // Construct the relative path for storage operations
        let relative_path_str = format!("agent/{}.json", agentid);
        println!(
            "[fs_agent_save] Calculated relative path for storage ops: {}",
            relative_path_str
        );

        // Calculate the absolute path for the return value
        let agentpath_absolute: PathBuf =
            self.build_filepath(&"agent".to_string(), &format!("{}.json", agentid))?; // Need to add .json for build_filepath
        println!(
            "[fs_agent_save] Calculated absolute save path for return: {:?}",
            agentpath_absolute
        );

        let storage = match MultiStorage::new(None) {
            Ok(s) => {
                println!("[fs_agent_save] MultiStorage created successfully.");
                s
            }
            Err(e) => {
                println!("[fs_agent_save] Error creating MultiStorage: {}", e);
                return Err(e.into());
            }
        };

        // --- Use RELATIVE path for storage operations ---
        println!(
            "[fs_agent_save] Checking existence relative path: {}",
            relative_path_str
        );
        match storage.file_exists(&relative_path_str, Some(StorageType::FS)) {
            Ok(true) => {
                // Construct relative backup path
                let relative_backup_path = format!("{}.bak", relative_path_str);
                warn!(
                    "[fs_agent_save] Agent file exists (relative path), backing up to: {}",
                    relative_backup_path
                );
                match storage.rename_file(&relative_path_str, &relative_backup_path) {
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
            relative_path_str
        );
        storage
            .save_file(&relative_path_str, agent_string.as_bytes())
            .map_err(|e| {
                error!(
                    "[fs_agent_save] storage.save_file failed (relative path): {}",
                    e
                );
                Box::new(e) as Box<dyn Error>
            })?;

        // Return the calculated ABSOLUTE path string
        let absolute_path_string = agentpath_absolute.to_string_lossy().to_string();
        println!(
            "[fs_agent_save] Save successful. Returning absolute path: {}",
            absolute_path_string
        );
        Ok(absolute_path_string)
    }

    fn fs_document_archive(&self, lookup_key: &String) -> Result<(), Box<dyn Error>> {
        let storage = MultiStorage::new(None)?;
        let document_filename = format!("{}.json", lookup_key);
        let old_path = format!("documents/{}", document_filename);
        let new_path = format!("documents/archive/{}", document_filename);

        let contents = storage.get_file(&old_path, None)?;
        storage.save_file(&new_path, &contents)?;
        Ok(())
    }

    fn fs_document_save(
        &self,
        document_id: &String,
        document_string: &String,
        document_directory: &String,
        output_filename: Option<String>,
    ) -> Result<String, Box<dyn Error>> {
        if let Err(e) = check_data_directory() {
            error!("Failed to check data directory: {}", e);
        }

        let documentoutput_filename = match output_filename {
            Some(filename) => filename,
            _ => document_id.to_string(),
        };

        let document_path = format!("{}/{}", document_directory, documentoutput_filename);

        // Use MultiStorage to save the file
        let storage = MultiStorage::new(None)?;
        storage.save_file(&document_path, document_string.as_bytes())?;

        Ok(document_path)
    }

    fn fs_get_document_content(&self, document_filepath: String) -> Result<String, Box<dyn Error>> {
        let storage = MultiStorage::new(None)?;
        let contents = storage.get_file(&document_filepath, None)?;

        // Compress the contents using gzip
        let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gz_encoder.write_all(&contents)?;
        let compressed_contents = gz_encoder.finish()?;

        // Encode the compressed contents using base64
        Ok(base64::encode(&compressed_contents))
    }
}

/// private Helper function to create a backup file name based on the current timestamp
#[cfg(not(target_arch = "wasm32"))]
async fn create_backup(storage: &MultiStorage, file_path: &str) -> Result<String, Box<dyn Error>> {
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
    let contents = storage.get_file(file_path, None)?;
    storage.save_file(&backup_path, &contents)?;

    Ok(backup_path)
}

#[cfg(not(target_arch = "wasm32"))]
fn save_private_key(
    _: &Path, // Ignore path parameter since storage handles paths
    filename: &String,
    private_key: &[u8],
) -> Result<String, Box<dyn Error>> {
    let password = get_env_var("JACS_PRIVATE_KEY_PASSWORD", false)
        .unwrap_or(None)
        .unwrap_or_default();
    let storage = MultiStorage::new(Some(true))?;

    if !password.is_empty() {
        let encrypted_key = encrypt_private_key(private_key)?;
        let encrypted_filename = if !filename.ends_with(".enc") {
            format!("{}.enc", filename)
        } else {
            filename.to_string()
        };

        storage.save_file(&encrypted_filename, &encrypted_key)?;
        Ok(encrypted_filename)
    } else {
        storage.save_file(filename, private_key)?;
        Ok(filename.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn load_private_key(filename: &String) -> Result<Vec<u8>, Box<dyn Error>> {
    let loaded_key = load_key_file(filename)?;
    if filename.ends_with(".enc") {
        Ok(decrypt_private_key(&loaded_key)?)
    } else {
        Ok(loaded_key)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn load_key_file(filename: &String) -> Result<Vec<u8>, Box<dyn Error>> {
    let storage = MultiStorage::new(Some(true))?;
    storage
        .get_file(&filename, None)
        .map_err(|e| Box::new(e) as Box<dyn Error>)
}

// Helper function to convert PathBuf to object store Path
fn to_object_path(path: &PathBuf) -> ObjectPath {
    ObjectPath::from(path.to_string_lossy().as_ref())
}
