use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::security::check_data_directory;
use crate::crypt::aes_encrypt::decrypt_private_key;
use crate::crypt::aes_encrypt::encrypt_private_key;
use flate2::Compression;
use flate2::write::GzEncoder;
use regex::Regex;
use secrecy::ExposeSecret;
use walkdir::WalkDir;

use crate::storage::MultiStorage;
use crate::storage::StorageType;
use crate::storage::jenv::{get_env_var, get_required_env_var};
use chrono::Utc;
use log::{debug, error, info, warn};
use object_store::path::Path as ObjectPath;
use std::env;
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

        let path = format!(
            "{}/{}/{}",
            get_required_env_var("JACS_DATA_DIRECTORY", true)
                .expect("JACS_DATA_DIRECTORY must be set"),
            doctype,
            filename
        );

        Ok(PathBuf::from(path))
    }

    fn fs_save_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let storage = MultiStorage::new(Some(true))?;

        let private_key_filename = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let public_key_filename = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;

        let binding = self.get_private_key()?;
        let borrowed_key = binding.expose_secret();
        let key_vec = decrypt_private_key(borrowed_key)?;

        let private_path = format!("{}", private_key_filename);
        let public_path = format!("{}", public_key_filename);

        storage.save_file(&private_path, &key_vec)?;
        storage.save_file(&public_path, &self.get_public_key()?)?;

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
        let storage = MultiStorage::new(None)?;
        let agent_path = format!("agent/{}.json", agentid);
        let contents = storage.get_file(&agent_path, None)?;
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
        agentid: &String,
        agent_string: &String,
    ) -> Result<String, Box<dyn Error>> {
        let agentpath = self.build_filepath(&"agent".to_string(), agentid)?;
        Ok(save_to_filepath(&agentpath, agent_string.as_bytes())?)
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
    file_path: &Path,
    filename: &String,
    private_key: &[u8],
) -> Result<String, Box<dyn Error>> {
    let password = get_env_var("JACS_PRIVATE_KEY_PASSWORD", false)
        .unwrap_or(None)
        .unwrap_or_default();
    let storage = MultiStorage::new(Some(true))?;

    if !password.is_empty() {
        let encrypted_key = encrypt_private_key(private_key).map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Encryption error: {}", e),
            ))
        })?;
        let encrypted_filename = if !filename.ends_with(".enc") {
            format!("{}.enc", filename)
        } else {
            filename.to_string()
        };

        let full_path = format!("{}/{}", file_path.to_string_lossy(), encrypted_filename);
        storage.save_file(&full_path, &encrypted_key)?;
        Ok(full_path)
    } else {
        let full_path = format!("{}/{}", file_path.to_string_lossy(), filename);
        storage.save_file(&full_path, private_key)?;
        Ok(full_path)
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

#[cfg(not(target_arch = "wasm32"))]
fn save_file(
    file_path: &Path,
    filename: &String,
    content: &[u8],
) -> Result<String, Box<dyn Error>> {
    let full_path = file_path.join(filename);
    save_to_filepath(&full_path, content)
}

#[cfg(not(target_arch = "wasm32"))]
fn save_to_filepath(full_path: &PathBuf, content: &[u8]) -> Result<String, Box<dyn Error>> {
    let storage = MultiStorage::new(None)?;
    let path_str = full_path.to_string_lossy().to_string();

    if storage.file_exists(&path_str, None)? {
        warn!("path exists for {}, creating backup", path_str);
        let timestamp = Utc::now().format("backup-%Y-%m-%d-%H-%M").to_string();
        let backup_path = format!("{}.{}", path_str, timestamp);
        let existing_content = storage.get_file(&path_str, None)?;
        storage.save_file(&backup_path, &existing_content)?;
    }

    storage.save_file(&path_str, content)?;
    Ok(path_str)
}

// Helper function to convert PathBuf to object store Path
fn to_object_path(path: &PathBuf) -> ObjectPath {
    ObjectPath::from(path.to_string_lossy().as_ref())
}
