use crate::agent::boilerplate::BoilerPlate;
use crate::agent::security::check_data_directory;
use crate::agent::Agent;
use crate::crypt::aes_encrypt::decrypt_private_key;
use crate::crypt::aes_encrypt::encrypt_private_key;
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use secrecy::ExposeSecret;

use std::fs::File;
use std::io::Read;
use std::io::Write;

use chrono::Utc;
use log::{debug, error, info, warn};
use std::env;
use std::error::Error;
use std::{fs, path::Path, path::PathBuf};

fn not_implemented_error() -> Box<dyn Error> {
    error!("NOT IMPLEMENTED");
    return "NOT IMPLEMENTED".into();
}

/// This environment variable determine if files are saved to the filesystem at all
/// if you are building something that passing data through to a database, you'd set this flag to 0 or False
const JACS_USE_FILESYSTEM: &str = "JACS_USE_FILESYSTEM";

pub fn use_filesystem() -> bool {
    let env_var_value = env::var(JACS_USE_FILESYSTEM).unwrap_or_else(|_| "false".to_string());
    return matches!(env_var_value.to_lowercase().as_str(), "true" | "1");
}

/// The goal of fileloader is to prevent fileloading into arbitrary directories
/// by centralizing all filesystem access
/// Only an initilaized agent can perform some of the functions by calling isready()
/// as an attempt to ensure actions on the filesystem requiring
/// the agent are acted out by the agent
pub trait FileLoader {
    // utils
    fn build_filepath(&self, doctype: &String, docid: &String) -> Result<PathBuf, Box<dyn Error>>;
    fn build_key_filepath(
        &self,
        doctype: &String,
        key_filename: &String,
    ) -> Result<PathBuf, Box<dyn Error>>;

    // init
    fn fs_docs_load_all(&mut self) -> Result<Vec<String>, Box<dyn Error>>;
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
    fn build_filepath(&self, doctype: &String, docid: &String) -> Result<PathBuf, Box<dyn Error>> {
        if !use_filesystem() {
            let error_message = format!(
                " build_filepathFilesystem features set to off with JACS_USE_FILESYSTEM: {} {}",
                doctype, docid
            );
            error!("{}", error_message);
            return Err(error_message.into());
        }

        let current_dir = env::current_dir()?;
        let jacs_dir = env::var("JACS_DATA_DIRECTORY").expect("JACS_DATA_DIRECTORY");

        let path = current_dir.join(jacs_dir).join(doctype);

        let filename = if docid.ends_with(".json") {
            docid.to_string()
        } else {
            format!("{}.json", docid)
        };

        return Ok(path.join(filename));
    }

    fn build_key_filepath(
        &self,
        doctype: &String,
        key_filename: &String,
    ) -> Result<PathBuf, Box<dyn Error>> {
        if !use_filesystem() {
            let error_message = format!(
                "build_key_filepath Filesystem features set to off with JACS_USE_FILESYSTEM: {} {}",
                doctype, key_filename
            );
            error!("{}", error_message);
            return Err(error_message.into());
        }
        let current_dir = env::current_dir()?;
        return Ok(current_dir
            .join(env::var("JACS_KEY_DIRECTORY").expect("JACS_KEY_DIRECTORY"))
            .join(key_filename));
    }

    fn fs_save_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let pathstring: &String = &env::var("JACS_KEY_DIRECTORY").expect("JACS_DATA_DIRECTORY");
        let default_dir = Path::new(pathstring);
        let private_key_filename = env::var("JACS_AGENT_PRIVATE_KEY_FILENAME")?;
        let binding = self.get_private_key()?;
        let borrowed_key = binding.expose_secret();
        let key_vec = borrowed_key.use_secret();
        let _ = save_private_key(&default_dir, &private_key_filename, &key_vec)?;
        let public_key_filename = env::var("JACS_AGENT_PUBLIC_KEY_FILENAME")?;
        let _ = save_file(&default_dir, &public_key_filename, &self.get_public_key()?);
        Ok(())
    }

    fn fs_load_keys(&mut self) -> Result<(), Box<dyn Error>> {
        //todo save JACS_AGENT_PRIVATE_KEY_PASSWORD
        //todo use filepath builder
        let default_dir = env::var("JACS_KEY_DIRECTORY").expect("JACS_KEY_DIRECTORY");

        let private_key_filename = env::var("JACS_AGENT_PRIVATE_KEY_FILENAME")?;
        let private_key = load_private_key(&default_dir, &private_key_filename)?;
        let public_key_filename = env::var("JACS_AGENT_PUBLIC_KEY_FILENAME")?;
        let public_key = load_key_file(&default_dir, &public_key_filename)?;

        let key_algorithm = env::var("JACS_AGENT_KEY_ALGORITHM")?;
        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// in JACS the public keys need to be added manually
    fn fs_load_public_key(&self, agent_id_and_version: &String) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut default_dir = env::var("JACS_KEY_DIRECTORY").expect("JACS_KEY_DIRECTORY");
        default_dir = format!("{}/public_keys/", default_dir);
        let public_key_filename = format!("{}.pem", agent_id_and_version);
        // todo
        let public_key_type_filename = format!("{}.enc_type", agent_id_and_version);
        return Ok(load_key_file(&default_dir, &public_key_filename)?);
    }

    /// in JACS the public keys need to be added manually
    fn fs_save_remote_public_key(
        &self,
        agent_id_and_version: &String,
        public_key: &[u8],
        public_key_enc_type: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut default_dir = env::var("JACS_KEY_DIRECTORY").expect("JACS_KEY_DIRECTORY");
        default_dir = format!("{}/public_keys/", default_dir);
        let public_key_filename = format!("{}.pem", agent_id_and_version);
        let public_key_type_filename = format!("{}.enc_type", agent_id_and_version);
        let _ = save_file(&Path::new(&default_dir), &public_key_filename, public_key);
        let _ = save_file(
            &Path::new(&default_dir),
            &public_key_type_filename,
            public_key_enc_type,
        );
        Ok(())
    }

    /// a way to load keys that aren't default
    fn fs_preload_keys(
        &mut self,
        private_key_filename: &String,
        public_key_filename: &String,
        custom_key_algorithm: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        //todo save JACS_AGENT_PRIVATE_KEY_PASSWORD
        //todo use filepath builder
        let default_dir = env::var("JACS_KEY_DIRECTORY").expect("JACS_KEY_DIRECTORY");

        let private_key = load_private_key(&default_dir, &private_key_filename)?;
        let public_key = load_key_file(&default_dir, &public_key_filename)?;

        // todo make this optional param
        let key_algorithm = match custom_key_algorithm {
            Some(algo) => algo,
            _ => env::var("JACS_AGENT_KEY_ALGORITHM")?,
        };
        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// on instantiation load and validata all local documents
    fn fs_docs_load_all(&mut self) -> Result<Vec<String>, Box<dyn Error>> {
        Err(not_implemented_error())
    }

    fn fs_agent_load(&self, agentid: &String) -> Result<String, Box<dyn Error>> {
        let agentpath = self.build_filepath(&"agent".to_string(), agentid)?;
        let json_data = fs::read_to_string(agentpath.clone());
        match json_data {
            Ok(data) => {
                debug!("testing data {}", data);
                Ok(data.to_string())
            }
            Err(e) => {
                panic!(
                    "Failed to find agent: agentid {} \nat agentpath {:?} \n{} ",
                    agentid, agentpath, e
                );
            }
        }
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

    fn fs_document_save(
        &self,
        document_id: &String,
        document_string: &String,
        output_filename: Option<String>,
    ) -> Result<String, Box<dyn Error>> {
        if let Err(e) = check_data_directory() {
            error!("Failed to check data directory: {}", e);
        }
        let documentoutput_filename = match output_filename {
            Some(filname) => {
                // optional add jacs
                let re = Regex::new(r"(\.[^.]+)$").unwrap();
                let already_signed = Regex::new(r"\.jacs\.[^.]+$").unwrap();
                let signed_filename = if already_signed.is_match(&filname) {
                    filname.to_string() // Do not modify if '.jacs' is already there
                } else {
                    re.replace(&filname, ".jacs$1").to_string() // Append '.jacs' before the extension
                };
                signed_filename
            }
            _ => document_id.to_string(),
        };

        let document_path =
            self.build_filepath(&"documents".to_string(), &documentoutput_filename)?;
        info!("saving {:?} ", document_path);
        Ok(save_to_filepath(
            &document_path,
            document_string.as_bytes(),
        )?)
    }

    fn fs_get_document_content(&self, document_filepath: String) -> Result<String, Box<dyn Error>> {
        // if file_is_executable(&document_filepath) {
        //     return Err("Executable files are not allowed.".into());
        // }

        // Check if the file path is a local filesystem path
        if !Path::new(&document_filepath).is_file() {
            println!("document_filepath ? {}", document_filepath);
            return Err("File not found, only local filesystem paths are supported.".into());
        }

        let mut contents = Vec::new();
        let mut file = File::open(&document_filepath)?;
        file.read_to_end(&mut contents)?;

        // Compress the contents using gzip
        let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gz_encoder.write_all(&contents)?;
        let compressed_contents = gz_encoder.finish()?;

        // Encode the compressed contents using base64
        let base64_contents = base64::encode(&compressed_contents);

        Ok(base64_contents)
    }
}

/// private Helper function to create a backup file name based on the current timestamp
#[cfg(not(target_arch = "wasm32"))]
fn create_backup_path(file_path: &Path) -> std::io::Result<PathBuf> {
    let timestamp = Utc::now().format("backup-%Y-%m-%d-%H-%M").to_string();
    let file_stem =
        file_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to read file stem",
            ))?;
    let extension = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    let backup_filename = format!("{}.{}.{}", timestamp, file_stem, extension);
    let backup_path = file_path.with_file_name(backup_filename);

    Ok(backup_path)
}

#[cfg(not(target_arch = "wasm32"))]
fn save_private_key(
    file_path: &Path,
    filename: &String,
    private_key: &[u8],
) -> std::io::Result<String> {
    let password = env::var("JACS_PRIVATE_KEY_PASSWORD").unwrap_or_default();
    if !password.is_empty() {
        let encrypted_key = encrypt_private_key(private_key).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Encryption error: {}", e),
            )
        })?;
        let encrypted_filename = if !filename.ends_with(".enc") {
            format!("{}.enc", filename)
        } else {
            filename.to_string()
        };
        save_file(file_path, &encrypted_filename, &encrypted_key)
    } else {
        save_file(file_path, filename, private_key)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn load_private_key(file_path: &String, filename: &String) -> std::io::Result<Vec<u8>> {
    let loaded_key = load_key_file(file_path, filename)?;
    if filename.ends_with(".enc") {
        decrypt_private_key(&loaded_key).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Decryption error: {}", e),
            )
        })
    } else {
        Ok(loaded_key)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn load_key_file(file_path: &String, filename: &String) -> std::io::Result<Vec<u8>> {
    if let Some(parent) = Path::new(file_path).parent() {
        fs::create_dir_all(parent)?;
    }
    let full_path = Path::new(file_path).join(filename);
    return std::fs::read(full_path);
}

#[cfg(not(target_arch = "wasm32"))]
fn save_file(file_path: &Path, filename: &String, content: &[u8]) -> std::io::Result<String> {
    let full_path = file_path.join(filename);
    save_to_filepath(&full_path, content)
}

#[cfg(not(target_arch = "wasm32"))]
fn save_to_filepath(full_path: &PathBuf, content: &[u8]) -> std::io::Result<String> {
    if full_path.exists() {
        let backup_path = create_backup_path(&full_path)?;
        warn!(
            "path exists for {:?}, saving to {:?}",
            full_path, backup_path
        );
        fs::copy(&full_path, backup_path)?;
    }

    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)?; // Create the directory path if it doesn't exist
    }

    fs::write(full_path.clone(), content)?;
    // .to_string_lossy().into_owned()
    match full_path.clone().into_os_string().into_string() {
        Ok(path_string) => Ok(path_string),
        Err(os_string) => {
            // Convert the OsString into an io::Error
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Path contains invalid unicode: {:?}", os_string),
            ))
        }
    }
}
