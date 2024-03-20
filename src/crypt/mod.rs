pub mod hash;
pub mod pq;
pub mod ringwrapper;
pub mod rsawrapper;

use log::{debug, error, warn};

use crate::agent::Agent;
use chrono::Utc;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
enum CryptoSigningAlgorithm {
    RsaPss,
    RingEd25519,
    PqDilithium,
}
/* usage
    match algo {
        CryptoSigningAlgorithm::RsaPss => debug!("Using RSA-PSS"),
        CryptoSigningAlgorithm::RingEd25519 => debug!("Using ring-Ed25519"),
        CryptoSigningAlgorithm::PqDilithium => debug!("Using pq-dilithium"),
    }
*/

const KEY_DIRECTORY: &str = "JACS_KEY_DIRECTORY";
const PRIVATE_KEY_PASSWORD_ENV_VAR: &str = "JACS_AGENT_PRIVATE_KEY_PASSWORD";
const PRIVATE_KEY_FILENAME_ENV_VAR: &str = "JACS_AGENT_PRIVATE_KEY_FILENAME";
const PUBLIC_KEY_FILENAME_ENV_VAR: &str = "JACS_AGENT_PUBLIC_KEY_FILENAME";
const KEY_ALGORITHM_ENV_VAR: &str = "JACS_AGENT_KEY_ALGORITHM";

trait KeyManager {
    fn load_keys(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn generate_keys(&self) -> Result<(), Box<dyn std::error::Error>>;

    /// for validating signatures
    fn get_remote_foreign_agent_public_key(
        &mut self,
        agentid: &String,
    ) -> Result<String, Box<dyn std::error::Error>>;
    fn get_local_foreign_agent_public_key(
        &mut self,
        agentid: &String,
    ) -> Result<String, Box<dyn std::error::Error>>;
    // fn sign_string(filepath: &str, data: &str) -> Result<String, Box<dyn std::error::Error>>;
    // fn verify_string( public_key_path: &str,  data: &str, signature_base64: &str ) -> Result<(), Box<dyn std::error::Error>>;
}

impl KeyManager for Agent {
    fn load_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        //todo save JACS_AGENT_PRIVATE_KEY_PASSWORD
        let default_dir = env::var(KEY_DIRECTORY)?;

        let private_key_filename = env::var(PRIVATE_KEY_FILENAME_ENV_VAR)?;
        let private_key = load_key_file(&default_dir, &private_key_filename)?;
        let public_key_filename = env::var(PUBLIC_KEY_FILENAME_ENV_VAR)?;
        let public_key = load_key_file(&default_dir, &public_key_filename)?;

        let key_algorithm = env::var(KEY_ALGORITHM_ENV_VAR)?;
        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// this necessatates updateding the version of the agent
    fn generate_keys(&self) -> Result<(), Box<dyn std::error::Error>> {
        // todo encrypt private key
        let default_dir = env::var(KEY_DIRECTORY)?;
        let key_algorithm = env::var(KEY_ALGORITHM_ENV_VAR)?;
        let (mut private_key, mut public_key) = (Vec::new(), Vec::new());
        if key_algorithm == "rsa-pss" {
            (private_key, public_key) = rsawrapper::generate_keys().map_err(|e| e.to_string())?;
            let private_key_filename = env::var(PRIVATE_KEY_FILENAME_ENV_VAR)?;
            save_file(&default_dir, &private_key_filename, &private_key);
            let public_key_filename = env::var(PUBLIC_KEY_FILENAME_ENV_VAR)?;
            save_file(&default_dir, &public_key_filename, &public_key);
        } else if key_algorithm == "ring-Ed25519" {
            return Err("ring-Ed25519 key generation is not implemented.".into());
        } else if key_algorithm == "pq-dilithium" {
            return Err("pq-dilithium key generation is not implemented.".into());
        } else {
            // Handle other algorithms or return an error
            return Err(
                format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
            );
        }

        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// for validating signatures
    fn get_remote_foreign_agent_public_key(
        &mut self,
        agentid: &String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Ok("".to_string())
    }
    fn get_local_foreign_agent_public_key(
        &mut self,
        agentid: &String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Ok("".to_string())
    }
}

fn save_file(file_path: &String, filename: &String, content: &[u8]) -> std::io::Result<String> {
    let full_path = Path::new(file_path).join(filename);

    if full_path.exists() {
        let backup_path = create_backup_path(&full_path)?;
        fs::copy(&full_path, backup_path)?;
    }

    fs::write(full_path.clone(), content)?;
    // .to_string_lossy().into_owned()
    match full_path.into_os_string().into_string() {
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

fn load_key_file(file_path: &String, filename: &String) -> std::io::Result<Vec<u8>> {
    let full_path = Path::new(file_path).join(filename);
    return std::fs::read(full_path);
}

// Helper function to create a backup file name based on the current timestamp
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
