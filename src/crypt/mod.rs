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
use std::str::FromStr;

use crate::agent::boilerplate::BoilerPlate;
use strum_macros::{AsRefStr, Display, EnumString};

#[derive(Debug, AsRefStr, Display, EnumString)]
enum CryptoSigningAlgorithm {
    #[strum(serialize = "RSA-PSS")]
    RsaPss,
    #[strum(serialize = "ring-Ed25519")]
    RingEd25519,
    #[strum(serialize = "pq-dilithium")]
    PqDilithium,
}

const JACS_KEY_DIRECTORY: &str = "JACS_KEY_DIRECTORY";
const JACS_AGENT_PRIVATE_KEY_PASSWORD: &str = "JACS_AGENT_PRIVATE_KEY_PASSWORD";
const JACS_AGENT_PRIVATE_KEY_FILENAME: &str = "JACS_AGENT_PRIVATE_KEY_FILENAME";
const JACS_AGENT_PUBLIC_KEY_FILENAME: &str = "JACS_AGENT_PUBLIC_KEY_FILENAME";
const JACS_AGENT_KEY_ALGORITHM: &str = "JACS_AGENT_KEY_ALGORITHM";

pub trait KeyManager {
    fn load_keys(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    /// for validating signatures
    fn get_remote_foreign_agent_public_key(
        &mut self,
        agentid: &String,
    ) -> Result<String, Box<dyn std::error::Error>>;
    fn get_local_foreign_agent_public_key(
        &mut self,
        agentid: &String,
    ) -> Result<String, Box<dyn std::error::Error>>;
    fn sign_string(&mut self, data: &String) -> Result<String, Box<dyn std::error::Error>>;
    fn verify_string(
        &mut self,
        data: &String,
        signature_base64: &String,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

impl KeyManager for Agent {
    fn load_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        //todo save JACS_AGENT_PRIVATE_KEY_PASSWORD
        let default_dir = env::var(JACS_KEY_DIRECTORY)?;

        let private_key_filename = env::var(JACS_AGENT_PRIVATE_KEY_FILENAME)?;
        let private_key = load_key_file(&default_dir, &private_key_filename)?;
        let public_key_filename = env::var(JACS_AGENT_PUBLIC_KEY_FILENAME)?;
        let public_key = load_key_file(&default_dir, &public_key_filename)?;

        let key_algorithm = env::var(JACS_AGENT_KEY_ALGORITHM)?;
        self.set_keys(private_key, public_key, &key_algorithm)
    }

    /// this necessatates updateding the version of the agent
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // todo encrypt private key
        let default_dir = env::var(JACS_KEY_DIRECTORY)?;
        let key_algorithm = env::var(JACS_AGENT_KEY_ALGORITHM)?;
        let (mut private_key, mut public_key) = (Vec::new(), Vec::new());
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                (private_key, public_key) =
                    rsawrapper::generate_keys().map_err(|e| e.to_string())?;
                let private_key_filename = env::var(JACS_AGENT_PRIVATE_KEY_FILENAME)?;
                save_file(&default_dir, &private_key_filename, &private_key);
                let public_key_filename = env::var(JACS_AGENT_PUBLIC_KEY_FILENAME)?;
                save_file(&default_dir, &public_key_filename, &public_key);
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                return Err("ring-Ed25519 key generation is not implemented.".into());
            }
            CryptoSigningAlgorithm::PqDilithium => {
                return Err("pq-dilithium key generation is not implemented.".into());
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }

        self.set_keys(private_key, public_key, &key_algorithm)
    }

    fn sign_string(&mut self, data: &String) -> Result<String, Box<dyn std::error::Error>> {
        let key_algorithm = env::var(JACS_AGENT_KEY_ALGORITHM)?;
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                return rsawrapper::sign_string(self.get_private_key()?, data)
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                return Err("ring-Ed25519 key generation is not implemented.".into());
            }
            CryptoSigningAlgorithm::PqDilithium => {
                return Err("pq-dilithium key generation is not implemented.".into());
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }
    }
    fn verify_string(
        &mut self,
        data: &String,
        signature_base64: &String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key_algorithm = env::var(JACS_AGENT_KEY_ALGORITHM)?;
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                return rsawrapper::verify_string(self.get_public_key()?, data, signature_base64)
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                return Err("ring-Ed25519 key generation is not implemented.".into());
            }
            CryptoSigningAlgorithm::PqDilithium => {
                return Err("pq-dilithium key generation is not implemented.".into());
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }
        Ok(())
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

// TODO conditionally compile for WASM
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
