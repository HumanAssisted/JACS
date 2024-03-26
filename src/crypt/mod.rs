pub mod hash;
pub mod pq;
pub mod ringwrapper;
pub mod rsawrapper;

use log::{debug, error, warn};

use crate::agent::Agent;

use std::env;
use std::error::Error;

use std::str::FromStr;

use crate::agent::boilerplate::BoilerPlate;
#[cfg(not(target_arch = "wasm32"))]
use crate::agent::loaders::FileLoader;
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

pub const JACS_KEY_DIRECTORY: &str = "JACS_KEY_DIRECTORY";
const JACS_AGENT_PRIVATE_KEY_PASSWORD: &str = "JACS_AGENT_PRIVATE_KEY_PASSWORD";
pub const JACS_AGENT_PRIVATE_KEY_FILENAME: &str = "JACS_AGENT_PRIVATE_KEY_FILENAME";
pub const JACS_AGENT_PUBLIC_KEY_FILENAME: &str = "JACS_AGENT_PUBLIC_KEY_FILENAME";
pub const JACS_AGENT_KEY_ALGORITHM: &str = "JACS_AGENT_KEY_ALGORITHM";

pub trait KeyManager {
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn sign_string(&mut self, data: &String) -> Result<String, Box<dyn std::error::Error>>;
    fn verify_string(
        &mut self,
        data: &String,
        signature_base64: &String,
        public_key: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

impl KeyManager for Agent {
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

        self.set_keys(private_key, public_key, &key_algorithm);
        #[cfg(not(target_arch = "wasm32"))]
        self.fs_save_keys();

        Ok(())
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
        public_key: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key_algorithm = env::var(JACS_AGENT_KEY_ALGORITHM)?;
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                return rsawrapper::verify_string(public_key, data, signature_base64)
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
}
