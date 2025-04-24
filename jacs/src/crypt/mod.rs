use secrecy::ExposeSecret;
pub mod hash;
pub mod pq;
pub mod ringwrapper;
pub mod rsawrapper;
// pub mod private_key;
pub mod aes_encrypt;

use crate::agent::Agent;
use crate::storage::jenv::get_required_env_var;
use std::str::FromStr;

#[cfg(not(target_arch = "wasm32"))]
use crate::agent::loaders::FileLoader;
use strum_macros::{AsRefStr, Display, EnumString};

use crate::crypt::aes_encrypt::decrypt_private_key;

#[derive(Debug, AsRefStr, Display, EnumString)]
enum CryptoSigningAlgorithm {
    #[strum(serialize = "RSA-PSS")]
    RsaPss,
    #[strum(serialize = "ring-Ed25519")]
    RingEd25519,
    #[strum(serialize = "pq-dilithium")]
    PqDilithium,
}

pub const JACS_AGENT_PRIVATE_KEY_FILENAME: &str = "JACS_AGENT_PRIVATE_KEY_FILENAME";
pub const JACS_AGENT_PUBLIC_KEY_FILENAME: &str = "JACS_AGENT_PUBLIC_KEY_FILENAME";

pub trait KeyManager {
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn sign_string(&mut self, data: &String) -> Result<String, Box<dyn std::error::Error>>;
    fn verify_string(
        &self,
        data: &String,
        signature_base64: &String,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

impl KeyManager for Agent {
    /// this necessatates updateding the version of the agent
    fn generate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let key_algorithm = self.config.as_ref().unwrap().get_key_algorithm()?;
        let (mut private_key, mut public_key) = (Vec::new(), Vec::new());
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                (private_key, public_key) =
                    rsawrapper::generate_keys().map_err(|e| e.to_string())?;
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                (private_key, public_key) =
                    ringwrapper::generate_keys().map_err(|e| e.to_string())?;
            }
            CryptoSigningAlgorithm::PqDilithium => {
                (private_key, public_key) = pq::generate_keys().map_err(|e| e.to_string())?;
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }

        let _ = self.set_keys(private_key, public_key, &key_algorithm);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = self.fs_save_keys();

        Ok(())
    }

    fn sign_string(&mut self, data: &String) -> Result<String, Box<dyn std::error::Error>> {
        let key_algorithm = self.config.as_ref().unwrap().get_key_algorithm()?;
        let algo = CryptoSigningAlgorithm::from_str(&key_algorithm).unwrap();
        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                let binding = self.get_private_key()?;
                let key_vec = decrypt_private_key(binding.expose_secret())?;
                return rsawrapper::sign_string(key_vec, data);
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                let binding = self.get_private_key()?;
                let key_vec = decrypt_private_key(binding.expose_secret())?;
                return ringwrapper::sign_string(key_vec, data);
            }
            CryptoSigningAlgorithm::PqDilithium => {
                let binding = self.get_private_key()?;
                let key_vec = decrypt_private_key(binding.expose_secret())?;
                return pq::sign_string(key_vec, data);
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }
    }
    fn verify_string(
        &self,
        data: &String,
        signature_base64: &String,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key_algorithm = self.config.as_ref().unwrap().get_key_algorithm()?;
        let algo = match public_key_enc_type {
            Some(public_key_enc_type) => CryptoSigningAlgorithm::from_str(&public_key_enc_type)?,
            None => CryptoSigningAlgorithm::from_str(&key_algorithm)?,
        };

        match algo {
            CryptoSigningAlgorithm::RsaPss => {
                return rsawrapper::verify_string(public_key, data, signature_base64);
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                return ringwrapper::verify_string(public_key, data, signature_base64);
            }
            CryptoSigningAlgorithm::PqDilithium => {
                return pq::verify_string(public_key, data, signature_base64);
            }
            _ => {
                return Err(
                    format!("{} is not a known or implemented algorithm.", key_algorithm).into(),
                );
            }
        }
    }
}
