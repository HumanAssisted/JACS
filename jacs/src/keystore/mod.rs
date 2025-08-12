use std::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyBackend {
    FsEncrypted,
    VaultTransit,
    AwsKms,
    GcpKms,
    AzureKeyVault,
    Pkcs11,
    IosKeychain,
    AndroidKeystore,
}

#[derive(Debug, Clone, Default)]
pub struct KeySpec {
    pub algorithm: String,      // "RSA-PSS", "ring-Ed25519", "pq-dilithium"
    pub key_id: Option<String>, // Remote key identifier / ARN / URL
}

pub trait KeyStore: Send + Sync {
    fn generate(&self, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>;
    fn load_private(&self) -> Result<Vec<u8>, Box<dyn Error>>;
    fn load_public(&self) -> Result<Vec<u8>, Box<dyn Error>>;
    fn sign_detached(&self, _message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

// Default filesystem-encrypted backend placeholder.
// Current code paths in Agent/crypt already implement FS behavior; this scaffold
// exists for future refactors. For now these functions are unimplemented.
use crate::crypt::aes_encrypt::{decrypt_private_key, encrypt_private_key};
use crate::crypt::{self, CryptoSigningAlgorithm};
use crate::storage::MultiStorage;
use crate::storage::jenv::{get_env_var, get_required_env_var};

pub struct FsEncryptedStore;
impl KeyStore for FsEncryptedStore {
    fn generate(&self, spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let algo = match spec.algorithm.as_str() {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq-dilithium" => CryptoSigningAlgorithm::PqDilithium,
            other => return Err(format!("Unsupported algorithm: {}", other).into()),
        };
        let (priv_key, pub_key) = match algo {
            CryptoSigningAlgorithm::RsaPss => crypt::rsawrapper::generate_keys()?,
            CryptoSigningAlgorithm::RingEd25519 => crypt::ringwrapper::generate_keys()?,
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                crypt::pq::generate_keys()?
            }
        };

        // Save using MultiStorage paths, mirroring Agent fs behavior
        let storage = MultiStorage::default_new()?;
        let key_dir = get_required_env_var("JACS_KEY_DIRECTORY", true)?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;

        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let pub_path = format!("{}/{}", key_dir.trim_start_matches("./"), pub_name);

        // Encrypt private key if password is present
        let password = get_env_var("JACS_PRIVATE_KEY_PASSWORD", false)?.unwrap_or_default();
        if !password.is_empty() {
            let enc = encrypt_private_key(&priv_key)?;
            let final_priv = if !priv_path.ends_with(".enc") {
                format!("{}.enc", priv_path)
            } else {
                priv_path.clone()
            };
            storage.save_file(&final_priv, &enc)?;
        } else {
            storage.save_file(&priv_path, &priv_key)?;
        }
        storage.save_file(&pub_path, &pub_key)?;

        Ok((priv_key, pub_key))
    }

    fn load_private(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let storage = MultiStorage::default_new()?;
        let key_dir = get_required_env_var("JACS_KEY_DIRECTORY", true)?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let bytes = storage
            .get_file(&priv_path, None)
            .or_else(|_| storage.get_file(&format!("{}.enc", priv_path), None))?;
        if priv_path.ends_with(".enc") || bytes.len() > 16 + 12 {
            return Ok(decrypt_private_key(&bytes)?);
        }
        Ok(bytes)
    }

    fn load_public(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let storage = MultiStorage::default_new()?;
        let key_dir = get_required_env_var("JACS_KEY_DIRECTORY", true)?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;
        let pub_path = format!("{}/{}", key_dir.trim_start_matches("./"), pub_name);
        let bytes = storage.get_file(&pub_path, None)?;
        Ok(bytes)
    }

    fn sign_detached(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let algo_str = get_required_env_var("JACS_AGENT_KEY_ALGORITHM", true)?;
        let algo = match algo_str.as_str() {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq-dilithium" => CryptoSigningAlgorithm::PqDilithium,
            other => return Err(format!("Unsupported algorithm: {}", other).into()),
        };
        let sk = self.load_private()?;
        let data = std::str::from_utf8(message).unwrap_or("").to_string();
        let sig_b64 = match algo {
            CryptoSigningAlgorithm::RsaPss => crypt::rsawrapper::sign_string(sk, &data)?,
            CryptoSigningAlgorithm::RingEd25519 => crypt::ringwrapper::sign_string(sk, &data)?,
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                crypt::pq::sign_string(sk, &data)?
            }
        };
        Ok(base64::decode(sig_b64)?)
    }
}

macro_rules! unimplemented_store {
    ($name:ident) => {
        pub struct $name;
        impl KeyStore for $name {
            fn generate(&self, _spec: &KeySpec) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn load_private(&self) -> Result<Vec<u8>, Box<dyn Error>> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn load_public(&self) -> Result<Vec<u8>, Box<dyn Error>> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
            fn sign_detached(&self, _message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
                Err(concat!(stringify!($name), " not implemented").into())
            }
        }
    };
}

unimplemented_store!(VaultTransitStore);
unimplemented_store!(AwsKmsStore);
unimplemented_store!(GcpKmsStore);
unimplemented_store!(AzureKeyVaultStore);
unimplemented_store!(Pkcs11Store);
unimplemented_store!(IosKeychainStore);
unimplemented_store!(AndroidKeystoreStore);
