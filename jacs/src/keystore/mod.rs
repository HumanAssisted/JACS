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
    fn sign_detached(
        &self,
        _private_key: &[u8],
        _message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>>;
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
        eprintln!(
            "[FsEncryptedStore::generate] Called with algorithm: {}",
            spec.algorithm
        );
        let algo = match spec.algorithm.as_str() {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq-dilithium" => CryptoSigningAlgorithm::PqDilithium,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => return Err(format!("Unsupported algorithm: {}", other).into()),
        };
        eprintln!("[FsEncryptedStore::generate] Matched to enum: {:?}", algo);
        let (priv_key, pub_key) = match algo {
            CryptoSigningAlgorithm::RsaPss => crypt::rsawrapper::generate_keys()?,
            CryptoSigningAlgorithm::RingEd25519 => crypt::ringwrapper::generate_keys()?,
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                crypt::pq::generate_keys()?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                eprintln!("[FsEncryptedStore::generate] Calling pq2025::generate_keys()");
                crypt::pq2025::generate_keys()?
            }
        };
        eprintln!(
            "[FsEncryptedStore::generate] Generated keys: priv={} bytes, pub={} bytes",
            priv_key.len(),
            pub_key.len()
        );
        // Persist using MultiStorage
        let storage = MultiStorage::default_new()?;
        let key_dir = get_required_env_var("JACS_KEY_DIRECTORY", true)?;
        let priv_name = get_required_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", true)?;
        let pub_name = get_required_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", true)?;

        let priv_path = format!("{}/{}", key_dir.trim_start_matches("./"), priv_name);
        let pub_path = format!("{}/{}", key_dir.trim_start_matches("./"), pub_name);

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

    fn sign_detached(
        &self,
        private_key: &[u8],
        message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let algo = match algorithm {
            "RSA-PSS" => CryptoSigningAlgorithm::RsaPss,
            "ring-Ed25519" => CryptoSigningAlgorithm::RingEd25519,
            "pq-dilithium" => CryptoSigningAlgorithm::PqDilithium,
            "pq2025" => CryptoSigningAlgorithm::Pq2025,
            other => return Err(format!("Unsupported algorithm: {}", other).into()),
        };
        let data = std::str::from_utf8(message).unwrap_or("").to_string();
        let sig_b64 = match algo {
            CryptoSigningAlgorithm::RsaPss => {
                crypt::rsawrapper::sign_string(private_key.to_vec(), &data)?
            }
            CryptoSigningAlgorithm::RingEd25519 => {
                crypt::ringwrapper::sign_string(private_key.to_vec(), &data)?
            }
            CryptoSigningAlgorithm::PqDilithium | CryptoSigningAlgorithm::PqDilithiumAlt => {
                crypt::pq::sign_string(private_key.to_vec(), &data)?
            }
            CryptoSigningAlgorithm::Pq2025 => {
                crypt::pq2025::sign_string(private_key.to_vec(), &data)?
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
            fn sign_detached(
                &self,
                _private_key: &[u8],
                _message: &[u8],
                _algorithm: &str,
            ) -> Result<Vec<u8>, Box<dyn Error>> {
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
