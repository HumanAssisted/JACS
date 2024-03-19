use log::debug;
use sha2::{Digest, Sha256};

pub fn hash_string(content: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let result = hasher.finalize();
    debug!("SHA-256 hash: {:x}", result);
    format!("{:x}", result)
}
