use sha2::{Digest, Sha256};

pub fn hash_string(input_string: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input_string.as_bytes());
    let result = hasher.finalize();
    let hash_string = format!("{:x}", result);
    return hash_string;
}
