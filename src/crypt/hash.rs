use encoding_rs::Encoding;
use sha2::{Digest, Sha256};

pub fn hash_string(input_string: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input_string.as_bytes());
    let result = hasher.finalize();
    let hashed_string = format!("{:x}", result);
    return hashed_string;
}

pub fn hash_public_key(public_key_bytes: Vec<u8>) -> String {
    let (encoding, _) =
        encoding_rs::Encoding::for_bom(&public_key_bytes).unwrap_or((encoding_rs::UTF_8, 0));
    let public_key_string = encoding.decode(&public_key_bytes).0.into_owned();
    println!("Detected encoding: {:?}", encoding);
    return hash_string(&public_key_string);
}
