use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{
    error::{KeyRejected, Unspecified},
    rand,
    signature::{self, KeyPair, UnparsedPublicKey},
};
use std::error::Error;
use std::fmt;

pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(RingError)?;
    let key_pair =
        signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(KeyRejectedError)?;
    let public_key = key_pair.public_key().as_ref().to_vec();
    let private_key = pkcs8_bytes.as_ref().to_vec();
    Ok((private_key, public_key))
}

pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, Box<dyn Error>> {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(&secret_key).map_err(KeyRejectedError)?;
    let signature = key_pair.sign(data.as_bytes());
    let signature_bytes = signature.as_ref();
    let signature_base64 = STANDARD.encode(signature_bytes);
    Ok(signature_base64)
}

pub fn verify_string(
    public_key: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), Box<dyn Error>> {
    let signature_bytes = STANDARD.decode(signature_base64)?;
    let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key);
    public_key
        .verify(data.as_bytes(), &signature_bytes)
        .map_err(RingError)?;
    Ok(())
}

#[derive(Debug)]
struct RingError(Unspecified);

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 cryptographic operation failed: {:?}", self.0)
    }
}

impl Error for RingError {}

impl From<Unspecified> for RingError {
    fn from(error: Unspecified) -> Self {
        RingError(error)
    }
}

#[derive(Debug)]
struct KeyRejectedError(KeyRejected);

impl fmt::Display for KeyRejectedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Ed25519 key parsing failed (invalid PKCS#8 format or corrupted key): {:?}",
            self.0
        )
    }
}

impl Error for KeyRejectedError {}

impl From<KeyRejected> for KeyRejectedError {
    fn from(error: KeyRejected) -> Self {
        KeyRejectedError(error)
    }
}
