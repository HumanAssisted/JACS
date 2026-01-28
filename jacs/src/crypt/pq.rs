use pqcrypto_dilithium::dilithium5::{
    DetachedSignature, PublicKey, SecretKey, detached_sign, keypair, verify_detached_signature,
};
use pqcrypto_traits::sign::DetachedSignature as DetachedSignatureTrait;
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;
use pqcrypto_traits::sign::SecretKey as SecretKeyTrait;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::error::Error;

pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let (pk, sk) = keypair();
    Ok((sk.as_bytes().to_vec(), pk.as_bytes().to_vec()))
}

pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, Box<dyn Error>> {
    let secret_key_obj: SecretKey = SecretKey::from_bytes(&secret_key)?;
    // Produce a detached signature, not a signed message
    let signature: DetachedSignature = detached_sign(data.as_bytes(), &secret_key_obj);
    let signature_base64 = B64.encode(signature.as_bytes());
    Ok(signature_base64)
}

pub fn verify_string(
    public_key: Vec<u8>,
    data: &String,
    signature_base64: &String,
) -> Result<(), Box<dyn Error>> {
    let signature_bytes = B64.decode(signature_base64)?;
    let signature = DetachedSignature::from_bytes(&signature_bytes)?;
    let pk = PublicKey::from_bytes(&public_key)?;
    verify_detached_signature(&signature, data.as_bytes(), &pk)
        .map_err(|e| format!("Verification failed: {:?}", e).into())
}
