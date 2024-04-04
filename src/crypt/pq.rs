use pqcrypto_dilithium::dilithium5::{
    keypair, sign, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::DetachedSignature as DetachedSignatureTrait;
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;
use pqcrypto_traits::sign::SecretKey as SecretKeyTrait;
use pqcrypto_traits::sign::SignedMessage as SignedMessageTrait;

use std::error::Error;

pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let (pk, sk) = keypair();
    Ok((sk.as_bytes().to_vec(), pk.as_bytes().to_vec()))
}

pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, Box<dyn Error>> {
    let mut secret_key_obj: SecretKey = SecretKey::from_bytes(&secret_key)?;
    let signature = sign(data.as_bytes(), &secret_key_obj);
    let signature_bytes = signature.as_bytes();
    let signature_base64 = base64::encode(signature_bytes);
    Ok(signature_base64)
}

pub fn verify_string(
    public_key: Vec<u8>,
    data: &String,
    signature_base64: &String,
) -> Result<(), Box<dyn Error>> {
    let signature_bytes = base64::decode(signature_base64)?;
    let signature = DetachedSignature::from_bytes(&signature_bytes)?;
    let pk = PublicKey::from_bytes(&public_key)?;
    verify_detached_signature(&signature, data.as_bytes(), &pk)
        .map_err(|e| format!("Verification failed: {:?}", e).into())
}
