//! ML-DSA (FIPS-204) signature implementation for post-quantum security
//! Uses ML-DSA-87 (security level 5)

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use std::error::Error;
use tracing::trace;

/// Generate ML-DSA-87 keypair
/// Returns (private_key_bytes, public_key_bytes)
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let (pk, sk) = ml_dsa_87::KG::try_keygen()?;
    let sk_bytes = sk.into_bytes().to_vec();
    let pk_bytes = pk.into_bytes().to_vec();
    trace!(
        sk_len = sk_bytes.len(),
        pk_len = pk_bytes.len(),
        "ML-DSA-87 keypair generated"
    );
    Ok((sk_bytes, pk_bytes))
}

/// Sign string data with ML-DSA-87 private key
pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, Box<dyn Error>> {
    // Convert Vec<u8> to fixed-size array
    let sk_array: [u8; 4896] = secret_key
        .try_into()
        .map_err(|v: Vec<u8>| {
            format!(
                "Invalid private key length for ML-DSA-87: expected 4896 bytes, got {} bytes",
                v.len()
            )
        })?;
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_array)?;
    let sig = sk.try_sign(data.as_bytes(), b"")?; // empty context - returns [u8; 4627]
    Ok(B64.encode(sig))
}

/// Verify ML-DSA-87 signature
pub fn verify_string(
    public_key: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), Box<dyn Error>> {
    // Convert Vec<u8> to fixed-size array
    let pk_array: [u8; 2592] = public_key
        .try_into()
        .map_err(|v: Vec<u8>| {
            format!(
                "Invalid public key length for ML-DSA-87: expected 2592 bytes, got {} bytes",
                v.len()
            )
        })?;
    let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_array)?;

    let sig_bytes = B64.decode(signature_base64)?;
    let sig_array: [u8; 4627] = sig_bytes
        .try_into()
        .map_err(|v: Vec<u8>| {
            format!(
                "Invalid signature length for ML-DSA-87: expected 4627 bytes, got {} bytes",
                v.len()
            )
        })?;

    // verify() returns bool, not Result
    if pk.verify(data.as_bytes(), &sig_array, b"") {
        Ok(())
    } else {
        Err("ML-DSA signature verification failed".into())
    }
}
