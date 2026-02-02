use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::pss::VerifyingKey;
use rsa::pss::{BlindedSigningKey, Signature};
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{RandomizedSigner, SignatureEncoding, Verifier};
use tracing::{debug, trace, warn};

/// best for pure Rust, least secure

// Use smaller key size for tests, larger for production
static BITSOFBITS: usize = 4096; // Production value
//static BITSOFBITS: usize = 2048;

/// returns public, public_filepath, private, private_filepath
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, BITSOFBITS)
        .map_err(|e| format!("Failed to generate RSA key: {}", e))?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::CRLF)?;

    Ok((
        private_key_pem.as_bytes().to_vec(),
        public_key_pem.as_bytes().to_vec(),
    ))
}

pub fn sign_string(
    private_key_content: Vec<u8>,
    data: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let private_key_content_converted = std::str::from_utf8(&private_key_content)
        .map_err(|e| format!("Private key is not valid UTF-8: {}", e))?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_content_converted)?;
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut OsRng, data.as_bytes());
    let signature_bytes = signature.to_bytes();
    let signature_base64 = B64.encode(&signature_bytes);
    trace!(
        data_len = data.len(),
        signature_len = signature_base64.len(),
        "RSA-PSS signing completed"
    );
    Ok(signature_base64)
}

pub fn verify_string(
    public_key_content: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_content_converted = std::str::from_utf8(&public_key_content)
        .map_err(|e| format!("Public key is not valid UTF-8: {}", e))?;

    trace!(
        public_key_len = public_key_content.len(),
        "Parsing RSA public key"
    );

    let public_key = RsaPublicKey::from_public_key_pem(public_key_content_converted)?;

    // Updated instantiation of VerifyingKey
    let verifying_key = VerifyingKey::<Sha256>::from(public_key);

    trace!(
        data_len = data.len(),
        signature_len = signature_base64.len(),
        "RSA-PSS verification starting"
    );

    let signature_bytes = B64.decode(signature_base64)?;
    let signature = Signature::try_from(signature_bytes.as_slice())?;

    let result = verifying_key.verify(data.as_bytes(), &signature);

    match result {
        Ok(()) => {
            debug!("RSA-PSS signature verification succeeded");
            Ok(())
        }
        Err(e) => {
            warn!("RSA-PSS signature verification failed");
            Err(Box::new(std::io::Error::other(format!(
                "Signature verification failed: {}",
                e
            ))))
        }
    }
}
