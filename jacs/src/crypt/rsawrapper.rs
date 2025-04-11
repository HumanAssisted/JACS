use base64::{decode, encode};
use log::debug;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::pss::VerifyingKey;
use rsa::pss::{BlindedSigningKey, Signature};
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{RandomizedSigner, SignatureEncoding, Verifier}; // Correctly import VerifyingKey

/// best for pure Rust, least secure

// Use smaller key size for tests, larger for production
static BITSOFBITS: usize = 4096; // Production value
//static BITSOFBITS: usize = 2048;

/// returns public, public_filepath, private, private_filepath
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, BITSOFBITS).expect("failed to generate a key");
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
    let private_key_content_converted =
        std::str::from_utf8(&private_key_content).expect("Failed to convert bytes to string");
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_content_converted)?;
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut OsRng, data.as_bytes());
    let signature_bytes = signature.to_bytes();
    let signature_base64 = encode(&signature_bytes);
    // TODO
    // assert_ne!(signature.to_bytes().as_ref(), data);
    debug!(
        "xxx sign_string  sig: {}     --------CONTENT: {}",
        signature_base64, data
    );
    Ok(signature_base64)
}

pub fn verify_string(
    public_key_content: Vec<u8>,
    data: &String,
    signature_base64: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_content_converted =
        std::str::from_utf8(&public_key_content).expect("Failed to convert bytes to string");

    debug!(
        "public_key_content_converted {}",
        public_key_content_converted
    );

    let public_key = RsaPublicKey::from_public_key_pem(&public_key_content_converted)?;

    debug!("public_key_content_converted pem {:?}", public_key);

    // Updated instantiation of VerifyingKey
    let verifying_key = VerifyingKey::<Sha256>::from(public_key);
    debug!("verifying_key pem {:?}", verifying_key);

    debug!(
        "xxx verify_string  sig: {}     --------CONTENT: {}",
        signature_base64, data
    );

    let signature_bytes = decode(signature_base64)?;
    debug!("Decoded signature bytes: {:?}", signature_bytes);

    let signature = Signature::try_from(signature_bytes.as_slice())?;
    debug!("Created Signature object: {:?}", signature);

    let result = verifying_key.verify(data.as_bytes(), &signature);

    match result {
        Ok(()) => {
            debug!("Signature verification succeeded");
            Ok(())
        }
        Err(e) => {
            let error_message = format!("Signature verification failed: {}", e);
            eprintln!("{}", error_message);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                error_message,
            )))
        }
    }
}
