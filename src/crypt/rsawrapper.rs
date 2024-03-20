use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{BlindedSigningKey, Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use signature::SignatureEncoding;

use rand::{rngs::ThreadRng, thread_rng};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{RandomizedSigner, Verifier};

/// best for pure Rust, least secure

// todo option for more secure
//static BITSOFBITS: usize = 4096;
static BITSOFBITS: usize = 2048;

/// returns public, public_filepath, private, private_filepath
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
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
    let mut rng = thread_rng();
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut rng, data.as_bytes());
    let signature_bytes = signature.to_bytes();
    let signature_base64 = general_purpose::STANDARD.encode(signature_bytes);
    // TODO
    // assert_ne!(signature.to_bytes().as_ref(), data);
    Ok(signature_base64)
}

pub fn verify_string(
    public_key_content: Vec<u8>,
    data: &String,
    signature_base64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_content_converted =
        std::str::from_utf8(&public_key_content).expect("Failed to convert bytes to string");
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_content_converted)?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let signature_bytes = general_purpose::STANDARD.decode(signature_base64)?;
    // println!("Decoded signature bytes: {:?}", signature_bytes);

    let signature = Signature::try_from(signature_bytes.as_slice())?;
    // println!("Created Signature object: {:?}", signature);

    let result = verifying_key.verify(data.as_bytes(), &signature);

    match result {
        Ok(()) => {
            println!("Signature verification succeeded");
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
