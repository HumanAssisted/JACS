use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{BlindedSigningKey, Signature, VerifyingKey};
use rsa::sha2::Sha256;

use rand::{rngs::ThreadRng, thread_rng};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{RandomizedSigner, Verifier};

/// best for pure Rust, least secure

//static BITSOFBITS: usize = 4096;
static BITSOFBITS: usize = 2048;
static RSA_PSS_PRIVATE_KEY_FILENAME: &str = "rsa_pss_private.pem";
static RSA_PSS_PUBLIC_KEY_FILENAME: &str = "rsa_pss_public.pem";

fn load_private_key_from_file(
    filepath: &'static str,
) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    let pem = super::load_file(filepath, RSA_PSS_PRIVATE_KEY_FILENAME)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)?;
    Ok(private_key)
}

fn load_public_key_from_file(
    filepath: &'static str,
) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let pem = super::load_file(filepath, RSA_PSS_PUBLIC_KEY_FILENAME)?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem)?;
    Ok(public_key)
}

/// returns public, public_filepath, private, private_filepath
pub fn generate_keys(
    filepath: &'static str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, BITSOFBITS).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::CRLF)?;

    let private_key_path = super::save_file(
        filepath,
        RSA_PSS_PRIVATE_KEY_FILENAME,
        private_key_pem.as_bytes(),
    )?;
    let public_key_path = super::save_file(
        filepath,
        RSA_PSS_PUBLIC_KEY_FILENAME,
        public_key_pem.as_bytes(),
    )?;

    Ok((private_key_path, public_key_path))
}

pub fn sign_string(
    filepath: &'static str,
    data: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let private_key = load_private_key_from_file(filepath)?;
    // let mut rng = OsRng;
    let mut rng = thread_rng();
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut rng, data.as_bytes());
    // let signature = private_key.sign(&mut rng, padding, data.as_bytes())?;
    let signature_bytes = signature.to_string();
    let signature_base64 = general_purpose::STANDARD.encode(signature_bytes);
    // TODO
    // assert_ne!(signature.to_bytes().as_ref(), data);
    Ok(signature_base64)
}

// pub fn verify_string(filepath: &'static str, data: &str, signature_base64: &str) -> Result<(), Box<dyn std::error::Error>> {
//     let public_key = load_public_key_from_file(filepath)?;

//     let verifying_key = VerifyingKey::<Sha256>::new(public_key);

//     let signature_bytes = general_purpose::STANDARD.decode(signature_base64)?;
//     let signature = Signature::try_from(signature_bytes.as_slice())?;

//     let result = verifying_key.verify(data.as_bytes(), &signature);

//     match result {
//         Ok(()) => Ok(()),
//         Err(e) => {
//             let error_message = format!("Signature verification failed: {}", e);
//             Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, error_message)))
//         }
//     }
// }

pub fn verify_string(
    public_key_path: &'static str,
    data: &str,
    signature_base64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = load_public_key_from_file(public_key_path)?;
    println!("Loaded public key: {:?}", public_key);

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let signature_bytes = general_purpose::STANDARD.decode(signature_base64)?;
    println!("Decoded signature bytes: {:?}", signature_bytes);

    let signature = Signature::try_from(signature_bytes.as_slice())?;
    println!("Created Signature object: {:?}", signature);

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

// pub fn verify_string(public_key_path: &'static str, data: &str, signature_base64: &str) -> Result<(), Box<dyn std::error::Error>> {
//     let public_key = load_public_key_from_file(public_key_path)?;
//     let verifying_key = VerifyingKey::<Sha256>::new(public_key);

//     let signature_bytes = general_purpose::STANDARD.decode(signature_base64)?;
//     let signature = rsa::pss::Signature::from_bytes(&signature_bytes)?;

//     let result = verifying_key.verify(data.as_bytes(), &signature);

//     match result {
//         Ok(()) => Ok(()),
//         Err(e) => Err(Box::new(e)),
//     }
// }

// // Sign
// let data = b"hello world";
// let signature = signing_key.sign_with_rng(&mut rng, data);
// assert_ne!(signature.to_bytes().as_ref(), data);

//     match is_signature_different(signature, data) {
//         Ok(()) => {
//             // Continue processing as normal
//         },
//         Err(err_msg) => {
//             // Handle the error
//             // e.g. return Err from the current function if it also returns a Result
//             return Err(err_msg);
//         },
//     }

// // Verify
// let verifying_key = signing_key.verifying_key();
// verifying_key.verify(data, &signature).expect("failed to verify");
