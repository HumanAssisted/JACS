use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{BlindedSigningKey, VerifyingKey};

use rsa::sha2::Sha256;

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::Path;

/// best for pure Rust, least secure

static BITSOFBITS: usize = 4096;
static private_key_filename: &str = "rsa_pss_private.pem";
static public_key_filename: &str = "rsa_pss_public.pem";

fn load_private_key_from_file<P: AsRef<Path>>(
    file_path: P,
) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    let pem = std::fs::read_to_string(file_path)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)?;
    Ok(private_key)
}

fn load_public_key_from_file<P: AsRef<Path>>(
    file_path: P,
) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let pem = std::fs::read_to_string(file_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem)?;
    Ok(public_key)
}

/// returns public, public_filepath, private, private_filepath
pub fn generate_keys(
    outputpath: &'static str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, BITSOFBITS).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // let signing_key = BlindedSigningKey::<Sha256>::new(private_key.clone());
    // let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::CRLF)?;

    let private_key_path = super::save_file(
        outputpath,
        &private_key_filename,
        private_key_pem.as_bytes(),
    )?;
    let public_key_path =
        super::save_file(outputpath, &public_key_filename, public_key_pem.as_bytes())?;

    Ok((private_key_path, public_key_path))
}

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
