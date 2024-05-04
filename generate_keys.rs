use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey}};
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // Output the generated keys in PEM format
    println!("{}", private_key.to_pkcs8_pem().unwrap());
    println!("{}", public_key.to_public_key_pem().unwrap());
}
