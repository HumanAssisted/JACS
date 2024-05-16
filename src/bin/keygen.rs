use rand::rngs::OsRng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};

fn main() {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // Output the generated keys in PEM format
    // Unwrap the Result and then dereference to get the inner String for printing
    println!(
        "{}",
        private_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    );
    println!(
        "{}",
        public_key
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    );
}
