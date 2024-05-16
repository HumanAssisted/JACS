use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use std::time::{Duration, Instant};

fn main() {
    let start = Instant::now();
    println!("Starting keypair generation using pqcrypto_dilithium::dilithium5");
    let (pk, sk) = dilithium5::keypair();
    let duration = start.elapsed();

    println!("Keypair generation completed.");
    println!("Public Key: {:?}", pk.as_bytes());
    println!("Secret Key: {:?}", sk.as_bytes());
    println!("Duration: {:?}", duration);

    if duration > Duration::from_secs(10) {
        println!(
            "Warning: Keypair generation took longer than expected: {:?}",
            duration
        );
    }
}
