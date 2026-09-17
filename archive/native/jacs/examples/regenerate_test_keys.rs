//! Rewrap existing, disposable encrypted test fixtures with the current KDF.
//!
//! No raw private-key fixture is read or written. Existing encrypted fixtures
//! and their known test passwords are public interoperability data, never real
//! agent identities. Run manually with: cargo run --example regenerate_test_keys

use jacs::crypt::aes_encrypt::{
    decrypt_private_key_secure_with_password, encrypt_private_key_with_password,
};
use std::{fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = Path::new("tests/fixtures/keys");
    for (name, password) in [
        ("agent-one.private.pem.enc", "secretpassord"),
        ("jacs.private.pq.pem.enc", "testpassword"),
        ("test-ring-Ed25519-private.pem.enc", "testpassword"),
    ] {
        let path = fixtures.join(name);
        let envelope = fs::read(&path)?;
        let private = decrypt_private_key_secure_with_password(&envelope, password)?;
        let updated = encrypt_private_key_with_password(private.as_slice(), password)?;
        fs::write(path, updated)?;
        println!("Rewrapped disposable encrypted fixture: {name}");
    }
    Ok(())
}
