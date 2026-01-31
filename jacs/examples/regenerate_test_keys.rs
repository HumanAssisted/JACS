//! Utility to regenerate test encrypted keys with the new PBKDF2 KDF
//!
//! Run with: cargo run --example regenerate_test_keys

use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures_dir = Path::new("tests/fixtures/keys");

    // Re-encrypt agent-one.private.pem with "secretpassord"
    // (matches set_min_test_env_vars in tests/utils.rs)
    unsafe {
        env::set_var("JACS_PRIVATE_KEY_PASSWORD", "secretpassord");
    }

    let agent_one_path = fixtures_dir.join("agent-one.private.pem");
    if agent_one_path.exists() {
        println!("Re-encrypting agent-one.private.pem with password 'secretpassord'...");
        let private_key = fs::read(&agent_one_path)?;
        let encrypted = jacs::crypt::aes_encrypt::encrypt_private_key(&private_key)?;
        fs::write(fixtures_dir.join("agent-one.private.pem.enc"), &encrypted)?;
        println!(
            "  Created agent-one.private.pem.enc ({} bytes)",
            encrypted.len()
        );
    }

    // Re-encrypt test-pq-private.pem -> jacs.private.pq.pem.enc with "testpassword"
    // (matches pq.jacs.config.json)
    unsafe {
        env::set_var("JACS_PRIVATE_KEY_PASSWORD", "testpassword");
    }

    let pq_path = fixtures_dir.join("test-pq-private.pem");
    if pq_path.exists() {
        println!("Re-encrypting test-pq-private.pem with password 'testpassword'...");
        let private_key = fs::read(&pq_path)?;
        let encrypted = jacs::crypt::aes_encrypt::encrypt_private_key(&private_key)?;
        fs::write(fixtures_dir.join("jacs.private.pq.pem.enc"), &encrypted)?;
        println!(
            "  Created jacs.private.pq.pem.enc ({} bytes)",
            encrypted.len()
        );
    }

    // For ring-Ed25519, use "testpassword"
    // (matches get_ring_config() in tests/ring_tests.rs which overrides the config)
    unsafe {
        env::set_var("JACS_PRIVATE_KEY_PASSWORD", "testpassword");
    }

    let ring_path = fixtures_dir.join("test-ring-Ed25519-private.pem");
    if ring_path.exists() {
        println!("Re-encrypting test-ring-Ed25519-private.pem with password 'testpassword'...");
        let private_key = fs::read(&ring_path)?;
        let encrypted = jacs::crypt::aes_encrypt::encrypt_private_key(&private_key)?;
        fs::write(
            fixtures_dir.join("test-ring-Ed25519-private.pem.enc"),
            &encrypted,
        )?;
        println!(
            "  Created test-ring-Ed25519-private.pem.enc ({} bytes)",
            encrypted.len()
        );
    } else {
        println!("Warning: test-ring-Ed25519-private.pem not found, skipping");
    }

    println!("\nDone! Test encrypted keys regenerated with PBKDF2 KDF.");
    Ok(())
}
