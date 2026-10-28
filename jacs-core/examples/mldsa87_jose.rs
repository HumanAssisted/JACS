//! Emit public-only JOSE material for independent RFC 9964 interoperability checks.
use jacs_core::{DetachedSigner, Pq2025Signer, jose};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Pq2025Signer::generate()?;
    let jwk = jose::mldsa87_public_jwk(signer.public_key())?;
    let payload =
        jacs_core::canonical::canonicalize_json_try(&serde_json::json!({"hello": "ML-DSA-87"}))?;
    let jws = jose::sign_mldsa87_jws(
        payload.as_bytes(),
        &signer,
        jwk["kid"].as_str().ok_or("missing kid")?,
    )?;
    println!("{}", serde_json::json!({"jwk": jwk, "jws": jws}));
    Ok(())
}
