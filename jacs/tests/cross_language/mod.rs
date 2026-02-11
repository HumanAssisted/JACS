//! Cross-language interop test fixtures.
//!
//! These tests generate signed documents and export public keys so that
//! Python and Node.js test suites can verify them, proving cross-language
//! signature compatibility.
//!
//! All tests are `#[serial]` because `quickstart()` mutates CWD and env vars.

use jacs::simple::SimpleAgent;
use jacs_binding_core::verify_document_standalone;
use serial_test::serial;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

/// Root of the cross-language fixtures directory (relative to workspace root).
fn fixtures_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tests").join("fixtures").join("cross-language")
}

fn should_update_fixtures() -> bool {
    matches!(
        std::env::var("UPDATE_CROSS_LANG_FIXTURES")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

/// Helper: create an agent via quickstart in a temp dir, sign a document,
/// export everything needed for cross-language verification.
fn generate_fixture(algorithm: &str, prefix: &str) {
    let tmp = std::env::temp_dir().join(format!("jacs_cross_lang_{}", prefix));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create temp dir");

    // Save and restore cwd since quickstart writes relative to cwd
    let original_cwd = std::env::current_dir().expect("get cwd");

    // Clear password env so quickstart generates a fresh one for this agent
    // SAFETY: tests are serial so no concurrent env var access
    unsafe { std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD") };

    std::env::set_current_dir(&tmp).expect("cd to temp");

    let (agent, _info) =
        SimpleAgent::quickstart(Some(algorithm), None).expect("quickstart should succeed");

    // Sign a canonical test payload
    let payload = json!({
        "test": "cross-language-interop",
        "algorithm": algorithm,
        "generated_by": "rust",
        "version": env!("CARGO_PKG_VERSION"),
    });
    let signed = agent.sign_message(&payload).expect("sign should succeed");

    // Parse signed document to extract publicKeyHash and signingAlgorithm
    let signed_value: Value =
        serde_json::from_str(&signed.raw).expect("signed doc should be valid JSON");
    let sig = signed_value
        .get("jacsSignature")
        .expect("signed doc should have jacsSignature");
    let public_key_hash = sig
        .get("publicKeyHash")
        .and_then(|v| v.as_str())
        .expect("should have publicKeyHash")
        .to_string();
    let signing_algorithm = sig
        .get("signingAlgorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Read public key bytes from disk
    let pub_key_path = tmp.join("jacs_keys").join("jacs.public.pem");
    let pub_key_bytes = fs::read(&pub_key_path).expect("read public key file");

    // Restore cwd before writing fixtures
    std::env::set_current_dir(&original_cwd).expect("restore cwd");

    // Write fixtures
    let out = fixtures_dir();
    fs::create_dir_all(&out).expect("create fixtures dir");

    // 1. Signed document
    let signed_path = out.join(format!("{}_signed.json", prefix));
    fs::write(&signed_path, &signed.raw).expect("write signed doc");

    // 2. Public key (raw bytes)
    let key_path = out.join(format!("{}_public_key.pem", prefix));
    fs::write(&key_path, &pub_key_bytes).expect("write public key");

    // 3. Metadata for other languages
    let metadata = json!({
        "algorithm": algorithm,
        "signing_algorithm": signing_algorithm,
        "agent_id": signed.agent_id,
        "document_id": signed.document_id,
        "timestamp": signed.timestamp,
        "public_key_hash": public_key_hash,
        "generated_by": "rust",
        "jacs_version": env!("CARGO_PKG_VERSION"),
    });
    let meta_path = out.join(format!("{}_metadata.json", prefix));
    fs::write(
        &meta_path,
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .expect("write metadata");

    // 4. Public key in the format standalone verify expects:
    //    {data_dir}/public_keys/{hash}.pem and {hash}.enc_type
    let pk_dir = out.join("public_keys");
    fs::create_dir_all(&pk_dir).expect("create public_keys dir");
    fs::write(pk_dir.join(format!("{}.pem", public_key_hash)), &pub_key_bytes)
        .expect("write hash-keyed public key");
    fs::write(
        pk_dir.join(format!("{}.enc_type", public_key_hash)),
        &signing_algorithm,
    )
    .expect("write enc_type");

    // Clean up temp dir
    let _ = fs::remove_dir_all(&tmp);

    println!(
        "Generated {} fixture: signed={}, key={}, meta={}",
        prefix,
        signed_path.display(),
        key_path.display(),
        meta_path.display()
    );
}

/// Verify a previously-generated fixture using verify_document_standalone.
fn verify_fixture(prefix: &str) {
    let out = fixtures_dir();
    let signed_path = out.join(format!("{}_signed.json", prefix));

    assert!(
        signed_path.exists(),
        "Fixture not found: {}. Run generate test first.",
        signed_path.display()
    );

    let signed_doc = fs::read_to_string(&signed_path).expect("read signed fixture");

    // verify_document_standalone re-roots the FS storage at "/" when given
    // absolute paths, so we can pass the fixtures dir directly.
    let out_str = out.to_str().unwrap();
    let result = verify_document_standalone(
        &signed_doc,
        Some("local"),
        Some(out_str),
        Some(out_str),
    )
    .expect("standalone verify should not error");

    assert!(
        result.valid,
        "{} fixture verification failed. signer_id={}, timestamp={}",
        prefix, result.signer_id, result.timestamp
    );
    assert!(
        !result.signer_id.is_empty(),
        "{} fixture should have a signer_id",
        prefix
    );
    assert!(
        !result.timestamp.is_empty(),
        "{} fixture should have a timestamp",
        prefix
    );

    println!(
        "Verified {} fixture: signer={}, timestamp={}",
        prefix, result.signer_id, result.timestamp
    );
}

// ---------------------------------------------------------------------------
// Tests — all serial due to shared CWD and env vars
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn generate_ed25519_fixture() {
    if !should_update_fixtures() {
        eprintln!("Skipping fixture regeneration (set UPDATE_CROSS_LANG_FIXTURES=1 to update)");
        return;
    }
    generate_fixture("ed25519", "ed25519");
}

#[test]
#[serial]
fn generate_pq2025_fixture() {
    if !should_update_fixtures() {
        eprintln!("Skipping fixture regeneration (set UPDATE_CROSS_LANG_FIXTURES=1 to update)");
        return;
    }
    generate_fixture("pq2025", "pq2025");
}

#[test]
#[serial]
fn verify_ed25519_fixture_standalone() {
    if should_update_fixtures() {
        generate_fixture("ed25519", "ed25519");
    }
    verify_fixture("ed25519");
}

#[test]
#[serial]
fn verify_pq2025_fixture_standalone() {
    if should_update_fixtures() {
        generate_fixture("pq2025", "pq2025");
    }
    verify_fixture("pq2025");
}
