#![cfg(feature = "mcp")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jacs_core::sign::SigningAlgorithm;
use jacs_mcp::{JacsMcpServer, Profile, contract, vault};
use serde_json::json;
#[cfg(unix)]
use zeroize::Zeroizing;

#[cfg(unix)]
fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[tokio::test]
async fn default_profile_cannot_reach_any_local_operation() {
    let server = JacsMcpServer::default();
    assert_eq!(server.profile(), Profile::VerifyOnly);
    assert_eq!(server.active_tools().len(), 1);
    assert_eq!(server.active_tools()[0].name, "jacs_verify_document");
    for name in contract::TOOL_NAMES
        .iter()
        .filter(|name| **name != "jacs_verify_document")
    {
        assert!(server.execute(name, json!({})).await.is_err());
    }
    for removed in [
        "jacs_trust_agent",
        "jacs_search",
        "jacs_sign_image",
        "jacs_sign_email",
        "jacs_create_agreement",
        "jacs_a2a_discover",
        "jacs_attest",
    ] {
        assert!(server.execute(removed, json!({})).await.is_err());
    }
    for invalid in ["full", "core", "trust-admin", "legacy-core", " local-sign"] {
        assert!(Profile::parse(invalid).is_err());
    }
}

#[tokio::test]
#[cfg(unix)]
async fn local_scope_create_sign_export_reencrypt_and_verify() {
    let directory = private_dir();
    let path = directory.path().join("identity.json");
    let server = JacsMcpServer::local_sign(
        path.clone(),
        Zeroizing::new("synthetic-old-password".into()),
        Some(Zeroizing::new("synthetic-new-password".into())),
    )
    .unwrap();
    assert_eq!(server.active_tools().len(), 7);
    assert!(
        server
            .execute(
                "jacs_create_agent",
                json!({"password":"must-not-be-accepted"})
            )
            .await
            .is_err()
    );
    let public = server
        .execute("jacs_create_agent", json!({}))
        .await
        .unwrap();
    assert_eq!(public["algorithm"], "pq2025");
    assert!(
        server
            .execute("jacs_create_agent", json!({}))
            .await
            .is_err()
    );
    let signed = server
        .execute("jacs_sign_document", json!({"document":"{\"test\":true}"}))
        .await
        .unwrap();
    assert_eq!(signed["algorithm"], "pq2025");
    let verifier = JacsMcpServer::verify_only();
    let result = verifier.execute("jacs_verify_document", json!({"document":signed["document"].to_string(), "public_key":public["public_key"], "algorithm":"pq2025"})).await.unwrap();
    assert_eq!(result["valid"], true);
    server
        .execute("jacs_reencrypt_key", json!({}))
        .await
        .unwrap();
    let material = vault::read_material(&path).unwrap();
    assert!(vault::unlock(&material, "synthetic-old-password").is_err());
    assert!(vault::unlock(&material, "synthetic-new-password").is_ok());
    assert!(
        server
            .execute("jacs_reencrypt_key", json!({}))
            .await
            .is_err()
    );
    let exported = server
        .execute("jacs_export_encrypted_agent", json!({}))
        .await
        .unwrap();
    assert_eq!(exported["material"]["algorithm"], "pq2025");
    assert!(exported["material"]["encrypted_private_key"].is_string());
    assert!(
        server
            .execute(
                "jacs_sign_document",
                json!({"document":"{\"test\":true,\"test\":false}"})
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn verification_requires_the_explicit_matching_key_and_algorithm() {
    let material = vault::create_material(SigningAlgorithm::Ed25519, "synthetic-password").unwrap();
    let signed = vault::unlock(&material, "synthetic-password")
        .unwrap()
        .sign_message(&json!({"data":42}))
        .unwrap();
    let server = JacsMcpServer::verify_only();
    assert!(server.execute("jacs_verify_document", json!({"document":signed.to_string(), "public_key":STANDARD.encode(&material.public_key), "algorithm":"pq2025"})).await.is_err());
    assert!(server.execute("jacs_verify_document", json!({"document":"x".repeat(1024 * 1024 + 1), "public_key":"", "algorithm":"pq2025"})).await.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn startup_scope_rejects_an_external_identity_even_with_the_same_password() {
    let directory = private_dir();
    let path = directory.path().join("identity.json");
    let password = "synthetic-shared-password";
    let original = vault::create_material(SigningAlgorithm::Ed25519, password).unwrap();
    vault::write_material(&path, &original).unwrap();
    let server =
        JacsMcpServer::local_sign(path.clone(), Zeroizing::new(password.into()), None).unwrap();
    let other = vault::create_material(SigningAlgorithm::Ed25519, password).unwrap();
    vault::replace_material(&path, &original, &other).unwrap();
    assert!(
        server
            .execute("jacs_sign_document", json!({"document":"{}"}))
            .await
            .is_err()
    );
    assert!(
        server
            .execute("jacs_export_encrypted_agent", json!({}))
            .await
            .is_err()
    );
    assert!(server.execute("jacs_rotate_keys", json!({})).await.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn encrypted_import_checks_password_and_never_overwrites() {
    let directory = private_dir();
    let path = directory.path().join("identity.json");
    let material =
        vault::create_material(SigningAlgorithm::Pq2025, "synthetic-import-password").unwrap();
    let args = json!({"material_json":serde_json::to_string(&material).unwrap()});
    let rejected =
        JacsMcpServer::local_sign(path.clone(), Zeroizing::new("wrong-password".into()), None)
            .unwrap();
    assert!(
        rejected
            .execute("jacs_import_encrypted_agent", args.clone())
            .await
            .is_err()
    );
    assert!(!path.exists());
    let server = JacsMcpServer::local_sign(
        path.clone(),
        Zeroizing::new("synthetic-import-password".into()),
        None,
    )
    .unwrap();
    server
        .execute("jacs_import_encrypted_agent", args.clone())
        .await
        .unwrap();
    assert_eq!(
        vault::read_material(&path).unwrap().public_key,
        material.public_key
    );
    assert!(
        server
            .execute("jacs_import_encrypted_agent", args)
            .await
            .is_err()
    );
}

#[tokio::test]
#[cfg(unix)]
async fn failed_persistence_preserves_current_password_and_pending_replacement_password() {
    let directory = private_dir();
    let path = directory.path().join("identity.json");
    let current =
        vault::create_material(SigningAlgorithm::Ed25519, "synthetic-old-password").unwrap();
    vault::write_material(&path, &current).unwrap();
    let server = JacsMcpServer::local_sign(
        path.clone(),
        Zeroizing::new("synthetic-old-password".into()),
        Some(Zeroizing::new("synthetic-new-password".into())),
    )
    .unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("identity.json.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    for tool in ["jacs_reencrypt_key", "jacs_rotate_keys"] {
        let error = server.execute(tool, json!({})).await.unwrap_err();
        assert!(error.message.contains("busy"));
        assert_eq!(vault::read_material(&path).unwrap(), current);
        assert!(
            server
                .execute("jacs_sign_document", json!({"document":"{}"}))
                .await
                .is_ok()
        );
    }
    drop(lock);
    server
        .execute("jacs_reencrypt_key", json!({}))
        .await
        .unwrap();
    let replaced = vault::read_material(&path).unwrap();
    assert_eq!(replaced.agent, current.agent);
    assert!(vault::unlock(&replaced, "synthetic-old-password").is_err());
    assert!(vault::unlock(&replaced, "synthetic-new-password").is_ok());
}

#[test]
fn checked_in_contract_matches_the_only_registered_surface() {
    let snapshot: serde_json::Value =
        serde_json::from_str(include_str!("../contract/jacs-mcp-contract.json")).unwrap();
    assert_eq!(snapshot, contract::canonical_contract_snapshot());
}
