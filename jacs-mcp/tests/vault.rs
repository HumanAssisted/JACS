#[cfg(unix)]
use jacs_core::agent::CoreAgent;
use jacs_core::sign::SigningAlgorithm;
use jacs_mcp::vault::{self, VaultError};
#[cfg(unix)]
use std::fs;

const PASSWORD: &str = "synthetic-vault-test-password";
const NEW_PASSWORD: &str = "synthetic-replacement-password";

fn private_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

#[test]
#[cfg(unix)]
fn encrypted_roundtrip_reencrypt_and_stale_writer_rejection() {
    let directory = private_dir();
    let path = directory.path().join("agent.json");
    let material = vault::create_material(SigningAlgorithm::Pq2025, PASSWORD).unwrap();
    vault::write_material(&path, &material).unwrap();
    assert!(matches!(
        vault::write_material(&path, &material),
        Err(VaultError::AlreadyExists)
    ));
    assert_eq!(vault::read_material(&path).unwrap(), material);
    assert!(vault::unlock(&material, "wrong password").is_err());

    let replacement = vault::reencrypt(&material, PASSWORD, NEW_PASSWORD).unwrap();
    assert_eq!(replacement.agent, material.agent);
    assert_eq!(replacement.public_key, material.public_key);
    assert_eq!(replacement.algorithm, SigningAlgorithm::Pq2025);
    vault::replace_material(&path, &material, &replacement).unwrap();
    assert!(matches!(
        vault::replace_material(&path, &material, &material),
        Err(VaultError::Conflict)
    ));
    assert_eq!(vault::read_material(&path).unwrap(), replacement);
    assert!(vault::unlock(&replacement, PASSWORD).is_err());
    let mut agent = vault::unlock(&replacement, NEW_PASSWORD).unwrap();
    let signed = agent
        .sign_message(&serde_json::json!({"message":"portable PQ"}))
        .unwrap();
    assert!(
        CoreAgent::verify_with_key(&signed, &replacement.public_key, replacement.algorithm)
            .unwrap()
            .valid
    );
}

#[test]
fn tampered_unsigned_plaintext_duplicate_and_oversized_material_are_rejected() {
    let mut material = vault::create_material(SigningAlgorithm::Ed25519, PASSWORD).unwrap();
    let bytes = serde_json::to_vec(&material).unwrap();
    let mut duplicate = bytes.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"algorithm\":\"ed25519\"}");
    assert!(vault::parse_material(&duplicate).is_err());
    assert!(vault::parse_material(&vec![b' '; vault::MAX_MATERIAL_BYTES + 1]).is_err());
    material.encrypted_private_key = b"plaintext-key".to_vec();
    assert!(vault::validate_material(&material).is_err());
    let mut material = vault::parse_material(&bytes).unwrap();
    material.agent["jacsId"] = "replaced-identity".into();
    assert!(vault::validate_material(&material).is_err());
    material
        .agent
        .as_object_mut()
        .unwrap()
        .remove("jacsSignature");
    assert!(vault::validate_material(&material).is_err());
}

#[test]
fn rotation_preserves_identity_and_carries_authenticated_transition() {
    let material = vault::create_material(SigningAlgorithm::Pq2025, PASSWORD).unwrap();
    let rotated = vault::rotate(&material, PASSWORD, NEW_PASSWORD, None).unwrap();
    assert_eq!(rotated.algorithm, SigningAlgorithm::Pq2025);
    assert_eq!(rotated.agent["jacsId"], material.agent["jacsId"]);
    assert_ne!(rotated.agent["jacsVersion"], material.agent["jacsVersion"]);
    assert_ne!(rotated.public_key, material.public_key);
    assert!(rotated.agent.get("jacsKeyRotationProof").is_some());
    let previous = vault::unlock(&material, PASSWORD).unwrap();
    previous
        .verify_key_rotation(&rotated.agent, &rotated.public_key, rotated.algorithm)
        .unwrap();
    assert!(vault::unlock(&rotated, NEW_PASSWORD).is_ok());
    assert!(
        vault::rotate(
            &material,
            PASSWORD,
            NEW_PASSWORD,
            Some(SigningAlgorithm::Ed25519)
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn files_are_private_and_symlinks_hardlinks_and_public_directories_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = private_dir();
    let path = directory.path().join("agent.json");
    let material = vault::create_material(SigningAlgorithm::Ed25519, PASSWORD).unwrap();
    vault::write_material(&path, &material).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = directory.path().join("link.json");
    symlink(&path, &link).unwrap();
    assert!(vault::read_material(&link).is_err());
    assert!(vault::write_material(&link, &material).is_err());
    let hard = directory.path().join("hard.json");
    fs::hard_link(&path, &hard).unwrap();
    assert!(vault::read_material(&path).is_err());
    fs::remove_file(&hard).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(vault::read_material(&path).is_err());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(vault::write_material(&directory.path().join("another.json"), &material).is_err());
}

#[test]
#[cfg(unix)]
fn simultaneous_writers_cannot_both_create_or_replace() {
    let directory = private_dir();
    let path = directory.path().join("agent.json");
    let material = vault::create_material(SigningAlgorithm::Ed25519, PASSWORD).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = &path;
                let material = &material;
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    vault::write_material(path, material)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let replacement = vault::reencrypt(&material, PASSWORD, NEW_PASSWORD).unwrap();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = &path;
                let material = &material;
                let replacement = &replacement;
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    vault::replace_material(path, material, replacement)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(vault::read_material(&path).unwrap(), replacement);
}

#[cfg(not(unix))]
#[test]
fn unsupported_filesystem_policy_fails_closed() {
    let directory = private_dir();
    let material = vault::create_material(SigningAlgorithm::Ed25519, PASSWORD).unwrap();
    assert!(matches!(
        vault::write_material(&directory.path().join("agent.json"), &material),
        Err(VaultError::UnsupportedPlatform)
    ));
}
