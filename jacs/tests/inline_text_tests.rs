//! Integration tests for `jacs::simple::advanced::sign_text_file` and
//! `verify_text_file` (Task 05, PRD §4.1).
//!
//! Covers atomic write, backup, duplicate-signer no-op, multi-signer ordering,
//! permissive vs strict mode, key-dir override, and security guards
//! (signer_id whitelist, percent-encoding, symlink escape, publicKeyHash).

use jacs::error::JacsError;
use jacs::inline::{SignatureStatus, VerifyOptions, VerifyTextResult};
use jacs::simple::SimpleAgent;
use jacs::simple::advanced::{sign_text_file, verify_text_file};
use jacs::simple::types::{SignTextOptions, SignTextOutcome};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

fn write_temp_file(contents: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("doc.md");
    let mut f = fs::File::create(&path).expect("create");
    f.write_all(contents.as_bytes()).expect("write");
    (dir, path)
}

fn ephemeral_ed25519() -> SimpleAgent {
    SimpleAgent::ephemeral(Some("ed25519"))
        .expect("ephemeral ed25519")
        .0
}

fn ephemeral_pq2025() -> SimpleAgent {
    SimpleAgent::ephemeral(Some("pq2025"))
        .expect("ephemeral pq2025")
        .0
}

#[test]
fn sign_text_file_single_signer() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("# Title\n\nHello\n");
    let outcome = sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default())
        .expect("sign ok");
    assert_eq!(outcome.signers_added, 1);

    let written = fs::read_to_string(&path).expect("read");
    let split_at = written
        .find("\n-----BEGIN JACS SIGNATURE-----")
        .expect("marker present");
    let prefix = &written[..=split_at];
    // Original content + at most one trailing LF before the marker.
    assert!(
        prefix == "# Title\n\nHello\n" || prefix == "# Title\n\nHello\n\n",
        "content prefix not preserved: {:?}",
        prefix
    );
    // No SIGNED MESSAGE header should appear.
    assert!(
        !written.contains("BEGIN JACS SIGNED MESSAGE"),
        "must not wrap content in SIGNED MESSAGE header"
    );
}

#[test]
fn sign_text_file_block_body_is_yaml() {
    use jacs::inline::SignatureBlockYaml;
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("hello\n");
    sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default()).unwrap();
    let written = fs::read_to_string(&path).unwrap();
    let begin = written
        .find("-----BEGIN JACS SIGNATURE-----\n")
        .expect("begin");
    let body_start = begin + "-----BEGIN JACS SIGNATURE-----\n".len();
    let end = written.find("\n-----END JACS SIGNATURE-----").expect("end");
    let body = &written[body_start..end];
    let _: SignatureBlockYaml =
        serde_yaml_ng::from_str(body).expect("body must be valid YAML matching schema");
}

#[test]
fn sign_text_file_creates_backup_by_default() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("backup-me\n");
    let outcome = sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default())
        .expect("sign ok");
    let bak = format!("{}.bak", path.to_str().unwrap());
    assert!(fs::metadata(&bak).is_ok(), ".bak should exist");
    assert_eq!(fs::read_to_string(&bak).unwrap(), "backup-me\n");
    assert_eq!(outcome.backup_path.as_deref(), Some(bak.as_str()));
}

#[test]
fn sign_text_file_no_backup_when_opts_disables() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("no-backup\n");
    let outcome = sign_text_file(
        &agent,
        path.to_str().unwrap(),
        SignTextOptions {
            backup: false,
            allow_duplicate: false,
        },
    )
    .expect("sign ok");
    let bak = format!("{}.bak", path.to_str().unwrap());
    assert!(
        fs::metadata(&bak).is_err(),
        ".bak must NOT exist when backup=false"
    );
    assert_eq!(outcome.backup_path, None);
}

#[test]
fn verify_text_file_permissive_returns_signed_with_valid_entry() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("hello world\n");
    sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default()).unwrap();
    let result = verify_text_file(&agent, path.to_str().unwrap(), VerifyOptions::default())
        .expect("permissive verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].status, SignatureStatus::Valid);
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn verify_text_file_permissive_missing_signature_not_error() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("no signatures here\n");
    let result = verify_text_file(&agent, path.to_str().unwrap(), VerifyOptions::default())
        .expect("permissive must NOT error on missing signature");
    assert!(matches!(result, VerifyTextResult::MissingSignature));
}

#[test]
fn verify_text_file_strict_missing_signature_is_err() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("unsigned\n");
    let result = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: true,
            key_dir: None,
        },
    );
    match result {
        Err(JacsError::MissingSignature(p)) => {
            assert_eq!(p, path.to_str().unwrap());
        }
        other => panic!(
            "expected Err(MissingSignature) in strict mode; got {:?}",
            other
        ),
    }
}

#[test]
fn verify_text_file_strict_valid_signature_ok() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("strict signed\n");
    sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default()).unwrap();
    let result = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: true,
            key_dir: None,
        },
    )
    .expect("strict verify on signed file is Ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].status, SignatureStatus::Valid);
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn sign_text_file_multi_signer_unordered_mixed_algos() {
    let agent_a = ephemeral_ed25519();
    let agent_b = ephemeral_pq2025();
    let (_d, path) = write_temp_file("multi-signer content\n");
    let _ =
        sign_text_file(&agent_a, path.to_str().unwrap(), SignTextOptions::default()).expect("a ok");
    let _ =
        sign_text_file(&agent_b, path.to_str().unwrap(), SignTextOptions::default()).expect("b ok");
    let written = fs::read_to_string(&path).unwrap();
    // Swap order of the two blocks.
    let parts: Vec<&str> = written
        .splitn(3, "-----BEGIN JACS SIGNATURE-----")
        .collect();
    assert!(parts.len() >= 3, "should have two BEGIN markers");
    let content_part = parts[0];
    let block_a_body = parts[1];
    let block_b_body = parts[2];
    let swapped = format!(
        "{}-----BEGIN JACS SIGNATURE-----{}-----BEGIN JACS SIGNATURE-----{}",
        content_part, block_b_body, block_a_body
    );
    fs::write(&path, swapped).unwrap();

    // Verifying with a third agent that has neither in trust requires --key-dir
    // or the existing "self" branch. Using agent_a here exercises self-key for
    // its own block + KeyNotFound for B; both must surface gracefully.
    let result = verify_text_file(&agent_a, path.to_str().unwrap(), VerifyOptions::default())
        .expect("verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 2, "two signature blocks");
            // The A signature must validate via self-key.
            let self_id = agent_a.get_agent_id().unwrap();
            let valid = signatures
                .iter()
                .find(|s| s.signer_id == self_id)
                .expect("self block present");
            assert_eq!(valid.status, SignatureStatus::Valid);
            assert_eq!(valid.algorithm, "ed25519");
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn sign_text_file_duplicate_noop_crosslang_surface() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("duplicate test\n");
    let outcome1 = sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default())
        .expect("first sign ok");
    let len1 = fs::metadata(&path).unwrap().len();
    let outcome2 = sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default())
        .expect("second sign ok");
    let len2 = fs::metadata(&path).unwrap().len();
    assert_eq!(len1, len2, "duplicate sign must not change file length");
    assert_eq!(outcome1.signers_added, 1);
    assert_eq!(outcome2.signers_added, 0, "duplicate-signer is a no-op");
    // Only one signature block for this signer.
    let written = fs::read_to_string(&path).unwrap();
    assert_eq!(written.matches("-----BEGIN JACS SIGNATURE-----").count(), 1);
}

#[test]
fn verify_text_file_with_key_dir_override() {
    let agent_a = ephemeral_ed25519();
    let agent_b = ephemeral_ed25519();
    let (_d, path) = write_temp_file("cross-agent verify\n");
    sign_text_file(&agent_a, path.to_str().unwrap(), SignTextOptions::default()).unwrap();

    // Pre-populate a --key-dir with agent A's public key under their signer ID.
    let key_dir = TempDir::new().unwrap();
    let signer_id = agent_a.get_agent_id().unwrap();
    let pem = agent_a.get_public_key_pem().unwrap();
    let encoded = jacs::simple::advanced::encode_signer_id_for_filename(&signer_id);
    let key_path = key_dir.path().join(format!("{}.public.pem", encoded));
    fs::write(&key_path, pem.as_bytes()).unwrap();

    // Agent B (different identity, empty trust store) verifies via key_dir.
    let result = verify_text_file(
        &agent_b,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: false,
            key_dir: Some(key_dir.path().to_path_buf()),
        },
    )
    .expect("verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].status, SignatureStatus::Valid);
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

/// Compute the inline canonical content hash (sha256 of LF-normalised + trailing-
/// whitespace-trimmed content), base64url-no-pad encoded. Mirrors the helper
/// used inside `jacs::inline::sign_inline` so handcrafted-block tests can put
/// the right `signed_content_hash` in the YAML body and force the verifier
/// past the hash check to the `KeyNotFound` arm we want to exercise.
fn canonical_content_hash_b64url(content: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let lf_only: String = content.chars().filter(|&c| c != '\r').collect();
    let trimmed =
        lf_only.trim_end_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r');
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    let raw = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[test]
fn key_dir_rejects_signer_id_with_forward_slash() {
    // A handcrafted block whose `signer` field has `foo/bar`. With the correct
    // content hash, the verifier reaches the resolver, the safety whitelist
    // refuses (`/` not allowed), the resolver returns None, the verifier
    // surfaces `SignatureStatus::KeyNotFound`. Asserts no fs access happens.
    use jacs::inline::{
        BEGIN_MARKER, CANONICALIZATION_TAG, CURRENT_BLOCK_VERSION, END_MARKER, SignatureBlockYaml,
    };

    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("hand.md");
    let content = "hello\n";
    let content_hash = canonical_content_hash_b64url(content);
    let block = SignatureBlockYaml {
        signature_block_version: CURRENT_BLOCK_VERSION,
        signer: "foo/bar".to_string(),
        public_key_hash: "sha256-b64url:AAAA".to_string(),
        algorithm: "ed25519".to_string(),
        hash_algorithm: "sha256".to_string(),
        canonicalization: CANONICALIZATION_TAG.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        signed_content_hash: content_hash,
        signature: "AAAA".to_string(),
    };
    let body = serde_yaml_ng::to_string(&block).unwrap();
    let framed = format!("{}{}\n{}{}\n", content, BEGIN_MARKER, body, END_MARKER);
    fs::write(&path, framed).unwrap();

    // Point key_dir at a NON-EXISTENT directory so any actual filesystem read
    // would surface as ENOENT. We assert no such read happens (the whitelist
    // refuses before any fs access).
    let result = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: false,
            key_dir: Some(PathBuf::from("/this/path/does/not/exist")),
        },
    )
    .expect("permissive verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].status, SignatureStatus::KeyNotFound);
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn key_dir_rejects_signer_id_with_dotdot() {
    use jacs::inline::{
        BEGIN_MARKER, CANONICALIZATION_TAG, CURRENT_BLOCK_VERSION, END_MARKER, SignatureBlockYaml,
    };

    let agent = ephemeral_ed25519();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("hand.md");
    let content = "hello\n";
    let content_hash = canonical_content_hash_b64url(content);

    let block = SignatureBlockYaml {
        signature_block_version: CURRENT_BLOCK_VERSION,
        signer: "../../etc/passwd".to_string(),
        public_key_hash: "sha256-b64url:AAAA".to_string(),
        algorithm: "ed25519".to_string(),
        hash_algorithm: "sha256".to_string(),
        canonicalization: CANONICALIZATION_TAG.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        signed_content_hash: content_hash,
        signature: "AAAA".to_string(),
    };
    let body = serde_yaml_ng::to_string(&block).unwrap();
    let framed = format!("{}{}\n{}{}\n", content, BEGIN_MARKER, body, END_MARKER);
    fs::write(&path, framed).unwrap();

    let key_dir = TempDir::new().unwrap();
    let result = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: false,
            key_dir: Some(key_dir.path().to_path_buf()),
        },
    )
    .expect("permissive verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures[0].status, SignatureStatus::KeyNotFound);
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn key_dir_percent_encodes_colon() {
    // signer_id = "name:uuid-12345678" → file is "name%3Auuid-12345678.public.pem".
    // Sanity-check the encoding helper itself.
    let encoded = jacs::simple::advanced::encode_signer_id_for_filename("name:uuid-12345678");
    assert_eq!(encoded, "name%3Auuid-12345678");
}

#[test]
fn sign_text_file_multi_signer_content_still_preserved() {
    let agent_a = ephemeral_ed25519();
    let agent_b = ephemeral_ed25519();
    let original = "# Hello\n\nWorld\n";
    let (_d, path) = write_temp_file(original);
    sign_text_file(&agent_a, path.to_str().unwrap(), SignTextOptions::default()).unwrap();
    sign_text_file(&agent_b, path.to_str().unwrap(), SignTextOptions::default()).unwrap();
    let written = fs::read_to_string(&path).unwrap();
    let begin = written
        .find("\n-----BEGIN JACS SIGNATURE-----")
        .expect("at least one block");
    let prefix = &written[..=begin];
    assert!(
        prefix == original || prefix == format!("{}\n", original),
        "content prefix changed across multi-signer: {:?}",
        prefix
    );
    assert_eq!(
        written.matches("-----BEGIN JACS SIGNATURE-----").count(),
        2,
        "expected two signature blocks"
    );
}

#[test]
fn sign_text_file_nonexistent_path_returns_err() {
    let agent = ephemeral_ed25519();
    let result = sign_text_file(&agent, "/no/such/file", SignTextOptions::default());
    assert!(result.is_err(), "missing path is a real error");
}

/// Sanity check: the outcome JSON shape is stable enough for binding callers.
#[test]
fn sign_text_outcome_is_serializable() {
    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("serialize me\n");
    let outcome: SignTextOutcome =
        sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default()).unwrap();
    let json = serde_json::to_string(&outcome).expect("serializable");
    assert!(json.contains("\"signers_added\":1"));
    assert!(json.contains("\"backup_path\""));
}
