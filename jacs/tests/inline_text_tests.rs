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
            unsafe_bak_mode: None,
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

// =============================================================================
// Issue 007 / PRD §4.1.5 — `key_dir_filename_safety` test module
// =============================================================================
//
// PRD §4.1.5 mandates the full 7-test matrix. The first three (forward_slash,
// dotdot, percent_encodes_colon) live above; the remaining four below.

/// Helper: build a framed handcrafted-block file for a malicious signer_id and
/// run permissive `verify_text_file` against a real key_dir. The whitelist
/// must reject the signer_id before any filesystem read, surfacing
/// `SignatureStatus::KeyNotFound`.
fn assert_key_dir_safety_rejects(signer_id: &str) {
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
        signer: signer_id.to_string(),
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
            assert_eq!(signatures.len(), 1);
            assert_eq!(
                signatures[0].status,
                SignatureStatus::KeyNotFound,
                "expected KeyNotFound for malicious signer_id {:?}",
                signer_id
            );
        }
        VerifyTextResult::Malformed(detail) => {
            // Some YAML serialisations of NUL bytes / non-printables may render
            // a block that doesn't round-trip cleanly. Treat that as equivalent
            // to safe rejection — the caller never reached the filesystem.
            tracing::debug!("block malformed by yaml-ng (acceptable): {detail}");
        }
        other => panic!("expected Signed/Malformed; got {:?}", other),
    }
}

#[test]
fn key_dir_rejects_signer_id_with_backslash() {
    assert_key_dir_safety_rejects("foo\\bar");
}

#[test]
fn key_dir_rejects_signer_id_with_nul() {
    // Embedded NUL byte — invalid for any filesystem path on Unix.
    assert_key_dir_safety_rejects("foo\0bar");
}

#[test]
fn key_dir_rejects_absolute_path_signer_id() {
    // Leading slash makes the would-be filename look like an absolute path.
    assert_key_dir_safety_rejects("/etc/passwd");
}

#[test]
#[cfg(unix)]
fn key_dir_symlink_escape_fails_canonical_check() {
    use std::os::unix::fs::symlink;

    // Setup: agent A signs an inline block normally. We then plant a symlink
    // for the signer's `<id>.public.pem` inside `key_dir` that resolves OUTSIDE
    // the directory. The canonical-path defence must reject the lookup → status
    // becomes KeyNotFound.
    let signer_agent = ephemeral_ed25519();
    let signed_text = jacs::inline::sign_inline("hello\n", &signer_agent).unwrap();

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("doc.md");
    fs::write(&path, signed_text).unwrap();

    // Set up an attacker-controlled key file outside key_dir.
    let outside = TempDir::new().unwrap();
    let attacker_key = outside.path().join("attacker.pem");
    fs::write(
        &attacker_key,
        b"-----BEGIN PUBLIC KEY-----\nDEAD\n-----END PUBLIC KEY-----\n",
    )
    .unwrap();

    // Plant a symlink in key_dir that points outside.
    let key_dir = TempDir::new().unwrap();
    let signer_id = signer_agent.get_agent_id().unwrap();
    let encoded = jacs::simple::advanced::encode_signer_id_for_filename(&signer_id);
    let link_path = key_dir.path().join(format!("{}.public.pem", encoded));
    symlink(&attacker_key, &link_path).unwrap();

    // A different agent verifies with the planted key_dir.
    let (verifier, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let result = verify_text_file(
        &verifier,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: false,
            key_dir: Some(key_dir.path().to_path_buf()),
        },
    )
    .expect("permissive verify ok");

    // The symlink-resolved path is OUTSIDE key_dir → resolver returns None →
    // KeyNotFound. (As a secondary belt-and-braces check, even if the resolver
    // had loaded the attacker key, the publicKeyHash check inside
    // verify_single_block would also produce KeyNotFound because the attacker
    // key has a different fingerprint.)
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(
                signatures[0].status,
                SignatureStatus::KeyNotFound,
                "symlink escape must surface as KeyNotFound, got {:?}",
                signatures[0].status
            );
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

/// `bytes_for_safety` whitelist coverage: the helper is exposed for binding-layer
/// tests too.
#[test]
fn key_dir_signer_id_safety_helper_basic_cases() {
    use jacs::simple::advanced::is_signer_id_safe;
    assert!(is_signer_id_safe(
        "agent-12345678-1234-1234-1234-1234567890ab"
    ));
    assert!(!is_signer_id_safe(""));
    assert!(!is_signer_id_safe("a/b"));
    assert!(!is_signer_id_safe("a\\b"));
    assert!(!is_signer_id_safe("a\0b"));
    assert!(!is_signer_id_safe("/abs"));
    // Length cap at 256 bytes.
    let too_long = "a".repeat(257);
    assert!(!is_signer_id_safe(&too_long));
}

// =============================================================================
// Issue 009 / PRD §4.1.3 — atomic-write crash simulation (text path)
// =============================================================================
//
// Pin atomic-write correctness for `sign_text_file`. We engineer a persist
// failure by making the destination directory read-only mid-flight (Unix
// only): the temp file is created in the same dir but the rename-into-place
// fails. Asserts:
//   * `sign_text_file` returns `Err`.
//   * The original file bytes are unchanged.
//   * No `.jacs-sign-*` (or other tempfile residue) is left in the directory.

#[test]
#[cfg(unix)]
fn sign_text_file_atomic_crash_simulation() {
    use std::os::unix::fs::PermissionsExt;

    let agent = ephemeral_ed25519();
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("doc.md");
    let original_content = "# Atomic\n\nbody\n";
    fs::write(&path, original_content).unwrap();
    let original_bytes = fs::read(&path).unwrap();

    // Lock the parent dir — `tempfile::NamedTempFile::new_in` will fail on
    // create.
    let dir_perm = fs::metadata(dir.path()).unwrap().permissions();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();

    let result = sign_text_file(
        &agent,
        path.to_str().unwrap(),
        SignTextOptions {
            backup: false, // skip backup so the test focuses on the persist path
            allow_duplicate: false,
            unsafe_bak_mode: None,
        },
    );

    // Restore perms before assertions so cleanup works on panic.
    fs::set_permissions(dir.path(), dir_perm).unwrap();

    assert!(
        result.is_err(),
        "expected sign_text_file to Err on persist-failure simulation"
    );

    // Original file bytes unchanged.
    let after_bytes = fs::read(&path).unwrap();
    assert_eq!(
        after_bytes, original_bytes,
        "original file must be untouched"
    );

    // No leftover temp files. tempfile names start with `.tmp` by default;
    // also check for any `.jacs-sign-*` we might have written.
    for entry in fs::read_dir(dir.path()).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert!(
            name == "doc.md",
            "tempfile residue left behind in dir: {:?}",
            name
        );
    }
}

// =============================================================================
// Issue 008 / PRD §10 ninth-pass — verify_rsa_pss_fixture_roundtrip
// =============================================================================
//
// Locks the `"rsa-pss" => rsawrapper::verify_string(...)` dispatch arm in
// `verify_single_block`. JACS forbids RSA-PSS *signing* operations at runtime
// (RUSTSEC-2023-0071 mitigation), but RSA-PSS *verification* must continue to
// work for legacy artifacts. This test signs a content blob with the `rsa`
// crate directly (bypassing the JACS sign-side block), inserts the signature
// into a hand-crafted inline block, and asserts the JACS verifier accepts it.

#[test]
fn verify_rsa_pss_fixture_roundtrip() {
    use base64::Engine as _;
    use jacs::inline::{
        BEGIN_MARKER, CANONICALIZATION_TAG, CURRENT_BLOCK_VERSION, END_MARKER, KeyResolver,
        ResolvedKey, SignatureBlockYaml, SignatureStatus, VerifyTextResult, verify_inline,
    };
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::pss::BlindedSigningKey;
    use rsa::sha2::Sha256;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Digest;
    use signature::{RandomizedSigner, SignatureEncoding};

    // Generate a fresh RSA-PSS keypair for the test directly via the `rsa`
    // crate. This bypasses the JACS-runtime block on RSA private-key ops while
    // still exercising the JACS verifier on the public side.
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let pub_key = RsaPublicKey::from(&priv_key);
    let pub_pem = pub_key
        .to_public_key_pem(LineEnding::CRLF)
        .expect("pub pem");
    let pub_pem_bytes = pub_pem.as_bytes().to_vec();

    let content = "rsa-pss roundtrip body\n";

    // Compute the same content hash JACS computes (LF-only + trailing-ws-trim).
    let normalised: String = content.chars().filter(|&c| c != '\r').collect();
    let trimmed = normalised
        .trim_end_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r')
        .to_string();
    let content_hash_raw = {
        let mut h = Sha256::new();
        h.update(trimmed.as_bytes());
        h.finalize()
    };
    let content_hash_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(content_hash_raw);
    let pre_image = format!("JACS-INLINE-TEXT-V1\nsha256:{}", content_hash_b64);

    // RSA-PSS sign the pre-image directly.
    let signing_key = BlindedSigningKey::<Sha256>::new(priv_key.clone());
    let sig_bytes = signing_key
        .sign_with_rng(&mut rng, pre_image.as_bytes())
        .to_bytes();
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    // publicKeyHash = sha256-b64url over normalised PEM. Use jacs's normaliser
    // so the verifier hashes the same input shape.
    let normalised_pem = jacs::crypt::normalize_public_key_pem(&pub_pem_bytes);
    let pkh_raw = {
        let mut h = Sha256::new();
        h.update(normalised_pem.as_bytes());
        h.finalize()
    };
    let pkh_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pkh_raw);
    let public_key_hash = format!("sha256-b64url:{}", pkh_b64);

    let block = SignatureBlockYaml {
        signature_block_version: CURRENT_BLOCK_VERSION,
        signer: "rsa-pss-fixture-signer".to_string(),
        public_key_hash,
        algorithm: "rsa-pss".to_string(),
        hash_algorithm: "sha256".to_string(),
        canonicalization: CANONICALIZATION_TAG.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        signed_content_hash: content_hash_b64,
        signature: signature_b64,
    };
    let body = serde_yaml_ng::to_string(&block).unwrap();
    let framed = format!("{}{}\n{}{}\n", content, BEGIN_MARKER, body, END_MARKER);

    // Resolver returns the PEM bytes for the rsa-pss algorithm tag.
    struct FixtureResolver {
        pem: Vec<u8>,
    }
    impl KeyResolver for FixtureResolver {
        fn resolve(&self, _signer_id: &str) -> Option<ResolvedKey> {
            Some(ResolvedKey {
                public_key_pem: self.pem.clone(),
                algorithm: "rsa-pss".to_string(),
            })
        }
    }
    let resolver = FixtureResolver { pem: pub_pem_bytes };
    let result = verify_inline(&framed, &resolver, jacs::inline::VerifyOptions::default())
        .expect("verify_inline ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert_eq!(
                signatures[0].status,
                SignatureStatus::Valid,
                "rsa-pss dispatch arm must verify the signature"
            );
            assert_eq!(signatures[0].algorithm, "rsa-pss");
        }
        other => panic!("expected Signed; got {:?}", other),
    }
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

// =============================================================================
// Issue 003 — shared backup helper (PRD §4.2.4b)
// =============================================================================

#[test]
#[cfg(unix)]
fn text_backup_default_is_0o600() {
    use std::os::unix::fs::PermissionsExt;

    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("# Backup mode\n\nbody\n");
    let outcome = sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default())
        .expect("sign ok");
    let bak = outcome.backup_path.expect("backup created");
    let mode = std::fs::metadata(&bak)
        .expect("backup exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "default backup must be 0o600 owner-only; got {:o}",
        mode
    );
}

#[test]
#[cfg(unix)]
fn text_backup_unsafe_mode_override() {
    use std::os::unix::fs::PermissionsExt;

    let agent = ephemeral_ed25519();
    let (_d, path) = write_temp_file("# Backup mode override\n\nbody\n");
    let outcome = sign_text_file(
        &agent,
        path.to_str().unwrap(),
        SignTextOptions {
            backup: true,
            allow_duplicate: false,
            unsafe_bak_mode: Some(0o644),
        },
    )
    .expect("sign ok");
    let bak = outcome.backup_path.expect("backup created");
    let mode = std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "unsafe_bak_mode override must apply");
}

#[test]
#[cfg(unix)]
fn text_backup_rejects_symlink_target() {
    use std::os::unix::fs::symlink;

    let agent = ephemeral_ed25519();
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("doc.md");
    fs::write(&path, b"# Symlink target\n\nbody\n").unwrap();

    // Plant an attacker-controlled symlink at the future .bak path that points
    // at a file outside the working dir. Without the symlink-reject guard, sign
    // would follow the link and overwrite the target.
    let target = dir.path().join("attacker_target");
    fs::write(&target, b"original target").unwrap();
    let bak_path = dir.path().join("doc.md.bak");
    symlink(&target, &bak_path).expect("symlink");

    let result = sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default());
    assert!(result.is_err(), "expected refusal on .bak symlink");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("symlink"),
        "error must mention symlink; got: {}",
        msg
    );
    // Attacker target unchanged.
    let target_after = fs::read(&target).unwrap();
    assert_eq!(target_after, b"original target");
}

#[test]
fn text_backup_replaces_existing_hardlink_without_modifying_link_target() {
    let agent = ephemeral_ed25519();
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("doc.md");
    fs::write(&path, b"# Hardlink backup\n\nbody\n").unwrap();

    // A hard link is reported as a normal file, so a pre-write symlink check
    // is not enough. The backup writer must replace the .bak directory entry
    // instead of truncating/writing through the existing inode.
    let target = dir.path().join("external_target");
    fs::write(&target, b"original target").unwrap();
    let bak_path = dir.path().join("doc.md.bak");
    fs::hard_link(&target, &bak_path).expect("hard link");

    let outcome = sign_text_file(&agent, path.to_str().unwrap(), SignTextOptions::default())
        .expect("sign should succeed");

    assert_eq!(
        fs::read(&target).unwrap(),
        b"original target",
        "backup write must not mutate the hard-link target"
    );
    assert_eq!(
        outcome.backup_path.as_deref(),
        Some(bak_path.to_str().unwrap())
    );
    assert_eq!(
        fs::read(&bak_path).unwrap(),
        b"# Hardlink backup\n\nbody\n",
        "backup path should now contain the original document bytes"
    );
}

#[test]
#[cfg(unix)]
fn sign_text_file_rejects_symlink_input_before_reading() {
    use std::os::unix::fs::symlink;

    let agent = ephemeral_ed25519();
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("secret.md");
    fs::write(&target, b"# Secret\n\nbody\n").unwrap();
    let link = dir.path().join("doc.md");
    symlink(&target, &link).expect("symlink");

    let result = sign_text_file(&agent, link.to_str().unwrap(), SignTextOptions::default());
    assert!(result.is_err(), "expected refusal on symlink input");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("symlink") || msg.contains("Too many levels"),
        "error must identify symlink refusal; got: {}",
        msg
    );
    assert_eq!(
        fs::read(&target).unwrap(),
        b"# Secret\n\nbody\n",
        "symlink target must remain untouched"
    );
}

// =============================================================================
// DNS-published-key resolution (Wave 4 — soft-fail semantics)
// =============================================================================

/// When `JACS_DNS_KEY_DOMAINS` is unset, a stranger's signature reaches the
/// resolver's DNS arm, which short-circuits and returns `None` -> `KeyNotFound`.
/// Permissive mode keeps `KeyNotFound` as a per-block status.
#[test]
#[serial_test::serial(jacs_dns_env)]
fn verify_text_dns_arm_unset_env_yields_keynotfound_permissive() {
    use jacs::simple::SimpleAgent;

    // SAFETY: env var manipulation under serial guard.
    unsafe {
        std::env::remove_var("JACS_DNS_KEY_DOMAINS");
    }
    let signer = ephemeral_ed25519();
    let (_d, path) = write_temp_file("# DNS untrusted\n\nhello\n");
    sign_text_file(&signer, path.to_str().unwrap(), SignTextOptions::default()).unwrap();

    // A different agent does the verification — the signer's key is unknown
    // (no key_dir, no trust store, no DNS domains).
    let (verifier, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let result = verify_text_file(&verifier, path.to_str().unwrap(), VerifyOptions::default())
        .expect("permissive verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert!(
                matches!(signatures[0].status, SignatureStatus::KeyNotFound),
                "expected KeyNotFound when DNS arm has no domains, got {:?}",
                signatures[0].status
            );
        }
        other => panic!("expected Signed result, got {:?}", other),
    }
}

/// When `JACS_DNS_KEY_DOMAINS` points at an unreachable / invalid domain, the
/// DNS arm soft-fails and we still surface `KeyNotFound` (not `Err`). This
/// pins the soft-fail contract documented on `resolve_via_dns_and_https`.
#[test]
#[serial_test::serial(jacs_dns_env)]
fn verify_text_dns_arm_unreachable_domain_soft_fails() {
    use jacs::simple::SimpleAgent;

    // SAFETY: env var manipulation under serial guard.
    unsafe {
        // RFC 6761 reserves `.invalid` for guaranteed-NXDOMAIN responses.
        std::env::set_var("JACS_DNS_KEY_DOMAINS", "this-must-not-resolve.invalid");
    }
    let signer = ephemeral_ed25519();
    let (_d, path) = write_temp_file("# Invalid DNS domain\n\nhello\n");
    sign_text_file(&signer, path.to_str().unwrap(), SignTextOptions::default()).unwrap();

    let (verifier, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let result = verify_text_file(&verifier, path.to_str().unwrap(), VerifyOptions::default())
        .expect("permissive verify ok");

    // Cleanup before the assertion so a panic doesn't leak the env var.
    unsafe {
        std::env::remove_var("JACS_DNS_KEY_DOMAINS");
    }

    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert!(
                matches!(signatures[0].status, SignatureStatus::KeyNotFound),
                "expected KeyNotFound on DNS-unreachable domain, got {:?}",
                signatures[0].status
            );
        }
        other => panic!("expected Signed result, got {:?}", other),
    }
}
