//! CLI integration tests for `jacs sign-text` and `jacs verify-text`.
//!
//! Covers PRD §3.1 (inline text signing), C1 (strict vs permissive),
//! C2 (content preserved byte-for-byte), and PRD §4.1.5 (--key-dir,
//! filename-safety).
//!
//! Pattern follows `cli_convert_tests.rs`. Uses `assert_cmd` + `tempfile`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestSignText!2026";

fn cmd() -> Command {
    let mut c = Command::cargo_bin("jacs").expect("jacs binary should exist");
    c.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    c
}

fn fresh_tmpdir() -> TempDir {
    TempDir::new().expect("tmpdir")
}

/// Bootstrap a persistent agent in `dir` via `jacs quickstart`. After this,
/// subsequent CLI calls with `current_dir(dir.path())` use the same on-disk
/// agent so sign + verify share key material.
fn bootstrap_agent(dir: &TempDir, algorithm: &str) {
    cmd()
        .current_dir(dir.path())
        .args([
            "quickstart",
            "--algorithm",
            algorithm,
            "--name",
            "test-agent",
            "--domain",
            "localhost",
        ])
        .assert()
        .success();
}

fn write_text(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write text fixture");
    path
}

// =============================================================================
// sign-text — basic flow + content preservation
// =============================================================================

#[test]
fn sign_text_success_exit_zero() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(&dir, "doc.md", "# Hello\n\nA short doc.\n");

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    let after = std::fs::read_to_string(&path).expect("file readable");
    assert!(
        after.contains("-----BEGIN JACS SIGNATURE-----"),
        "signature block must be embedded; got:\n{}",
        after
    );
}

#[test]
fn sign_text_content_preserved_byte_for_byte() {
    // C2: prefix bytes before the first signature marker must equal the
    // original content (modulo at most one optional trailing LF).
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let original = "# Title\n\nbody text\n";
    let path = write_text(&dir, "doc.md", original);

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    let after = std::fs::read_to_string(&path).expect("read");
    let marker = "-----BEGIN JACS SIGNATURE-----";
    let idx = after
        .find(marker)
        .expect("signature marker must appear in signed file");
    let prefix = &after[..idx];
    // Allow at most one trailing LF inserted between content and marker.
    let stripped = prefix.trim_end_matches('\n');
    let original_stripped = original.trim_end_matches('\n');
    assert_eq!(
        stripped, original_stripped,
        "content prefix must equal original byte-for-byte (modulo trailing LF)"
    );
    assert!(
        !after.contains("-----BEGIN JACS SIGNED MESSAGE-----"),
        "no signed-message wrapper should appear"
    );
}

#[test]
fn sign_text_creates_backup_by_default() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let original = "Hello world.\n";
    let path = write_text(&dir, "doc.md", original);

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    let bak_path = dir.path().join("doc.md.bak");
    assert!(bak_path.exists(), "default backup .bak file must exist");
    let bak = std::fs::read_to_string(&bak_path).expect("read .bak");
    assert_eq!(bak, original, ".bak must contain original unsigned bytes");
}

#[test]
fn sign_text_no_backup_flag_suppresses() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(&dir, "doc.md", "x\n");

    cmd()
        .current_dir(dir.path())
        .args(["sign-text", "--no-backup"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    let bak_path = dir.path().join("doc.md.bak");
    assert!(
        !bak_path.exists(),
        "--no-backup must suppress .bak creation"
    );
}

// =============================================================================
// verify-text — happy path + tampering
// =============================================================================

#[test]
fn verify_text_valid_exit_zero() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(&dir, "doc.md", "## Heading\n\nBody.\n");

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .current_dir(dir.path())
        .args(["verify-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn verify_text_tampered_exit_one() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(&dir, "doc.md", "Original body.\n");

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    // Mutate the content prefix by appending text after the original line
    // BEFORE the signature marker. We rewrite the file to have a different
    // prefix while keeping the signature block intact.
    let signed = std::fs::read_to_string(&path).expect("read");
    let marker = "\n-----BEGIN JACS SIGNATURE-----";
    let idx = signed.find(marker).expect("marker present");
    let (prefix, suffix) = signed.split_at(idx);
    let tampered = format!("{}TAMPER{}", prefix, suffix);
    std::fs::write(&path, &tampered).expect("write tampered");

    cmd()
        .current_dir(dir.path())
        .args(["verify-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .code(1);
}

// =============================================================================
// C1: strict vs permissive — missing signature
// =============================================================================

#[test]
fn verify_text_permissive_missing_signature_exit_two() {
    // Fresh .md with no signature → permissive verify exits 2.
    let dir = fresh_tmpdir();
    let path = write_text(&dir, "plain.md", "no signature here\n");

    cmd()
        .current_dir(dir.path())
        .args(["verify-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no JACS signature found"));
}

#[test]
fn verify_text_strict_missing_signature_exit_one() {
    // Fresh .md with no signature → strict verify exits 1 (not 2).
    let dir = fresh_tmpdir();
    let path = write_text(&dir, "plain.md", "no signature here\n");

    cmd()
        .current_dir(dir.path())
        .args(["verify-text", "--strict"])
        .arg(path.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no JACS signature found"));
}

#[test]
fn verify_text_strict_valid_exit_zero() {
    // Strict mode only changes the missing-signature branch — a valid
    // signature still exits 0.
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(&dir, "doc.md", "Body\n");

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .current_dir(dir.path())
        .args(["verify-text", "--strict"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();
}

// =============================================================================
// JSON output shapes
// =============================================================================

#[test]
fn verify_text_json_output_shape() {
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(&dir, "doc.md", "Body\n");

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    let output = cmd()
        .current_dir(dir.path())
        .args(["verify-text", "--json"])
        .arg(path.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value =
        serde_json::from_slice(&output).expect("verify-text --json must emit parseable JSON");
    let status = value
        .get("status")
        .and_then(|v| v.as_str())
        .expect("status field");
    assert!(
        ["signed", "missing_signature", "malformed"].contains(&status),
        "status must be one of signed|missing_signature|malformed; got {}",
        status
    );
    assert_eq!(status, "signed", "should be signed after sign-text");
    assert!(
        value.get("signatures").is_some(),
        "signed result must include signatures array"
    );
}

#[test]
fn verify_text_strict_json_error_shape() {
    // Strict + missing-signature + JSON: error envelope on stderr, exit 1.
    let dir = fresh_tmpdir();
    let path = write_text(&dir, "plain.md", "no signature\n");

    let assert = cmd()
        .current_dir(dir.path())
        .args(["verify-text", "--strict", "--json"])
        .arg(path.to_str().unwrap())
        .assert()
        .code(1);
    let output = assert.get_output().stderr.clone();

    let value: serde_json::Value =
        serde_json::from_slice(&output).expect("strict missing-signature must emit JSON on stderr");
    assert_eq!(
        value.get("error_kind").and_then(|v| v.as_str()),
        Some("MissingSignature"),
        "error_kind must be MissingSignature"
    );
    assert!(
        value.get("error").and_then(|v| v.as_str()).is_some(),
        "error field must be a string"
    );
}

// =============================================================================
// --key-dir override + algorithm coverage
// =============================================================================

#[test]
fn verify_text_pq2025_fixture_exit_zero() {
    // Produce a pq2025-signed file by running `jacs sign-text` in a tmpdir
    // configured to use the pq2025 algorithm via a config file. Then verify
    // it. This proves the CLI routes a non-default algorithm through the
    // full sign/verify pipeline.
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "pq2025");
    let path = write_text(&dir, "doc.md", "PQ body\n");

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    let output = cmd()
        .current_dir(dir.path())
        .args(["verify-text", "--json"])
        .arg(path.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).expect("parse JSON");
    let signatures = value
        .get("signatures")
        .and_then(|v| v.as_array())
        .expect("signatures array");
    assert!(
        signatures
            .iter()
            .any(|s| s.get("algorithm").and_then(|v| v.as_str()) == Some("pq2025")),
        "at least one signature with algorithm=pq2025 must be present; got {:?}",
        signatures
    );
}

#[test]
fn verify_text_key_dir_override() {
    // Agent A signs a file. Fresh agent B (in a different tmpdir, empty
    // trust store) verifies with --key-dir pointing at a directory holding
    // A's public key. This exercises the explicit key-dir resolver arm.
    let agent_a_dir = fresh_tmpdir();
    bootstrap_agent(&agent_a_dir, "ed25519");
    let path = write_text(&agent_a_dir, "doc.md", "A signed this\n");
    cmd()
        .current_dir(agent_a_dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    // Extract A's id + public key from the signed file's signature block.
    let signed = std::fs::read_to_string(&path).expect("read signed");
    let signer_id = extract_first_signer_id(&signed).expect("signer_id present");
    let public_key_pem =
        read_agent_public_key(agent_a_dir.path()).expect("public key file readable");

    // Build a key dir for verification with the percent-encoded filename.
    let key_dir = fresh_tmpdir();
    let encoded = signer_id.replace(':', "%3A");
    let pubkey_path = key_dir.path().join(format!("{}.public.pem", encoded));
    std::fs::write(&pubkey_path, public_key_pem).expect("write pubkey");

    // Verifier B runs from a fresh config-less directory.
    let agent_b_dir = fresh_tmpdir();
    cmd()
        .current_dir(agent_b_dir.path())
        .args(["verify-text", "--key-dir"])
        .arg(key_dir.path().to_str().unwrap())
        .arg(path.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn verify_text_key_dir_rejects_malicious_signer_id() {
    // PRD §4.1.5 filename-safety. Build a signature block with a malicious
    // signer field and confirm verify reports the per-block status as
    // malformed in the --json output, exits 1, and does NOT attempt any
    // filesystem access outside the key_dir.
    let dir = fresh_tmpdir();
    let key_dir = fresh_tmpdir(); // legitimate empty key-dir
    let path = dir.path().join("evil.md");
    let framed = malicious_signer_block();
    std::fs::write(&path, &framed).expect("write framed");

    let output = cmd()
        .current_dir(dir.path())
        .args(["verify-text", "--json", "--key-dir"])
        .arg(key_dir.path().to_str().unwrap())
        .arg(path.to_str().unwrap())
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).expect("parse JSON");
    let signatures = value
        .get("signatures")
        .and_then(|v| v.as_array())
        .expect("signatures array");
    assert!(
        signatures
            .iter()
            .any(|s| s.get("status").and_then(|v| v.as_str()) == Some("malformed")),
        "the malicious signer block should be reported as malformed; got {:?}",
        signatures
    );

    // Pointing --key-dir at a non-existent directory must NOT cause a
    // panic — the malformed status is reached before any FS read of the
    // pubkey file. Use an absolute non-existent path.
    let nonexistent = std::env::temp_dir().join("jacs-nonexistent-keydir-zzz");
    let _ = std::fs::remove_dir_all(&nonexistent);
    let output2 = cmd()
        .current_dir(dir.path())
        .args(["verify-text", "--json", "--key-dir"])
        .arg(nonexistent.to_str().unwrap())
        .arg(path.to_str().unwrap())
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let _value2: serde_json::Value =
        serde_json::from_slice(&output2).expect("parse JSON even with bad key-dir");
}

// =============================================================================
// PRD §4.1.1 column-zero marker refusal
// =============================================================================

#[test]
fn sign_text_refuses_existing_marker_input() {
    // A document containing a column-zero literal JACS-Signature marker
    // (with an unparseable body) must be refused — otherwise an attacker
    // could pre-poison content with a fake signature block.
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(
        &dir,
        "x.md",
        "# Body\n\n-----BEGIN JACS SIGNATURE-----\nbogus: yes\n-----END JACS SIGNATURE-----\n",
    );

    let original_bytes = std::fs::read(&path).expect("read");
    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to sign"));

    // File must be untouched.
    let after_bytes = std::fs::read(&path).expect("read");
    assert_eq!(
        original_bytes, after_bytes,
        "file must be unchanged on refusal"
    );
    let bak_path = dir.path().join("x.md.bak");
    assert!(!bak_path.exists(), "no .bak should be written on refusal");
}

#[test]
fn sign_text_permits_indented_marker_workaround() {
    // PRD §4.1.1 documented workaround: indenting the marker breaks the
    // column-zero literal match and is accepted as ordinary content.
    let dir = fresh_tmpdir();
    bootstrap_agent(&dir, "ed25519");
    let path = write_text(
        &dir,
        "x.md",
        "    -----BEGIN JACS SIGNATURE-----\n    indented prose\n    -----END JACS SIGNATURE-----\n\nReal body\n",
    );

    cmd()
        .current_dir(dir.path())
        .args(["sign-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .current_dir(dir.path())
        .args(["verify-text"])
        .arg(path.to_str().unwrap())
        .assert()
        .success();
}

// =============================================================================
// Helpers
// =============================================================================

/// Read the most-recently-created agent's public key from a fresh-config
/// CWD directory and return it as a normalised PEM string suitable for
/// dropping into a `--key-dir` directory. The on-disk `jacs.public.pem`
/// file actually contains raw algorithm-specific bytes (32B for Ed25519,
/// 2592B for ML-DSA), not real PEM — so we PEM-armor those bytes here.
fn read_agent_public_key(dir: &std::path::Path) -> Option<String> {
    let path = dir.join("jacs_keys").join("jacs.public.pem");
    let raw = std::fs::read(&path).ok()?;
    Some(jacs::crypt::normalize_public_key_pem(&raw))
}

/// Extract the first signer's id from a signed text file. The YAML uses
/// `serde(rename_all = "camelCase")` so the key is plain `signer:` (not
/// `signer_id:` — that was renamed during serialization).
fn extract_first_signer_id(signed: &str) -> Option<String> {
    let begin = "-----BEGIN JACS SIGNATURE-----\n";
    let end = "\n-----END JACS SIGNATURE-----";
    let start = signed.find(begin)? + begin.len();
    let stop = signed[start..].find(end)? + start;
    let body = &signed[start..stop];
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("signer:") {
            return Some(rest.trim().trim_matches('"').to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("signer_id:") {
            return Some(rest.trim().trim_matches('"').to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("signerId:") {
            return Some(rest.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Construct a synthetic framed signature block whose signer field contains
/// path-traversal characters. The block uses the camelCase YAML field names
/// matching `SignatureBlockYaml`'s `serde(rename_all = "camelCase")`.
fn malicious_signer_block() -> String {
    String::from(
        "# Doc\n\
         body\n\
         -----BEGIN JACS SIGNATURE-----\n\
         signatureBlockVersion: 1\n\
         signer: \"../../etc/passwd\"\n\
         publicKeyHash: \"sha256-b64url:bogus\"\n\
         algorithm: ed25519\n\
         hashAlgorithm: sha256\n\
         canonicalization: jacs-inline-text-v1\n\
         timestamp: \"2024-01-01T00:00:00Z\"\n\
         signedContentHash: \"bogus\"\n\
         signature: \"bogus\"\n\
         -----END JACS SIGNATURE-----\n",
    )
}
