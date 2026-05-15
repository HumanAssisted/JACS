//! Cross-language provenance fixture tests (Task 13, PRD §5.1 / §5.2).
//!
//! Verifies committed Rust-signed fixtures under
//! `jacs/tests/fixtures/provenance/`. Each binding (Python, Node, Go) has a
//! matching test suite; the contract is that all of them load the same
//! fixtures and reach the same verdicts.
//!
//! To regenerate the fixtures (agent IDs and timestamps will change):
//!
//! ```bash
//! UPDATE_PROVENANCE_FIXTURES=1 cargo test -p jacs --test provenance_cross_language_tests \
//!     -- --ignored regenerate_provenance_fixtures
//! ```

#[path = "support/mod.rs"]
mod support;

use jacs::error::JacsError;
use jacs::inline::{SignatureStatus, VerifyOptions, VerifyTextResult};
use jacs::simple::SimpleAgent;
use jacs::simple::advanced::{verify_image, verify_text_file};
use jacs::simple::types::{MediaVerifyStatus, VerifyImageOptions};
use serde_json::Value;
use serial_test::serial;
use std::fs;
use std::path::PathBuf;

use support::generate_provenance_fixtures::{
    FIXTURE_MARKDOWN, fixtures_dir, keys_dir, regenerate_all, should_regenerate,
};

fn ephemeral_ed25519() -> SimpleAgent {
    SimpleAgent::ephemeral(Some("ed25519"))
        .expect("ephemeral")
        .0
}

fn skip_if_missing(name: &str) -> Option<PathBuf> {
    let path = fixtures_dir().join(name);
    if !path.exists() {
        eprintln!(
            "Skipping: fixture {} not present (run regenerate_provenance_fixtures with \
             UPDATE_PROVENANCE_FIXTURES=1 to materialise it)",
            path.display()
        );
        return None;
    }
    Some(path)
}

// ---------------------------------------------------------------------------
// Fixture regeneration helper (only runs when UPDATE_PROVENANCE_FIXTURES=1).
// ---------------------------------------------------------------------------

/// Regenerate all committed fixtures. Run with:
///
/// ```bash
/// UPDATE_PROVENANCE_FIXTURES=1 cargo test -p jacs --test provenance_cross_language_tests \
///     -- --nocapture --ignored regenerate_provenance_fixtures
/// ```
#[test]
#[ignore]
#[serial]
fn regenerate_provenance_fixtures() {
    if !should_regenerate() {
        eprintln!(
            "Skipping fixture regeneration (set UPDATE_PROVENANCE_FIXTURES=1 to actually \
             regenerate). Re-run with --ignored to invoke this test."
        );
        return;
    }
    regenerate_all().expect("regenerate fixtures");
    println!(
        "Regenerated provenance fixtures at {}",
        fixtures_dir().display()
    );
}

// ---------------------------------------------------------------------------
// Acceptance #2 — Rust verifies Rust-signed fixtures (md, png, jpg, webp).
// ---------------------------------------------------------------------------

#[test]
fn rust_verifies_rust_signed_md_ed25519() {
    let Some(path) = skip_if_missing("rust_signed_ed25519.md") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let result = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: false,
            key_dir: Some(keys_dir()),
        },
    )
    .expect("verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].status, SignatureStatus::Valid);
            assert_eq!(signatures[0].algorithm, "ed25519");
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn rust_verifies_rust_signed_md_pq2025() {
    let Some(path) = skip_if_missing("rust_signed_pq2025.md") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let result = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: false,
            key_dir: Some(keys_dir()),
        },
    )
    .expect("verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].status, SignatureStatus::Valid);
            assert_eq!(signatures[0].algorithm, "pq2025");
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn rust_verifies_rust_signed_md_multi_algo() {
    let Some(path) = skip_if_missing("rust_signed_multi_algo.md") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let result = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: false,
            key_dir: Some(keys_dir()),
        },
    )
    .expect("verify ok");
    match result {
        VerifyTextResult::Signed { signatures } => {
            assert_eq!(signatures.len(), 2, "two signature blocks expected");
            // Both signatures must be Valid.
            for entry in &signatures {
                assert_eq!(
                    entry.status,
                    SignatureStatus::Valid,
                    "block for signer {} not valid: {:?}",
                    entry.signer_id,
                    entry.status
                );
            }
            // Both algorithms present (order is irrelevant per Q3).
            let mut algos: Vec<&str> = signatures.iter().map(|e| e.algorithm.as_str()).collect();
            algos.sort();
            assert_eq!(algos, vec!["ed25519", "pq2025"]);
        }
        other => panic!("expected Signed; got {:?}", other),
    }
}

#[test]
fn rust_verifies_rust_signed_png() {
    let Some(path) = skip_if_missing("rust_signed_ed25519.png") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let result = verify_image(
        &agent,
        path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: false,
                key_dir: Some(keys_dir()),
            },
            scan_robust: false,
        },
    )
    .expect("verify ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
    assert_eq!(result.format.as_deref(), Some("png"));
}

#[test]
fn rust_verifies_rust_signed_jpeg() {
    let Some(path) = skip_if_missing("rust_signed_ed25519.jpg") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let result = verify_image(
        &agent,
        path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: false,
                key_dir: Some(keys_dir()),
            },
            scan_robust: false,
        },
    )
    .expect("verify ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
    assert_eq!(result.format.as_deref(), Some("jpeg"));
}

#[test]
fn rust_verifies_rust_signed_webp() {
    let Some(path) = skip_if_missing("rust_signed_ed25519.webp") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let result = verify_image(
        &agent,
        path.to_str().unwrap(),
        VerifyImageOptions {
            base: VerifyOptions {
                strict: false,
                key_dir: Some(keys_dir()),
            },
            scan_robust: false,
        },
    )
    .expect("verify ok");
    assert_eq!(result.status, MediaVerifyStatus::Valid);
    assert_eq!(result.format.as_deref(), Some("webp"));
}

// ---------------------------------------------------------------------------
// Acceptance #2 — strict + permissive paths on unsigned fixtures (C1).
// ---------------------------------------------------------------------------

#[test]
fn unsigned_md_permissive_returns_missing_signature() {
    let Some(path) = skip_if_missing("unsigned.md") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let result = verify_text_file(&agent, path.to_str().unwrap(), VerifyOptions::default())
        .expect("permissive must not error");
    assert!(matches!(result, VerifyTextResult::MissingSignature));
}

#[test]
fn unsigned_md_strict_raises_missing_signature() {
    let Some(path) = skip_if_missing("unsigned.md") else {
        return;
    };
    let agent = ephemeral_ed25519();
    let res = verify_text_file(
        &agent,
        path.to_str().unwrap(),
        VerifyOptions {
            strict: true,
            key_dir: None,
        },
    );
    match res {
        Err(JacsError::MissingSignature(p)) => {
            assert_eq!(p, path.to_str().unwrap());
        }
        other => panic!("expected MissingSignature; got {:?}", other),
    }
}

#[test]
fn unsigned_images_permissive_and_strict_consistent() {
    let agent = ephemeral_ed25519();
    for name in &["unsigned.png", "unsigned.jpg", "unsigned.webp"] {
        let Some(path) = skip_if_missing(name) else {
            continue;
        };
        // Permissive → MissingSignature status, no Err.
        let permissive = verify_image(
            &agent,
            path.to_str().unwrap(),
            VerifyImageOptions::default(),
        )
        .unwrap_or_else(|e| panic!("permissive {} errored: {:?}", name, e));
        assert_eq!(
            permissive.status,
            MediaVerifyStatus::MissingSignature,
            "{} should be permissive missing_signature",
            name
        );

        // Strict → Err(MissingSignature).
        let strict = verify_image(
            &agent,
            path.to_str().unwrap(),
            VerifyImageOptions {
                base: VerifyOptions {
                    strict: true,
                    key_dir: None,
                },
                scan_robust: false,
            },
        );
        assert!(
            matches!(strict, Err(JacsError::MissingSignature(_))),
            "{} strict should Err MissingSignature; got {:?}",
            name,
            strict
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance #6 — `all_bindings_share_canonical_content_hash` lock test.
// ---------------------------------------------------------------------------
//
// Computes sha256(normalise(content)) of the committed unsigned.md AND
// extracts the first signature block's `content.signedContentHash` from
// rust_signed_ed25519.md. They must be byte-for-byte identical, otherwise
// some part of the canonicalisation contract drifted.

#[test]
fn all_bindings_share_canonical_content_hash() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let Some(unsigned_path) = skip_if_missing("unsigned.md") else {
        return;
    };
    let Some(signed_path) = skip_if_missing("rust_signed_ed25519.md") else {
        return;
    };

    // 1. Compute canonical content hash from unsigned.md.
    let unsigned = fs::read_to_string(&unsigned_path).expect("read unsigned");
    let lf_only: String = unsigned.chars().filter(|&c| c != '\r').collect();
    let trimmed = lf_only.trim_end_matches([' ', '\t', '\n', '\r']);
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    let computed_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    // Sanity — ensure the unsigned fixture matches the canonical body the
    // generator declares. If this fails the lock test would silently no-op
    // against drifted content.
    assert_eq!(
        unsigned, FIXTURE_MARKDOWN,
        "unsigned.md drifted from FIXTURE_MARKDOWN"
    );

    // 2. Extract content.signedContentHash from the first full-JACS footer.
    let signed = fs::read_to_string(&signed_path).expect("read signed");
    let begin = signed
        .find("-----BEGIN JACS SIGNATURE-----\n")
        .expect("BEGIN marker");
    let body_start = begin + "-----BEGIN JACS SIGNATURE-----\n".len();
    let end = signed
        .find("\n-----END JACS SIGNATURE-----")
        .expect("END marker");
    let body = &signed[body_start..end];
    let json = jacs::convert::yaml_to_jacs(body).expect("yaml body parses as JACS");
    let parsed: Value = serde_json::from_str(&json).expect("JACS JSON parses");
    let block_hash = parsed
        .pointer("/content/signedContentHash")
        .and_then(|v| v.as_str())
        .expect("content.signedContentHash present");

    assert_eq!(
        computed_hash, block_hash,
        "canonical content hash drift — unsigned.md and \
         rust_signed_ed25519.md disagree about the signedContentHash"
    );
}
