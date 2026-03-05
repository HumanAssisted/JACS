//! Digest utility functions for attestation components.
//!
//! Provides consistent digest computation using JCS canonicalization (RFC 8785).
//! All attestation-level digests use DigestSet (sha256 required, others optional).

use crate::attestation::types::{DigestSet, EvidenceSensitivity};
use crate::crypt::hash::{hash_bytes, hash_string};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;

/// Auto-embed threshold: evidence smaller than 64 KB is embedded by default.
pub const AUTO_EMBED_THRESHOLD: usize = 64 * 1024;

/// Compute a DigestSet from a serde_json Value using JCS canonicalization.
pub fn compute_digest_set(value: &Value) -> Result<DigestSet, Box<dyn Error>> {
    let canonical = serde_json_canonicalizer::to_string(value)?;
    let sha256 = hash_string(&canonical);
    Ok(DigestSet {
        sha256,
        sha512: None,
        additional: HashMap::new(),
    })
}

/// Compute a DigestSet from raw bytes.
pub fn compute_digest_set_bytes(data: &[u8]) -> DigestSet {
    let sha256 = hash_bytes(data);
    DigestSet {
        sha256,
        sha512: None,
        additional: HashMap::new(),
    }
}

/// Compute a DigestSet from a string.
pub fn compute_digest_set_string(s: &str) -> DigestSet {
    let sha256 = hash_string(s);
    DigestSet {
        sha256,
        sha512: None,
        additional: HashMap::new(),
    }
}

/// Whether data should be auto-embedded (< 64KB).
pub fn should_embed(data: &[u8]) -> bool {
    data.len() < AUTO_EMBED_THRESHOLD
}

/// Whether data should be auto-embedded, respecting sensitivity.
/// `Confidential` evidence is never auto-embedded regardless of size.
pub fn should_embed_with_sensitivity(data: &[u8], sensitivity: &EvidenceSensitivity) -> bool {
    if *sensitivity == EvidenceSensitivity::Confidential {
        return false;
    }
    should_embed(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compute_digest_set_sha256() {
        let value = json!({"hello": "world"});
        let ds = compute_digest_set(&value).unwrap();
        assert!(!ds.sha256.is_empty(), "sha256 must be non-empty");
        assert!(ds.sha512.is_none(), "sha512 should be None");
    }

    #[test]
    fn compute_digest_canonical() {
        // JCS canonicalization: different key ordering produces the same digest
        let v1 = json!({"b": 1, "a": 2});
        let v2 = json!({"a": 2, "b": 1});
        let d1 = compute_digest_set(&v1).unwrap();
        let d2 = compute_digest_set(&v2).unwrap();
        assert_eq!(d1.sha256, d2.sha256, "JCS-canonicalized digests must match");
    }

    #[test]
    fn compute_digest_bytes() {
        let data = b"test data";
        let ds = compute_digest_set_bytes(data);
        assert!(!ds.sha256.is_empty());
    }

    #[test]
    fn should_embed_under_threshold() {
        let small = vec![0u8; 100];
        assert!(should_embed(&small));
        let large = vec![0u8; 100_000];
        assert!(!should_embed(&large));
    }

    #[test]
    fn digest_set_from_value() {
        let value = json!({"key": "value"});
        let ds = compute_digest_set(&value).unwrap();
        assert!(!ds.sha256.is_empty());
        // Verify determinism
        let ds2 = compute_digest_set(&value).unwrap();
        assert_eq!(ds.sha256, ds2.sha256);
    }
}
