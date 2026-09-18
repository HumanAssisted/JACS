use sha2::{Digest, Sha256};

// ============================================================================
// Centralized SHA-256 Hash Helpers
// ============================================================================
// All SHA-256 hash computations in JACS should use these helpers for consistency.
// This module provides a layered API: bytes -> string -> specialized use cases.

/// Computes SHA-256 hash of bytes, returns raw 32-byte array.
/// Use this when you need the raw hash bytes for further processing.
#[inline]
pub fn hash_bytes_raw(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

/// Computes SHA-256 hash of bytes, returns lowercase hex string.
/// This is the most common format for displaying/storing hashes.
#[inline]
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// Computes SHA-256 hash of a string (UTF-8 bytes), returns lowercase hex string.
#[inline]
pub fn hash_string(input_string: &str) -> String {
    hash_bytes(input_string.as_bytes())
}

/// Computes SHA-256 hash of a public key with legacy normalization.
/// This function handles BOM detection and normalizes line endings for compatibility.
/// Used primarily for `publicKeyHash` fields in signatures.
pub fn hash_public_key(public_key_bytes: impl AsRef<[u8]>) -> String {
    let public_key_bytes = public_key_bytes.as_ref();
    let (encoding, _) =
        encoding_rs::Encoding::for_bom(public_key_bytes).unwrap_or((encoding_rs::UTF_8, 0));
    let public_key_string = encoding.decode(public_key_bytes).0.into_owned();
    // see test ... cargo test   --test key_tests -- --nocapture
    let normalized = public_key_string.trim().replace("\r", "");
    hash_string(&normalized)
}

#[cfg(test)]
mod tests {
    use super::hash_public_key;

    #[test]
    fn hash_public_key_normalizes_line_endings_and_trailing_whitespace() {
        let with_crlf = b"-----BEGIN KEY-----\r\nabc123\r\n-----END KEY-----\r\n".as_slice();
        let with_lf = b"-----BEGIN KEY-----\nabc123\n-----END KEY-----".as_slice();

        assert_eq!(hash_public_key(with_crlf), hash_public_key(with_lf));
    }

    #[test]
    fn hash_public_key_accepts_vec_and_slice_inputs() {
        let public_key = b"demo-public-key".to_vec();
        let from_vec = hash_public_key(&public_key);
        let from_slice = hash_public_key(public_key.as_slice());

        assert_eq!(from_vec, from_slice);
    }
}
