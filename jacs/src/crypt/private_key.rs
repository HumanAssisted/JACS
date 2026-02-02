//! Secure private key handling with automatic memory zeroization.
//!
//! This module provides types that ensure private key material is securely
//! erased from memory when it goes out of scope, preventing potential
//! exposure through memory dumps or other side-channel attacks.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper for decrypted private key material that is zeroized on drop.
///
/// This type should be used whenever working with unencrypted private key
/// bytes to ensure the sensitive data is securely erased from memory.
///
/// # Example
/// ```ignore
/// let decrypted = ZeroizingVec::new(decrypt_private_key(encrypted)?);
/// // Use decrypted key...
/// // When decrypted goes out of scope, memory is automatically zeroized
/// ```
#[derive(Clone)]
pub struct ZeroizingVec(Vec<u8>);

impl ZeroizingVec {
    /// Create a new ZeroizingVec from a Vec<u8>.
    ///
    /// The input Vec's contents are moved into the ZeroizingVec.
    pub fn new(data: Vec<u8>) -> Self {
        ZeroizingVec(data)
    }

    /// Get a reference to the underlying bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Get the length of the key material.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the key material is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for ZeroizingVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for ZeroizingVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Automatically zeroize when dropped
impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Mark as ZeroizeOnDrop for compile-time verification
impl ZeroizeOnDrop for ZeroizingVec {}

// Hide contents in debug output
impl std::fmt::Debug for ZeroizingVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizingVec([REDACTED, {} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroizing_vec_basic() {
        let data = vec![1, 2, 3, 4, 5];
        let zv = ZeroizingVec::new(data);
        assert_eq!(zv.as_slice(), &[1, 2, 3, 4, 5]);
        assert_eq!(zv.len(), 5);
        assert!(!zv.is_empty());
    }

    #[test]
    fn test_zeroizing_vec_debug_redacted() {
        let zv = ZeroizingVec::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug_str = format!("{:?}", zv);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("DE"));
        assert!(!debug_str.contains("AD"));
    }

    #[test]
    fn test_as_ref() {
        let zv = ZeroizingVec::new(vec![1, 2, 3]);
        let slice: &[u8] = zv.as_ref();
        assert_eq!(slice, &[1, 2, 3]);
    }
}
