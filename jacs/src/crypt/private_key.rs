//! Secure private key handling with automatic memory zeroization and memory pinning.
//!
//! This module provides types that ensure private key material is securely
//! erased from memory when it goes out of scope, preventing potential
//! exposure through memory dumps or other side-channel attacks.
//!
//! ## Types
//!
//! - [`ZeroizingVec`]: Zeroizes memory on drop. Suitable for transient decryption buffers.
//! - [`LockedVec`]: Pins memory with `mlock()` (prevents swap), excludes from core dumps
//!   via `madvise(MADV_DONTDUMP)` on Linux, and zeroizes on drop. Preferred for long-lived
//!   key storage (e.g., `InMemoryKeyStore`).

use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Platform-specific memory locking helpers
// ---------------------------------------------------------------------------

/// Lock a memory region so it cannot be paged to swap.
/// Returns `true` if mlock succeeded, `false` otherwise (non-fatal).
#[cfg(unix)]
fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Unlock a previously mlocked memory region.
#[cfg(unix)]
fn unlock_memory(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Exclude a memory region from core dumps (Linux only).
/// On macOS this is a no-op because core dumps are disabled by default for
/// non-root processes.
#[cfg(unix)]
fn exclude_from_core_dump(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
    }
    // macOS: no-op (core dumps disabled by default for non-root)
    #[cfg(not(target_os = "linux"))]
    let _ = (ptr, len);
}

#[cfg(not(unix))]
fn lock_memory(_ptr: *const u8, _len: usize) -> bool {
    false
}
#[cfg(not(unix))]
fn unlock_memory(_ptr: *const u8, _len: usize) {}
#[cfg(not(unix))]
fn exclude_from_core_dump(_ptr: *const u8, _len: usize) {}

// ---------------------------------------------------------------------------
// LockedVec — mlock'd + zeroize-on-drop wrapper for private key bytes
// ---------------------------------------------------------------------------

/// A `Vec<u8>` whose backing memory is mlock'd (pinned to RAM, excluded from
/// core dumps) and zeroized on drop.
///
/// Falls back gracefully if `mlock()` fails (e.g., `RLIMIT_MEMLOCK` exhausted
/// in an unprivileged container). In that case a `tracing::warn!` is emitted
/// but the vec remains fully usable — security is degraded, not broken.
///
/// Preferred over [`ZeroizingVec`] for long-lived key storage such as
/// `InMemoryKeyStore`.
pub struct LockedVec {
    inner: Vec<u8>,
    /// Whether mlock() succeeded on construction.
    locked: bool,
}

impl LockedVec {
    /// Create a new `LockedVec`, calling `mlock()` on the backing buffer and
    /// `madvise(MADV_DONTDUMP)` on Linux.
    pub fn new(data: Vec<u8>) -> Self {
        let locked = lock_memory(data.as_ptr(), data.len());
        if !locked && !data.is_empty() {
            tracing::warn!(
                bytes = data.len(),
                "mlock failed for key material; memory may be swappable. \
                 This is non-fatal but reduces security on this platform."
            );
        }
        exclude_from_core_dump(data.as_ptr(), data.len());
        LockedVec {
            inner: data,
            locked,
        }
    }

    /// Returns `true` if the memory was successfully mlocked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Get a reference to the underlying bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Get the length of the key material.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the key material is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<[u8]> for LockedVec {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Zeroize for LockedVec {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for LockedVec {
    fn drop(&mut self) {
        // Zeroize BEFORE unlocking so the zeroed page cannot be swapped out
        // between the zeroize and munlock calls.
        self.inner.zeroize();
        if self.locked {
            // Use capacity, not len (which is 0 after zeroize on Vec), to
            // ensure the full allocation is unlocked.
            unlock_memory(self.inner.as_ptr(), self.inner.capacity());
        }
    }
}

impl ZeroizeOnDrop for LockedVec {}

impl std::fmt::Debug for LockedVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LockedVec([REDACTED, {} bytes, locked={}])",
            self.inner.len(),
            self.locked
        )
    }
}

// ---------------------------------------------------------------------------
// ZeroizingVec — zeroize-on-drop wrapper (no mlock)
// ---------------------------------------------------------------------------

/// A wrapper for decrypted private key material that is zeroized on drop.
///
/// This type should be used whenever working with unencrypted private key
/// bytes to ensure the sensitive data is securely erased from memory.
///
/// For long-lived key storage, prefer [`LockedVec`] which additionally pins
/// memory to RAM and excludes it from core dumps.
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
    /// Create a new ZeroizingVec from a `Vec<u8>`.
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

    // ===== ZeroizingVec tests (existing) =====

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

    // ===== LockedVec tests =====

    #[test]
    fn test_locked_vec_basic_operations() {
        let data = vec![10, 20, 30, 40, 50];
        let lv = LockedVec::new(data);
        assert_eq!(lv.as_slice(), &[10, 20, 30, 40, 50]);
        assert_eq!(lv.len(), 5);
        assert!(!lv.is_empty());

        // AsRef should work
        let slice: &[u8] = lv.as_ref();
        assert_eq!(slice, &[10, 20, 30, 40, 50]);
    }

    #[test]
    fn test_locked_vec_empty() {
        let lv = LockedVec::new(vec![]);
        assert!(lv.is_empty());
        assert_eq!(lv.len(), 0);
        let empty: &[u8] = &[];
        assert_eq!(lv.as_slice(), empty);
        // mlock on empty data should report locked=true (vacuously)
        assert!(lv.is_locked());
    }

    #[test]
    fn test_locked_vec_zeroizes_on_drop() {
        // Verify that LockedVec's Zeroize impl zeroes the bytes.
        // We call zeroize() explicitly (rather than relying on Drop + raw pointer
        // inspection, which is racy due to allocator reuse). This verifies the
        // Zeroize trait implementation that Drop delegates to.
        let mut lv = LockedVec::new(vec![0xAA_u8; 64]);
        assert_eq!(lv.as_slice()[0], 0xAA);

        // Explicitly zeroize (same code path as Drop)
        lv.zeroize();
        // After zeroize, the inner vec is cleared (len=0). Verify that:
        assert!(
            lv.inner.is_empty(),
            "inner Vec should be empty after zeroize"
        );
        // The capacity is still allocated and should contain zeros.
        // Read via the capacity-backed buffer.
        let cap = lv.inner.capacity();
        if cap > 0 {
            let zeroed_bytes = unsafe { std::slice::from_raw_parts(lv.inner.as_ptr(), cap) };
            let all_zero = zeroed_bytes.iter().all(|&b| b == 0);
            assert!(
                all_zero,
                "LockedVec backing memory should be zeroed after zeroize (capacity={})",
                cap
            );
        }
    }

    #[test]
    fn test_locked_vec_debug_redacted() {
        let lv = LockedVec::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug_str = format!("{:?}", lv);
        assert!(
            debug_str.contains("REDACTED"),
            "Debug output should contain REDACTED, got: {}",
            debug_str
        );
        assert!(
            !debug_str.contains("222"), // 0xDE = 222 decimal
            "Debug output should not leak byte values, got: {}",
            debug_str
        );
        assert!(
            debug_str.contains("locked="),
            "Debug output should show lock status, got: {}",
            debug_str
        );
    }

    #[test]
    fn test_locked_vec_mlock_called() {
        // On Unix, mlock should succeed for a small allocation (well within
        // RLIMIT_MEMLOCK). On non-Unix, locked will be false.
        let data = vec![1_u8; 128];
        let lv = LockedVec::new(data);

        if cfg!(unix) {
            assert!(lv.is_locked(), "mlock should succeed for 128 bytes on Unix");
        }
        // Regardless of platform, the data should be accessible
        assert_eq!(lv.len(), 128);
    }

    #[test]
    fn test_locked_vec_fallback_on_mlock_failure() {
        // We cannot easily simulate mlock failure in a unit test without
        // manipulating RLIMIT_MEMLOCK (which requires privileges). Instead,
        // we verify the contract: even when locked=false, the vec is usable.
        //
        // On non-Unix platforms, locked is always false, so this exercises
        // the fallback path naturally.
        let data = vec![42_u8; 256];
        let lv = LockedVec::new(data);
        // Data is accessible regardless of lock status
        assert_eq!(lv.as_slice()[0], 42);
        assert_eq!(lv.len(), 256);
        // Dropping should not panic even if unlocked
        drop(lv);
    }

    #[test]
    fn test_locked_vec_large_allocation() {
        // ML-DSA-87 private key is ~4896 bytes. Test with a larger buffer.
        let data = vec![0xFF_u8; 8192];
        let lv = LockedVec::new(data);
        assert_eq!(lv.len(), 8192);
        if cfg!(unix) {
            assert!(
                lv.is_locked(),
                "mlock should succeed for 8192 bytes on Unix"
            );
        }
    }
}
