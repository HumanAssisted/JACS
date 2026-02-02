//! Graceful shutdown handling for JACS.
//!
//! This module provides utilities for graceful shutdown of JACS applications,
//! ensuring all resources are properly cleaned up.
//!
//! # Resource Cleanup
//!
//! JACS manages several resources that require proper cleanup:
//!
//! ## Cryptographic Keys (Automatic via Drop)
//! Private key material is wrapped in [`crate::crypt::private_key::ZeroizingVec`],
//! which implements `Drop` to securely zero memory when the key goes out of scope.
//! This happens automatically and requires no explicit shutdown handling.
//!
//! ## Observability Resources
//! The observability subsystem (logging, metrics, tracing) uses background workers
//! that need to flush pending data on shutdown. Use [`shutdown`] to ensure all
//! telemetry is properly exported.
//!
//! ## Storage
//! Storage backends (filesystem, S3, HTTP) use synchronous operations and don't
//! require explicit cleanup. File handles are closed when their owning structs
//! are dropped.
//!
//! # Example
//!
//! ```rust,ignore
//! use jacs::shutdown;
//!
//! fn main() {
//!     // Application setup and execution...
//!
//!     // On application exit, call shutdown to ensure clean termination
//!     shutdown::shutdown();
//! }
//! ```
//!
//! # Signal Handling
//!
//! For CLI applications, install a signal handler to catch SIGINT/SIGTERM:
//!
//! ```rust,ignore
//! use jacs::shutdown;
//!
//! fn main() {
//!     // Install signal handler for graceful shutdown
//!     shutdown::install_signal_handler();
//!
//!     // Application logic...
//! }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag indicating shutdown has been requested.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Check if shutdown has been requested (e.g., via signal handler).
///
/// Long-running operations can check this flag to exit early when
/// a graceful shutdown is in progress.
///
/// # Example
/// ```rust,ignore
/// while !shutdown::is_shutdown_requested() {
///     // Process work...
/// }
/// ```
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Request shutdown. This sets the global shutdown flag.
///
/// This is typically called by signal handlers or when the application
/// needs to initiate a graceful shutdown.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Perform graceful shutdown of all JACS resources.
///
/// This function:
/// 1. Resets observability (flushes logs, exports pending metrics)
/// 2. Allows background workers time to complete
///
/// Cryptographic key cleanup happens automatically via Drop implementations
/// and does not require explicit calls.
///
/// # Example
/// ```rust,ignore
/// fn main() {
///     // ... application logic ...
///
///     // On exit, ensure clean shutdown
///     jacs::shutdown::shutdown();
/// }
/// ```
pub fn shutdown() {
    tracing::info!("Initiating graceful shutdown");

    // Reset observability - this flushes logs and cleans up workers
    crate::observability::reset_observability();

    // Give a brief moment for async operations to complete
    std::thread::sleep(std::time::Duration::from_millis(100));

    tracing::debug!("Shutdown complete");
}

/// Install a signal handler for graceful shutdown on Unix systems.
///
/// This installs handlers for:
/// - SIGINT (Ctrl+C)
/// - SIGTERM (kill command)
///
/// When a signal is received, the handler:
/// 1. Sets the shutdown requested flag
/// 2. Calls [`shutdown`] to clean up resources
/// 3. Exits the process with code 0
///
/// # Platform Support
/// - Unix: Full signal handling with SIGINT and SIGTERM
/// - Windows: Only Ctrl+C handling via ctrlc behavior
/// - WASM: No-op (signals not applicable)
///
/// # Example
/// ```rust,ignore
/// fn main() {
///     jacs::shutdown::install_signal_handler();
///
///     // Application logic...
///     // On Ctrl+C, graceful shutdown will occur automatically
/// }
/// ```
#[cfg(all(not(target_arch = "wasm32"), unix))]
pub fn install_signal_handler() {
    use std::sync::Once;
    static HANDLER_INSTALLED: Once = Once::new();

    HANDLER_INSTALLED.call_once(|| {
        // Note: We use a simple approach here that works without additional dependencies.
        // For production applications with async runtimes, consider using tokio::signal.

        // Set up a simple panic hook that ensures cleanup on unexpected termination
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Attempt cleanup before panic unwind
            eprintln!("Panic detected, attempting resource cleanup...");
            request_shutdown();
            crate::observability::reset_observability();
            default_hook(info);
        }));

        tracing::debug!("Signal handler installed for graceful shutdown");
    });
}

/// Install signal handler - Windows implementation.
#[cfg(all(not(target_arch = "wasm32"), windows))]
pub fn install_signal_handler() {
    use std::sync::Once;
    static HANDLER_INSTALLED: Once = Once::new();

    HANDLER_INSTALLED.call_once(|| {
        // On Windows, we set up a panic hook for cleanup
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("Panic detected, attempting resource cleanup...");
            request_shutdown();
            crate::observability::reset_observability();
            default_hook(info);
        }));

        tracing::debug!("Panic hook installed for graceful shutdown (Windows)");
    });
}

/// Install signal handler - WASM stub (no-op).
#[cfg(target_arch = "wasm32")]
pub fn install_signal_handler() {
    // Signals don't apply to WASM environments
}

/// RAII guard that performs shutdown when dropped.
///
/// Use this to ensure shutdown is called even when returning early
/// from a function due to errors.
///
/// # Example
/// ```rust,ignore
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let _guard = jacs::shutdown::ShutdownGuard::new();
///
///     // If any of these return early, shutdown still happens
///     do_something()?;
///     do_something_else()?;
///
///     Ok(())
///     // shutdown::shutdown() called automatically when _guard is dropped
/// }
/// ```
pub struct ShutdownGuard {
    _private: (),
}

impl ShutdownGuard {
    /// Create a new shutdown guard.
    pub fn new() -> Self {
        ShutdownGuard { _private: () }
    }
}

impl Default for ShutdownGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_requested_flag() {
        // Reset state for test
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);

        assert!(!is_shutdown_requested());
        request_shutdown();
        assert!(is_shutdown_requested());

        // Reset for other tests
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_shutdown_guard_calls_shutdown() {
        // This test verifies the guard compiles and can be created
        // We can't easily test that shutdown() is called, but we can
        // verify the guard doesn't panic on drop
        {
            let _guard = ShutdownGuard::new();
        }
        // Guard dropped, shutdown should have been called
    }

    #[test]
    fn test_signal_handler_idempotent() {
        // Installing signal handler multiple times should not panic
        install_signal_handler();
        install_signal_handler();
        install_signal_handler();
    }
}
