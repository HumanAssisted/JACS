//! Simple initialization functions for JACS observability.
//!
//! This module provides two entry points:
//!
//! - [`init_logging()`] — Quick stderr logging with sensible defaults.
//!   Uses `RUST_LOG` for customization, defaults to `jacs=info`.
//!
//! - [`init_tracing()`] — Full tracing subscriber setup (stderr output).
//!   For OTLP export, use [`super::init_observability()`] with a
//!   [`TracingConfig`] that has `enabled: true` and the appropriate
//!   `otlp-tracing` feature flag.
//!
//! # Examples
//!
//! ```rust,ignore
//! use jacs::observability::init::{init_logging, init_tracing};
//!
//! // Quick start — stderr logging only
//! init_logging();
//!
//! // Or full tracing subscriber
//! init_tracing();
//! ```

use std::io;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize logging with sensible defaults.
///
/// Sets up a `tracing-subscriber` that:
/// - Outputs to **stderr**
/// - Defaults to `info` level for JACS modules
/// - Reads `RUST_LOG` environment variable for customization
/// - Suppresses verbose output from networking crates (hyper, tonic, h2, reqwest)
///
/// Safe to call multiple times — subsequent calls are no-ops if a global
/// subscriber is already set.
///
/// # Environment Variables
///
/// - `RUST_LOG`: Standard Rust log filter. Defaults to `jacs=info` if unset.
///   Examples: `RUST_LOG=debug`, `RUST_LOG=jacs=trace,jacs::crypt=debug`
pub fn init_logging() {
    // Delegate to the canonical implementation in logs.rs
    super::logs::init_logging();
}

/// Initialize a full tracing subscriber with stderr output.
///
/// Sets up `tracing-subscriber` with:
/// - `EnvFilter` respecting `RUST_LOG` (defaults to `jacs=info`)
/// - Formatted output to stderr with ANSI colors
/// - Suppressed networking crate noise
///
/// This does **not** enable OTLP export. For OTLP tracing, use
/// [`super::init_observability()`] with the `otlp-tracing` feature enabled.
///
/// Safe to call multiple times — subsequent calls are no-ops.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("jacs=info"))
        .add_directive("hyper=warn".parse().expect("valid directive"))
        .add_directive("tonic=warn".parse().expect("valid directive"))
        .add_directive("h2=warn".parse().expect("valid directive"))
        .add_directive("reqwest=warn".parse().expect("valid directive"));

    // try_init is a no-op if a subscriber is already set
    let _ = Registry::default()
        .with(filter)
        .with(fmt::layer().with_writer(io::stderr).with_ansi(true))
        .try_init();
}
