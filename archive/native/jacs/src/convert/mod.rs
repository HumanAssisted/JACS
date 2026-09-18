//! Format conversion utilities for JACS documents.
//!
//! This module provides lossless round-trip conversion between the canonical
//! JACS JSON representation and YAML and HTML formats, with the invariant
//! that converting away from JSON and back always produces a document that
//! passes JACS signature verification.
//!
//! # Supported Conversions
//!
//! - **JSON to YAML**: Human-readable representation for viewing/authoring.
//! - **YAML to JSON**: Parse YAML back to JSON for signing/verification.
//! - **JSON to HTML**: Self-contained HTML with embedded JSON for display/sharing.
//! - **HTML to JSON**: Extract the embedded JSON from an HTML document.
//!
//! # Example
//!
//! ```rust
//! use jacs::convert::{jacs_to_yaml, yaml_to_jacs};
//!
//! let json = r#"{"hello": "world"}"#;
//! let yaml = jacs_to_yaml(json).unwrap();
//! let back = yaml_to_jacs(&yaml).unwrap();
//! // The canonical JSON will be identical
//! ```

pub mod html;
pub mod yaml;

// Re-export public API
pub use html::{html_to_jacs, jacs_to_html};
pub use yaml::{jacs_to_yaml, yaml_to_jacs, yaml_to_jacs_canonical};
