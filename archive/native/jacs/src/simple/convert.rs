//! Conversion convenience methods on `SimpleAgent`.
//!
//! These methods delegate to `jacs::convert::*` functions and do not require
//! the agent lock (conversion is stateless). The `verify_yaml` method is the
//! exception -- it converts YAML to JSON and then delegates to `self.verify()`.

use crate::convert;
use crate::error::JacsError;
use crate::simple::types::VerificationResult;

use super::core::SimpleAgent;

impl SimpleAgent {
    /// Convert a JSON string to YAML.
    ///
    /// This is a stateless convenience wrapper over [`convert::jacs_to_yaml`].
    pub fn to_yaml(&self, json_str: &str) -> Result<String, JacsError> {
        convert::jacs_to_yaml(json_str)
    }

    /// Convert a YAML string to pretty-printed JSON.
    ///
    /// This is a stateless convenience wrapper over [`convert::yaml_to_jacs`].
    pub fn from_yaml(&self, yaml_str: &str) -> Result<String, JacsError> {
        convert::yaml_to_jacs(yaml_str)
    }

    /// Convert a YAML string to JSON and verify the document.
    ///
    /// This is equivalent to calling `from_yaml()` followed by `verify()`.
    pub fn verify_yaml(&self, yaml_str: &str) -> Result<VerificationResult, JacsError> {
        let json_str = convert::yaml_to_jacs(yaml_str)?;
        self.verify(&json_str)
    }

    /// Convert a JSON string to a self-contained HTML document.
    ///
    /// This is a stateless convenience wrapper over [`convert::jacs_to_html`].
    pub fn to_html(&self, json_str: &str) -> Result<String, JacsError> {
        convert::jacs_to_html(json_str)
    }

    /// Extract JSON from an HTML document produced by [`to_html`](Self::to_html).
    ///
    /// This is a stateless convenience wrapper over [`convert::html_to_jacs`].
    pub fn from_html(&self, html_str: &str) -> Result<String, JacsError> {
        convert::html_to_jacs(html_str)
    }
}
