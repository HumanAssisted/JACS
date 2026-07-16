//! Runtime tool profiles for jacs-mcp.
//!
//! When jacs-mcp is compiled with `full-tools` (as pre-built binaries are),
//! the runtime profile controls which tools are *registered* with the MCP
//! client. This complements the compile-time feature gating: features control
//! what code is compiled, profiles control what is exposed at runtime.
//!
//! ## Resolution order
//!
//! 1. `--profile <name>` CLI flag (highest priority)
//! 2. `JACS_MCP_PROFILE` environment variable
//! 3. Default: `core`
//!
//! Only `core` and `full` are valid. Unknown explicit values are rejected;
//! they never silently fall back to a different capability set.

use crate::tools::{ClassifiedTool, ToolFamily, all_classified_tools};
use rmcp::model::Tool;

/// Runtime tool profile for filtering which tools are registered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Profile {
    /// Core tools only (default). Includes the standard families:
    /// document, trust, search, key, and W3C.
    #[default]
    Core,

    /// All compiled-in tools. Includes core + advanced families:
    /// agreements, a2a, attestation.
    Full,
}

/// Error returned when a runtime profile selector is not one of the supported
/// values. Invalid selectors are never coerced to `core`, because doing so can
/// silently expose a different capability set than the operator requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError {
    value: String,
}

impl ProfileError {
    fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// The normalized invalid value supplied by the caller.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid MCP profile '{}'; expected 'core' or 'full'",
            self.value
        )
    }
}

impl std::error::Error for ProfileError {}

impl Profile {
    /// Parse a profile from a string.
    ///
    /// Values are case-insensitive and surrounding whitespace is ignored.
    /// Unknown or empty values are rejected rather than silently becoming
    /// `Core`.
    pub fn parse(s: &str) -> Result<Self, ProfileError> {
        match s.trim().to_lowercase().as_str() {
            "core" => Ok(Profile::Core),
            "full" => Ok(Profile::Full),
            _ => Err(ProfileError::new(s.trim())),
        }
    }

    /// Resolve the active profile from CLI args and environment.
    ///
    /// Checks (in order):
    /// 1. `cli_profile` argument (from `--profile` flag)
    /// 2. `JACS_MCP_PROFILE` environment variable
    /// 3. Defaults to `Core`
    ///
    /// An empty environment value is treated as absent. Any other unknown
    /// value returns [`ProfileError`].
    pub fn resolve(cli_profile: Option<&str>) -> Result<Self, ProfileError> {
        if let Some(p) = cli_profile {
            return Self::parse(p);
        }

        match std::env::var("JACS_MCP_PROFILE") {
            Ok(env_val) if !env_val.trim().is_empty() => Self::parse(&env_val),
            Ok(_) | Err(std::env::VarError::NotPresent) => Ok(Profile::Core),
            Err(std::env::VarError::NotUnicode(_)) => Err(ProfileError::new("<non-unicode>")),
        }
    }

    /// Filter compiled-in tools based on this profile.
    ///
    /// - `Core`: only tools from core families
    /// - `Full`: all compiled-in tools
    pub fn filter_tools(&self, classified: Vec<ClassifiedTool>) -> Vec<Tool> {
        classified
            .into_iter()
            .filter(|ct| match self {
                Profile::Full => true,
                Profile::Core => ct.family.is_core(),
            })
            .map(|ct| ct.tool)
            .collect()
    }

    /// Convenience: get all tools for this profile from the compiled-in set.
    pub fn tools(&self) -> Vec<Tool> {
        self.filter_tools(all_classified_tools())
    }

    /// Return the profile name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Core => "core",
            Profile::Full => "full",
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Names of all core tool families for documentation/logging.
pub const CORE_FAMILIES: &[ToolFamily] = &[
    ToolFamily::Document,
    ToolFamily::Trust,
    ToolFamily::Search,
    ToolFamily::Key,
    ToolFamily::W3c,
];

/// Names of all advanced tool families for documentation/logging.
pub const ADVANCED_FAMILIES: &[ToolFamily] = &[
    ToolFamily::Agreement,
    ToolFamily::A2a,
    ToolFamily::Attestation,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_core() {
        assert_eq!(Profile::parse("core").unwrap(), Profile::Core);
        assert_eq!(Profile::parse("Core").unwrap(), Profile::Core);
        assert_eq!(Profile::parse("CORE").unwrap(), Profile::Core);
    }

    #[test]
    fn parse_full() {
        assert_eq!(Profile::parse("full").unwrap(), Profile::Full);
        assert_eq!(Profile::parse("Full").unwrap(), Profile::Full);
        assert_eq!(Profile::parse("FULL").unwrap(), Profile::Full);
    }

    #[test]
    fn parse_rejects_unknown_and_empty_values() {
        for value in ["unknown", "", "  "] {
            let error = Profile::parse(value).expect_err("invalid profile must be rejected");
            assert!(error.to_string().contains("core"));
            assert!(error.to_string().contains("full"));
        }
    }

    #[test]
    fn resolve_cli_core_overrides_anything() {
        // CLI flag always wins regardless of env state.
        let profile = Profile::resolve(Some("core")).unwrap();
        assert_eq!(profile, Profile::Core);
    }

    #[test]
    fn resolve_cli_full() {
        let profile = Profile::resolve(Some("full")).unwrap();
        assert_eq!(profile, Profile::Full);
    }

    // NOTE: Env-var-dependent resolve tests are in the integration test
    // `tests/profiles.rs` where they can run serially without racing
    // with parallel unit tests that share the process environment.

    #[test]
    fn default_is_core() {
        assert_eq!(Profile::default(), Profile::Core);
    }

    #[test]
    fn display_trait() {
        assert_eq!(format!("{}", Profile::Core), "core");
        assert_eq!(format!("{}", Profile::Full), "full");
    }

    #[test]
    fn core_profile_filters_advanced_tools() {
        use crate::tools::{ClassifiedTool, ToolFamily};
        use rmcp::model::Tool;

        let tools = vec![
            ClassifiedTool {
                tool: Tool::new("document_tool", "A document tool", serde_json::Map::new()),
                family: ToolFamily::Document,
            },
            ClassifiedTool {
                tool: Tool::new(
                    "agreement_tool",
                    "An agreement tool",
                    serde_json::Map::new(),
                ),
                family: ToolFamily::Agreement,
            },
        ];

        let core = Profile::Core.filter_tools(tools.clone());
        assert_eq!(core.len(), 1);
        assert_eq!(core[0].name.as_ref(), "document_tool");

        let full = Profile::Full.filter_tools(tools);
        assert_eq!(full.len(), 2);
    }
}
