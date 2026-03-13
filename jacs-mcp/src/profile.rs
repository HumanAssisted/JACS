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

use crate::tools::{ClassifiedTool, ToolFamily, all_classified_tools};
use rmcp::model::Tool;

/// Runtime tool profile for filtering which tools are registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// Core tools only (default). Includes the 7 standard families:
    /// state, document, trust, audit, memory, search, key.
    Core,

    /// All compiled-in tools. Includes core + advanced families:
    /// agreements, messaging, a2a, attestation.
    Full,
}

impl Profile {
    /// Parse a profile from a string. Unrecognised values default to `Core`.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "full" => Profile::Full,
            _ => Profile::Core,
        }
    }

    /// Resolve the active profile from CLI args and environment.
    ///
    /// Checks (in order):
    /// 1. `cli_profile` argument (from `--profile` flag)
    /// 2. `JACS_MCP_PROFILE` environment variable
    /// 3. Defaults to `Core`
    pub fn resolve(cli_profile: Option<&str>) -> Self {
        if let Some(p) = cli_profile {
            return Self::parse(p);
        }

        if let Ok(env_val) = std::env::var("JACS_MCP_PROFILE") {
            if !env_val.trim().is_empty() {
                return Self::parse(&env_val);
            }
        }

        Profile::Core
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

impl Default for Profile {
    fn default() -> Self {
        Profile::Core
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Names of all core tool families for documentation/logging.
pub const CORE_FAMILIES: &[ToolFamily] = &[
    ToolFamily::State,
    ToolFamily::Document,
    ToolFamily::Trust,
    ToolFamily::Audit,
    ToolFamily::Memory,
    ToolFamily::Search,
    ToolFamily::Key,
];

/// Names of all advanced tool families for documentation/logging.
pub const ADVANCED_FAMILIES: &[ToolFamily] = &[
    ToolFamily::Agreement,
    ToolFamily::Messaging,
    ToolFamily::A2a,
    ToolFamily::Attestation,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_core() {
        assert_eq!(Profile::parse("core"), Profile::Core);
        assert_eq!(Profile::parse("Core"), Profile::Core);
        assert_eq!(Profile::parse("CORE"), Profile::Core);
    }

    #[test]
    fn parse_full() {
        assert_eq!(Profile::parse("full"), Profile::Full);
        assert_eq!(Profile::parse("Full"), Profile::Full);
        assert_eq!(Profile::parse("FULL"), Profile::Full);
    }

    #[test]
    fn parse_unknown_defaults_to_core() {
        assert_eq!(Profile::parse("unknown"), Profile::Core);
        assert_eq!(Profile::parse(""), Profile::Core);
    }

    #[test]
    fn resolve_cli_core_overrides_anything() {
        // CLI flag always wins regardless of env state.
        let profile = Profile::resolve(Some("core"));
        assert_eq!(profile, Profile::Core);
    }

    #[test]
    fn resolve_cli_full() {
        let profile = Profile::resolve(Some("full"));
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
                tool: Tool::new("state_tool", "A state tool", serde_json::Map::new()),
                family: ToolFamily::State,
            },
            ClassifiedTool {
                tool: Tool::new("messaging_tool", "A messaging tool", serde_json::Map::new()),
                family: ToolFamily::Messaging,
            },
        ];

        let core = Profile::Core.filter_tools(tools.clone());
        assert_eq!(core.len(), 1);
        assert_eq!(core[0].name.as_ref(), "state_tool");

        let full = Profile::Full.filter_tools(tools);
        assert_eq!(full.len(), 2);
    }
}
