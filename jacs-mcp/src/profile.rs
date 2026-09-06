//! Fail-closed MCP process profiles.
//!
//! Profiles describe eligible effects; they are not authority. The default
//! exposes verification/inspection/public-export tools only. A privileged
//! `local-sign` selection additionally needs the existing signed config loaded
//! through the explicit local server constructor. Administrative profiles are
//! parked. An enum or environment variable alone never authorizes key use.

use crate::tools::{ClassifiedTool, all_classified_tools};
use rmcp::model::Tool;

/// The four and only four TP-39 process-profile names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    #[default]
    VerifyOnly,
    LocalSign,
    TrustAdmin,
    LegacyCore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError {
    value: String,
    reason: ProfileErrorReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileErrorReason {
    Unknown,
    CapabilityBrokerUnavailable,
}

impl ProfileError {
    fn unknown(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            reason: ProfileErrorReason::Unknown,
        }
    }

    fn capability_broker_unavailable(profile: Profile) -> Self {
        Self {
            value: profile.as_str().to_string(),
            reason: ProfileErrorReason::CapabilityBrokerUnavailable,
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            ProfileErrorReason::Unknown => write!(
                f,
                "invalid MCP profile '{}'; expected exactly 'verify-only', 'local-sign', 'trust-admin', or 'legacy-core'",
                self.value
            ),
            ProfileErrorReason::CapabilityBrokerUnavailable => write!(
                f,
                "MCP profile '{}' requires the complete TP-39 capability/status/approval WAL broker, which is not available; refusing privileged startup",
                self.value
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

impl Profile {
    /// Parse an exact, case-sensitive wire value. Whitespace is not
    /// normalized because configuration authority must not be ambiguous.
    pub fn parse(value: &str) -> Result<Self, ProfileError> {
        match value {
            "verify-only" => Ok(Self::VerifyOnly),
            "local-sign" => Ok(Self::LocalSign),
            "trust-admin" => Ok(Self::TrustAdmin),
            "legacy-core" => Ok(Self::LegacyCore),
            _ => Err(ProfileError::unknown(value)),
        }
    }

    /// Resolve eligibility only. The CLI must construct `local-sign` through
    /// the authenticated local-config constructor; this value is not authority.
    pub fn resolve(cli_profile: Option<&str>) -> Result<Self, ProfileError> {
        let profile = match cli_profile {
            Some(value) => Self::parse(value)?,
            None => match std::env::var("JACS_MCP_PROFILE") {
                Ok(value) => Self::parse(&value)?,
                Err(std::env::VarError::NotPresent) => Self::VerifyOnly,
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(ProfileError::unknown("<non-unicode>"));
                }
            },
        };
        if matches!(profile, Self::VerifyOnly | Self::LocalSign) {
            Ok(profile)
        } else {
            Err(ProfileError::capability_broker_unavailable(profile))
        }
    }

    /// Return the safe advertised surface. Even a programmatically
    /// constructed privileged profile receives only verification tools; the
    /// profile enum is eligibility metadata, never capability evidence.
    pub fn filter_tools(&self, classified: Vec<ClassifiedTool>) -> Vec<Tool> {
        classified
            .into_iter()
            .filter(|classified| is_verify_only_tool(classified.tool.name.as_ref()))
            .map(|classified| classified.tool)
            .collect()
    }

    pub fn tools(&self) -> Vec<Tool> {
        self.filter_tools(all_classified_tools())
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::VerifyOnly => "verify-only",
            Self::LocalSign => "local-sign",
            Self::TrustAdmin => "trust-admin",
            Self::LegacyCore => "legacy-core",
        }
    }

    /// Eligibility metadata only; local tools also need the validated config
    /// scope. The other profiles remain parked and cannot be activated.
    pub fn is_privileged_tool_eligible(&self, tool_id: &str) -> bool {
        match self {
            Self::VerifyOnly => false,
            Self::LocalSign => {
                crate::local_signing::allows_tool(tool_id) && !is_verify_only_tool(tool_id)
            }
            Self::TrustAdmin => matches!(tool_id, "jacs_trust_agent" | "jacs_untrust_agent"),
            // The old `core` contract is compatibility eligibility only. Its
            // exact contract digest/cutoff and every effect still require the
            // missing broker, so nothing is registered from this table today.
            Self::LegacyCore => matches!(
                tool_id,
                "jacs_sign_document"
                    | "jacs_sign_text"
                    | "jacs_sign_image"
                    | "jacs_w3c_sign_request"
                    | "jacs_trust_agent"
                    | "jacs_untrust_agent"
                    | "jacs_create_agent"
                    | "jacs_rotate_keys"
            ),
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn is_verify_only_tool(tool_id: &str) -> bool {
    // The default process has no loaded Agent or SimpleAgent. Expand this
    // list only when a handler is proven to use explicit caller-selected
    // public evidence and no ambient config, key store, trust store, or disk.
    tool_id == "jacs_verify_document"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_closed_profile_names_parse() {
        assert_eq!(Profile::parse("verify-only").unwrap(), Profile::VerifyOnly);
        assert_eq!(Profile::parse("local-sign").unwrap(), Profile::LocalSign);
        assert_eq!(Profile::parse("trust-admin").unwrap(), Profile::TrustAdmin);
        assert_eq!(Profile::parse("legacy-core").unwrap(), Profile::LegacyCore);
        for invalid in ["", "core", "full", "Verify-Only", " verify-only"] {
            assert!(Profile::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn default_is_verification_only() {
        assert_eq!(Profile::default(), Profile::VerifyOnly);
        assert_eq!(
            Profile::resolve(Some("verify-only")).unwrap(),
            Profile::VerifyOnly
        );
    }

    #[test]
    fn profile_name_alone_never_activates_privileged_tools() {
        for profile in [Profile::LocalSign, Profile::TrustAdmin, Profile::LegacyCore] {
            if profile != Profile::LocalSign {
                assert!(Profile::resolve(Some(profile.as_str())).is_err());
            }
            assert!(
                profile
                    .tools()
                    .iter()
                    .all(|tool| !profile.is_privileged_tool_eligible(tool.name.as_ref()))
            );
        }
    }

    #[test]
    fn legacy_agreement_signing_is_ineligible_and_v2_needs_local_scope() {
        for profile in [
            Profile::VerifyOnly,
            Profile::LocalSign,
            Profile::TrustAdmin,
            Profile::LegacyCore,
        ] {
            assert!(!profile.is_privileged_tool_eligible("jacs_sign_agreement"));
            assert_eq!(
                profile.is_privileged_tool_eligible("jacs_sign_agreement_v2"),
                profile == Profile::LocalSign
            );
        }
    }
}
