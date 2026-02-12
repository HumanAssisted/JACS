//! A2A trust policy evaluation for JACS agents.
//!
//! This module defines the trust policy framework for A2A (Agent-to-Agent)
//! interactions. It determines whether a remote agent should be allowed to
//! communicate based on its JACS registration status and trust store presence.
//!
//! # Trust Policies
//!
//! - **Open**: Accept any A2A agent, including those without JACS signatures.
//! - **Verified** (default): Only accept agents with valid JACS signatures
//!   (the JACS provenance extension must be declared in the Agent Card).
//! - **Strict**: Only accept agents that are explicitly in the local trust store.
//!
//! # Trust Levels
//!
//! Each assessed agent receives a trust level:
//!
//! - **Untrusted**: No JACS provenance, or signature could not be verified.
//! - **JacsVerified**: Has a valid JACS signature and declares the JACS extension,
//!   but is not in the local trust store.
//! - **ExplicitlyTrusted**: In the local trust store with a verified signature.

use crate::a2a::{AgentCard, JACS_EXTENSION_URI};
use crate::agent::Agent;
use crate::trust;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Trust policy controlling which remote agents are allowed to interact.
///
/// The default policy is `Verified`, requiring agents to have valid JACS
/// provenance signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum A2ATrustPolicy {
    /// Accept any A2A agent, even those without JACS signatures.
    Open,
    /// Only accept agents that have valid JACS signatures and declare
    /// the JACS provenance extension. This is the default.
    Verified,
    /// Only accept agents that are explicitly in the local trust store.
    Strict,
}

impl Default for A2ATrustPolicy {
    fn default() -> Self {
        A2ATrustPolicy::Verified
    }
}

impl fmt::Display for A2ATrustPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            A2ATrustPolicy::Open => write!(f, "open"),
            A2ATrustPolicy::Verified => write!(f, "verified"),
            A2ATrustPolicy::Strict => write!(f, "strict"),
        }
    }
}

impl A2ATrustPolicy {
    /// Parse a trust policy from a string.
    ///
    /// Accepts case-insensitive variants: "open", "verified", "strict".
    /// Also accepts legacy names: "allow_all" (Open), "require_jacs" (Verified),
    /// "require_trusted" (Strict).
    pub fn from_str_loose(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "open" | "allow_all" => Ok(A2ATrustPolicy::Open),
            "verified" | "require_jacs" => Ok(A2ATrustPolicy::Verified),
            "strict" | "require_trusted" => Ok(A2ATrustPolicy::Strict),
            _ => Err(format!(
                "Unknown trust policy '{}'. Valid values: open, verified, strict",
                s
            )),
        }
    }
}

/// The assessed trust level of a remote agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// No JACS provenance, or signature could not be verified.
    Untrusted,
    /// Has a valid JACS signature and declares the JACS extension,
    /// but is not in the local trust store.
    JacsVerified,
    /// In the local trust store with a verified signature.
    ExplicitlyTrusted,
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Untrusted => write!(f, "untrusted"),
            TrustLevel::JacsVerified => write!(f, "jacs_verified"),
            TrustLevel::ExplicitlyTrusted => write!(f, "explicitly_trusted"),
        }
    }
}

/// Result of assessing a remote agent's trustworthiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAssessment {
    /// Whether the agent is allowed to interact under the applied policy.
    pub allowed: bool,
    /// The assessed trust level.
    pub trust_level: TrustLevel,
    /// Human-readable explanation of the assessment.
    pub reason: String,
    /// Whether the remote agent declares the JACS provenance extension.
    pub jacs_registered: bool,
    /// The agent ID from the remote card's metadata (if available).
    pub agent_id: Option<String>,
    /// The policy that was applied.
    pub policy: A2ATrustPolicy,
}

/// Check whether a remote Agent Card declares the JACS provenance extension.
///
/// Looks for `JACS_EXTENSION_URI` in the card's `capabilities.extensions` list.
pub fn has_jacs_extension(card: &AgentCard) -> bool {
    card.capabilities
        .extensions
        .as_ref()
        .map(|exts| exts.iter().any(|ext| ext.uri == JACS_EXTENSION_URI))
        .unwrap_or(false)
}

/// Extract the JACS agent ID from an Agent Card's metadata.
///
/// The agent ID is expected in `metadata.jacsId`.
fn extract_agent_id(card: &AgentCard) -> Option<String> {
    card.metadata
        .as_ref()
        .and_then(|m| m.get("jacsId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract the JACS agent version from an Agent Card's metadata.
fn extract_agent_version(card: &AgentCard) -> Option<String> {
    card.metadata
        .as_ref()
        .and_then(|m| m.get("jacsVersion"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Build the full "id:version" key used by the trust store.
fn build_trust_store_key(card: &AgentCard) -> Option<String> {
    let id = extract_agent_id(card)?;
    let version = extract_agent_version(card)?;
    if id.contains(':') {
        Some(id)
    } else {
        Some(format!("{}:{}", id, version))
    }
}

/// Assess whether a remote A2A agent should be allowed to interact.
///
/// This function evaluates the remote agent's Agent Card against the specified
/// trust policy and the local agent's context (trust store, key resolution).
///
/// # Arguments
///
/// * `_agent` - The local agent (used for key resolution context in future)
/// * `remote_card` - The remote agent's A2A Agent Card
/// * `policy` - The trust policy to apply
///
/// # Returns
///
/// A `TrustAssessment` indicating whether the agent is allowed and at what
/// trust level.
pub fn assess_a2a_agent(
    _agent: &Agent,
    remote_card: &AgentCard,
    policy: A2ATrustPolicy,
) -> TrustAssessment {
    let jacs_registered = has_jacs_extension(remote_card);
    let agent_id = extract_agent_id(remote_card);
    let trust_store_key = build_trust_store_key(remote_card);

    // Determine if the agent is in the local trust store
    let in_trust_store = trust_store_key
        .as_ref()
        .map(|key| trust::is_trusted(key))
        .unwrap_or(false);

    // Determine trust level
    let trust_level = if in_trust_store {
        TrustLevel::ExplicitlyTrusted
    } else if jacs_registered {
        TrustLevel::JacsVerified
    } else {
        TrustLevel::Untrusted
    };

    // Apply policy
    let (allowed, reason) = match policy {
        A2ATrustPolicy::Open => (
            true,
            format!(
                "Open policy: agent accepted (trust level: {})",
                trust_level
            ),
        ),
        A2ATrustPolicy::Verified => match trust_level {
            TrustLevel::ExplicitlyTrusted => (
                true,
                "Verified policy: agent is explicitly trusted".to_string(),
            ),
            TrustLevel::JacsVerified => (
                true,
                "Verified policy: agent has JACS provenance extension".to_string(),
            ),
            TrustLevel::Untrusted => (
                false,
                format!(
                    "Verified policy: agent '{}' does not declare JACS provenance extension ({})",
                    agent_id.as_deref().unwrap_or("unknown"),
                    JACS_EXTENSION_URI
                ),
            ),
        },
        A2ATrustPolicy::Strict => match trust_level {
            TrustLevel::ExplicitlyTrusted => (
                true,
                "Strict policy: agent is in local trust store".to_string(),
            ),
            _ => (
                false,
                format!(
                    "Strict policy: agent '{}' is not in the local trust store. \
                     Use trust_agent() to add it first.",
                    agent_id.as_deref().unwrap_or("unknown")
                ),
            ),
        },
    };

    TrustAssessment {
        allowed,
        trust_level,
        reason,
        jacs_registered,
        agent_id,
        policy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::{
        AgentCapabilities, AgentCard, AgentExtension, AgentInterface, A2A_PROTOCOL_VERSION,
    };
    use serde_json::json;

    /// Create a minimal Agent Card for testing.
    fn make_card(
        name: &str,
        with_jacs_extension: bool,
        agent_id: Option<&str>,
        version: Option<&str>,
    ) -> AgentCard {
        let extensions = if with_jacs_extension {
            Some(vec![AgentExtension {
                uri: JACS_EXTENSION_URI.to_string(),
                description: Some("JACS cryptographic provenance".to_string()),
                required: Some(false),
            }])
        } else {
            None
        };

        let metadata = match (agent_id, version) {
            (Some(id), Some(ver)) => Some(json!({
                "jacsId": id,
                "jacsVersion": ver,
            })),
            (Some(id), None) => Some(json!({ "jacsId": id })),
            _ => None,
        };

        AgentCard {
            name: name.to_string(),
            description: format!("Test agent: {}", name),
            version: "1.0".to_string(),
            protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            supported_interfaces: vec![AgentInterface {
                url: "https://test.example.com".to_string(),
                protocol_binding: "jsonrpc".to_string(),
                tenant: None,
            }],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            capabilities: AgentCapabilities {
                streaming: None,
                push_notifications: None,
                extended_agent_card: None,
                extensions,
            },
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security: None,
            signatures: None,
            metadata,
        }
    }

    /// Create an empty agent for testing (no loaded state needed).
    fn test_agent() -> Agent {
        crate::get_empty_agent()
    }

    // =========================================================================
    // A2ATrustPolicy tests
    // =========================================================================

    #[test]
    fn test_default_policy_is_verified() {
        assert_eq!(A2ATrustPolicy::default(), A2ATrustPolicy::Verified);
    }

    #[test]
    fn test_policy_display() {
        assert_eq!(A2ATrustPolicy::Open.to_string(), "open");
        assert_eq!(A2ATrustPolicy::Verified.to_string(), "verified");
        assert_eq!(A2ATrustPolicy::Strict.to_string(), "strict");
    }

    #[test]
    fn test_policy_from_str_loose() {
        assert_eq!(
            A2ATrustPolicy::from_str_loose("open").unwrap(),
            A2ATrustPolicy::Open
        );
        assert_eq!(
            A2ATrustPolicy::from_str_loose("VERIFIED").unwrap(),
            A2ATrustPolicy::Verified
        );
        assert_eq!(
            A2ATrustPolicy::from_str_loose("Strict").unwrap(),
            A2ATrustPolicy::Strict
        );
        // Legacy names
        assert_eq!(
            A2ATrustPolicy::from_str_loose("allow_all").unwrap(),
            A2ATrustPolicy::Open
        );
        assert_eq!(
            A2ATrustPolicy::from_str_loose("require_jacs").unwrap(),
            A2ATrustPolicy::Verified
        );
        assert_eq!(
            A2ATrustPolicy::from_str_loose("require_trusted").unwrap(),
            A2ATrustPolicy::Strict
        );
        // Invalid
        assert!(A2ATrustPolicy::from_str_loose("invalid").is_err());
    }

    #[test]
    fn test_policy_serialization_round_trip() {
        let policies = [
            A2ATrustPolicy::Open,
            A2ATrustPolicy::Verified,
            A2ATrustPolicy::Strict,
        ];
        for policy in policies {
            let json = serde_json::to_string(&policy).unwrap();
            let deserialized: A2ATrustPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, deserialized);
        }
    }

    // =========================================================================
    // has_jacs_extension tests
    // =========================================================================

    #[test]
    fn test_has_jacs_extension_true() {
        let card = make_card("jacs-agent", true, Some("id-1"), Some("v1"));
        assert!(has_jacs_extension(&card));
    }

    #[test]
    fn test_has_jacs_extension_false_no_extensions() {
        let card = make_card("plain-agent", false, None, None);
        assert!(!has_jacs_extension(&card));
    }

    #[test]
    fn test_has_jacs_extension_false_other_extensions() {
        let mut card = make_card("other-ext", false, None, None);
        card.capabilities.extensions = Some(vec![AgentExtension {
            uri: "urn:example:other-extension".to_string(),
            description: None,
            required: None,
        }]);
        assert!(!has_jacs_extension(&card));
    }

    // =========================================================================
    // assess_a2a_agent: Open policy
    // =========================================================================

    #[test]
    fn test_open_policy_accepts_untrusted_agent() {
        let agent = test_agent();
        let card = make_card("untrusted", false, None, None);
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Open);
        assert!(result.allowed);
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
        assert!(!result.jacs_registered);
        assert_eq!(result.policy, A2ATrustPolicy::Open);
    }

    #[test]
    fn test_open_policy_accepts_jacs_agent() {
        let agent = test_agent();
        let card = make_card("jacs-agent", true, Some("agent-123"), Some("v1"));
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Open);
        assert!(result.allowed);
        assert_eq!(result.trust_level, TrustLevel::JacsVerified);
        assert!(result.jacs_registered);
    }

    // =========================================================================
    // assess_a2a_agent: Verified policy
    // =========================================================================

    #[test]
    fn test_verified_policy_accepts_jacs_agent() {
        let agent = test_agent();
        let card = make_card("jacs-agent", true, Some("agent-456"), Some("v2"));
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        assert!(result.allowed);
        assert_eq!(result.trust_level, TrustLevel::JacsVerified);
        assert!(result.jacs_registered);
    }

    #[test]
    fn test_verified_policy_rejects_non_jacs_agent() {
        let agent = test_agent();
        let card = make_card("vanilla-a2a", false, None, None);
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        assert!(!result.allowed);
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
        assert!(!result.jacs_registered);
        assert!(result.reason.contains("does not declare JACS provenance"));
    }

    #[test]
    fn test_verified_policy_rejects_agent_with_other_extension() {
        let agent = test_agent();
        let mut card = make_card("other-ext", false, Some("ext-agent"), Some("v1"));
        card.capabilities.extensions = Some(vec![AgentExtension {
            uri: "urn:example:some-other".to_string(),
            description: None,
            required: None,
        }]);
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        assert!(!result.allowed);
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
    }

    // =========================================================================
    // assess_a2a_agent: Strict policy
    // =========================================================================

    #[test]
    fn test_strict_policy_rejects_jacs_agent_not_in_store() {
        let agent = test_agent();
        // Agent with JACS extension but not in trust store
        let card = make_card(
            "jacs-not-trusted",
            true,
            Some("550e8400-e29b-41d4-a716-446655440099"),
            Some("550e8400-e29b-41d4-a716-446655440098"),
        );
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Strict);
        assert!(!result.allowed);
        // JacsVerified because it has the extension, but strict rejects it
        assert_eq!(result.trust_level, TrustLevel::JacsVerified);
        assert!(result.reason.contains("not in the local trust store"));
    }

    #[test]
    fn test_strict_policy_rejects_non_jacs_agent() {
        let agent = test_agent();
        let card = make_card("untrusted", false, None, None);
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Strict);
        assert!(!result.allowed);
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
    }

    // =========================================================================
    // TrustAssessment serialization
    // =========================================================================

    #[test]
    fn test_trust_assessment_serialization() {
        let assessment = TrustAssessment {
            allowed: true,
            trust_level: TrustLevel::JacsVerified,
            reason: "Verified policy: agent has JACS provenance extension".to_string(),
            jacs_registered: true,
            agent_id: Some("agent-789".to_string()),
            policy: A2ATrustPolicy::Verified,
        };

        let json = serde_json::to_string_pretty(&assessment).unwrap();
        let deserialized: TrustAssessment = serde_json::from_str(&json).unwrap();

        assert!(deserialized.allowed);
        assert_eq!(deserialized.trust_level, TrustLevel::JacsVerified);
        assert!(deserialized.jacs_registered);
        assert_eq!(deserialized.agent_id, Some("agent-789".to_string()));
        assert_eq!(deserialized.policy, A2ATrustPolicy::Verified);
    }

    // =========================================================================
    // TrustLevel tests
    // =========================================================================

    #[test]
    fn test_trust_level_display() {
        assert_eq!(TrustLevel::Untrusted.to_string(), "untrusted");
        assert_eq!(TrustLevel::JacsVerified.to_string(), "jacs_verified");
        assert_eq!(
            TrustLevel::ExplicitlyTrusted.to_string(),
            "explicitly_trusted"
        );
    }

    #[test]
    fn test_trust_level_serialization() {
        let levels = [
            TrustLevel::Untrusted,
            TrustLevel::JacsVerified,
            TrustLevel::ExplicitlyTrusted,
        ];
        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, deserialized);
        }
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn test_agent_id_extracted_from_metadata() {
        let card = make_card("with-id", true, Some("my-agent-id"), Some("v1"));
        let assessment = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Open);
        assert_eq!(assessment.agent_id, Some("my-agent-id".to_string()));
    }

    #[test]
    fn test_agent_id_none_when_no_metadata() {
        let card = make_card("no-metadata", false, None, None);
        let assessment = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Open);
        assert_eq!(assessment.agent_id, None);
    }
}
