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

use crate::a2a::extension::verify_agent_card_jws;
use crate::a2a::keys::Jwk;
use crate::a2a::{AgentCard, JACS_EXTENSION_URI};
use crate::agent::Agent;
use crate::trust;
#[cfg(not(target_arch = "wasm32"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use url::Url;

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
            TrustLevel::Untrusted => write!(f, "Untrusted"),
            TrustLevel::JacsVerified => write!(f, "JacsVerified"),
            TrustLevel::ExplicitlyTrusted => write!(f, "ExplicitlyTrusted"),
        }
    }
}

/// Result of assessing a remote agent's trustworthiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

fn agent_card_signature_key_id(card: &AgentCard) -> Option<&str> {
    card.signatures
        .as_ref()
        .and_then(|signatures| signatures.first())
        .and_then(|signature| signature.key_id.as_deref())
}

#[cfg(not(target_arch = "wasm32"))]
fn agent_card_origin(card: &AgentCard) -> Result<String, String> {
    let interface_url = card
        .supported_interfaces
        .first()
        .map(|interface| interface.url.as_str())
        .ok_or_else(|| "Agent Card does not declare a supported interface URL".to_string())?;

    let parsed = Url::parse(interface_url).map_err(|e| {
        format!(
            "Invalid Agent Card interface URL '{}': {}",
            interface_url, e
        )
    })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "Agent Card interface URL does not include a host".to_string())?;

    let mut origin = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }

    Ok(origin)
}

#[cfg(not(target_arch = "wasm32"))]
fn fetch_jwks(card: &AgentCard) -> Result<Vec<Jwk>, String> {
    let jwks_url = format!("{}/.well-known/jwks.json", agent_card_origin(card)?);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to build JWKS client: {}", e))?;

    let response = client
        .get(&jwks_url)
        .send()
        .map_err(|e| format!("Failed to fetch JWKS from '{}': {}", jwks_url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "JWKS endpoint '{}' returned HTTP {}",
            jwks_url,
            response.status()
        ));
    }

    let value = response
        .json::<serde_json::Value>()
        .map_err(|e| format!("Failed to parse JWKS JSON from '{}': {}", jwks_url, e))?;

    let keys_value = value
        .get("keys")
        .ok_or_else(|| format!("JWKS endpoint '{}' did not return a 'keys' array", jwks_url))?
        .clone();

    serde_json::from_value::<Vec<Jwk>>(keys_value)
        .map_err(|e| format!("Failed to decode JWKS keys from '{}': {}", jwks_url, e))
}

#[cfg(not(target_arch = "wasm32"))]
fn select_jwk<'a>(card: &AgentCard, jwks: &'a [Jwk]) -> Result<&'a Jwk, String> {
    let signature_key_id = agent_card_signature_key_id(card);
    if let Some(key_id) = signature_key_id {
        jwks.iter()
            .find(|jwk| jwk.kid == key_id)
            .ok_or_else(|| format!("JWKS does not contain key '{}'", key_id))
    } else if jwks.len() == 1 {
        Ok(&jwks[0])
    } else {
        Err("Agent Card signature does not declare key_id and JWKS has multiple keys".to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn jwk_to_verifier(jwk: &Jwk) -> Result<(Vec<u8>, &'static str), String> {
    match jwk.kty.as_str() {
        "OKP" if jwk.crv.as_deref() == Some("Ed25519") => {
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| "Ed25519 JWK is missing 'x'".to_string())?;
            let public_key = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| format!("Failed to decode Ed25519 JWK x coordinate: {}", e))?;
            Ok((public_key, "ring-Ed25519"))
        }
        "RSA" => {
            use rsa::pkcs8::{EncodePublicKey, LineEnding};
            use rsa::{BigUint, RsaPublicKey};

            let modulus = jwk
                .n
                .as_deref()
                .ok_or_else(|| "RSA JWK is missing 'n'".to_string())?;
            let exponent = jwk
                .e
                .as_deref()
                .ok_or_else(|| "RSA JWK is missing 'e'".to_string())?;

            let n = BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD
                    .decode(modulus)
                    .map_err(|e| format!("Failed to decode RSA modulus: {}", e))?,
            );
            let e = BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD
                    .decode(exponent)
                    .map_err(|e| format!("Failed to decode RSA exponent: {}", e))?,
            );

            let public_key = RsaPublicKey::new(n, e)
                .map_err(|e| format!("Invalid RSA public key in JWKS: {}", e))?;
            let pem = public_key
                .to_public_key_pem(LineEnding::CRLF)
                .map_err(|e| format!("Failed to encode RSA key from JWKS: {}", e))?;
            Ok((pem.into_bytes(), "rsa"))
        }
        other => Err(format!("Unsupported JWKS key type '{}'", other)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_agent_card_signature(card: &AgentCard) -> Result<bool, String> {
    if card
        .signatures
        .as_ref()
        .is_none_or(|signatures| signatures.is_empty())
    {
        return Err("Agent Card has no embedded signatures".to_string());
    }

    let jwks = fetch_jwks(card)?;
    let jwk = select_jwk(card, &jwks)?;
    let (public_key, algorithm) = jwk_to_verifier(jwk)?;

    verify_agent_card_jws(card, &public_key, algorithm)
        .map_err(|e| format!("Agent Card signature verification failed: {}", e))
}

#[cfg(target_arch = "wasm32")]
fn verify_agent_card_signature(_card: &AgentCard) -> Result<bool, String> {
    Err("Agent Card JWKS verification is not supported on wasm32".to_string())
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
    let signature_verification = if jacs_registered {
        verify_agent_card_signature(remote_card)
    } else {
        Ok(false)
    };
    let card_signature_verified = signature_verification.as_ref().copied().unwrap_or(false);

    // Determine if the agent is in the local trust store
    let in_trust_store = trust_store_key
        .as_ref()
        .map(|key| trust::is_verified_trusted(key))
        .unwrap_or(false);

    // Determine trust level
    let trust_level = if in_trust_store {
        TrustLevel::ExplicitlyTrusted
    } else if card_signature_verified {
        TrustLevel::JacsVerified
    } else {
        TrustLevel::Untrusted
    };

    let unverified_reason = if jacs_registered {
        let mut reason = format!(
            "agent '{}' declares JACS provenance but its Agent Card could not be cryptographically verified",
            agent_id.as_deref().unwrap_or("unknown")
        );
        if let Err(err) = signature_verification {
            reason.push_str(": ");
            reason.push_str(&err);
        }
        reason
    } else {
        format!(
            "agent '{}' does not declare JACS provenance extension ({})",
            agent_id.as_deref().unwrap_or("unknown"),
            JACS_EXTENSION_URI
        )
    };

    // Apply policy
    let (allowed, reason) = match policy {
        A2ATrustPolicy::Open => {
            let reason = match trust_level {
                TrustLevel::ExplicitlyTrusted => {
                    "Open policy: agent accepted and explicitly trusted".to_string()
                }
                TrustLevel::JacsVerified => {
                    "Open policy: agent accepted and Agent Card signature verified".to_string()
                }
                TrustLevel::Untrusted => {
                    format!("Open policy: agent accepted, but {}", unverified_reason)
                }
            };
            (true, reason)
        }
        A2ATrustPolicy::Verified => match trust_level {
            TrustLevel::ExplicitlyTrusted => (
                true,
                "Verified policy: agent is explicitly trusted".to_string(),
            ),
            TrustLevel::JacsVerified => (
                true,
                "Verified policy: Agent Card signature verified against advertised JWKS"
                    .to_string(),
            ),
            TrustLevel::Untrusted => (false, format!("Verified policy: {}", unverified_reason)),
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
    use crate::a2a::extension::{embed_signature_in_agent_card, sign_agent_card_jws};
    use crate::a2a::keys::{create_jwk_set, export_as_jwk};
    use crate::a2a::{
        A2A_PROTOCOL_VERSION, AgentCapabilities, AgentCard, AgentExtension, AgentInterface,
    };
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

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
    fn test_open_policy_treats_unsigned_jacs_card_as_untrusted() {
        let agent = test_agent();
        let card = make_card(
            "unsigned-jacs-agent",
            true,
            Some("550e8400-e29b-41d4-a716-446655440010"),
            Some("550e8400-e29b-41d4-a716-446655440011"),
        );
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Open);
        assert!(result.allowed);
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
        assert!(result.jacs_registered);
        assert!(
            result
                .reason
                .contains("could not be cryptographically verified"),
            "unexpected reason: {}",
            result.reason
        );
    }

    // =========================================================================
    // assess_a2a_agent: Verified policy
    // =========================================================================

    #[test]
    fn test_verified_policy_rejects_unsigned_jacs_agent() {
        let agent = test_agent();
        let card = make_card(
            "unsigned-jacs-agent",
            true,
            Some("550e8400-e29b-41d4-a716-446655440020"),
            Some("550e8400-e29b-41d4-a716-446655440021"),
        );
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        assert!(!result.allowed);
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
        assert!(result.jacs_registered);
        assert!(
            result
                .reason
                .contains("could not be cryptographically verified"),
            "unexpected reason: {}",
            result.reason
        );
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
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
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
        assert_eq!(TrustLevel::Untrusted.to_string(), "Untrusted");
        assert_eq!(TrustLevel::JacsVerified.to_string(), "JacsVerified");
        assert_eq!(
            TrustLevel::ExplicitlyTrusted.to_string(),
            "ExplicitlyTrusted"
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

    fn serve_jwks_once(body: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buf = [0_u8; 4096];
            let read = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..read]);
            let (status, payload) = if request.starts_with("GET /.well-known/jwks.json ") {
                ("200 OK", body)
            } else {
                ("404 Not Found", "{\"error\":\"not found\"}".to_string())
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                payload.len(),
                payload
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (format!("http://{}", addr), handle)
    }

    fn make_signed_card_with_local_jwks() -> (AgentCard, thread::JoinHandle<()>) {
        let agent_id = "550e8400-e29b-41d4-a716-446655440030";
        let version = "550e8400-e29b-41d4-a716-446655440031";
        let mut card = make_card("signed-jacs-agent", true, Some(agent_id), Some(version));
        let (private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("generate ed25519 keys");
        let jwk = export_as_jwk(&public_key, "ring-Ed25519", agent_id).expect("export jwk");
        let jwks = create_jwk_set(vec![jwk]).to_string();
        let (origin, handle) = serve_jwks_once(jwks);
        card.supported_interfaces[0].url = format!("{}/agent/{}", origin, agent_id);
        let jws =
            sign_agent_card_jws(&card, &private_key, "ring-Ed25519", agent_id).expect("sign card");
        let signed_card = embed_signature_in_agent_card(&card, &jws, Some(agent_id));
        (signed_card, handle)
    }

    #[test]
    fn test_verified_policy_accepts_signed_jacs_agent() {
        let agent = test_agent();
        let (card, server_handle) = make_signed_card_with_local_jwks();
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        server_handle.join().expect("join jwks server");

        assert!(
            result.allowed,
            "assessment should allow signed card: {:?}",
            result
        );
        assert_eq!(result.trust_level, TrustLevel::JacsVerified);
        assert!(result.jacs_registered);
        assert!(
            result.reason.contains("Agent Card signature verified"),
            "unexpected reason: {}",
            result.reason
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_strict_policy_rejects_unverified_a2a_card_bookmark() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", temp_dir.path());
        }

        let agent_id = "550e8400-e29b-41d4-a716-446655440040";
        let version = "550e8400-e29b-41d4-a716-446655440041";
        let key = format!("{}:{}", agent_id, version);
        let card = make_card("bookmarked-card", true, Some(agent_id), Some(version));
        crate::trust::trust_a2a_card(&key, &serde_json::to_string(&card).unwrap())
            .expect("store unverified a2a card");

        let result = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        assert!(!result.allowed, "strict policy must reject bookmarks");
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
        assert!(result.reason.contains("not in the local trust store"));

        unsafe {
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }
    }

    // =========================================================================
    // Golden serialization tests (Task 006)
    // =========================================================================

    /// Pin exact JSON shape for TrustAssessment — all fields present, camelCase.
    #[test]
    fn test_trust_assessment_golden() {
        let assessment = TrustAssessment {
            allowed: true,
            trust_level: TrustLevel::JacsVerified,
            reason: "Verified policy: Agent Card signature verified against advertised JWKS"
                .to_string(),
            jacs_registered: true,
            agent_id: Some("agent-golden-trust".to_string()),
            policy: A2ATrustPolicy::Verified,
        };

        let actual: serde_json::Value = serde_json::to_value(&assessment).unwrap();
        let expected = json!({
            "allowed": true,
            "trustLevel": "JacsVerified",
            "reason": "Verified policy: Agent Card signature verified against advertised JWKS",
            "jacsRegistered": true,
            "agentId": "agent-golden-trust",
            "policy": "Verified"
        });

        assert_eq!(actual, expected, "Golden JSON mismatch for TrustAssessment");

        // Also pin with agent_id = None (Untrusted, Open policy)
        let assessment_none = TrustAssessment {
            allowed: true,
            trust_level: TrustLevel::Untrusted,
            reason: "Open policy: agent accepted (trust level: Untrusted)".to_string(),
            jacs_registered: false,
            agent_id: None,
            policy: A2ATrustPolicy::Open,
        };

        let actual_none: serde_json::Value = serde_json::to_value(&assessment_none).unwrap();
        let expected_none = json!({
            "allowed": true,
            "trustLevel": "Untrusted",
            "reason": "Open policy: agent accepted (trust level: Untrusted)",
            "jacsRegistered": false,
            "agentId": null,
            "policy": "Open"
        });

        assert_eq!(
            actual_none, expected_none,
            "Golden JSON mismatch for TrustAssessment (Untrusted/None)"
        );

        // Pin ExplicitlyTrusted + Strict policy
        let assessment_strict = TrustAssessment {
            allowed: true,
            trust_level: TrustLevel::ExplicitlyTrusted,
            reason: "Strict policy: agent is in local trust store".to_string(),
            jacs_registered: true,
            agent_id: Some("trusted-agent-xyz".to_string()),
            policy: A2ATrustPolicy::Strict,
        };

        let actual_strict: serde_json::Value = serde_json::to_value(&assessment_strict).unwrap();
        let expected_strict = json!({
            "allowed": true,
            "trustLevel": "ExplicitlyTrusted",
            "reason": "Strict policy: agent is in local trust store",
            "jacsRegistered": true,
            "agentId": "trusted-agent-xyz",
            "policy": "Strict"
        });

        assert_eq!(
            actual_strict, expected_strict,
            "Golden JSON mismatch for TrustAssessment (Strict)"
        );
    }
}
