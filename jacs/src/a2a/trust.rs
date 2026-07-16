//! A2A trust policy evaluation for JACS agents.
//!
//! This module defines the trust policy framework for A2A (Agent-to-Agent)
//! interactions. It determines whether a remote agent should be allowed to
//! communicate based on its JACS registration status and trust store presence.
//!
//! # Trust Policies
//!
//! - **Open**: Accept any A2A agent, including those without JACS signatures.
//! - **Verified** (default): Require a valid card signature plus a durable
//!   same-origin JWKS key pin. This proves origin/key continuity, not the
//!   claimed native JACS identity.
//! - **Strict**: Require an explicitly trusted native JACS root and, for the
//!   generated ES256 card, a valid native-root-signed compatibility binding.
//!
//! # Trust Levels
//!
//! Each assessed agent receives a trust level:
//!
//! - **Untrusted**: No JACS provenance, or signature could not be verified.
//! - **JacsVerified**: Card signature and origin key pin verified, but the
//!   claimed native identity is not explicitly trusted.
//! - **ExplicitlyTrusted**: Card signature and native identity binding verified
//!   against an explicitly trusted root.

use crate::a2a::extension::verify_agent_card_jws;
use crate::a2a::keys::Jwk;
use crate::a2a::{AgentCard, JACS_EXTENSION_URI};
use crate::agent::Agent;
use crate::config::{NetworkCapability, ensure_network_access};
use crate::trust;
#[cfg(not(target_arch = "wasm32"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
const MAX_JWKS_RESPONSE_BYTES: usize = 256 * 1024;

/// Fetch an A2A Agent Card through the shared trust-boundary transport.
///
/// Language bindings use this entry point so Python and Node discovery inherit
/// the same DNS/IP pinning, proxy isolation, redirect, MIME, timeout, and body
/// limits as JWKS and compatibility-binding resolution.
#[cfg(not(target_arch = "wasm32"))]
pub fn fetch_agent_card_json(
    base_url: &str,
    timeout_ms: Option<u64>,
) -> Result<String, crate::error::JacsError> {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(crate::error::JacsError::ValidationError(
            "Agent base URL cannot be empty".to_string(),
        ));
    }
    let card_url = format!("{trimmed}/.well-known/agent-card.json");
    ensure_network_access(NetworkCapability::AgentCardFetch)?;
    let total_timeout = Duration::from_millis(timeout_ms.unwrap_or(10_000).clamp(1, 30_000));
    let policy = crate::secure_fetch::SecureFetchPolicy::new(
        "A2A Agent Card",
        MAX_JWKS_RESPONSE_BYTES,
        &["application/agent-card+json", "application/json"],
    )
    .max_redirects(3)
    .timeouts(
        total_timeout,
        Duration::from_secs(3),
        Duration::from_secs(3),
    )
    .redirect_scope(crate::secure_fetch::RedirectScope::SameOrigin)
    .allow_exact_loopback(crate::secure_fetch::is_exact_textual_loopback_endpoint(
        &card_url,
    ));
    let response = crate::secure_fetch::secure_get(
        &card_url,
        "application/agent-card+json, application/json",
        &policy,
    )?;
    if !response.status.is_success() {
        return Err(crate::error::JacsError::NetworkError(format!(
            "A2A Agent Card endpoint returned HTTP {}",
            response.status
        )));
    }
    let value =
        jacs_core::strict_json::parse_strict_json_slice(&response.body).map_err(|error| {
            crate::error::JacsError::ValidationError(format!(
                "A2A Agent Card response is not valid strict JSON: {error}"
            ))
        })?;
    if !value.is_object() {
        return Err(crate::error::JacsError::ValidationError(
            "A2A Agent Card response must be a JSON object".to_string(),
        ));
    }
    serde_json::to_string(&value).map_err(crate::error::JacsError::from)
}

#[cfg(target_arch = "wasm32")]
pub fn fetch_agent_card_json(
    _base_url: &str,
    _timeout_ms: Option<u64>,
) -> Result<String, crate::error::JacsError> {
    Err(crate::error::JacsError::NetworkError(
        "A2A Agent Card network fetch is not supported on wasm32".to_string(),
    ))
}

/// Trust policy controlling which remote agents are allowed to interact.
///
/// The default policy is `Verified`, requiring a valid Agent Card JWS plus a
/// durable same-origin key pin. This proves origin/key continuity, not native
/// JACS identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum A2ATrustPolicy {
    /// Accept any A2A agent, even those without JACS signatures.
    Open,
    /// Require a valid card signature and durable same-origin key pin. This is
    /// origin continuity, not proof of the claimed native JACS identity.
    #[default]
    Verified,
    /// Require an explicitly trusted native root and a valid identity binding.
    Strict,
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
    /// Card signature and origin key pin verified, but no explicitly trusted
    /// native identity binding was established.
    JacsVerified,
    /// Explicit native root trust plus a verified card identity binding.
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
    /// Whether this is the FIRST contact with the agent's `id:version` (the
    /// verifying A2A key was just pinned trust-on-first-use). When `true`, a
    /// `JacsVerified` result proves only control of the card origin — NOT that
    /// the signer is the claimed `jacsId`. Machine consumers should refuse to
    /// treat a first-contact assessment as proof of identity (A2A-1).
    #[serde(default)]
    pub first_contact: bool,
}

/// Caveat appended to a `JacsVerified` reason when the verifying key was pinned
/// on first contact (A2A-1). Signals that the result proves card-origin control,
/// not the claimed identity, on this contact.
const FIRST_CONTACT_CAVEAT: &str = " (first contact: verifying key pinned trust-on-first-use — proves control of the \
     card origin, NOT the claimed identity; native identity remains unconfirmed \
     without explicit root trust and a valid compatibility binding)";

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
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Agent Card interface URL must not contain credentials".to_string());
    }

    // SECURITY (A2A-2): the JWKS fetched from this origin supplies the public
    // key that decides whether the Agent Card signature verifies. Fetching it
    // over plaintext http lets a network MITM substitute their own key and
    // forge any agent identity. Require https for trust decisions; permit http
    // only for loopback hosts (local development), which are not MITM-exposed.
    let scheme = parsed.scheme();
    let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if scheme != "https" && !(scheme == "http" && is_loopback) {
        return Err(format!(
            "Refusing to fetch JWKS for A2A trust over insecure scheme '{}' (host '{}'). \
             JWKS used for trust decisions must be served over https; http is permitted only \
             for loopback hosts. A plaintext origin lets a network attacker substitute the \
             verifying key and forge agent identities.",
            scheme, host
        ));
    }

    Ok(parsed.origin().ascii_serialization())
}

#[cfg(not(target_arch = "wasm32"))]
fn private_loopback_jwks_opted_in() -> bool {
    std::env::var("JACS_ALLOW_PRIVATE_JWKS")
        .ok()
        .is_some_and(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true"))
}

#[cfg(not(target_arch = "wasm32"))]
fn fetch_a2a_json(
    url: &str,
    surface: &'static str,
    accept: &'static str,
    mime_types: &'static [&'static str],
) -> Result<Vec<u8>, String> {
    let policy =
        crate::secure_fetch::SecureFetchPolicy::new(surface, MAX_JWKS_RESPONSE_BYTES, mime_types)
            .max_redirects(3)
            .timeouts(
                Duration::from_secs(5),
                Duration::from_secs(3),
                Duration::from_secs(3),
            )
            .redirect_scope(crate::secure_fetch::RedirectScope::SameOrigin)
            .allow_exact_loopback(private_loopback_jwks_opted_in());
    let response =
        crate::secure_fetch::secure_get(url, accept, &policy).map_err(|error| error.to_string())?;
    if !response.status.is_success() {
        return Err(format!(
            "{surface} endpoint returned HTTP {}",
            response.status
        ));
    }
    Ok(response.body)
}

#[cfg(not(target_arch = "wasm32"))]
fn fetch_jwks(card: &AgentCard) -> Result<Vec<Jwk>, String> {
    let jwks_url = format!("{}/.well-known/jwks.json", agent_card_origin(card)?);

    #[cfg(test)]
    if agent_card_origin(card)
        .ok()
        .as_deref()
        .is_some_and(|origin| origin == "https://local-jwks.invalid")
        && let Ok(jwks_json) = std::env::var("JACS_TEST_JWKS_JSON")
    {
        let value = jacs_core::strict_json::parse_strict_json(&jwks_json).map_err(|e| {
            format!(
                "Failed to parse test JWKS JSON from JACS_TEST_JWKS_JSON: {}",
                e
            )
        })?;
        let keys_value = value
            .get("keys")
            .ok_or_else(|| "Test JWKS JSON did not include a 'keys' array".to_string())?
            .clone();
        return serde_json::from_value::<Vec<Jwk>>(keys_value).map_err(|e| {
            format!(
                "Failed to decode test JWKS keys from JACS_TEST_JWKS_JSON: {}",
                e
            )
        });
    }

    ensure_network_access(NetworkCapability::JwksFetch).map_err(|e| e.to_string())?;
    let body = fetch_a2a_json(
        &jwks_url,
        "A2A JWKS",
        "application/jwk-set+json, application/json",
        &["application/jwk-set+json", "application/json"],
    )?;
    let value = jacs_core::strict_json::parse_strict_json_slice(&body)
        .map_err(|e| format!("Failed to parse JWKS JSON from '{}': {}", jwks_url, e))?;

    let keys_value = value
        .get("keys")
        .ok_or_else(|| format!("JWKS endpoint '{}' did not return a 'keys' array", jwks_url))?
        .clone();

    serde_json::from_value::<Vec<Jwk>>(keys_value)
        .map_err(|e| format!("Failed to decode JWKS keys from '{}': {}", jwks_url, e))
}

#[cfg(not(target_arch = "wasm32"))]
fn fetch_compat_binding(card: &AgentCard) -> Result<serde_json::Value, String> {
    let binding_path = card
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("jacsCompatBindingPath"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            "Agent Card metadata is missing deterministic jacsCompatBindingPath".to_string()
        })?;
    if binding_path != crate::compatibility::exports::A2A_COMPAT_BINDING_PATH {
        return Err(format!(
            "Agent Card compatibility binding path '{}' is not the fixed same-origin path '{}'",
            binding_path,
            crate::compatibility::exports::A2A_COMPAT_BINDING_PATH
        ));
    }

    let origin = agent_card_origin(card)?;
    #[cfg(test)]
    if origin == "https://local-jwks.invalid" {
        let binding_json = std::env::var("JACS_TEST_COMPAT_BINDING_JSON").map_err(|_| {
            "Agent Card compatibility binding could not be resolved from the test origin"
                .to_string()
        })?;
        return jacs_core::strict_json::parse_strict_json(&binding_json).map_err(|error| {
            format!(
                "Failed to parse test compatibility binding JSON from \
                 JACS_TEST_COMPAT_BINDING_JSON: {error}"
            )
        });
    }

    ensure_network_access(NetworkCapability::JwksFetch).map_err(|error| error.to_string())?;
    let mut endpoint = Url::parse(&origin)
        .map_err(|error| format!("Invalid Agent Card origin '{origin}': {error}"))?;
    endpoint.set_path(binding_path);
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let body = fetch_a2a_json(
        endpoint.as_str(),
        "A2A compatibility binding",
        "application/json",
        &["application/json"],
    )?;
    jacs_core::strict_json::parse_strict_json_slice(&body).map_err(|error| {
        format!(
            "Failed to parse compatibility binding JSON from '{}': {error}",
            endpoint
        )
    })
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
        "EC" if jwk.crv.as_deref() == Some("P-256") => {
            let public_pem = crate::a2a::keys::es256_jwk_public_pem(jwk)
                .map_err(|error| format!("Invalid ES256 A2A JWK: {error}"))?;
            Ok((public_pem.into_bytes(), "ES256"))
        }
        other => Err(format!("Unsupported JWKS key type '{}'", other)),
    }
}

struct VerifiedAgentCardSignature {
    public_key: Vec<u8>,
    algorithm: &'static str,
    jwk: Jwk,
}

/// Verify a remote Agent Card's embedded JWS against its advertised JWKS.
///
/// Returns `(verified, public_key)` where `public_key` is the JWKS key the
/// signature was checked against. The key is surfaced (A2A-1) so the caller
/// can bind the card to a pinned identity key — a verified JWKS only proves
/// control of the card's origin, not the claimed `jacsId`.
#[cfg(not(target_arch = "wasm32"))]
fn verify_agent_card_signature(card: &AgentCard) -> Result<VerifiedAgentCardSignature, String> {
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

    let verified = verify_agent_card_jws(card, &public_key, algorithm)
        .map_err(|e| format!("Agent Card signature verification failed: {}", e))?;
    if !verified {
        return Err("Agent Card signature verifier returned false".to_string());
    }
    Ok(VerifiedAgentCardSignature {
        public_key,
        algorithm,
        jwk: jwk.clone(),
    })
}

#[cfg(target_arch = "wasm32")]
fn verify_agent_card_signature(_card: &AgentCard) -> Result<VerifiedAgentCardSignature, String> {
    Err("Agent Card JWKS verification is not supported on wasm32".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_explicit_trusted_identity_binding(
    card: &AgentCard,
    trust_store_key: &str,
    verified_signature: &VerifiedAgentCardSignature,
) -> Result<(), String> {
    let trusted_native_root = trust::get_trusted_public_key(trust_store_key)
        .map_err(|error| format!("trusted native root could not be loaded: {error}"))?;

    // Historical cards signed directly by the trusted native Ed25519 root do
    // not need an ES256 delegation artifact. The exact trusted key must still
    // be the key that verified the card.
    if verified_signature.algorithm == "ring-Ed25519" {
        let trusted_hash = crate::crypt::hash::hash_public_key(&trusted_native_root);
        let card_hash = crate::crypt::hash::hash_public_key(&verified_signature.public_key);
        return if trusted_hash == card_hash {
            Ok(())
        } else {
            Err(format!(
                "card key substitution: directly signed Ed25519 card key hash '{card_hash}' \
                 does not match trusted native root '{trusted_hash}'"
            ))
        };
    }

    if verified_signature.algorithm != "ES256" {
        return Err(format!(
            "unsupported Agent Card verification algorithm '{}'",
            verified_signature.algorithm
        ));
    }

    let agent_id = extract_agent_id(card)
        .ok_or_else(|| "Agent Card is missing metadata.jacsId".to_string())?;
    let agent_version = extract_agent_version(card)
        .ok_or_else(|| "Agent Card is missing metadata.jacsVersion".to_string())?;
    if card.version != agent_version {
        return Err(format!(
            "Agent Card version '{}' does not match metadata.jacsVersion '{}'",
            card.version, agent_version
        ));
    }
    let metadata = card
        .metadata
        .as_ref()
        .ok_or_else(|| "Agent Card metadata is missing".to_string())?;
    let compat_kid = metadata
        .get("jacsCompatKid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Agent Card metadata is missing jacsCompatKid".to_string())?;
    if compat_kid != verified_signature.jwk.kid {
        return Err(format!(
            "Agent Card compatibility kid '{}' does not match the JWKS key '{}' that verified \
             the card",
            compat_kid, verified_signature.jwk.kid
        ));
    }
    let binding_hash = metadata
        .get("jacsCompatBindingHash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Agent Card metadata is missing jacsCompatBindingHash".to_string())?;
    let binding = fetch_compat_binding(card)?;
    let compat_jwk = serde_json::to_value(&verified_signature.jwk)
        .map_err(|error| format!("Failed to serialize verified A2A JWK: {error}"))?;
    let verdict = crate::compatibility::binding::verify_remote_a2a_binding(
        &binding,
        &agent_id,
        &agent_version,
        binding_hash,
        &compat_jwk,
        &trusted_native_root,
    )
    .map_err(|error| format!("native compatibility binding verification failed: {error}"))?;
    if verdict.valid {
        let binding_issued_at = binding
            .pointer("/compatibilityKeyBinding/issuedAt")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "compatibility binding is missing issuedAt".to_string())?;
        trust::enforce_a2a_binding_lifecycle(
            trust_store_key,
            binding_hash,
            compat_kid,
            binding_issued_at,
        )
        .map_err(|error| format!("compatibility binding lifecycle check failed: {error}"))?;
        Ok(())
    } else {
        Err(format!(
            "native compatibility binding verification failed: {}",
            verdict.reason
        ))
    }
}

#[cfg(target_arch = "wasm32")]
fn verify_explicit_trusted_identity_binding(
    _card: &AgentCard,
    _trust_store_key: &str,
    _verified_signature: &VerifiedAgentCardSignature,
) -> Result<(), String> {
    Err("strict A2A compatibility binding verification is not supported on wasm32".to_string())
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
        Err("Agent Card does not declare JACS provenance".to_string())
    };
    let card_signature_verified = signature_verification.is_ok();
    // Hash of the JWKS key that actually verified the card (A2A-1). Used to
    // pin the agent's A2A key trust-on-first-use.
    let verifying_key_hash = match &signature_verification {
        Ok(verified) if !verified.public_key.is_empty() => {
            Some(crate::crypt::hash::hash_public_key(&verified.public_key))
        }
        _ => None,
    };

    // Determine if the agent is in the local trust store
    let in_trust_store = trust_store_key
        .as_ref()
        .map(|key| trust::is_verified_trusted(key))
        .unwrap_or(false);

    // Determine trust level.
    //
    // A2A-1: a verified self-published JWKS proves only that whoever controls
    // the card's origin signed it — NOT that they are the claimed jacsId. To
    // bind identity to key material, the verifying (A2A) key is pinned
    // trust-on-first-use, keyed by `id:version`. A later card for the same
    // id:version that presents a DIFFERENT key is a key-substitution signal and
    // is downgraded to Untrusted. (Legitimate key rotation bumps the version,
    // producing a fresh pin rather than a false-positive mismatch.) Pin-store
    // failures fail closed: accepting without a durable/readable binding would
    // turn each store outage into a fresh TOFU opportunity.
    let mut key_binding_failure: Option<String> = None;
    // A2A-1: whether the verifying key was pinned on THIS assessment (first
    // contact). A first-contact JacsVerified proves origin control, not the
    // claimed identity, so callers must be able to distinguish it.
    let mut first_contact = false;
    let trust_level = if card_signature_verified {
        match (trust_store_key.as_deref(), &verifying_key_hash) {
            (Some(key), Some(_seen)) if in_trust_store => match &signature_verification {
                Ok(verified) => {
                    match verify_explicit_trusted_identity_binding(remote_card, key, verified) {
                        Ok(()) => TrustLevel::ExplicitlyTrusted,
                        Err(error) => {
                            tracing::warn!(
                                event = "a2a_identity_binding_verify_failed",
                                agent_id = agent_id.as_deref().unwrap_or("unknown"),
                                trust_store_key = key,
                                reason = %error,
                                "A2A Agent Card identity binding verification failed"
                            );
                            key_binding_failure = Some(format!(
                                "agent '{}' has a cryptographically valid Agent Card, but its \
                                 explicitly trusted identity binding failed: {}",
                                agent_id.as_deref().unwrap_or("unknown"),
                                error
                            ));
                            TrustLevel::Untrusted
                        }
                    }
                }
                Err(error) => {
                    key_binding_failure = Some(format!(
                        "agent '{}' has an explicit trust entry, but Agent Card signature \
                             verification failed: {}",
                        agent_id.as_deref().unwrap_or("unknown"),
                        error
                    ));
                    TrustLevel::Untrusted
                }
            },
            (Some(key), Some(seen)) => match trust::pin_a2a_key(key, seen) {
                Ok(trust::A2aPinOutcome::Mismatch { pinned }) => {
                    key_binding_failure = Some(format!(
                        "agent '{}' presents an Agent Card key (hash {}) that differs from \
                         the key pinned on first contact (hash {}); refusing trust \
                         (possible key substitution)",
                        agent_id.as_deref().unwrap_or("unknown"),
                        seen,
                        pinned
                    ));
                    TrustLevel::Untrusted
                }
                Ok(trust::A2aPinOutcome::FirstUse) => {
                    first_contact = true;
                    TrustLevel::JacsVerified
                }
                Ok(trust::A2aPinOutcome::Match) => TrustLevel::JacsVerified,
                Err(e) => {
                    tracing::warn!(
                        event = "a2a_key_pin_failed",
                        agent_id = agent_id.as_deref().unwrap_or("unknown"),
                        "A2A key pinning unavailable ({}); refusing verification",
                        e
                    );
                    key_binding_failure = Some(format!(
                        "agent '{}' Agent Card signature verified, but its A2A key pin could not \
                         be persisted or read: {}",
                        agent_id.as_deref().unwrap_or("unknown"),
                        e
                    ));
                    TrustLevel::Untrusted
                }
            },
            _ => {
                key_binding_failure = Some(format!(
                    "agent '{}' Agent Card signature verified, but no complete id/version and \
                     verifying-key binding was available to pin",
                    agent_id.as_deref().unwrap_or("unknown")
                ));
                TrustLevel::Untrusted
            }
        }
    } else {
        TrustLevel::Untrusted
    };

    // A2A-1: when the assessment is JacsVerified purely on first contact, the
    // verifying key was just pinned — this binds future contacts to the same
    // key but does NOT prove the signer is the claimed jacsId on this contact.
    // Append a caveat so a human/LLM reading the reason is not misled, and
    // emit a structured WARN for the operator's audit trail.
    if first_contact {
        tracing::warn!(
            event = "a2a_first_contact_pinned",
            agent_id = agent_id.as_deref().unwrap_or("unknown"),
            "A2A agent verified on FIRST CONTACT (key pinned trust-on-first-use); \
             this proves card-origin control, not the claimed identity"
        );
    }

    let unverified_reason = if let Some(failure) = key_binding_failure {
        failure
    } else if jacs_registered {
        let mut reason = format!(
            "agent '{}' declares JACS provenance but its Agent Card could not be cryptographically verified",
            agent_id.as_deref().unwrap_or("unknown")
        );
        if let Err(err) = &signature_verification {
            reason.push_str(": ");
            reason.push_str(err);
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
                    let mut reason = "Open policy: agent accepted with verified same-origin Agent \
                                      Card signature and durable key pin; native JACS identity is \
                                      not explicitly trusted"
                        .to_string();
                    if first_contact {
                        reason.push_str(FIRST_CONTACT_CAVEAT);
                    }
                    reason
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
            TrustLevel::JacsVerified => {
                let mut reason = "Verified policy: Agent Card signature verified against \
                                  same-origin JWKS and durable key pin; this establishes \
                                  origin/key continuity, not the claimed native JACS identity"
                    .to_string();
                if first_contact {
                    reason.push_str(FIRST_CONTACT_CAVEAT);
                }
                (true, reason)
            }
            TrustLevel::Untrusted => (false, format!("Verified policy: {}", unverified_reason)),
        },
        A2ATrustPolicy::Strict => match trust_level {
            TrustLevel::ExplicitlyTrusted => (
                true,
                "Strict policy: explicitly trusted native root and compatibility binding verified"
                    .to_string(),
            ),
            _ if in_trust_store => (
                false,
                format!(
                    "Strict policy: a local trust entry exists, but {}",
                    unverified_reason
                ),
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
        first_contact,
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
    use crate::agent::document::DocumentTraits;
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
    // agent_card_origin: scheme enforcement (A2A-2)
    // =========================================================================

    #[test]
    fn agent_card_origin_rejects_plaintext_http() {
        let mut card = make_card("http-agent", true, Some("id-http"), Some("v1"));
        card.supported_interfaces[0].url = "http://evil.example.com/agent".to_string();
        let err = agent_card_origin(&card).expect_err("plaintext http origin must be rejected");
        assert!(
            err.contains("https") && err.contains("insecure"),
            "error should explain the https requirement: {}",
            err
        );
    }

    #[test]
    fn agent_card_origin_allows_https() {
        let card = make_card("https-agent", true, Some("id-https"), Some("v1"));
        // make_card defaults to https://test.example.com
        let origin = agent_card_origin(&card).expect("https origin must be allowed");
        assert_eq!(origin, "https://test.example.com");
    }

    #[test]
    fn agent_card_origin_allows_http_loopback_for_dev() {
        let mut card = make_card("local-agent", true, Some("id-local"), Some("v1"));
        card.supported_interfaces[0].url = "http://localhost:8080/agent".to_string();
        let origin = agent_card_origin(&card).expect("loopback http must be allowed for dev");
        assert_eq!(origin, "http://localhost:8080");
    }

    // A2A JWKS and binding fetches delegate to `crate::secure_fetch`; its test
    // module owns the shared DNS/SSRF/redirect/MIME/size/deadline matrix.

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
            first_contact: false,
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

    fn make_signed_card_with_test_jwks() -> AgentCard {
        let agent_id = "550e8400-e29b-41d4-a716-446655440030";
        let version = "550e8400-e29b-41d4-a716-446655440031";
        let mut card = make_card("signed-jacs-agent", true, Some(agent_id), Some(version));
        let (private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("generate ed25519 keys");
        let jwk = export_as_jwk(&public_key, "ring-Ed25519", agent_id).expect("export jwk");
        let jwks = create_jwk_set(vec![jwk]).to_string();
        unsafe {
            std::env::set_var("JACS_TEST_JWKS_JSON", &jwks);
        }
        card.supported_interfaces[0].url = format!("https://local-jwks.invalid/agent/{}", agent_id);
        let jws =
            sign_agent_card_jws(&card, &private_key, "ring-Ed25519", agent_id).expect("sign card");
        embed_signature_in_agent_card(&card, &jws, Some(agent_id))
    }

    fn write_explicit_trust_record(
        trust_store_dir: &std::path::Path,
        key: &str,
        public_key: &[u8],
    ) {
        let public_key_hash = crate::crypt::hash::hash_public_key(public_key);
        let trusted_document = json!({
            "jacsSignature": {
                "publicKeyHash": public_key_hash,
            }
        });
        std::fs::write(
            trust_store_dir.join(format!("{key}.json")),
            serde_json::to_vec(&trusted_document).expect("serialize trusted document"),
        )
        .expect("write trusted document");
        let metadata = crate::trust::TrustedAgent {
            agent_id: key.to_string(),
            name: None,
            public_key_pem: crate::crypt::normalize_public_key_pem(public_key),
            public_key_hash: public_key_hash.clone(),
            trusted_at: crate::time_utils::now_rfc3339(),
            verified: true,
        };
        std::fs::write(
            trust_store_dir.join(format!("{key}.meta.json")),
            serde_json::to_vec(&metadata).expect("serialize trust metadata"),
        )
        .expect("write trust metadata");
        let keys_dir = trust_store_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).expect("create trusted key cache");
        std::fs::write(keys_dir.join(format!("{public_key_hash}.pem")), public_key)
            .expect("write trusted key cache");
    }

    #[test]
    #[serial_test::serial(jacs_env, home_env)]
    fn test_verified_policy_accepts_signed_jacs_agent() {
        // Isolate the trust store so first-contact A2A key pinning (A2A-1)
        // starts from a clean slate on every run.
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let trust_store_dir = temp_dir.path().canonicalize().expect("canonical tempdir");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", &trust_store_dir);
        }

        let agent = test_agent();
        let card = make_signed_card_with_test_jwks();
        let result = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        unsafe {
            std::env::remove_var("JACS_TEST_JWKS_JSON");
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }

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

    // A2A-1: the verifying (A2A) key is pinned trust-on-first-use. Re-presenting
    // the same key for the same id:version stays JacsVerified.
    #[test]
    #[serial_test::serial(jacs_env, home_env)]
    fn test_a2a_first_use_then_same_key_stays_verified() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let trust_store_dir = temp_dir.path().canonicalize().expect("canonical tempdir");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", &trust_store_dir);
        }

        let agent = test_agent();
        let card = make_signed_card_with_test_jwks();

        // First contact pins the key.
        let r1 = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        assert!(r1.allowed, "first contact should be allowed: {:?}", r1);
        assert_eq!(r1.trust_level, TrustLevel::JacsVerified);
        // A2A-1: first contact must be flagged so callers don't mistake
        // origin-control for identity, and the reason must carry the caveat.
        assert!(
            r1.first_contact,
            "first contact must set first_contact=true: {:?}",
            r1
        );
        assert!(
            r1.reason.contains("first contact"),
            "first-contact reason must carry the caveat: {}",
            r1.reason
        );

        // Second contact with the SAME key (same card, JWKS env unchanged).
        let r2 = assess_a2a_agent(&agent, &card, A2ATrustPolicy::Verified);
        unsafe {
            std::env::remove_var("JACS_TEST_JWKS_JSON");
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }
        assert!(
            r2.allowed,
            "matching pinned key should stay allowed: {:?}",
            r2
        );
        assert_eq!(r2.trust_level, TrustLevel::JacsVerified);
        // A matched pin is an established identity, NOT a first contact.
        assert!(
            !r2.first_contact,
            "matched pin must set first_contact=false: {:?}",
            r2
        );
    }

    // A2A-1: a later card for the same id:version that presents a DIFFERENT key
    // (key substitution) is downgraded to Untrusted and refused under Verified.
    #[test]
    #[serial_test::serial(jacs_env, home_env)]
    fn test_a2a_key_substitution_is_downgraded() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let trust_store_dir = temp_dir.path().canonicalize().expect("canonical tempdir");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", &trust_store_dir);
        }

        let agent = test_agent();

        // First contact pins key #1 for this id:version.
        let card1 = make_signed_card_with_test_jwks();
        let r1 = assess_a2a_agent(&agent, &card1, A2ATrustPolicy::Verified);
        assert!(r1.allowed, "first contact should be allowed: {:?}", r1);
        assert_eq!(r1.trust_level, TrustLevel::JacsVerified);

        // Second contact: SAME id:version but a freshly generated key #2 and a
        // matching JWKS (a substitution attempt). make_signed_card_with_test_jwks
        // regenerates the key and overwrites JACS_TEST_JWKS_JSON.
        let card2 = make_signed_card_with_test_jwks();
        let r2 = assess_a2a_agent(&agent, &card2, A2ATrustPolicy::Verified);
        unsafe {
            std::env::remove_var("JACS_TEST_JWKS_JSON");
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }

        assert!(
            !r2.allowed,
            "substituted key must NOT be allowed under Verified policy: {:?}",
            r2
        );
        assert_eq!(r2.trust_level, TrustLevel::Untrusted);
        assert!(
            r2.reason.contains("substitution"),
            "reason should flag key substitution: {}",
            r2.reason
        );
    }

    #[test]
    #[serial_test::serial(jacs_env, home_env)]
    fn strict_policy_requires_card_signature_to_match_explicit_trust_key() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let trust_store_dir = temp_dir.path().canonicalize().expect("canonical tempdir");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", &trust_store_dir);
        }

        let card = make_signed_card_with_test_jwks();
        let key = build_trust_store_key(&card).expect("card trust key");
        let verifying_key = verify_agent_card_signature(&card)
            .expect("signed card should verify")
            .public_key;
        write_explicit_trust_record(&trust_store_dir, &key, &verifying_key);

        let accepted = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        write_explicit_trust_record(&trust_store_dir, &key, b"different-trusted-key");
        let mismatch = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        unsafe {
            std::env::remove_var("JACS_TEST_JWKS_JSON");
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }

        assert!(
            accepted.allowed,
            "matching trusted card key should pass: {accepted:?}"
        );
        assert_eq!(accepted.trust_level, TrustLevel::ExplicitlyTrusted);
        assert!(
            !mismatch.allowed,
            "trusted-key mismatch must fail: {mismatch:?}"
        );
        assert_eq!(mismatch.trust_level, TrustLevel::Untrusted);
        assert!(mismatch.reason.contains("substitution"));
    }

    #[test]
    #[serial_test::serial(jacs_env, home_env)]
    fn test_strict_policy_rejects_unverified_a2a_card_bookmark() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let trust_store_dir = temp_dir.path().canonicalize().expect("canonical tempdir");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", &trust_store_dir);
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

    #[test]
    #[serial_test::serial(jacs_env, home_env)]
    fn strict_policy_rejects_unsigned_card_that_copies_verified_identity() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let trust_store_dir = temp_dir.path().canonicalize().expect("canonical tempdir");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", &trust_store_dir);
        }

        let agent_id = "550e8400-e29b-41d4-a716-446655440050";
        let version = "550e8400-e29b-41d4-a716-446655440051";
        let key = format!("{agent_id}:{version}");
        let card = make_card(
            "copied-trusted-identity",
            true,
            Some(agent_id),
            Some(version),
        );

        // Model an already verified native-agent trust entry. The remote card
        // is attacker-controlled and merely copies its id/version metadata.
        std::fs::write(
            trust_store_dir.join(format!("{key}.json")),
            serde_json::to_vec(&card).expect("serialize card"),
        )
        .expect("write trusted record");
        let metadata = crate::trust::TrustedAgent {
            agent_id: key.clone(),
            name: None,
            public_key_pem: "trusted-key".to_string(),
            public_key_hash: crate::crypt::hash::hash_public_key(b"trusted-key"),
            trusted_at: crate::time_utils::now_rfc3339(),
            verified: true,
        };
        std::fs::write(
            trust_store_dir.join(format!("{key}.meta.json")),
            serde_json::to_vec(&metadata).expect("serialize trust metadata"),
        )
        .expect("write trust metadata");

        let result = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        unsafe {
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }

        assert!(
            !result.allowed,
            "copied trusted metadata must not replace card signature verification: {result:?}"
        );
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
    }

    #[test]
    #[serial_test::serial(jacs_env, home_env, cwd_env)]
    fn strict_policy_accepts_generated_es256_card_only_with_native_binding() {
        use crate::simple::{CreateAgentParams, SimpleAgent};

        struct EnvGuard {
            cwd: std::path::PathBuf,
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.cwd);
                unsafe {
                    std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
                    std::env::remove_var("JACS_TEST_JWKS_JSON");
                    std::env::remove_var("JACS_TEST_COMPAT_BINDING_JSON");
                    std::env::remove_var("JACS_TRUST_STORE_DIR");
                }
            }
        }

        let cwd = std::env::current_dir().expect("cwd");
        let temp = tempfile::tempdir().expect("tempdir");
        let temp_root = temp.path().canonicalize().expect("canonical tempdir");
        std::env::set_current_dir(&temp_root).expect("enter tempdir");
        let _guard = EnvGuard { cwd };
        let password = "StrictA2aBindingTest!2026";
        unsafe {
            std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", password);
            std::env::set_var("JACS_TRUST_STORE_DIR", temp_root.join("trust"));
        }
        let params = CreateAgentParams::builder()
            .name("strict-bound-remote")
            .password(password)
            .domain("https://local-jwks.invalid")
            .key_directory("./keys")
            .data_directory("./data")
            .config_path("./jacs.config.json")
            .build();
        let (remote, _) = SimpleAgent::create_with_params(params).expect("create remote agent");
        let documents = crate::a2a::simple::generate_well_known_documents(&remote, None)
            .expect("generate bound discovery");
        let document = |path: &str| {
            documents
                .iter()
                .find(|(candidate, _)| candidate == path)
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| panic!("missing discovery path {path}"))
        };
        let card_value = document("/.well-known/agent-card.json");
        let jwks = document("/.well-known/jwks.json");
        let binding = document("/.well-known/jacs-compat-binding.json");
        unsafe {
            std::env::set_var("JACS_TEST_JWKS_JSON", jwks.to_string());
            std::env::set_var("JACS_TEST_COMPAT_BINDING_JSON", binding.to_string());
        }

        let trusted_id = crate::trust::trust_agent_with_key(
            &remote.export_agent().expect("export native identity"),
            Some(
                &remote
                    .get_public_key_pem()
                    .expect("export native root public key"),
            ),
        )
        .expect("explicitly trust the native JACS identity");
        let card: AgentCard =
            serde_json::from_value(card_value.clone()).expect("decode Agent Card");
        assert_eq!(
            build_trust_store_key(&card).as_deref(),
            Some(trusted_id.as_str())
        );

        // First-observation replay regression: a native-root-signed legacy
        // binding with expiresAt:null must not become immortal merely because
        // this verifier has not observed a newer binding yet. Re-sign both the
        // old binding and its matching ES256 card so every cryptographic check
        // succeeds; only the absolute Strict freshness boundary should deny.
        let stale_issued_at =
            (crate::time_utils::now_utc() - chrono::Duration::days(8)).to_rfc3339();
        let mut stale_binding = binding.clone();
        stale_binding["compatibilityKeyBinding"]["issuedAt"] =
            serde_json::Value::String(stale_issued_at);
        let mut stale_card_value = card_value.clone();
        {
            let mut inner = remote.agent.lock().expect("lock remote agent");
            stale_binding["jacsSignature"] = inner
                .signing_procedure(&stale_binding, None, "jacsSignature")
                .expect("native re-sign stale binding");
            stale_binding["jacsSha256"] = serde_json::Value::String(
                inner
                    .hash_doc(&stale_binding)
                    .expect("recompute stale binding hash"),
            );
            stale_card_value["metadata"]["jacsCompatBindingHash"] =
                stale_binding["jacsSha256"].clone();
            stale_card_value
                .as_object_mut()
                .expect("card object")
                .remove("signatures");
            let payload = jacs_core::canonical::canonicalize_json_try(&stale_card_value)
                .expect("canonicalize stale card");
            let compat = crate::keystore::compat::ecosystem_key_info("./keys")
                .expect("load compatibility key");
            let header = json!({ "alg": "ES256", "typ": "JOSE", "kid": compat.kid });
            let header_b64 = URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).expect("serialize protected header"));
            let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
            let signing_input = format!("{header_b64}.{payload_b64}");
            let private_key = crate::compatibility::decrypt_ecosystem_private_key(&inner, &compat)
                .expect("decrypt compatibility key");
            let signature = crate::crypt::es256::sign_es256_jose(
                private_key.as_slice(),
                signing_input.as_bytes(),
            )
            .expect("sign stale card");
            let jws = format!(
                "{header_b64}.{payload_b64}.{}",
                URL_SAFE_NO_PAD.encode(signature)
            );
            stale_card_value["signatures"] = json!([{ "jws": jws, "keyId": compat.kid }]);
        }
        let stale_card: AgentCard =
            serde_json::from_value(stale_card_value).expect("decode stale Agent Card");
        unsafe {
            std::env::set_var("JACS_TEST_COMPAT_BINDING_JSON", stale_binding.to_string());
        }
        let stale_first = assess_a2a_agent(&test_agent(), &stale_card, A2ATrustPolicy::Strict);
        assert!(
            !stale_first.allowed,
            "an old null-expiry binding must fail on the verifier's first Strict observation: \
             {stale_first:?}"
        );
        assert!(
            stale_first.reason.contains("stale"),
            "unexpected first-observation freshness reason: {}",
            stale_first.reason
        );

        unsafe {
            std::env::set_var("JACS_TEST_COMPAT_BINDING_JSON", binding.to_string());
        }

        let accepted = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        assert!(
            accepted.allowed,
            "valid native-root-bound ES256 Agent Card must pass strict trust: {accepted:?}"
        );
        assert_eq!(accepted.trust_level, TrustLevel::ExplicitlyTrusted);

        // A newer native-root-signed binding advances the durable Strict
        // lifecycle pin. Once observed, replaying the older card/binding pair
        // must fail even though both signatures remain cryptographically valid.
        let refreshed_binding = remote
            .issue_compat_binding(None, None)
            .expect("reissue compatibility binding");
        let refreshed_documents = crate::a2a::simple::generate_well_known_documents(&remote, None)
            .expect("generate refreshed discovery");
        let refreshed_card_value = refreshed_documents
            .iter()
            .find(|(path, _)| path == "/.well-known/agent-card.json")
            .map(|(_, value)| value.clone())
            .expect("refreshed card");
        let refreshed_jwks = refreshed_documents
            .iter()
            .find(|(path, _)| path == "/.well-known/jwks.json")
            .map(|(_, value)| value.clone())
            .expect("refreshed JWKS");
        unsafe {
            std::env::set_var("JACS_TEST_JWKS_JSON", refreshed_jwks.to_string());
            std::env::set_var(
                "JACS_TEST_COMPAT_BINDING_JSON",
                refreshed_binding.to_string(),
            );
        }
        let refreshed_card: AgentCard =
            serde_json::from_value(refreshed_card_value).expect("decode refreshed card");
        let refreshed = assess_a2a_agent(&test_agent(), &refreshed_card, A2ATrustPolicy::Strict);
        assert!(
            refreshed.allowed,
            "a newer valid binding must advance Strict lifecycle state: {refreshed:?}"
        );

        unsafe {
            std::env::set_var("JACS_TEST_JWKS_JSON", jwks.to_string());
            std::env::set_var("JACS_TEST_COMPAT_BINDING_JSON", binding.to_string());
        }
        let replayed = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        assert!(
            !replayed.allowed,
            "an older valid card/binding must not roll Strict lifecycle state back: {replayed:?}"
        );
        assert!(
            replayed.reason.contains("rollback") || replayed.reason.contains("lifecycle"),
            "unexpected rollback reason: {}",
            replayed.reason
        );

        unsafe {
            std::env::set_var("JACS_TEST_JWKS_JSON", refreshed_jwks.to_string());
            std::env::set_var(
                "JACS_TEST_COMPAT_BINDING_JSON",
                refreshed_binding.to_string(),
            );
        }
        let refreshed_again =
            assess_a2a_agent(&test_agent(), &refreshed_card, A2ATrustPolicy::Strict);
        assert!(
            refreshed_again.allowed,
            "rollback attempts must not disturb the current lifecycle pin: {refreshed_again:?}"
        );

        let mut tampered_binding = binding.clone();
        tampered_binding["compatibilityKeyBinding"]["compatibilityKey"]["kid"] =
            serde_json::Value::String("attacker-substituted-kid".to_string());
        unsafe {
            std::env::set_var(
                "JACS_TEST_COMPAT_BINDING_JSON",
                tampered_binding.to_string(),
            );
        }
        let tampered = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        assert!(
            !tampered.allowed,
            "strict trust must reject a tampered compatibility binding"
        );
        assert!(
            tampered.reason.contains("binding"),
            "unexpected tamper failure reason: {}",
            tampered.reason
        );

        unsafe {
            std::env::remove_var("JACS_TEST_COMPAT_BINDING_JSON");
        }
        let missing_binding = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Strict);
        assert!(
            !missing_binding.allowed,
            "strict trust must fail when the compatibility binding cannot be resolved"
        );
        assert!(
            missing_binding.reason.contains("binding"),
            "unexpected strict failure reason: {}",
            missing_binding.reason
        );
    }

    #[test]
    #[serial_test::serial(jacs_env, home_env)]
    fn verified_policy_fails_closed_when_first_contact_pin_cannot_persist() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let unusable_trust_root = temp_dir.path().join("not-a-directory");
        std::fs::write(&unusable_trust_root, b"occupied").expect("create blocking file");
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", &unusable_trust_root);
        }

        let card = make_signed_card_with_test_jwks();
        let result = assess_a2a_agent(&test_agent(), &card, A2ATrustPolicy::Verified);
        unsafe {
            std::env::remove_var("JACS_TEST_JWKS_JSON");
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }

        assert!(
            !result.allowed,
            "a failed TOFU persistence boundary must reject Verified policy: {result:?}"
        );
        assert_eq!(result.trust_level, TrustLevel::Untrusted);
        assert!(
            result.reason.contains("pin"),
            "unexpected reason: {}",
            result.reason
        );
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
            first_contact: false,
        };

        let actual: serde_json::Value = serde_json::to_value(&assessment).unwrap();
        let expected = json!({
            "allowed": true,
            "trustLevel": "JacsVerified",
            "reason": "Verified policy: Agent Card signature verified against advertised JWKS",
            "jacsRegistered": true,
            "agentId": "agent-golden-trust",
            "policy": "Verified",
            "firstContact": false
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
            first_contact: false,
        };

        let actual_none: serde_json::Value = serde_json::to_value(&assessment_none).unwrap();
        let expected_none = json!({
            "allowed": true,
            "trustLevel": "Untrusted",
            "reason": "Open policy: agent accepted (trust level: Untrusted)",
            "jacsRegistered": false,
            "agentId": null,
            "policy": "Open",
            "firstContact": false
        });

        assert_eq!(
            actual_none, expected_none,
            "Golden JSON mismatch for TrustAssessment (Untrusted/None)"
        );

        // Pin ExplicitlyTrusted + Strict policy
        let assessment_strict = TrustAssessment {
            allowed: true,
            trust_level: TrustLevel::ExplicitlyTrusted,
            reason:
                "Strict policy: explicitly trusted native root and compatibility binding verified"
                    .to_string(),
            jacs_registered: true,
            agent_id: Some("trusted-agent-xyz".to_string()),
            policy: A2ATrustPolicy::Strict,
            first_contact: false,
        };

        let actual_strict: serde_json::Value = serde_json::to_value(&assessment_strict).unwrap();
        let expected_strict = json!({
            "allowed": true,
            "trustLevel": "ExplicitlyTrusted",
            "reason": "Strict policy: explicitly trusted native root and compatibility binding verified",
            "jacsRegistered": true,
            "agentId": "trusted-agent-xyz",
            "policy": "Strict",
            "firstContact": false
        });

        assert_eq!(
            actual_strict, expected_strict,
            "Golden JSON mismatch for TrustAssessment (Strict)"
        );
    }
}
