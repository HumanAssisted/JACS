//! Identity exports for the ES256 ecosystem compatibility key (P2 Task 004-A).
//!
//! JWKS and binding exports — the surfaces that make a JACS agent's
//! compatibility key legible to JOSE ecosystems. Every export is gated by
//! the native-root-signed binding scope (`require_scope`). Identity exports
//! may auto-issue the DEFAULT (identity-scopes-only) binding when none
//! exists yet — the current native root signs it in-process at that moment; content
//! exports (Tasks 004b/004c) never auto-issue.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::error::JacsError;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::info;

/// Deterministic discovery path for the native-root-signed compatibility
/// binding referenced by A2A Agent Cards.
pub const A2A_COMPAT_BINDING_PATH: &str = "/.well-known/jacs-compat-binding.json";

const IDENTITY_BINDING_LOCK_FILENAME: &str = ".jacs.compat-binding.issue.lock";
const IDENTITY_BINDING_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

struct IdentityBindingIssueGuard {
    _file: std::fs::File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityBindingReissueReason {
    StaleAgentVersion,
    A2aFreshness,
}

/// Identify the two narrow cases an identity exporter may repair with the
/// loaded native root. Corrupt, foreign, expired, or otherwise invalid
/// bindings deliberately return `None` and remain hard failures in the normal
/// scope verifier.
fn identity_binding_reissue_reason(
    agent: &Agent,
    key_directory: &str,
    binding: &Value,
    refresh_for_a2a: bool,
) -> Result<Option<IdentityBindingReissueReason>, JacsError> {
    if super::binding::authentic_binding_has_stale_agent_version(agent, key_directory, binding)? {
        return Ok(Some(IdentityBindingReissueReason::StaleAgentVersion));
    }
    if !refresh_for_a2a {
        return Ok(None);
    }

    // Refresh only a fully valid CURRENT binding. A malformed timestamp or a
    // failed signature is never converted into an opportunity to invoke the
    // signing key and overwrite evidence of tampering.
    let verdict = super::binding::verify_compat_binding(agent, key_directory, binding)?;
    if !verdict.valid {
        return Ok(None);
    }
    let issued_at = binding["compatibilityKeyBinding"]["issuedAt"]
        .as_str()
        .ok_or_else(|| {
            JacsError::ValidationError(
                "valid compatibility binding is missing issuedAt; refusing freshness reissue"
                    .to_string(),
            )
        })?;
    let issued_at = chrono::DateTime::parse_from_rfc3339(issued_at)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|error| {
            JacsError::ValidationError(format!(
                "compatibility binding issuedAt is invalid; refusing freshness reissue: {error}"
            ))
        })?;
    let now = crate::time_utils::now_utc();
    let refresh_before =
        now - chrono::Duration::seconds(super::binding::A2A_BINDING_REFRESH_AFTER_SECONDS);
    let future_limit =
        now + chrono::Duration::seconds(super::binding::STRICT_A2A_BINDING_MAX_FUTURE_SECONDS);
    if issued_at <= refresh_before || issued_at > future_limit {
        Ok(Some(IdentityBindingReissueReason::A2aFreshness))
    } else {
        Ok(None)
    }
}

/// Load the persisted default identity binding or issue it exactly once across
/// concurrent processes sharing the same key directory.
///
/// A persistent 0600 lock file carries an OS advisory lock. The kernel releases
/// that lock automatically on process death, so a crashed issuer cannot leave a
/// permanent lock-file denial of service. Waiters read the winner's atomically
/// replaced binding rather than signing a second timestamp/JTI variant.
fn load_or_issue_default_identity_binding(
    agent: &mut Agent,
    key_directory: &str,
    requested_export: Option<&str>,
    refresh_for_a2a: bool,
) -> Result<Value, JacsError> {
    let lock_path = PathBuf::from(key_directory).join(IDENTITY_BINDING_LOCK_FILENAME);
    let deadline = Instant::now() + IDENTITY_BINDING_LOCK_TIMEOUT;
    let lock_file =
        crate::secure_io::open_private_lock_file_no_follow(&lock_path).map_err(|error| {
            JacsError::FileWriteFailed {
                path: lock_path.to_string_lossy().into_owned(),
                reason: format!("failed to open compatibility binding issuance lock: {error}"),
            }
        })?;

    loop {
        if let Some(binding) = super::binding::load_compat_binding(key_directory)?
            && identity_binding_reissue_reason(agent, key_directory, &binding, refresh_for_a2a)?
                .is_none()
        {
            return Ok(binding);
        }

        match lock_file.try_lock() {
            Ok(()) => {
                let _guard = IdentityBindingIssueGuard { _file: lock_file };
                let mut preserved_scopes: Option<Vec<String>> = None;
                let mut preserved_expiry: Option<String> = None;
                // Another issuer may have completed between our initial check
                // and lock acquisition. Return its current binding, repair an
                // authentic same-root stale-version binding, or issue the
                // first binding. Corrupt/foreign bindings are returned to the
                // normal verifier and remain hard failures.
                if let Some(binding) = super::binding::load_compat_binding(key_directory)? {
                    let Some(reissue_reason) = identity_binding_reissue_reason(
                        agent,
                        key_directory,
                        &binding,
                        refresh_for_a2a,
                    )?
                    else {
                        return Ok(binding);
                    };
                    match reissue_reason {
                        IdentityBindingReissueReason::StaleAgentVersion => {
                            tracing::warn!(
                                event = "compatibility_binding_stale_version_reissue",
                                jacs_id = %agent.get_id().unwrap_or_default(),
                                old_agent_version = binding["jacsSignature"]["agentVersion"]
                                    .as_str()
                                    .unwrap_or(""),
                                current_agent_version = %agent.get_version().unwrap_or_default(),
                                old_binding_hash = %super::binding::binding_hash(&binding),
                                "reissuing an authentic compatibility binding after a same-root agent version update"
                            );
                        }
                        IdentityBindingReissueReason::A2aFreshness => {
                            tracing::warn!(
                                event = "a2a_compatibility_binding_freshness_reissue",
                                jacs_id = %agent.get_id().unwrap_or_default(),
                                old_issued_at = binding["compatibilityKeyBinding"]["issuedAt"]
                                    .as_str()
                                    .unwrap_or(""),
                                old_binding_hash = %super::binding::binding_hash(&binding),
                                max_age_seconds = super::binding::STRICT_A2A_BINDING_MAX_AGE_SECONDS,
                                refresh_after_seconds = super::binding::A2A_BINDING_REFRESH_AFTER_SECONDS,
                                "reissuing an authentic A2A compatibility binding before the Strict freshness cutoff"
                            );
                        }
                    }
                    preserved_scopes =
                        binding["compatibilityKeyBinding"]["scope"]
                            .as_array()
                            .map(|scopes| {
                                scopes
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect()
                            });
                    preserved_expiry = binding["compatibilityKeyBinding"]["expiresAt"]
                        .as_str()
                        .map(str::to_string);
                }
                if let Some(scopes) = preserved_scopes {
                    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
                    return super::binding::issue_compat_binding_ctx(
                        agent,
                        key_directory,
                        &scope_refs,
                        preserved_expiry.as_deref(),
                        requested_export,
                    );
                }
                return super::binding::issue_compat_binding_ctx(
                    agent,
                    key_directory,
                    super::binding::DEFAULT_IDENTITY_SCOPES,
                    None,
                    requested_export,
                );
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    tracing::warn!(
                        event = "compatibility_binding_issue_lock_timeout",
                        path = %lock_path.display(),
                        timeout_ms = IDENTITY_BINDING_LOCK_TIMEOUT.as_millis() as u64,
                        "timed out waiting for another process to issue the identity binding"
                    );
                    return Err(JacsError::ValidationError(format!(
                        "timed out after {} ms waiting for compatibility binding issuance lock \
                         '{}'",
                        IDENTITY_BINDING_LOCK_TIMEOUT.as_millis(),
                        lock_path.display()
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(JacsError::FileWriteFailed {
                    path: lock_path.to_string_lossy().into_owned(),
                    reason: format!("failed to acquire identity binding issuance lock: {error}"),
                });
            }
        }
    }
}

/// Ensure a binding exists (issuing the default identity binding if not),
/// then require `scope`. Used by IDENTITY exports only.
fn require_identity_scope(
    agent: &mut Agent,
    key_directory: &str,
    scope: &str,
) -> Result<Value, JacsError> {
    // Auto-issue needs the ES256 key on disk; a fresh agent without one fails
    // HERE with `KeyNotFound`. The filesystem lock makes simultaneous first
    // exports from replicas converge on one persisted signed binding.
    let binding = load_or_issue_default_identity_binding(
        agent,
        key_directory,
        Some(scope),
        scope == "a2a-agent-card",
    )
    .inspect_err(|e| {
        if matches!(e, JacsError::KeyNotFound { .. }) {
            super::record_export_error(scope, "missing_key");
        }
    })?;
    super::binding::require_scope_on(agent, key_directory, scope, binding)
}

/// Export the agent's compatibility JWKS: a JWK Set holding the ES256
/// public key (kty EC / crv P-256, `kid` = RFC 7638 thumbprint,
/// `use: sig`, `alg: ES256`). Native (PQ) key material is NEVER included:
/// the JWKS is the classical-ecosystem view, and PQ keys have no
/// standardized JWK form to publish here.
pub fn export_compatibility_jwks(
    agent: &mut Agent,
    key_directory: &str,
) -> Result<Value, JacsError> {
    let binding = require_identity_scope(agent, key_directory, "jwks")?;
    let binding_hash = super::binding::binding_hash(&binding);

    // The scope gate above already verified the key exists (missing keys
    // fail inside `require_identity_scope` and count there); this re-read
    // just fetches the descriptor.
    let compat = crate::keystore::compat::ecosystem_key_info(key_directory)?;
    let (x, y) = compat.public_jwk_xy()?;

    let mut key = crate::crypt::es256::public_jwk(&x, &y, Some(&compat.kid));
    key["use"] = json!("sig");
    let jwks = json!({ "keys": [key] });

    info!(
        event = "ecosystem_export_generated",
        format = "jwks",
        jacs_id = %agent.get_id().unwrap_or_default(),
        kid = %compat.kid,
        binding_hash = %binding_hash,
        "compatibility JWKS exported"
    );
    super::record_export_generated("jwks");
    Ok(jwks)
}

#[cfg(feature = "a2a")]
/// Export the A2A agent card signed with the ES256 compatibility key
/// (P2 Task 004-B). Card-typed exporter, never a generic JWS API: the
/// target schema is the A2A card, the algorithm is fixed to ES256, and
/// the `a2a-agent-card` binding scope gates it. The JWS protected header
/// is pinned per FR14: `alg`, `kid`, `typ: "JOSE"` (not "JWT"). The
/// card's metadata carries the binding reference AS A CONTENT HASH.
pub fn export_a2a_agent_card(agent: &mut Agent, key_directory: &str) -> Result<Value, JacsError> {
    let card = crate::a2a::agent_card::export_agent_card(agent)?;
    export_a2a_agent_card_from(agent, key_directory, card)
}

/// Scope-check, bind, and sign an already-constructed A2A Agent Card.
///
/// Binding surfaces use this crate-private variant to preserve their explicit
/// skill projection while sharing the one ES256/JCS signing implementation.
#[cfg(feature = "a2a")]
pub(crate) fn export_a2a_agent_card_from(
    agent: &mut Agent,
    key_directory: &str,
    card: crate::a2a::AgentCard,
) -> Result<Value, JacsError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let binding = require_identity_scope(agent, key_directory, "a2a-agent-card")?;
    let binding_hash = super::binding::binding_hash(&binding);
    // Missing keys fail (and count) inside the scope gate above.
    let compat = crate::keystore::compat::ecosystem_key_info(key_directory)?;

    // Base card plus the deterministic binding resolution information. A
    // content hash alone is not resolvable by a remote verifier; publishing
    // both keeps the hash as the integrity reference and gives discovery a
    // same-origin, fixed path with no attacker-controlled URL.
    let mut card_value = serde_json::to_value(&card)?;
    if !card_value["metadata"].is_object() {
        card_value["metadata"] = json!({});
    }
    card_value["metadata"]["jacsCompatKid"] = json!(compat.kid);
    card_value["metadata"]["jacsCompatBindingHash"] = json!(binding_hash);
    card_value["metadata"]["jacsCompatBindingPath"] = json!(A2A_COMPAT_BINDING_PATH);

    // Sign the card (without signatures) with the ES256 compat key. This
    // is the card-typed path — it never routes through the generic
    // `a2a::keys::sign_jws` (whose ES256 arms stay errors, FR25).
    let mut unsigned = card_value.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("signatures");
    }
    // FR14: the signed payload is the JCS (RFC 8785) canonicalization of
    // the card without `signatures` — pinned explicitly, never plain
    // serde serialization (which only coincides with JCS while the map is
    // sorted and the card carries no floats/non-ASCII). Default-valued
    // card fields are omitted BEFORE canonicalization by the card
    // serializer itself: every optional `AgentCard` field carries
    // `#[serde(skip_serializing_if = "Option::is_none")]`.
    let payload = jacs_core::canonical::canonicalize_json_try(&unsigned)
        .map_err(|e| JacsError::ValidationError(format!("JCS canonicalization failed: {e}")))?;
    let payload = payload.into_bytes();

    let header = json!({
        "alg": "ES256",
        "typ": "JOSE",
        "kid": compat.kid
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Decrypt the ES256 private key with the agent password; the plaintext
    // PKCS#8 DER lives only in the returned zeroizing buffer.
    let private_der = super::decrypt_ecosystem_private_key(agent, &compat)?;
    let signature =
        crate::crypt::es256::sign_es256_jose(private_der.as_slice(), signing_input.as_bytes())?;
    let jws = format!(
        "{}.{}.{}",
        header_b64,
        payload_b64,
        URL_SAFE_NO_PAD.encode(&signature)
    );

    card_value["signatures"] = json!([{ "jws": jws, "keyId": compat.kid }]);

    info!(
        event = "ecosystem_export_generated",
        format = "a2a-agent-card",
        jacs_id = %agent.get_id().unwrap_or_default(),
        kid = %compat.kid,
        binding_hash = %binding_hash,
        "A2A agent card exported with ES256 compatibility signature"
    );
    super::record_export_generated("a2a-agent-card");
    Ok(card_value)
}

/// Export the current (verified) compatibility key binding document so a
/// JACS-aware relying party can trace the ES256 key to the PQ root. A
/// binding reference elsewhere is always a content hash — never a URL;
/// P2 defines no resolution protocol and requires no hosted endpoint.
pub fn export_compatibility_key_binding(
    agent: &mut Agent,
    key_directory: &str,
) -> Result<Value, JacsError> {
    // The binding itself is the artifact — gate on the broadest identity
    // scope semantics by verifying the binding outright. Issuance returns
    // the persisted binding, so no disk re-load.
    let binding = load_or_issue_default_identity_binding(agent, key_directory, None, false)?;
    let verdict = super::binding::verify_compat_binding(agent, key_directory, &binding)?;
    if !verdict.valid {
        return Err(JacsError::ValidationError(format!(
            "compatibility binding invalid: {}",
            verdict.reason
        )));
    }

    // The binding is the trust artifact behind the six scoped ecosystem
    // exports, not one of them: PRD §9.4 pins the `format` label set of
    // `ecosystem_export_generated` / `jacs_compatibility_export_total` to
    // exactly the six binding scopes, so this export logs a plain INFO
    // (no event name, no export counters).
    info!(
        jacs_id = %agent.get_id().unwrap_or_default(),
        binding_hash = %super::binding::binding_hash(&binding),
        "compatibility key binding exported"
    );
    Ok(binding)
}
