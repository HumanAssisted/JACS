//! Identity exports for the ES256 ecosystem compatibility key (P2 Task 004-A).
//!
//! JWKS and binding exports — the surfaces that make a JACS agent's
//! compatibility key legible to JOSE ecosystems. Every export is gated by
//! the PQ-root-signed binding scope (`require_scope`). Identity exports
//! may auto-issue the DEFAULT (identity-scopes-only) binding when none
//! exists yet — the PQ root signs it in-process at that moment; content
//! exports (Tasks 004b/004c) never auto-issue.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::error::JacsError;
use serde_json::{Value, json};
use tracing::info;

/// Ensure a binding exists (issuing the default identity binding if not),
/// then require `scope`. Used by IDENTITY exports only.
fn require_identity_scope(
    agent: &mut Agent,
    key_directory: &str,
    scope: &str,
) -> Result<Value, JacsError> {
    let binding = match super::binding::load_compat_binding(key_directory)? {
        Some(binding) => binding,
        // Auto-issue needs the ES256 key on disk; a fresh agent without
        // one fails HERE with `KeyNotFound` — record the documented
        // `reason="missing_key"` error counter under the requested format.
        // Issuance returns the persisted binding, so no disk re-load.
        None => super::binding::issue_compat_binding_ctx(
            agent,
            key_directory,
            super::binding::DEFAULT_IDENTITY_SCOPES,
            None,
            Some(scope),
        )
        .inspect_err(|e| {
            if matches!(e, JacsError::KeyNotFound { .. }) {
                super::record_export_error(scope, "missing_key");
            }
        })?,
    };
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
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let binding = require_identity_scope(agent, key_directory, "a2a-agent-card")?;
    let binding_hash = super::binding::binding_hash(&binding);
    // Missing keys fail (and count) inside the scope gate above.
    let compat = crate::keystore::compat::ecosystem_key_info(key_directory)?;

    // Base card from the existing exporter, plus the binding reference.
    let card = crate::a2a::agent_card::export_agent_card(agent)?;
    let mut card_value = serde_json::to_value(&card)?;
    card_value["metadata"]["jacsCompatKid"] = json!(compat.kid);
    card_value["metadata"]["jacsCompatBindingHash"] = json!(binding_hash);

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
    let binding = match super::binding::load_compat_binding(key_directory)? {
        Some(binding) => binding,
        None => super::binding::issue_compat_binding(
            agent,
            key_directory,
            super::binding::DEFAULT_IDENTITY_SCOPES,
            None,
        )?,
    };
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
