//! Identity exports for the ES256 ecosystem compatibility key (P2 Task 004-A).
//!
//! JWKS and binding exports — the surfaces that make a JACS agent's
//! compatibility key legible to JOSE ecosystems. Every export is gated by
//! the PQ-root-signed binding scope (`require_scope`). Identity exports
//! may auto-issue the DEFAULT (identity-scopes-only) binding when none
//! exists yet — the PQ root signs it in-process at that moment; content
//! exports (Tasks 004b/004c) never auto-issue.

use crate::agent::Agent;
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
    if super::binding::load_compat_binding(key_directory)?.is_none() {
        super::binding::issue_compat_binding(
            agent,
            key_directory,
            super::binding::DEFAULT_IDENTITY_SCOPES,
            None,
        )?;
    }
    super::binding::require_scope(agent, key_directory, scope)
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
    require_identity_scope(agent, key_directory, "jwks")?;

    let compat = crate::keystore::compat::ecosystem_key_info(key_directory)?;
    let public_pem = std::fs::read_to_string(&compat.public_key_path).map_err(|e| {
        JacsError::FileReadFailed {
            path: compat.public_key_path.clone(),
            reason: e.to_string(),
        }
    })?;
    let (x, y) = crate::crypt::es256::jwk_xy_from_spki_pem(&public_pem)?;

    let jwks = json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": compat.kid,
            "use": "sig",
            "alg": "ES256"
        }]
    });

    info!(
        event = "ecosystem_export_generated",
        format = "jwks",
        kid = %compat.kid,
        "compatibility JWKS exported"
    );
    Ok(jwks)
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
    // scope semantics by verifying the binding outright.
    if super::binding::load_compat_binding(key_directory)?.is_none() {
        super::binding::issue_compat_binding(
            agent,
            key_directory,
            super::binding::DEFAULT_IDENTITY_SCOPES,
            None,
        )?;
    }
    let binding = super::binding::load_compat_binding(key_directory)?.ok_or_else(|| {
        JacsError::ValidationError("binding issuance failed to persist".to_string())
    })?;
    let verdict = super::binding::verify_compat_binding(agent, key_directory, &binding)?;
    if !verdict.valid {
        return Err(JacsError::ValidationError(format!(
            "compatibility binding invalid: {}",
            verdict.reason
        )));
    }

    info!(
        event = "ecosystem_export_generated",
        format = "compat-binding",
        "compatibility key binding exported"
    );
    Ok(binding)
}
