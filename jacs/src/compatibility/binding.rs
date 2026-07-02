//! The compatibility key binding document (P2 Task 003).
//!
//! A PQ-root-signed JACS document that binds the agent's ES256
//! `ecosystem_signing` key to its JACS identity and authorizes explicit
//! export scopes. The trust bridge between native (post-quantum) JACS
//! identity and W3C/JOSE ecosystems:
//!
//! - the NATIVE root signs the binding, so granting or widening a scope
//!   always requires the PQ root — the ES256 holder cannot self-escalate;
//! - the binding persists as ONE canonical-JSON file in the agent key
//!   directory (`jacs.compat-binding.json`); re-issue replaces it —
//!   latest `issuedAt` wins, no version chains, no registries;
//! - a binding signed by a rotated-away root fails current-binding
//!   verification and must be re-issued;
//! - an expired binding denies export; `expiresAt: null` is permitted
//!   (revocation/status is a later phase);
//! - identity scopes are granted by default at issuance; content scopes
//!   (`ap2-mandate`, `agreement-vc`) require an explicit re-issue.
//!
//! Scope checks here are a locally enforced authorization policy and an
//! auditable delegation record for relying parties — not isolation
//! between two keys that share one process and password.

use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::agent::{Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, SHA256_FIELDNAME};
use crate::error::JacsError;
use serde_json::{Value, json};
use tracing::{info, warn};

/// On-disk name of the current binding inside the key directory.
pub const BINDING_FILENAME: &str = "jacs.compat-binding.json";

/// The identity scopes granted by default at issuance.
pub const DEFAULT_IDENTITY_SCOPES: &[&str] =
    &["jwks", "did", "a2a-agent-card", "w3c-agent-identity"];

/// All scopes the P2 schema accepts (content scopes require explicit grant).
pub const ALL_SCOPES: &[&str] = &[
    "jwks",
    "did",
    "a2a-agent-card",
    "w3c-agent-identity",
    "ap2-mandate",
    "agreement-vc",
];

fn binding_path(key_directory: &str) -> String {
    format!(
        "{}/{}",
        key_directory.trim_end_matches('/'),
        BINDING_FILENAME
    )
}

/// Issue (or re-issue) the compatibility key binding, signed by the
/// agent's native root. Persists to the key directory, replacing any
/// prior binding (latest `issuedAt` wins).
pub fn issue_compat_binding(
    agent: &mut Agent,
    key_directory: &str,
    scopes: &[&str],
    expires_at: Option<&str>,
) -> Result<Value, JacsError> {
    issue_compat_binding_ctx(agent, key_directory, scopes, expires_at, None)
}

/// [`issue_compat_binding`] with the requesting export format threaded
/// into the `compatibility_key_missing` WARN (PRD §9.8) when issuance is
/// an auto-issue on behalf of an identity export.
pub(crate) fn issue_compat_binding_ctx(
    agent: &mut Agent,
    key_directory: &str,
    scopes: &[&str],
    expires_at: Option<&str>,
    requested_export: Option<&str>,
) -> Result<Value, JacsError> {
    for s in scopes {
        if !ALL_SCOPES.contains(s) {
            return Err(JacsError::ValidationError(format!(
                "unknown compatibility binding scope '{s}'"
            )));
        }
    }

    let agent_id = agent.get_id()?;
    let compat = crate::keystore::compat::ecosystem_key_info_ctx(
        key_directory,
        Some(&agent_id),
        requested_export,
    )?;
    let public_pem = std::fs::read_to_string(&compat.public_key_path).map_err(|e| {
        JacsError::FileReadFailed {
            path: compat.public_key_path.clone(),
            reason: e.to_string(),
        }
    })?;
    let (x, y) = crate::crypt::es256::jwk_xy_from_spki_pem(&public_pem)?;

    let native_algorithm = {
        let config = agent.config.as_ref().ok_or(JacsError::AgentNotLoaded)?;
        config.get_key_algorithm()?
    };
    let native_public_key = agent.get_public_key()?;
    let native_kid = crate::crypt::hash::hash_public_key(&native_public_key);

    let envelope = json!({
        "$schema": "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json",
        "jacsType": "compatibilityKeyBinding",
        "jacsLevel": "config",
        "compatibilityKeyBinding": {
            "agentId": agent_id,
            "rootKey": { "algorithm": native_algorithm, "kid": native_kid },
            "compatibilityKey": {
                "algorithm": "ES256",
                "kid": compat.kid,
                "publicJwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y }
            },
            "scope": scopes,
            "issuedAt": crate::time_utils::now_rfc3339(),
            "expiresAt": expires_at,
        }
    });

    // Header fields (jacsId, jacsVersion, …) + header-schema validation.
    let envelope_str = serde_json::to_string(&envelope)?;
    let mut instance = agent.schema.create(&envelope_str)?;

    // Validate against the binding schema, then sign with the native root.
    let instance_str = serde_json::to_string(&instance)?;
    agent.schema.validate_compat_binding(&instance_str)?;
    instance[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] =
        agent.signing_procedure(&instance, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)?;
    let document_hash = agent.hash_doc(&instance)?;
    instance[SHA256_FIELDNAME] = json!(document_hash);

    // Persist: single file, atomic replace — latest issuedAt wins.
    let path = binding_path(key_directory);
    let bytes = serde_json::to_vec_pretty(&instance)?;
    crate::secure_io::write_atomic_replace_no_symlink(
        std::path::Path::new(&path),
        &bytes,
        0o600,
        false,
    )
    .map_err(|e| JacsError::FileWriteFailed {
        path: path.clone(),
        reason: e.to_string(),
    })?;

    info!(
        event = "compatibility_binding_created",
        jacs_id = %agent_id,
        kid = %compat.kid,
        binding_hash = %instance[SHA256_FIELDNAME].as_str().unwrap_or(""),
        scopes = ?scopes,
        "compatibility key binding issued"
    );

    Ok(instance)
}

/// Load the current binding from the key directory (None if never issued).
pub fn load_compat_binding(key_directory: &str) -> Result<Option<Value>, JacsError> {
    let path = binding_path(key_directory);
    match std::fs::read_to_string(&path) {
        Ok(raw) => Ok(Some(serde_json::from_str(&raw).map_err(|e| {
            JacsError::ValidationError(format!("binding parse failed ({path}): {e}"))
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(JacsError::FileReadFailed {
            path,
            reason: e.to_string(),
        }),
    }
}

/// Verification verdict for a binding under the CURRENT agent state.
#[derive(Debug)]
pub struct BindingVerification {
    pub valid: bool,
    pub reason: String,
    pub scopes: Vec<String>,
}

/// Verify a binding document against the CURRENT agent: schema-valid,
/// signed by the agent's CURRENT native root (a binding signed by a
/// rotated-away root is superseded), ES256 key material matches the
/// on-disk ecosystem key, and not expired.
pub fn verify_compat_binding(
    agent: &Agent,
    key_directory: &str,
    binding: &Value,
) -> Result<BindingVerification, JacsError> {
    verify_compat_binding_ctx(agent, key_directory, binding, None)
}

/// [`verify_compat_binding`] with the requesting export format threaded
/// into the `compatibility_key_missing` WARN (PRD §9.8) when verification
/// runs on behalf of an export (`require_scope`).
pub(crate) fn verify_compat_binding_ctx(
    agent: &Agent,
    key_directory: &str,
    binding: &Value,
    requested_export: Option<&str>,
) -> Result<BindingVerification, JacsError> {
    // §9.8 identity fields for the WARN: the agent id and the compat kid
    // the binding CLAIMS (empty when the document is malformed).
    let jacs_id = agent.get_id().unwrap_or_default();
    let binding_kid = binding["compatibilityKeyBinding"]["compatibilityKey"]["kid"]
        .as_str()
        .unwrap_or("")
        .to_string();
    // `metric_reason` is a FIXED low-cardinality label; `reason` is the
    // free-text diagnostic for the log line and the verdict.
    let fail = |metric_reason: &'static str, reason: String| {
        warn!(
            event = "compatibility_binding_verify_failed",
            jacs_id = %jacs_id,
            kid = %binding_kid,
            reason = %reason,
            "compatibility binding verification failed"
        );
        let mut tags = std::collections::HashMap::new();
        tags.insert("reason".to_string(), metric_reason.to_string());
        crate::observability::metrics::increment_counter(
            "jacs_compatibility_binding_verify_failed_total",
            1,
            Some(tags),
        );
        Ok(BindingVerification {
            valid: false,
            reason,
            scopes: vec![],
        })
    };

    // 1. Schema.
    let binding_str = serde_json::to_string(binding)?;
    if let Err(e) = agent.schema.validate_compat_binding(&binding_str) {
        return fail("schema_invalid", format!("schema validation failed: {e}"));
    }
    let body = &binding["compatibilityKeyBinding"];

    // 2. Signed by the CURRENT native root: verify signature cryptographically
    //    and pin the signing key hash to the agent's current public key.
    let current_public_key = agent.get_public_key()?;
    let current_kid = crate::crypt::hash::hash_public_key(&current_public_key);
    let current_public_key = current_public_key.clone();
    let sig_hash = binding[DOCUMENT_AGENT_SIGNATURE_FIELDNAME]["publicKeyHash"]
        .as_str()
        .unwrap_or("");
    if sig_hash != current_kid {
        return fail(
            "rotated_root",
            "binding was signed by a previous (rotated-away) root; re-issue the binding"
                .to_string(),
        );
    }
    if let Err(e) = agent.signature_verification_procedure(
        binding,
        None,
        DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
        current_public_key,
        None,
        None,
        None,
    ) {
        return fail(
            "signature_invalid",
            format!("native signature verification failed: {e}"),
        );
    }

    // 3. Root metadata pins the same current root.
    if body["rootKey"]["kid"].as_str().unwrap_or("") != current_kid {
        return fail(
            "root_kid_mismatch",
            "binding rootKey.kid does not match the current native root".to_string(),
        );
    }

    // 4. ES256 key material matches the on-disk ecosystem key. This is
    //    where a deleted/never-minted key surfaces as `KeyNotFound` on
    //    export paths — the ctx threads §9.8 fields into the WARN.
    let compat = crate::keystore::compat::ecosystem_key_info_ctx(
        key_directory,
        Some(&jacs_id),
        requested_export,
    )?;
    if body["compatibilityKey"]["kid"].as_str().unwrap_or("") != compat.kid {
        return fail(
            "compat_kid_mismatch",
            "binding compatibilityKey.kid does not match the ecosystem key".to_string(),
        );
    }
    let public_pem = std::fs::read_to_string(&compat.public_key_path).map_err(|e| {
        JacsError::FileReadFailed {
            path: compat.public_key_path.clone(),
            reason: e.to_string(),
        }
    })?;
    let (x, y) = crate::crypt::es256::jwk_xy_from_spki_pem(&public_pem)?;
    if body["compatibilityKey"]["publicJwk"]["x"].as_str() != Some(x.as_str())
        || body["compatibilityKey"]["publicJwk"]["y"].as_str() != Some(y.as_str())
    {
        return fail(
            "jwk_mismatch",
            "binding publicJwk does not match the on-disk ecosystem key".to_string(),
        );
    }

    // 5. Expiry.
    if let Some(expires) = body["expiresAt"].as_str() {
        let now = crate::time_utils::now_rfc3339();
        if expires < now.as_str() {
            return fail("expired", format!("binding expired at {expires}"));
        }
    }

    let scopes = body["scope"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(BindingVerification {
        valid: true,
        reason: "ok".to_string(),
        scopes,
    })
}

/// Authorization gate used by exporters: the CURRENT binding must verify
/// and include `scope`. Returns the verified binding on success.
pub fn require_scope(agent: &Agent, key_directory: &str, scope: &str) -> Result<Value, JacsError> {
    // Scopes map 1:1 to export formats, so `scope` is the `format` label.
    let binding = load_compat_binding(key_directory)?.ok_or_else(|| {
        super::record_export_error(scope, "no_binding");
        JacsError::ValidationError(format!(
            "no compatibility binding issued; run issue_compat_binding before exporting '{scope}'"
        ))
    })?;
    // A missing/deleted ES256 key surfaces as `KeyNotFound` inside
    // verification (step 4) — this gate knows the requested format, so the
    // documented `reason="missing_key"` counter increments here.
    let verdict = verify_compat_binding_ctx(agent, key_directory, &binding, Some(scope))
        .inspect_err(|e| {
            if matches!(e, JacsError::KeyNotFound { .. }) {
                super::record_export_error(scope, "missing_key");
            }
        })?;
    if !verdict.valid {
        super::record_export_error(scope, "binding_invalid");
        return Err(JacsError::ValidationError(format!(
            "compatibility binding invalid: {}",
            verdict.reason
        )));
    }
    if !verdict.scopes.iter().any(|s| s == scope) {
        warn!(
            event = "content_export_scope_denied",
            jacs_id = %agent.get_id().unwrap_or_default(),
            format = %scope,
            required_scope = %scope,
            binding_hash = %binding[SHA256_FIELDNAME].as_str().unwrap_or(""),
            "export denied: scope not granted by the PQ-root-signed binding"
        );
        super::record_export_error(scope, "scope_denied");
        let mut tags = std::collections::HashMap::new();
        tags.insert("format".to_string(), scope.to_string());
        crate::observability::metrics::increment_counter(
            "jacs_content_export_scope_denied_total",
            1,
            Some(tags),
        );
        return Err(JacsError::ValidationError(format!(
            "scope '{scope}' is not granted by the compatibility binding; re-issue the binding \
             with that scope (requires the PQ root)"
        )));
    }
    Ok(binding)
}

/// Gate-and-enrich probe for identity views that FALL BACK to their
/// pre-P2 (native-only) shape instead of failing — the DID document and
/// the W3C agent description. Returns `Some((compat, binding))` only when
/// the agent has an ES256 compat key AND the CURRENT binding verifies AND
/// grants `scope`. A missing key or absent binding is not a failed export
/// attempt here, so the probe is quiet: no `compatibility_key_missing`
/// WARN, no export-error counter. An INVALID binding still WARNs and
/// counts through [`verify_compat_binding`] — a bad trust artifact is
/// always operator-visible.
pub(crate) fn compat_enrichment_if_authorized(
    agent: &Agent,
    scope: &str,
) -> Result<Option<(crate::keystore::compat::CompatKeyInfo, Value)>, JacsError> {
    let key_directory = match agent.config.as_ref() {
        Some(config) => config
            .jacs_key_directory()
            .as_deref()
            .unwrap_or("./jacs_keys")
            .to_string(),
        None => return Ok(None),
    };
    let compat = match crate::keystore::compat::try_ecosystem_key_info(&key_directory) {
        Some(c) => c,
        None => return Ok(None),
    };
    let binding = match load_compat_binding(&key_directory)? {
        Some(b) => b,
        None => return Ok(None),
    };
    let verdict = verify_compat_binding(agent, &key_directory, &binding)?;
    if !verdict.valid || !verdict.scopes.iter().any(|s| s == scope) {
        return Ok(None);
    }
    Ok(Some((compat, binding)))
}
