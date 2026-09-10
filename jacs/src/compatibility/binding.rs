//! The compatibility key binding document (P2 Task 003).
//!
//! A native-root-signed JACS document that binds the agent's ES256
//! `ecosystem_signing` key to its JACS identity and authorizes explicit
//! export scopes. The trust bridge between native JACS identity and W3C/JOSE
//! ecosystems (`pq2025` is the default native root; Ed25519 is supported):
//!
//! - the NATIVE root signs the binding, so granting or widening a scope
//!   always requires that root — the ES256 holder cannot self-escalate;
//! - the binding persists as ONE canonical-JSON file in the agent key
//!   directory (`jacs.compat-binding.json`); re-issue replaces it —
//!   latest `issuedAt` wins, no version chains, no registries; "latest
//!   wins" is ENFORCED at verification against the last-issued watermark
//!   recorded in the keyring metadata, so a validly-signed OLDER binding
//!   restored over a re-issue no longer authorizes (issue 013);
//! - a binding signed by a rotated-away root fails current-binding
//!   verification and must be re-issued;
//! - an expired binding denies export; expiry is compared as RFC 3339
//!   INSTANTS and fails closed — an unparseable `expiresAt` denies at
//!   verification and is rejected at issuance (issue 007);
//!   `expiresAt: null` is permitted for local/non-A2A exports. Strict remote
//!   A2A trust independently limits `issuedAt` to a seven-day acceptance
//!   window, so a null expiry cannot make a replay valid indefinitely;
//! - identity scopes are granted by default at issuance; content scopes
//!   (`ap2-mandate`, `agreement-vc`) require an explicit re-issue.
//!
//! Scope checks here are a locally enforced authorization policy and an
//! auditable delegation record for relying parties — not isolation
//! between two keys that share one process and password.

use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::agent::{
    Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, JACS_IGNORE_FIELDS, SHA256_FIELDNAME,
    SIGNATURE_CONTENT_VERSION_FIELDNAME, SIGNATURE_CONTENT_VERSION_V2, build_signature_content_v2,
    extract_signature_fields,
};
use crate::error::JacsError;
use base64::Engine as _;
use serde_json::{Value, json};
use std::collections::BTreeSet;
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

/// Strict A2A accepts a native-root-signed compatibility binding for at most
/// seven days after its signed `issuedAt`. This is deliberately independent of
/// `expiresAt`: legacy/local bindings may have a null or very distant expiry,
/// but neither can become an indefinite first-contact replay credential.
pub(crate) const STRICT_A2A_BINDING_MAX_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Discovery generation refreshes the signed binding one day before Strict's
/// maximum-age cutoff. The six-day threshold leaves a full day for clock skew,
/// caches, and rolling replica restarts while keeping the hard verifier window
/// at seven days.
pub(crate) const A2A_BINDING_REFRESH_AFTER_SECONDS: i64 = 6 * 24 * 60 * 60;

/// Strict A2A uses the repository-wide five-minute future timestamp tolerance.
pub(crate) const STRICT_A2A_BINDING_MAX_FUTURE_SECONDS: i64 =
    crate::time_utils::MAX_FUTURE_TIMESTAMP_SECONDS;

fn binding_path(key_directory: &str) -> String {
    format!(
        "{}/{}",
        key_directory.trim_end_matches('/'),
        BINDING_FILENAME
    )
}

/// The binding's `jacsSha256` content hash ("" when absent) — the ONE
/// extraction of the reference exporters stamp into ecosystem artifacts.
/// Safe sugar: `verify_compat_binding` recomputes and authenticates the
/// hash before any exporter trusts it (issue 023).
pub(crate) fn binding_hash(binding: &Value) -> String {
    binding[SHA256_FIELDNAME].as_str().unwrap_or("").to_string()
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

    // FR24 fail-closed lifecycle (issue 007): an expiry that does not
    // parse as RFC 3339 could never be honored at verification — reject
    // it at the source with a typed error (the CLI surfaces this for
    // `--expires-at`).
    if let Some(expires) = expires_at
        && let Err(e) = chrono::DateTime::parse_from_rfc3339(expires)
    {
        return Err(JacsError::ValidationError(format!(
            "invalid expiresAt '{expires}': must be an RFC 3339 timestamp \
                 (e.g. 2027-01-01T00:00:00Z): {e}"
        )));
    }

    let agent_id = agent.get_id()?;
    let compat = crate::keystore::compat::ecosystem_key_info_ctx(
        key_directory,
        Some(&agent_id),
        requested_export,
    )?;
    let (x, y) = compat.public_jwk_xy()?;

    let native_algorithm = {
        let config = agent.config.as_ref().ok_or(JacsError::AgentNotLoaded)?;
        config.get_key_algorithm()?
    };
    let native_public_key = agent.get_public_key()?;
    let native_kid = crate::crypt::hash::hash_public_key(&native_public_key);

    let issued_at = crate::time_utils::now_rfc3339();
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
                // Bare key-material JWK (no kid/alg): the binding pins the
                // curve point; JOSE identity members live on the exports.
                "publicJwk": crate::crypt::es256::public_jwk(&x, &y, None)
            },
            "scope": scopes,
            "issuedAt": issued_at.clone(),
            "expiresAt": expires_at,
        }
    });

    // Header fields (jacsId, jacsVersion, …) + header-schema validation.
    let envelope_str = serde_json::to_string(&envelope)?;
    let mut instance = agent.schema.create(&envelope_str)?;

    // Sign with the native root FIRST, then validate against the binding
    // schema: the schema requires the native `jacsSignature` (issue 010),
    // so validation runs on the signed document.
    instance[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] =
        agent.signing_procedure(&instance, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)?;
    let instance_str = serde_json::to_string(&instance)?;
    agent.schema.validate_compat_binding(&instance_str)?;
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

    // Supersession watermark (issue 013): record the new binding's
    // issuedAt + content hash in the 0600 keyring metadata. Verification
    // denies any binding whose issuedAt predates this watermark, so a
    // validly-signed OLDER binding restored from backup cannot
    // re-authorize a withdrawn scope.
    crate::keystore::compat::record_binding_watermark(key_directory, &issued_at, &document_hash)?;

    info!(
        event = "compatibility_binding_created",
        jacs_id = %agent_id,
        kid = %compat.kid,
        binding_hash = %binding_hash(&instance),
        scopes = ?scopes,
        "compatibility key binding issued"
    );

    Ok(instance)
}

/// Load the current binding from the key directory (None if never issued).
pub fn load_compat_binding(key_directory: &str) -> Result<Option<Value>, JacsError> {
    let path = binding_path(key_directory);
    match std::fs::read_to_string(&path) {
        Ok(raw) => Ok(Some(
            jacs_core::strict_json::parse_strict_json(&raw).map_err(|e| {
                JacsError::ValidationError(format!("binding parse failed ({path}): {e}"))
            })?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(JacsError::FileReadFailed {
            path,
            reason: e.to_string(),
        }),
    }
}

/// Fail-closed expiry gate for `expiresAt` (issue 007): parses the value
/// as RFC 3339 and compares INSTANTS against now-UTC — never lexicographic
/// strings, which fail open for non-UTC offsets and garbage. `Ok(true)`
/// means expired, `Ok(false)` means still valid, `Err` means the value
/// does not parse and the caller must deny.
#[doc(hidden)]
pub fn expiry_denies(expires_at: &str) -> Result<bool, String> {
    let expires = chrono::DateTime::parse_from_rfc3339(expires_at).map_err(|e| e.to_string())?;
    Ok(expires.with_timezone(&chrono::Utc) < crate::time_utils::now_utc())
}

/// Verification verdict for a binding under the CURRENT agent state.
#[derive(Debug)]
pub struct BindingVerification {
    pub valid: bool,
    pub reason: String,
    pub scopes: Vec<String>,
}

fn remote_binding_error(reason: impl Into<String>) -> JacsError {
    JacsError::SignatureVerificationFailed {
        reason: reason.into(),
    }
}

fn required_str<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, JacsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| remote_binding_error(format!("compatibility binding is missing {pointer}")))
}

/// Verify a remotely supplied A2A compatibility binding against a trusted
/// native JACS root.
///
/// This is the trust bridge used by strict A2A verification. It is deliberately
/// stateless: the relying party supplies the root key it already trusts, the
/// identity/version expected from the Agent Card, the card's binding hash, and
/// the exact JWKS entry that verified the ES256 card signature. A
/// self-advertised JWKS key alone never establishes the claimed JACS identity.
///
/// The verifier checks schema, full v2 signature coverage, root fingerprint and
/// algorithm, native signature, agent id/version, content hash, ES256 JWK and
/// RFC 7638 `kid`, `a2a-agent-card` scope, issuance/expiry timestamps, a hard
/// seven-day `issuedAt` freshness window with five-minute future skew, and the
/// card-to-binding hash reference.
pub fn verify_remote_a2a_binding(
    binding: &Value,
    expected_agent_id: &str,
    expected_agent_version: &str,
    expected_binding_hash: &str,
    expected_compat_jwk: &Value,
    trusted_native_public_key: &[u8],
) -> Result<BindingVerification, JacsError> {
    let schema = crate::schema::Schema::new("v1", "v1", "v1")?;
    schema.validate_compat_binding(&serde_json::to_string(binding)?)?;

    let body = binding
        .get("compatibilityKeyBinding")
        .ok_or_else(|| remote_binding_error("compatibility binding body is missing"))?;
    let signature = binding
        .get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .ok_or_else(|| remote_binding_error("compatibility binding native signature is missing"))?;

    let body_agent_id = required_str(binding, "/compatibilityKeyBinding/agentId")?;
    let signer_agent_id = required_str(binding, "/jacsSignature/agentID")?;
    let signer_agent_version = required_str(binding, "/jacsSignature/agentVersion")?;
    if body_agent_id != expected_agent_id || signer_agent_id != expected_agent_id {
        return Err(remote_binding_error(format!(
            "compatibility binding agent identity mismatch: expected '{expected_agent_id}', \
             body claims '{body_agent_id}', signer claims '{signer_agent_id}'"
        )));
    }
    if signer_agent_version != expected_agent_version {
        return Err(remote_binding_error(format!(
            "compatibility binding signer version mismatch: expected '{expected_agent_version}', \
             got '{signer_agent_version}'"
        )));
    }

    let declared_hash = required_str(binding, "/jacsSha256")?;
    if declared_hash != expected_binding_hash {
        return Err(remote_binding_error(format!(
            "Agent Card compatibility binding hash '{expected_binding_hash}' does not match \
             the resolved binding '{declared_hash}'"
        )));
    }
    let mut hash_input = binding.clone();
    hash_input
        .as_object_mut()
        .ok_or_else(|| remote_binding_error("compatibility binding must be a JSON object"))?
        .remove(SHA256_FIELDNAME);
    let canonical = jacs_core::canonical::canonicalize_json_try(&hash_input).map_err(|error| {
        remote_binding_error(format!("binding canonicalization failed: {error}"))
    })?;
    let computed_hash = crate::crypt::hash::hash_string(&canonical);
    if declared_hash != computed_hash {
        return Err(remote_binding_error(format!(
            "compatibility binding content hash mismatch: declared '{declared_hash}', computed \
             '{computed_hash}'"
        )));
    }

    let scope = body
        .get("scope")
        .and_then(Value::as_array)
        .ok_or_else(|| remote_binding_error("compatibility binding scope is missing"))?;
    if !scope.iter().any(|entry| entry == "a2a-agent-card") {
        return Err(remote_binding_error(
            "compatibility binding does not grant required 'a2a-agent-card' scope",
        ));
    }

    let issued_at = required_str(binding, "/compatibilityKeyBinding/issuedAt")?;
    let issued_at_instant = chrono::DateTime::parse_from_rfc3339(issued_at)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|error| {
            remote_binding_error(format!(
                "compatibility binding issuedAt is invalid: {error}"
            ))
        })?;
    let now = crate::time_utils::now_utc();
    let latest_accepted = now + chrono::Duration::seconds(STRICT_A2A_BINDING_MAX_FUTURE_SECONDS);
    if issued_at_instant > latest_accepted {
        return Err(remote_binding_error(format!(
            "compatibility binding issuedAt '{issued_at}' is too far in the future; Strict A2A \
             allows at most {} seconds of clock skew",
            STRICT_A2A_BINDING_MAX_FUTURE_SECONDS
        )));
    }
    let oldest_accepted = now - chrono::Duration::seconds(STRICT_A2A_BINDING_MAX_AGE_SECONDS);
    if issued_at_instant < oldest_accepted {
        return Err(remote_binding_error(format!(
            "compatibility binding issuedAt '{issued_at}' is stale; Strict A2A accepts bindings \
             for at most {} seconds after issuance",
            STRICT_A2A_BINDING_MAX_AGE_SECONDS
        )));
    }
    if let Some(expires_at) = body.get("expiresAt").and_then(Value::as_str) {
        match expiry_denies(expires_at) {
            Ok(false) => {}
            Ok(true) => {
                return Err(remote_binding_error(format!(
                    "compatibility binding expired at {expires_at}"
                )));
            }
            Err(error) => {
                return Err(remote_binding_error(format!(
                    "compatibility binding expiresAt is invalid: {error}"
                )));
            }
        }
    }

    for (pointer, expected) in [
        (
            "/compatibilityKeyBinding/compatibilityKey/algorithm",
            "ES256",
        ),
        (
            "/compatibilityKeyBinding/compatibilityKey/publicJwk/kty",
            "EC",
        ),
        (
            "/compatibilityKeyBinding/compatibilityKey/publicJwk/crv",
            "P-256",
        ),
        ("/alg", "ES256"),
        ("/kty", "EC"),
        ("/crv", "P-256"),
        ("/use", "sig"),
    ] {
        let actual = if pointer.starts_with("/compatibility") {
            required_str(binding, pointer)?
        } else {
            expected_compat_jwk
                .pointer(pointer)
                .and_then(Value::as_str)
                .ok_or_else(|| remote_binding_error(format!("A2A JWKS key is missing {pointer}")))?
        };
        if actual != expected {
            return Err(remote_binding_error(format!(
                "A2A compatibility key {pointer} must be '{expected}', got '{actual}'"
            )));
        }
    }

    let binding_kid = required_str(binding, "/compatibilityKeyBinding/compatibilityKey/kid")?;
    let jwks_kid = required_str(expected_compat_jwk, "/kid")?;
    if binding_kid != jwks_kid {
        return Err(remote_binding_error(format!(
            "compatibility binding kid '{binding_kid}' does not match JWKS kid '{jwks_kid}'"
        )));
    }
    let binding_x = required_str(
        binding,
        "/compatibilityKeyBinding/compatibilityKey/publicJwk/x",
    )?;
    let binding_y = required_str(
        binding,
        "/compatibilityKeyBinding/compatibilityKey/publicJwk/y",
    )?;
    let jwks_x = required_str(expected_compat_jwk, "/x")?;
    let jwks_y = required_str(expected_compat_jwk, "/y")?;
    if binding_x != jwks_x || binding_y != jwks_y {
        return Err(remote_binding_error(
            "compatibility binding public JWK does not match the JWKS key that verified the card",
        ));
    }
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwks_x)
        .map_err(|error| remote_binding_error(format!("invalid P-256 JWK x: {error}")))?;
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwks_y)
        .map_err(|error| remote_binding_error(format!("invalid P-256 JWK y: {error}")))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(remote_binding_error(format!(
            "P-256 JWK coordinates must each be 32 bytes (got x={}, y={})",
            x.len(),
            y.len()
        )));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let computed_kid = crate::crypt::es256::rfc7638_thumbprint_p256(&sec1)?;
    if computed_kid != binding_kid {
        return Err(remote_binding_error(format!(
            "compatibility key kid is not the RFC 7638 thumbprint of its JWK: declared \
             '{binding_kid}', computed '{computed_kid}'"
        )));
    }

    let trusted_root_hash = crate::crypt::hash::hash_public_key(trusted_native_public_key);
    let root_kid = required_str(binding, "/compatibilityKeyBinding/rootKey/kid")?;
    let signature_kid = required_str(binding, "/jacsSignature/publicKeyHash")?;
    if root_kid != trusted_root_hash || signature_kid != trusted_root_hash {
        return Err(remote_binding_error(format!(
            "compatibility binding native root mismatch: trusted root hash is \
             '{trusted_root_hash}', binding root is '{root_kid}', signature root is \
             '{signature_kid}'"
        )));
    }
    let root_algorithm = required_str(binding, "/compatibilityKeyBinding/rootKey/algorithm")?;
    let signature_algorithm = required_str(binding, "/jacsSignature/signingAlgorithm")?;
    if root_algorithm != signature_algorithm {
        return Err(remote_binding_error(format!(
            "compatibility binding root algorithm '{root_algorithm}' does not match native \
             signature algorithm '{signature_algorithm}'"
        )));
    }
    if !matches!(root_algorithm, "pq2025" | "ring-Ed25519") {
        return Err(remote_binding_error(format!(
            "unsupported compatibility binding root algorithm '{root_algorithm}'"
        )));
    }

    if signature
        .get(SIGNATURE_CONTENT_VERSION_FIELDNAME)
        .and_then(Value::as_str)
        != Some(SIGNATURE_CONTENT_VERSION_V2)
    {
        return Err(remote_binding_error(
            "compatibility binding must use fully authenticated v2 signature content",
        ));
    }
    if signature
        .get("iat")
        .and_then(Value::as_i64)
        .is_none_or(|iat| iat < 0)
    {
        return Err(remote_binding_error(
            "compatibility binding signature has missing or invalid iat",
        ));
    }
    if signature
        .get("jti")
        .and_then(Value::as_str)
        .is_none_or(|jti| jti.trim().is_empty())
    {
        return Err(remote_binding_error(
            "compatibility binding signature has missing or empty jti",
        ));
    }
    chrono::DateTime::parse_from_rfc3339(required_str(binding, "/jacsSignature/date")?).map_err(
        |error| remote_binding_error(format!("binding signature date is invalid: {error}")),
    )?;

    let fields = extract_signature_fields(binding, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .ok_or_else(|| remote_binding_error("compatibility binding v2 signature fields missing"))?;
    let signed_set: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    if signed_set.len() != fields.len() {
        return Err(remote_binding_error(
            "compatibility binding signature fields contain duplicates",
        ));
    }
    let expected_set: BTreeSet<&str> = binding
        .as_object()
        .ok_or_else(|| remote_binding_error("compatibility binding must be an object"))?
        .keys()
        .map(String::as_str)
        .filter(|key| {
            *key != DOCUMENT_AGENT_SIGNATURE_FIELDNAME && !JACS_IGNORE_FIELDS.contains(key)
        })
        .collect();
    if signed_set != expected_set {
        return Err(remote_binding_error(format!(
            "compatibility binding signature does not cover every non-reserved top-level field: \
             signed={signed_set:?}, expected={expected_set:?}"
        )));
    }
    let signing_input = build_signature_content_v2(
        binding,
        fields,
        DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
        signature,
    )?;
    let signature_base64 = required_str(binding, "/jacsSignature/signature")?;
    crate::crypt::verify_string_with_algorithm(
        trusted_native_public_key.to_vec(),
        &signing_input,
        signature_base64,
        root_algorithm,
    )?;

    Ok(BindingVerification {
        valid: true,
        reason: "ok".to_string(),
        scopes: scope
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    })
}

/// Verify a binding document against the CURRENT agent: schema-valid,
/// signed by the agent's CURRENT native root (a binding signed by a
/// rotated-away root is superseded), ES256 key material matches the
/// on-disk ecosystem key, signer/body identity and signer version match the
/// current agent, and the binding is not expired.
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
    verify_compat_binding_ctx_internal(agent, key_directory, binding, requested_export, true)
}

fn verify_compat_binding_ctx_internal(
    agent: &Agent,
    key_directory: &str,
    binding: &Value,
    requested_export: Option<&str>,
    enforce_current_identity: bool,
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

    // 2b. Content-hash integrity (issue 023): `jacsSha256` is excluded
    //     from the signature preimage (JACS_IGNORE_FIELDS), yet exporters
    //     stamp it into ecosystem artifacts as the binding reference
    //     (FR12). Recompute it before anything trusts it — a mismatch
    //     means the document lies about itself, mapped to the existing
    //     fixed "schema_invalid" reason.
    let computed_hash = agent.hash_doc(binding)?;
    if binding[SHA256_FIELDNAME].as_str() != Some(computed_hash.as_str()) {
        return fail(
            "schema_invalid",
            format!(
                "binding jacsSha256 '{}' does not match the recomputed content hash",
                binding[SHA256_FIELDNAME].as_str().unwrap_or("")
            ),
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
    let (x, y) = compat.public_jwk_xy()?;
    if body["compatibilityKey"]["publicJwk"]["x"].as_str() != Some(x.as_str())
        || body["compatibilityKey"]["publicJwk"]["y"].as_str() != Some(y.as_str())
    {
        return fail(
            "jwk_mismatch",
            "binding publicJwk does not match the on-disk ecosystem key".to_string(),
        );
    }

    // 5. Supersession — "latest issuedAt wins" (issue 013): the loaded
    //    binding must not predate the last-issued watermark recorded at
    //    issuance. A missing watermark (pre-fix keyring) is accepted and
    //    backfilled by the next issuance; an unorderable issuedAt fails
    //    closed. "superseded" is the one deliberate, documented addition
    //    to the fixed reason label set.
    let keyring = crate::keystore::compat::read_keyring(key_directory)?;
    if let Some(watermark) = keyring.last_binding_issued_at.as_deref()
        && let Ok(watermark_at) = chrono::DateTime::parse_from_rfc3339(watermark)
    {
        let issued_at = body["issuedAt"].as_str().unwrap_or("");
        match chrono::DateTime::parse_from_rfc3339(issued_at) {
            Ok(binding_at) if binding_at >= watermark_at => {}
            Ok(_) => {
                return fail(
                    "superseded",
                    format!(
                        "binding issuedAt {issued_at} predates the last-issued binding \
                             ({watermark}); a newer binding superseded this one — restore \
                             the current binding or re-issue"
                    ),
                );
            }
            Err(e) => {
                return fail(
                    "superseded",
                    format!(
                        "binding issuedAt '{issued_at}' is not valid RFC 3339 ({e}); \
                             cannot order it against the last-issued binding — failing closed"
                    ),
                );
            }
        }
    }

    // 6. Expiry — RFC 3339 INSTANT comparison, fail closed (issue 007):
    //    an unparseable expiresAt denies under the existing fixed
    //    "expired" reason (the free-text message names the parse failure).
    if let Some(expires) = body["expiresAt"].as_str() {
        match expiry_denies(expires) {
            Ok(false) => {}
            Ok(true) => {
                return fail("expired", format!("binding expired at {expires}"));
            }
            Err(parse_err) => {
                return fail(
                    "expired",
                    format!(
                        "binding expiresAt '{expires}' is not valid RFC 3339 ({parse_err}); \
                         failing closed as expired"
                    ),
                );
            }
        }
    }

    // 7. The binding is configuration for this exact current agent version.
    // A same-root agent update authenticates a new version, but the prior
    // binding must not silently authorize a card claiming that new version.
    // Identity exports may reissue an otherwise-authentic stale-version
    // binding; arbitrary ID mismatches remain hard failures.
    if enforce_current_identity {
        let current_id = agent.get_id()?;
        let current_version = agent.get_version()?;
        let body_agent_id = body["agentId"].as_str().unwrap_or("");
        let signer_agent_id = binding[DOCUMENT_AGENT_SIGNATURE_FIELDNAME]["agentID"]
            .as_str()
            .unwrap_or("");
        if body_agent_id != current_id || signer_agent_id != current_id {
            return fail(
                "identity_mismatch",
                format!(
                    "binding identity does not match the current agent: current '{current_id}', \
                     body '{body_agent_id}', signer '{signer_agent_id}'"
                ),
            );
        }
        let signer_version = binding[DOCUMENT_AGENT_SIGNATURE_FIELDNAME]["agentVersion"]
            .as_str()
            .unwrap_or("");
        if signer_version != current_version {
            return fail(
                "version_mismatch",
                format!(
                    "binding signer agentVersion '{signer_version}' does not match current agent \
                     version '{current_version}'; re-issue the compatibility binding"
                ),
            );
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

/// Whether `binding` is fully valid under the current root, compatibility key,
/// hash, watermark, and expiry but was signed for an earlier version of this
/// same agent. Identity exporters use this narrow predicate to repair a normal
/// same-root agent update without treating corruption or identity substitution
/// as a reason to invoke the native signing key.
pub(crate) fn authentic_binding_has_stale_agent_version(
    agent: &Agent,
    key_directory: &str,
    binding: &Value,
) -> Result<bool, JacsError> {
    let current_id = agent.get_id()?;
    let current_version = agent.get_version()?;
    let body_agent_id = binding["compatibilityKeyBinding"]["agentId"]
        .as_str()
        .unwrap_or("");
    let signer_agent_id = binding[DOCUMENT_AGENT_SIGNATURE_FIELDNAME]["agentID"]
        .as_str()
        .unwrap_or("");
    let signer_version = binding[DOCUMENT_AGENT_SIGNATURE_FIELDNAME]["agentVersion"]
        .as_str()
        .unwrap_or("");
    if body_agent_id != current_id
        || signer_agent_id != current_id
        || signer_version.is_empty()
        || signer_version == current_version
    {
        return Ok(false);
    }
    let verdict = verify_compat_binding_ctx_internal(agent, key_directory, binding, None, false)?;
    Ok(verdict.valid)
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
    require_scope_on(agent, key_directory, scope, binding)
}

/// [`require_scope`] for a binding the caller already holds (fresh from
/// an auto-issue) — skips the disk re-load; verification and scope gating
/// are identical.
pub(crate) fn require_scope_on(
    agent: &Agent,
    key_directory: &str,
    scope: &str,
    binding: Value,
) -> Result<Value, JacsError> {
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
            binding_hash = %binding_hash(&binding),
            "export denied: scope not granted by the native-root-signed binding"
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
             with that scope (requires the current native root)"
        )));
    }
    Ok(binding)
}

/// Gate-and-enrich probe for identity views that FALL BACK to their
/// pre-P2 (native-only) shape instead of failing — the DID document and
/// the W3C agent description. Returns `Some((compat, binding))` only when
/// the agent has an ES256 compat key AND the CURRENT binding verifies AND
/// grants `scope`. A NEVER-CONFIGURED key or absent binding is not a
/// failed export attempt here, so the probe is quiet: no
/// `compatibility_key_missing` WARN, no export-error counter. But a
/// corrupt keyring / missing key file (issue 020) is not that quiet
/// state: the export still degrades to its native-only shape, with a
/// `compatibility_key_unreadable` WARN (log event only, no counter) so
/// the operator can tell "never migrated" from "keyring corrupted". An
/// INVALID binding still WARNs and counts through
/// [`verify_compat_binding`] — a bad trust artifact is always
/// operator-visible.
pub(crate) fn compat_enrichment_if_authorized(
    agent: &Agent,
    scope: &str,
) -> Result<Option<(crate::keystore::compat::CompatKeyInfo, Value)>, JacsError> {
    let key_directory = match agent.key_paths() {
        Some(paths) => paths.key_directory.clone(),
        None => return Ok(None),
    };
    let compat = match crate::keystore::compat::probe_ecosystem_key_info(&key_directory) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(None),
        Err(e) => {
            warn!(
                event = "compatibility_key_unreadable",
                jacs_id = %agent.get_id().unwrap_or_default(),
                requested_export = %scope,
                key_directory = %key_directory,
                reason = %e,
                hint = "inspect jacs.keyring.json and the jacs.ecosystem.* key files in the \
                        key directory",
                "ES256 compatibility key state is unreadable; export degrades to its \
                 native-only shape"
            );
            return Ok(None);
        }
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
