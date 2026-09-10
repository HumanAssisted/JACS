//! JACS protocol helpers shared across SDKs.
//!
//! This module provides building blocks that every JACS-aware client needs:
//!
//! * [`canonicalize_json_try`] -- checked deterministic JSON serialization
//!   (RFC 8785), re-exported from [`jacs_core::canonical`].
//! * [`build_request_auth_header`] / [`verify_request_auth_header`] -- create
//!   and verify request-bound `Authorization: JACS v2...` credentials.
//! * [`build_auth_header`] -- source-compatible HAI credential; it remains
//!   available by default and can be rejected by strict deployments.
//! * [`sign_response`] -- build and sign a JACS response envelope.
//! * [`encode_verify_payload`] / [`decode_verify_payload`] -- URL-safe base64
//!   encoding/decoding for verification payloads.
//! * [`extract_document_id`] -- extract document ID for hosted verification.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::crypt::KeyManager;
use crate::error::JacsError;
use crate::observability::convenience::{
    SecurityOutcome, SecurityPolicy, SecuritySource, record_security_outcome,
    safe_security_identifier, security_outcome_for_error,
};
use crate::time_utils::now_rfc3339;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;

/// Version marker carried inside request-bound authorization claims.
pub const REQUEST_AUTH_VERSION: &str = "jacs-request-v2";
/// Domain separator for request-bound authorization signatures.
pub const REQUEST_AUTH_DOMAIN: &str = "JACS-REQUEST-AUTH-V2\n";
const MAX_REQUEST_AUTH_HEADER_BYTES: usize = 64 * 1024;
const MAX_VERIFY_PAYLOAD_DECODED_BYTES: usize = 10 * 1024 * 1024;
const MAX_VERIFY_PAYLOAD_ENCODED_BYTES: usize = MAX_VERIFY_PAYLOAD_DECODED_BYTES.div_ceil(3) * 4;

fn parse_bounded_protocol_json(input: &str, context: &str) -> Result<Value, JacsError> {
    crate::schema::utils::check_document_size(input)?;
    jacs_core::strict_json::parse_strict_json(input).map_err(|error| JacsError::DocumentMalformed {
        field: context.to_string(),
        reason: error.to_string(),
    })
}

fn current_unix_seconds(context: &str) -> Result<u64, JacsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| JacsError::Internal {
            message: format!("{context}: system clock error: {error}"),
        })
        .map(|duration| duration.as_secs())
}

fn replay_ttl_from_unix_seconds(
    issued_at: u64,
    max_age_seconds: u64,
    now: u64,
    context: &str,
) -> Result<Duration, JacsError> {
    if max_age_seconds == 0 {
        return Err(JacsError::ValidationError(format!(
            "{context} max_age_seconds must be greater than zero"
        )));
    }
    let expires_at = issued_at.checked_add(max_age_seconds).ok_or_else(|| {
        JacsError::ValidationError(format!("{context} expiry exceeds the Unix timestamp range"))
    })?;
    if expires_at < now {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!("{context} credential has expired"),
        });
    }
    let remaining = expires_at
        .checked_sub(now)
        .and_then(|seconds| seconds.checked_add(1))
        .ok_or_else(|| {
            JacsError::ValidationError(format!("{context} replay TTL exceeds the supported range"))
        })?;
    Ok(Duration::from_secs(remaining))
}

/// Authenticated request context returned after a v2 header verifies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestAuthClaims {
    pub version: String,
    pub key_id: String,
    pub issued_at: u64,
    pub nonce: String,
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub target: String,
    pub content_digest: String,
    pub audience: String,
    pub signing_algorithm: String,
    pub public_key_hash: String,
}

/// Current fully-bound response envelope version.
pub const RESPONSE_ENVELOPE_VERSION: &str = "2.0.0";
/// Signature-scope identifier carried inside v2 response signatures.
pub const RESPONSE_SIGNATURE_CONTENT_VERSION: &str = "jacs-response-v2";
/// Domain separator prepended to the canonical unsigned envelope.
pub const RESPONSE_SIGNATURE_DOMAIN: &str = "JACS-RESPONSE-V2\n";
const RESPONSE_DOCUMENT_TYPE: &str = "job_response";

/// Deterministically serialize a [`serde_json::Value`] per RFC 8785 (JCS).
///
/// Returns `"null"` if canonicalization fails (should not happen for valid
/// `Value` inputs).
///
/// Re-exported from `jacs_core::canonical` since the protocol layer was split
/// out for wasm support (PRD §4.4). Use [`canonicalize_json_try`] for signing,
/// verification, hashing, or untrusted programmatically constructed values so
/// unsafe integral values are rejected instead of rounded by binary64 JCS.
pub use jacs_core::canonical::{canonicalize_json, canonicalize_json_try};

/// Build the legacy unbound JACS `Authorization` header value.
///
/// Format: `"JACS {jacs_id}:{unix_timestamp}:{nonce}:{base64_signature}"`
///
/// The signed message is `"{jacs_id}:{unix_timestamp}:{nonce}"` where `jacs_id`
/// is the agent's lookup ID (`{id}:{version}`), the timestamp is seconds since
/// the Unix epoch, and the nonce is fresh per request.
///
/// This credential does **not** authenticate an HTTP method, target, body, or
/// audience. It remains available for source compatibility and is always
/// logged once at WARN. Endpoints that need transport-context binding can add
/// [`build_request_auth_header`] without breaking existing HAI authentication.
/// Strict deployments can reject this form with
/// `JACS_REJECT_UNBOUND_AUTH_HEADER=true`.
pub fn build_auth_header(agent: &mut Agent) -> Result<String, JacsError> {
    let explicitly_rejected = std::env::var("JACS_REJECT_UNBOUND_AUTH_HEADER")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    if explicitly_rejected {
        record_security_outcome(
            SecuritySource::RequestAuth,
            SecurityOutcome::PolicyRejected,
            SecurityPolicy::Strict,
            None,
            None,
        );
        return Err(JacsError::ValidationError(
            "Legacy unbound JACS Authorization headers are rejected by JACS_REJECT_UNBOUND_AUTH_HEADER because they do not authenticate the method, URL, body, or audience. Use build_request_auth_header."
                .to_string(),
        ));
    }
    static WARN_ONCE: Once = Once::new();
    WARN_ONCE.call_once(|| {
        tracing::warn!(
            event = "unbound_auth_header_allowed",
            reason = "compatibility_api",
            "Building a JACS Authorization header without HTTP request-context binding"
        );
    });
    let jacs_id = agent.get_lookup_id()?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("build_auth_header: system clock error: {}", e))?
        .as_secs();
    let nonce = Uuid::new_v4().simple().to_string();
    record_security_outcome(
        SecuritySource::RequestAuth,
        SecurityOutcome::Unverified,
        SecurityPolicy::Permissive,
        Some(&jacs_id),
        Some(&nonce),
    );
    let message = format!("{jacs_id}:{ts}:{nonce}");
    let signature = agent.sign_string(&message)?;
    Ok(format!("JACS {jacs_id}:{ts}:{nonce}:{signature}"))
}

/// Build a request-bound JACS Authorization header.
///
/// Format: `JACS v2.<base64url-canonical-claims>.<base64url-signature>`.
/// The signed claims bind the credential to one method, normalized absolute
/// URL (including query), exact body bytes, audience, signer/key, time, and
/// nonce. Use an empty byte slice for a request with no body.
pub fn build_request_auth_header(
    agent: &mut Agent,
    method: &str,
    url: &str,
    body: &[u8],
    audience: &str,
) -> Result<String, JacsError> {
    let key_id = agent.get_lookup_id()?;
    let signing_algorithm = configured_agent_signing_algorithm(agent, "request auth")?;
    let public_key = agent.get_public_key()?;
    let public_key_hash = crate::crypt::hash::hash_public_key(&public_key);
    build_request_auth_header_with_signer(
        &key_id,
        &signing_algorithm,
        &public_key_hash,
        method,
        url,
        body,
        audience,
        |signing_input| agent.sign_string(signing_input),
    )
}

pub(crate) fn configured_agent_signing_algorithm(
    agent: &Agent,
    operation: &str,
) -> Result<String, JacsError> {
    agent
        .get_key_algorithm()
        .cloned()
        .or_else(|| {
            agent
                .config
                .as_ref()
                .and_then(|config| config.jacs_agent_key_algorithm().clone())
        })
        .ok_or_else(|| JacsError::SigningFailed {
            reason: format!("{operation} requires a configured signing algorithm"),
        })
}

/// Build a request-bound header using caller-owned signing key material.
///
/// SDK adapters use this entry point to preserve the exact JACS v2 wire
/// contract without reimplementing claims, canonicalization, domain
/// separation, or base64url encoding. `sign` must return a standard-base64
/// detached signature over the supplied signing input.
#[allow(clippy::too_many_arguments)]
pub fn build_request_auth_header_with_signer(
    key_id: &str,
    signing_algorithm: &str,
    public_key_hash: &str,
    method: &str,
    url: &str,
    body: &[u8],
    audience: &str,
    sign: impl FnOnce(&str) -> Result<String, JacsError>,
) -> Result<String, JacsError> {
    let (scheme, authority, target) = canonical_request_url_components(url)?;
    let method = normalize_http_method(method)?;
    let audience = nonempty_request_auth_value(audience, "audience")?;
    let key_id = nonempty_request_auth_value(key_id, "key_id")?;
    let signing_algorithm = nonempty_request_auth_value(signing_algorithm, "signing_algorithm")?;
    let public_key_hash = nonempty_request_auth_value(public_key_hash, "public_key_hash")?;
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| JacsError::Internal {
            message: format!("build_request_auth_header: system clock error: {e}"),
        })?
        .as_secs();
    let nonce = Uuid::new_v4().simple().to_string();
    let claims = RequestAuthClaims {
        version: REQUEST_AUTH_VERSION.to_string(),
        key_id: key_id.to_string(),
        issued_at,
        nonce,
        method,
        scheme,
        authority,
        target,
        content_digest: request_content_digest(body),
        audience: audience.to_string(),
        signing_algorithm: signing_algorithm.to_string(),
        public_key_hash: public_key_hash.to_string(),
    };
    let canonical = request_auth_claims_canonical(&claims)?;
    let signing_input = format!("{REQUEST_AUTH_DOMAIN}{canonical}");
    let signature = sign(&signing_input)?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| JacsError::SigningFailed {
            reason: format!("request auth signer returned invalid base64: {e}"),
        })?;
    let claims_segment = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical);
    let signature_segment =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes);
    Ok(format!("JACS v2.{claims_segment}.{signature_segment}"))
}

/// Verify a request-bound JACS Authorization header with an explicitly trusted
/// public key and the actual request context.
///
/// Replay state is consumed only after the request binding, key binding,
/// timestamp, and cryptographic signature all verify. A successful return is
/// therefore safe to use as authenticated request provenance.
#[allow(clippy::too_many_arguments)]
pub fn verify_request_auth_header(
    verifier: &Agent,
    header: &str,
    public_key: &[u8],
    expected_key_id: &str,
    expected_method: &str,
    expected_url: &str,
    expected_body: &[u8],
    expected_audience: &str,
    max_age_seconds: u64,
) -> Result<RequestAuthClaims, JacsError> {
    let correlation_id = inspect_unverified_request_auth_header(header)
        .ok()
        .map(|claims| claims.nonce);
    let result = verify_request_auth_header_without_replay(
        verifier,
        header,
        public_key,
        expected_key_id,
        expected_method,
        expected_url,
        expected_body,
        expected_audience,
        max_age_seconds,
    )
    .and_then(|claims| {
        let replay_ttl = request_auth_replay_ttl(&claims, max_age_seconds)?;
        crate::replay::check_and_store_nonce_with_ttl(
            &format!("request-auth:{}", claims.key_id),
            &claims.nonce,
            replay_ttl,
        )?;
        Ok(claims)
    });
    let outcome = result
        .as_ref()
        .map(|_| SecurityOutcome::Valid)
        .unwrap_or_else(security_outcome_for_error);
    let subject_id = result
        .as_ref()
        .map(|claims| claims.key_id.as_str())
        .unwrap_or(expected_key_id);
    record_security_outcome(
        SecuritySource::RequestAuth,
        outcome,
        SecurityPolicy::Strict,
        Some(subject_id),
        correlation_id.as_deref(),
    );
    result
}

/// Inspect the canonical claims in a JACS v2 header before key lookup.
///
/// This function performs structural, strict-JSON, and canonical-encoding
/// validation only. The returned values are attacker-controlled until passed
/// to [`verify_request_auth_header_without_replay`] or
/// [`verify_request_auth_header`].
pub fn inspect_unverified_request_auth_header(
    header: &str,
) -> Result<RequestAuthClaims, JacsError> {
    Ok(parse_request_auth_header(header)?.claims)
}

/// Compute the minimum replay-store retention for verified request claims.
///
/// The TTL runs through the credential's absolute inclusive expiry
/// (`issued_at + max_age_seconds`). This is longer than `max_age_seconds` when
/// an accepted signer clock is ahead of the verifier. Servers using
/// [`verify_request_auth_header_without_replay`] with an application-owned
/// Redis/database nonce store **must** use this value (or a longer retention),
/// otherwise an accepted future-dated credential can outlive its replay key.
/// Call this only after cryptographic verification; unverified claims are
/// attacker-controlled.
pub fn request_auth_replay_ttl(
    verified_claims: &RequestAuthClaims,
    max_age_seconds: u64,
) -> Result<Duration, JacsError> {
    replay_ttl_from_unix_seconds(
        verified_claims.issued_at,
        max_age_seconds,
        current_unix_seconds("request_auth_replay_ttl")?,
        "request auth",
    )
}

/// Verify request binding, key binding, freshness, and signature without
/// consuming replay state.
///
/// This is intended for servers that atomically consume `claims.nonce` in an
/// application-owned shared store such as Redis. A successful result is not a
/// complete authentication decision until that atomic consume succeeds. Use
/// [`request_auth_replay_ttl`] for the store TTL; retaining a nonce for only
/// `max_age_seconds` is unsafe when the accepted signer clock is ahead.
#[allow(clippy::too_many_arguments)]
pub fn verify_request_auth_header_without_replay(
    _verifier: &Agent,
    header: &str,
    public_key: &[u8],
    expected_key_id: &str,
    expected_method: &str,
    expected_url: &str,
    expected_body: &[u8],
    expected_audience: &str,
    max_age_seconds: u64,
) -> Result<RequestAuthClaims, JacsError> {
    verify_request_auth_header_without_replay_inner(
        header,
        public_key,
        expected_key_id,
        expected_method,
        expected_url,
        expected_body,
        expected_audience,
        max_age_seconds,
    )
}

/// Stateless trusted-key variant of
/// [`verify_request_auth_header_without_replay`].
///
/// Servers should use this when replay is atomically enforced in an external
/// shared store. The returned nonce must be consumed before granting access,
/// with at least the TTL returned by [`request_auth_replay_ttl`].
#[allow(clippy::too_many_arguments)]
pub fn verify_request_auth_header_with_trusted_key_without_replay(
    header: &str,
    public_key: &[u8],
    expected_key_id: &str,
    expected_method: &str,
    expected_url: &str,
    expected_body: &[u8],
    expected_audience: &str,
    max_age_seconds: u64,
) -> Result<RequestAuthClaims, JacsError> {
    verify_request_auth_header_without_replay_inner(
        header,
        public_key,
        expected_key_id,
        expected_method,
        expected_url,
        expected_body,
        expected_audience,
        max_age_seconds,
    )
}

struct ParsedRequestAuthHeader {
    claims: RequestAuthClaims,
    canonical: String,
    signature: String,
}

fn parse_request_auth_header(header: &str) -> Result<ParsedRequestAuthHeader, JacsError> {
    if header.len() > MAX_REQUEST_AUTH_HEADER_BYTES {
        return Err(JacsError::DocumentMalformed {
            field: "authorization".to_string(),
            reason: format!(
                "JACS v2 header exceeds {} bytes",
                MAX_REQUEST_AUTH_HEADER_BYTES
            ),
        });
    }
    let token =
        header
            .strip_prefix("JACS v2.")
            .ok_or_else(|| JacsError::SignatureVerificationFailed {
                reason: "unsupported Authorization header; expected request-bound JACS v2"
                    .to_string(),
            })?;
    let (claims_segment, signature_segment) =
        token
            .split_once('.')
            .ok_or_else(|| JacsError::DocumentMalformed {
                field: "authorization".to_string(),
                reason: "JACS v2 header must contain claims and signature segments".to_string(),
            })?;
    if claims_segment.is_empty() || signature_segment.is_empty() || signature_segment.contains('.')
    {
        return Err(JacsError::DocumentMalformed {
            field: "authorization".to_string(),
            reason: "JACS v2 header contains an invalid segment count".to_string(),
        });
    }
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_segment)
        .map_err(|e| JacsError::DocumentMalformed {
            field: "authorization.claims".to_string(),
            reason: format!("invalid base64url claims: {e}"),
        })?;
    let claims: RequestAuthClaims =
        jacs_core::strict_json::deserialize_strict_json_slice(&claims_bytes).map_err(|e| {
            JacsError::DocumentMalformed {
                field: "authorization.claims".to_string(),
                reason: e.to_string(),
            }
        })?;
    let canonical = request_auth_claims_canonical(&claims)?;
    if canonical.as_bytes() != claims_bytes {
        return Err(JacsError::DocumentMalformed {
            field: "authorization.claims".to_string(),
            reason: "request auth claims must use canonical JSON encoding".to_string(),
        });
    }
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|e| JacsError::DocumentMalformed {
            field: "authorization.signature".to_string(),
            reason: format!("invalid base64url signature: {e}"),
        })?;

    Ok(ParsedRequestAuthHeader {
        claims,
        canonical,
        signature: base64::engine::general_purpose::STANDARD.encode(signature_bytes),
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_request_auth_header_without_replay_inner(
    header: &str,
    public_key: &[u8],
    expected_key_id: &str,
    expected_method: &str,
    expected_url: &str,
    expected_body: &[u8],
    expected_audience: &str,
    max_age_seconds: u64,
) -> Result<RequestAuthClaims, JacsError> {
    if max_age_seconds == 0 {
        return Err(JacsError::ValidationError(
            "request auth max_age_seconds must be greater than zero".to_string(),
        ));
    }
    let parsed = parse_request_auth_header(header)?;
    let claims = parsed.claims;

    validate_request_auth_claims(
        &claims,
        &RequestAuthExpectation {
            public_key,
            key_id: expected_key_id,
            method: expected_method,
            url: expected_url,
            body: expected_body,
            audience: expected_audience,
            max_age_seconds,
        },
    )?;

    let signing_input = format!("{REQUEST_AUTH_DOMAIN}{}", parsed.canonical);
    crate::crypt::verify_string_with_algorithm(
        response_verification_key(public_key),
        &signing_input,
        &parsed.signature,
        &claims.signing_algorithm,
    )?;
    Ok(claims)
}

struct RequestAuthExpectation<'a> {
    public_key: &'a [u8],
    key_id: &'a str,
    method: &'a str,
    url: &'a str,
    body: &'a [u8],
    audience: &'a str,
    max_age_seconds: u64,
}

fn validate_request_auth_claims(
    claims: &RequestAuthClaims,
    expected: &RequestAuthExpectation<'_>,
) -> Result<(), JacsError> {
    if claims.version != REQUEST_AUTH_VERSION {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!("unsupported request auth version: {}", claims.version),
        });
    }
    let expected_key_id = nonempty_request_auth_value(expected.key_id, "expected_key_id")?;
    if claims.key_id != expected_key_id {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth key ID does not match the trusted signer".to_string(),
        });
    }
    if claims.method != normalize_http_method(expected.method)? {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth method does not match the actual request".to_string(),
        });
    }
    let (scheme, authority, target) = canonical_request_url_components(expected.url)?;
    if claims.scheme != scheme || claims.authority != authority || claims.target != target {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth target URI does not match the actual request".to_string(),
        });
    }
    if claims.content_digest != request_content_digest(expected.body) {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth content digest does not match the actual body".to_string(),
        });
    }
    let expected_audience = nonempty_request_auth_value(expected.audience, "expected_audience")?;
    if claims.audience != expected_audience {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth audience does not match this service".to_string(),
        });
    }
    if claims.nonce.len() != 32 || !claims.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JacsError::DocumentMalformed {
            field: "authorization.claims.nonce".to_string(),
            reason: "request auth nonce must be a UUIDv4 hex value".to_string(),
        });
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| JacsError::Internal {
            message: format!("verify_request_auth_header: system clock error: {e}"),
        })?
        .as_secs();
    let future_limit = now.saturating_add(
        u64::try_from(crate::time_utils::MAX_FUTURE_TIMESTAMP_SECONDS).unwrap_or(300),
    );
    if claims.issued_at > future_limit {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth timestamp is too far in the future".to_string(),
        });
    }
    if now.saturating_sub(claims.issued_at) > expected.max_age_seconds {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth credential has expired".to_string(),
        });
    }
    if !public_key_hash_matches(&claims.public_key_hash, expected.public_key) {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "request auth publicKeyHash does not match the trusted key".to_string(),
        });
    }
    Ok(())
}

fn request_auth_claims_canonical(claims: &RequestAuthClaims) -> Result<String, JacsError> {
    let value = serde_json::to_value(claims).map_err(|e| JacsError::Internal {
        message: format!("failed to serialize request auth claims: {e}"),
    })?;
    jacs_core::canonical::canonicalize_json_try(&value).map_err(JacsError::from)
}

pub(crate) fn canonical_request_url_components(
    request_url: &str,
) -> Result<(String, String, String), JacsError> {
    let parsed = Url::parse(request_url).map_err(|e| {
        JacsError::ValidationError(format!("invalid absolute request URL '{request_url}': {e}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(JacsError::ValidationError(
            "request URL scheme must be http or https".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(JacsError::ValidationError(
            "request URL must not contain a fragment".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(JacsError::ValidationError(
            "request URL must not contain userinfo".to_string(),
        ));
    }
    let host = parsed.host_str().ok_or_else(|| {
        JacsError::ValidationError("request URL must include an authority".to_string())
    })?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let mut target = parsed.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    Ok((parsed.scheme().to_string(), authority, target))
}

pub(crate) fn request_content_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

pub(crate) fn normalize_http_method(method: &str) -> Result<String, JacsError> {
    let method = method.trim();
    if method.is_empty()
        || !method.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(JacsError::ValidationError(
            "request method must be a non-empty HTTP token".to_string(),
        ));
    }
    Ok(method.to_ascii_uppercase())
}

fn nonempty_request_auth_value<'a>(value: &'a str, field: &str) -> Result<&'a str, JacsError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(JacsError::ValidationError(format!(
            "request auth {field} must be non-empty"
        )));
    }
    Ok(value)
}

/// Build and sign a JACS response envelope.
///
/// The envelope format matches the HAI SDK `sign_response` contract:
///
/// ```json
/// {
///   "version": "2.0.0",
///   "document_type": "job_response",
///   "data": <canonicalized payload>,
///   "metadata": {
///     "issuer": "<jacs_id>",
///     "document_id": "<uuid-v4>",
///     "created_at": "<rfc3339>",
///     "hash": "<sha256-hex>"
///   },
///   "jacsSignature": {
///     "agentID": "<jacs_id>",
///     "date": "<rfc3339>",
///     "signingAlgorithm": "<algorithm>",
///     "publicKeyHash": "<sha256-hex>",
///     "signatureContentVersion": "jacs-response-v2",
///     "signature": "<base64-signature>"
///   }
/// }
/// ```
pub fn sign_response(agent: &mut Agent, payload: &Value) -> Result<Value, JacsError> {
    let jacs_id = agent.get_lookup_id()?;
    let now = now_rfc3339();
    let signing_algorithm = configured_agent_signing_algorithm(agent, "response signing")?;
    let public_key = agent.get_public_key()?;
    let public_key_hash = crate::crypt::hash::hash_public_key(&public_key);
    assemble_response_envelope(
        payload,
        &jacs_id,
        &now,
        &Uuid::new_v4().to_string(),
        &signing_algorithm,
        &public_key_hash,
        |input| agent.sign_string(input),
    )
}

/// Sign a TP-34 response-v2 context with the authorized operation selected by
/// the calling interface. Legacy sign_response remains available for inspection.
pub fn sign_response_with_context(
    agent: &mut Agent,
    data: &jacs_core::response_context::ResponseData,
    operation: jacs_core::response_context::ResponseOperation,
) -> Result<Value, JacsError> {
    let lookup_id = agent.get_lookup_id()?;
    let algorithm = configured_agent_signing_algorithm(agent, "contextual response signing")?;
    let public_key_hash = crate::crypt::hash::hash_public_key(&agent.get_public_key()?);
    build_response_with_context_and_signer(
        &lookup_id,
        &algorithm,
        &public_key_hash,
        data,
        operation,
        |input| agent.sign_string(input),
    )
}

/// Restricted remote/local signer adapter. Context and envelope construction
/// remain in JACS; the callback signs the exact domain-separated input.
pub fn build_response_with_context_and_signer(
    signer_lookup_id: &str,
    signing_algorithm: &str,
    public_key_hash: &str,
    data: &jacs_core::response_context::ResponseData,
    operation: jacs_core::response_context::ResponseOperation,
    sign: impl FnOnce(&str) -> Result<String, JacsError>,
) -> Result<Value, JacsError> {
    if data.operation() != operation {
        return Err(JacsError::SigningFailed {
            reason: "response context class does not match the authorized signing operation".into(),
        });
    }
    nonempty_request_auth_value(signer_lookup_id, "signer_lookup_id")?;
    nonempty_request_auth_value(signing_algorithm, "signing_algorithm")?;
    nonempty_request_auth_value(public_key_hash, "public_key_hash")?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let document_id = Uuid::new_v4().to_string();
    let mut data = data.clone();
    data.bind_event_metadata(signer_lookup_id, &document_id, &now);
    data.validate()?;
    let payload = serde_json::to_value(&data).map_err(|error| JacsError::Internal {
        message: error.to_string(),
    })?;
    assemble_response_envelope(
        &payload,
        signer_lookup_id,
        &now,
        &document_id,
        signing_algorithm,
        public_key_hash,
        sign,
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble_response_envelope(
    payload: &Value,
    jacs_id: &str,
    now: &str,
    document_id: &str,
    signing_algorithm: &str,
    public_key_hash: &str,
    sign: impl FnOnce(&str) -> Result<String, JacsError>,
) -> Result<Value, JacsError> {
    let canonical =
        jacs_core::canonical::canonicalize_json_try(payload).map_err(JacsError::from)?;

    // SHA-256 hex digest of the canonical bytes
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    };

    let data: Value = serde_json::from_str(&canonical)
        .map_err(|e| format!("sign_response: failed to re-parse canonical JSON: {e}"))?;

    let mut envelope = serde_json::json!({
        "version": RESPONSE_ENVELOPE_VERSION,
        "document_type": RESPONSE_DOCUMENT_TYPE,
        "data": data,
        "metadata": {
            "issuer": jacs_id,
            "document_id": document_id,
            "created_at": now,
            "hash": hash,
        },
        "jacsSignature": {
            "agentID": jacs_id,
            "date": now,
            "signingAlgorithm": signing_algorithm,
            "publicKeyHash": public_key_hash,
            "signatureContentVersion": RESPONSE_SIGNATURE_CONTENT_VERSION,
        },
    });

    let signing_input = response_signing_input(&envelope)?;
    let signature = sign(&signing_input)?;
    envelope["jacsSignature"]["signature"] = Value::String(signature);

    Ok(envelope)
}

/// Verify the frozen response-v2 signature plus an independently supplied
/// TP-34 context. This does not consume replay state or apply application
/// authorization; live event consumers must do both before releasing payloads.
pub fn verify_response_for_context_with_trusted_key(
    envelope: &Value,
    public_key: &[u8],
    expected: &jacs_core::response_context::ResponseExpectation,
) -> Result<jacs_core::response_context::ResponseData, JacsError> {
    verify_response_envelope_with_trusted_key(envelope, public_key)?;
    jacs_core::response_context::require_response_context(envelope, expected)
        .map_err(JacsError::from)
}

/// Strict exact-JSON variant of contextual response verification.
pub fn verify_response_json_for_context_with_trusted_key(
    raw: &str,
    public_key: &[u8],
    expected: &jacs_core::response_context::ResponseExpectation,
) -> Result<jacs_core::response_context::ResponseData, JacsError> {
    crate::schema::utils::check_document_size(raw)?;
    let envelope = jacs_core::strict_json::parse_strict_json(raw)?;
    verify_response_for_context_with_trusted_key(&envelope, public_key, expected)
}

/// Build the versioned, domain-separated response signature input.
///
/// Every envelope field is covered except `jacsSignature.signature` itself.
/// Unknown fields are intentionally retained, so inserting or removing one
/// after signing invalidates the signature.
pub fn response_signing_input(envelope: &Value) -> Result<String, JacsError> {
    jacs_core::response_context::response_signing_input(envelope).map_err(JacsError::from)
}

fn response_field<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, JacsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: pointer.trim_start_matches('/').replace('/', "."),
            reason: "response envelope field must be a non-empty string".to_string(),
        })
}

fn public_key_hash_matches(claimed: &str, public_key: &[u8]) -> bool {
    if claimed == crate::crypt::hash::hash_public_key(public_key) {
        return true;
    }

    // Registries and SDKs commonly exchange the same native key as PEM while
    // JACS agents may hash its raw algorithm-specific bytes. Treat those two
    // encodings as the same key identity after a successful PEM parse.
    pem::parse(public_key)
        .is_ok_and(|block| claimed == crate::crypt::hash::hash_public_key(block.contents()))
}

fn response_verification_key(public_key: &[u8]) -> Vec<u8> {
    // External registries and SDKs exchange PEM text, while the native
    // Ed25519 and ML-DSA verifiers consume the decoded algorithm-specific
    // bytes. Keep raw keys unchanged and unwrap only a well-formed PEM block.
    pem::parse(public_key)
        .map(|block| block.into_contents())
        .unwrap_or_else(|_| public_key.to_vec())
}

/// Verify a v2 response envelope with an explicitly trusted public key.
///
/// Success authenticates the complete envelope, not merely `data`: version,
/// document type, metadata, signer, timestamp, algorithm, key hash, payload,
/// and any additional fields all participate in the signature input.
///
/// This raw envelope primitive is intentionally stateless: it does not enforce
/// maximum age or replay consumption. Live event consumers must use
/// [`verify_signed_event_with_trusted_keys`] or
/// [`verify_signed_event_with_replay_store`].
pub fn verify_response_envelope_with_key(
    _agent: &Agent,
    envelope: &Value,
    public_key: &[u8],
) -> Result<Value, JacsError> {
    let result = verify_response_envelope_with_key_inner(envelope, public_key);
    let outcome = result
        .as_ref()
        .map(|_| SecurityOutcome::Valid)
        .unwrap_or_else(security_outcome_for_error);
    let signer_id = envelope
        .pointer("/jacsSignature/agentID")
        .and_then(Value::as_str);
    let correlation_id = envelope
        .pointer("/metadata/document_id")
        .and_then(Value::as_str);
    record_security_outcome(
        SecuritySource::ResponseEnvelope,
        outcome,
        SecurityPolicy::Strict,
        signer_id,
        correlation_id,
    );
    result
}

/// Verify a v2 response envelope with a trusted key and no agent instance.
///
/// This is the preferred explicit-key server path: verification is stateless
/// and cannot generate, load, or consult an unrelated identity. It does not
/// enforce maximum age or replay consumption; live event consumers must use a
/// `verify_signed_event_*` function.
pub fn verify_response_envelope_with_trusted_key(
    envelope: &Value,
    public_key: &[u8],
) -> Result<Value, JacsError> {
    let result = verify_response_envelope_with_key_inner(envelope, public_key);
    let outcome = result
        .as_ref()
        .map(|_| SecurityOutcome::Valid)
        .unwrap_or_else(security_outcome_for_error);
    let signer_id = envelope
        .pointer("/jacsSignature/agentID")
        .and_then(Value::as_str);
    let correlation_id = envelope
        .pointer("/metadata/document_id")
        .and_then(Value::as_str);
    record_security_outcome(
        SecuritySource::ResponseEnvelope,
        outcome,
        SecurityPolicy::Strict,
        signer_id,
        correlation_id,
    );
    result
}

fn verify_response_envelope_with_key_inner(
    envelope: &Value,
    public_key: &[u8],
) -> Result<Value, JacsError> {
    if response_field(envelope, "/version")? != RESPONSE_ENVELOPE_VERSION {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "unsupported response envelope version; expected {}",
                RESPONSE_ENVELOPE_VERSION
            ),
        });
    }
    if response_field(envelope, "/document_type")? != RESPONSE_DOCUMENT_TYPE {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "unexpected response document_type; expected {}",
                RESPONSE_DOCUMENT_TYPE
            ),
        });
    }
    if response_field(envelope, "/jacsSignature/signatureContentVersion")?
        != RESPONSE_SIGNATURE_CONTENT_VERSION
    {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "unsupported response signature scope; expected {}",
                RESPONSE_SIGNATURE_CONTENT_VERSION
            ),
        });
    }

    let signer_id = response_field(envelope, "/jacsSignature/agentID")?;
    let issuer = response_field(envelope, "/metadata/issuer")?;
    if issuer != signer_id {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "response metadata.issuer does not match jacsSignature.agentID".to_string(),
        });
    }
    let signed_at = response_field(envelope, "/jacsSignature/date")?;
    let created_at = response_field(envelope, "/metadata/created_at")?;
    if created_at != signed_at {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "response metadata.created_at does not match jacsSignature.date".to_string(),
        });
    }
    crate::time_utils::validate_signature_timestamp(signed_at)?;
    let document_id = response_field(envelope, "/metadata/document_id")?;
    Uuid::parse_str(document_id).map_err(|_| JacsError::DocumentMalformed {
        field: "metadata.document_id".to_string(),
        reason: "response document_id must be a UUID".to_string(),
    })?;

    let data = envelope
        .get("data")
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "data".to_string(),
            reason: "response envelope is missing data".to_string(),
        })?;
    let expected_hash = {
        let mut hasher = Sha256::new();
        let canonical =
            jacs_core::canonical::canonicalize_json_try(data).map_err(JacsError::from)?;
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    };
    let claimed_hash = response_field(envelope, "/metadata/hash")?;
    if claimed_hash != expected_hash {
        return Err(JacsError::HashMismatch {
            expected: expected_hash,
            got: claimed_hash.to_string(),
        });
    }

    let claimed_key_hash = response_field(envelope, "/jacsSignature/publicKeyHash")?;
    if !public_key_hash_matches(claimed_key_hash, public_key) {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "response publicKeyHash does not match the trusted verification key"
                .to_string(),
        });
    }

    let signature = response_field(envelope, "/jacsSignature/signature")?;
    let algorithm = response_field(envelope, "/jacsSignature/signingAlgorithm")?;
    let signing_input = response_signing_input(envelope)?;
    let verification_key = response_verification_key(public_key);
    crate::crypt::verify_string_with_algorithm(
        verification_key,
        &signing_input,
        signature,
        algorithm,
    )?;

    Ok(data.clone())
}

/// Strict raw-JSON variant of [`verify_response_envelope_with_key`].
pub fn verify_response_json_with_key(
    _agent: &Agent,
    envelope_json: &str,
    public_key: &[u8],
) -> Result<Value, JacsError> {
    let envelope = match parse_bounded_protocol_json(envelope_json, "response_envelope") {
        Ok(envelope) => envelope,
        Err(error) => {
            record_security_outcome(
                SecuritySource::ResponseEnvelope,
                security_outcome_for_error(&error),
                SecurityPolicy::Strict,
                None,
                None,
            );
            return Err(error);
        }
    };
    let signer_id = envelope
        .pointer("/jacsSignature/agentID")
        .and_then(Value::as_str);
    let correlation_id = envelope
        .pointer("/metadata/document_id")
        .and_then(Value::as_str);
    let result = verify_response_envelope_with_key_inner(&envelope, public_key);
    let outcome = result
        .as_ref()
        .map(|_| SecurityOutcome::Valid)
        .unwrap_or_else(security_outcome_for_error);
    record_security_outcome(
        SecuritySource::ResponseEnvelope,
        outcome,
        SecurityPolicy::Strict,
        signer_id,
        correlation_id,
    );
    result
}

/// Strict raw-JSON variant of [`verify_response_envelope_with_trusted_key`].
pub fn verify_response_json_with_trusted_key(
    envelope_json: &str,
    public_key: &[u8],
) -> Result<Value, JacsError> {
    let envelope = match parse_bounded_protocol_json(envelope_json, "response_envelope") {
        Ok(envelope) => envelope,
        Err(error) => {
            record_security_outcome(
                SecuritySource::ResponseEnvelope,
                security_outcome_for_error(&error),
                SecurityPolicy::Strict,
                None,
                None,
            );
            return Err(error);
        }
    };
    verify_response_envelope_with_trusted_key(&envelope, public_key)
}

/// Provenance returned only after complete v2 envelope verification succeeds.
///
/// Unlike a `(data, verified)` tuple, this type cannot contain unverified data:
/// construction is gated by signature, key-hash, payload-hash, and envelope
/// invariant checks.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedSignedEvent {
    pub data: Value,
    pub signer_id: String,
    pub timestamp: String,
    pub algorithm: String,
    pub document_id: String,
}

/// Proof that a signed event passed cryptographic and freshness checks but has
/// **not** yet passed application-owned replay consumption.
///
/// This deliberately contains no payload. A multi-replica binding must first
/// atomically consume [`Self::replay_key`] in its shared store for
/// [`Self::replay_ttl_seconds`], recheck [`Self::expires_at_unix_seconds`], and
/// only then release data parsed from the exact input identified by
/// [`Self::event_sha256`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEventReplayPreparation {
    pub contract_version: u8,
    pub status: String,
    pub cryptographically_verified: bool,
    pub freshness_verified: bool,
    pub replay_consumed: bool,
    pub signer_id: String,
    pub timestamp: String,
    pub algorithm: String,
    pub document_id: String,
    pub event_sha256: String,
    pub replay_key: String,
    pub replay_ttl_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug)]
struct PreparedSignedEvent {
    verified: VerifiedSignedEvent,
    replay_scope: String,
    replay_key: String,
    replay_ttl: Duration,
    expires_at_unix_seconds: u64,
}

/// Strictly verify a signed event and return provenance-bearing data.
///
/// Unknown keys, unsigned/plain events, legacy payload-only envelopes, and
/// malformed or invalid signatures are errors. No unverified payload is
/// included in an error result.
pub fn verify_signed_event_strict(
    _agent: &Agent,
    event: &Value,
    server_public_keys: &HashMap<String, Vec<u8>>,
) -> Result<VerifiedSignedEvent, JacsError> {
    verify_signed_event_with_trusted_keys(event, server_public_keys)
}

/// Strictly verify a signed event with caller-pinned server keys and no agent
/// instance. Unknown, unsigned, malformed, stale, replayed, or invalid events
/// fail closed. The default freshness window is
/// [`crate::replay::payload_replay_window_seconds`], and the installed replay
/// backend atomically consumes `(signer_id, document_id)`.
pub fn verify_signed_event_with_trusted_keys(
    event: &Value,
    server_public_keys: &HashMap<String, Vec<u8>>,
) -> Result<VerifiedSignedEvent, JacsError> {
    let max_age_seconds = crate::replay::payload_replay_window_seconds();
    verify_signed_event_live(event, server_public_keys, max_age_seconds, None)
}

/// Strictly parse and verify an exact signed-event JSON input.
///
/// This is the preferred live-transport entry point when the caller still has
/// the original wire bytes. It rejects duplicate object names and all other
/// strict-JSON violations before constructing a [`Value`], then performs the
/// same signature, freshness, trusted-key, and atomic replay checks as
/// [`verify_signed_event_with_trusted_keys`]. No payload is returned on error.
pub fn verify_signed_event_json_with_trusted_keys(
    event_json: &str,
    server_public_keys: &HashMap<String, Vec<u8>>,
) -> Result<VerifiedSignedEvent, JacsError> {
    let event = parse_signed_event_json_strict(event_json)?;
    let max_age_seconds = crate::replay::payload_replay_window_seconds();
    verify_signed_event_live(&event, server_public_keys, max_age_seconds, None)
}

/// Strictly verify a live signed event using an explicitly supplied atomic
/// replay backend.
///
/// Multi-replica services should pass their shared [`crate::replay::ReplayStore`]
/// implementation here. The event is released only after full envelope
/// verification, bounded freshness validation, and atomic consumption of the
/// `(signer_id, document_id)` replay key all succeed.
pub fn verify_signed_event_with_replay_store(
    event: &Value,
    server_public_keys: &HashMap<String, Vec<u8>>,
    replay_store: &dyn crate::replay::ReplayStore,
    max_age_seconds: u64,
) -> Result<VerifiedSignedEvent, JacsError> {
    verify_signed_event_live(
        event,
        server_public_keys,
        max_age_seconds,
        Some(replay_store),
    )
}

/// Verify an exact signed-event JSON input without consuming a replay store.
///
/// This is the bridge for Python, Node, Go, and other application runtimes
/// that own a shared atomic replay backend which Rust cannot call directly.
/// Successful preparation is intentionally **not** a verified-delivery result:
/// no payload is returned and `replayConsumed` is always false.
pub fn prepare_signed_event_replay_json(
    event_json: &str,
    server_public_keys: &HashMap<String, Vec<u8>>,
    max_age_seconds: u64,
) -> Result<SignedEventReplayPreparation, JacsError> {
    let event = parse_signed_event_json_strict(event_json)?;
    let result =
        prepare_signed_event_live(&event, server_public_keys, max_age_seconds).map(|prepared| {
            SignedEventReplayPreparation {
                contract_version: 1,
                status: "crypto_verified_replay_pending".to_string(),
                cryptographically_verified: true,
                freshness_verified: true,
                replay_consumed: false,
                signer_id: prepared.verified.signer_id,
                timestamp: prepared.verified.timestamp,
                algorithm: prepared.verified.algorithm,
                document_id: prepared.verified.document_id,
                event_sha256: hex::encode(Sha256::digest(event_json.as_bytes())),
                replay_key: prepared.replay_key,
                replay_ttl_seconds: prepared.replay_ttl.as_secs(),
                expires_at_unix_seconds: prepared.expires_at_unix_seconds,
            }
        });
    record_signed_event_result(&event, &result);
    result
}

fn parse_signed_event_json_strict(event_json: &str) -> Result<Value, JacsError> {
    match parse_bounded_protocol_json(event_json, "signed_event") {
        Ok(event) => Ok(event),
        Err(error) => {
            let outcome = security_outcome_for_error(&error);
            record_security_outcome(
                SecuritySource::SignedEvent,
                outcome,
                SecurityPolicy::Strict,
                None,
                None,
            );
            tracing::warn!(
                event = "signed_event_verification_failed",
                outcome = outcome.as_str(),
                error_kind = outcome.error_kind(),
                policy = SecurityPolicy::Strict.as_str(),
                "Signed event JSON rejected before payload release"
            );
            Err(error)
        }
    }
}

pub(crate) fn replay_ttl_from_rfc3339(
    timestamp: &str,
    max_age_seconds: u64,
    context: &str,
) -> Result<Duration, JacsError> {
    let issued_at = crate::time_utils::parse_rfc3339(timestamp)?.timestamp();
    let issued_at =
        u64::try_from(issued_at).map_err(|_| JacsError::SignatureVerificationFailed {
            reason: format!("{context} timestamp predates the Unix epoch"),
        })?;
    replay_ttl_from_unix_seconds(
        issued_at,
        max_age_seconds,
        current_unix_seconds("replay_ttl_from_rfc3339")?,
        context,
    )
}

fn prepare_signed_event_live(
    event: &Value,
    server_public_keys: &HashMap<String, Vec<u8>>,
    max_age_seconds: u64,
) -> Result<PreparedSignedEvent, JacsError> {
    let signer_id = event
        .pointer("/jacsSignature/agentID")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if event.get("data").is_none() || event.get("jacsSignature").is_none() {
        return Err(JacsError::DocumentMalformed {
            field: "event".to_string(),
            reason: "event is not a fully signed v2 response envelope".to_string(),
        });
    }
    if signer_id.is_empty() {
        return Err(JacsError::DocumentMalformed {
            field: "jacsSignature.agentID".to_string(),
            reason: "signed event is missing a non-empty signer ID".to_string(),
        });
    }
    let public_key =
        server_public_keys
            .get(&signer_id)
            .ok_or_else(|| JacsError::SignerUnknown {
                agent_id: signer_id.clone(),
            })?;
    let data = verify_response_envelope_with_key_inner(event, public_key)?;
    let verified = VerifiedSignedEvent {
        data,
        signer_id,
        timestamp: response_field(event, "/jacsSignature/date")?.to_string(),
        algorithm: response_field(event, "/jacsSignature/signingAlgorithm")?.to_string(),
        document_id: response_field(event, "/metadata/document_id")?.to_string(),
    };

    if max_age_seconds == 0 {
        return Err(JacsError::ValidationError(
            "signed event max_age_seconds must be greater than zero".to_string(),
        ));
    }
    let max_age_i64 = i64::try_from(max_age_seconds).map_err(|_| {
        JacsError::ValidationError(
            "signed event max_age_seconds exceeds the supported timestamp range".to_string(),
        )
    })?;
    crate::time_utils::validate_timestamp_not_future(&verified.timestamp)?;
    crate::time_utils::validate_timestamp_not_expired(&verified.timestamp, max_age_i64)?;

    let issued_at = crate::time_utils::parse_rfc3339(&verified.timestamp)?.timestamp();
    let issued_at =
        u64::try_from(issued_at).map_err(|_| JacsError::SignatureVerificationFailed {
            reason: "signed event timestamp predates the Unix epoch".to_string(),
        })?;
    let expires_at_unix_seconds = issued_at.checked_add(max_age_seconds).ok_or_else(|| {
        JacsError::ValidationError(
            "signed event expiry exceeds the Unix timestamp range".to_string(),
        )
    })?;
    let replay_ttl = replay_ttl_from_unix_seconds(
        issued_at,
        max_age_seconds,
        current_unix_seconds("prepare_signed_event_replay")?,
        "signed event",
    )?;
    let replay_scope = format!("signed-event:{}", verified.signer_id);
    let replay_key = crate::replay::replay_key(&replay_scope, &verified.document_id);

    Ok(PreparedSignedEvent {
        verified,
        replay_scope,
        replay_key,
        replay_ttl,
        expires_at_unix_seconds,
    })
}

fn record_signed_event_result<T>(event: &Value, result: &Result<T, JacsError>) {
    let signer_id = event
        .pointer("/jacsSignature/agentID")
        .and_then(Value::as_str)
        .unwrap_or("");
    let correlation_id = event
        .pointer("/metadata/document_id")
        .and_then(Value::as_str)
        .unwrap_or("");

    let outcome = result
        .as_ref()
        .map(|_| SecurityOutcome::Valid)
        .unwrap_or_else(security_outcome_for_error);
    record_security_outcome(
        SecuritySource::SignedEvent,
        outcome,
        SecurityPolicy::Strict,
        (!signer_id.is_empty()).then_some(signer_id),
        (!correlation_id.is_empty()).then_some(correlation_id),
    );

    if result.is_err() {
        let safe_signer_id = safe_security_identifier(Some(signer_id));
        tracing::warn!(
            event = "signed_event_verification_failed",
            signer_id = safe_signer_id,
            outcome = outcome.as_str(),
            error_kind = outcome.error_kind(),
            policy = SecurityPolicy::Strict.as_str(),
            "signed event rejected without releasing payload"
        );
    }
}

fn verify_signed_event_live(
    event: &Value,
    server_public_keys: &HashMap<String, Vec<u8>>,
    max_age_seconds: u64,
    replay_store: Option<&dyn crate::replay::ReplayStore>,
) -> Result<VerifiedSignedEvent, JacsError> {
    let result = (|| {
        let prepared = prepare_signed_event_live(event, server_public_keys, max_age_seconds)?;
        if let Some(store) = replay_store {
            crate::replay::check_and_store_nonce_with_store(
                store,
                &prepared.replay_scope,
                &prepared.verified.document_id,
                prepared.replay_ttl,
            )?;
        } else {
            crate::replay::check_and_store_nonce_with_ttl(
                &prepared.replay_scope,
                &prepared.verified.document_id,
                prepared.replay_ttl,
            )?;
        }
        Ok(prepared.verified)
    })();
    record_signed_event_result(event, &result);
    result
}

/// Encode a document as URL-safe base64 (no padding) for use in verification
/// links.
///
/// This is the JACS-level primitive. SDK clients are responsible for
/// constructing the full URL (e.g. `https://hai.ai/jacs/verify?s={encoded}`).
pub fn encode_verify_payload(document: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(document.as_bytes())
}

/// Decode a URL-safe base64 (no padding) verification payload back to the
/// original document string.
pub fn decode_verify_payload(encoded: &str) -> Result<String, JacsError> {
    if encoded.len() > MAX_VERIFY_PAYLOAD_ENCODED_BYTES {
        return Err(JacsError::ValidationError(format!(
            "decode_verify_payload: encoded input exceeds the {} byte limit",
            MAX_VERIFY_PAYLOAD_ENCODED_BYTES
        )));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("decode_verify_payload: invalid base64url: {e}"))?;
    if bytes.len() > MAX_VERIFY_PAYLOAD_DECODED_BYTES {
        return Err(JacsError::ValidationError(format!(
            "decode_verify_payload: decoded payload exceeds the {} byte limit",
            MAX_VERIFY_PAYLOAD_DECODED_BYTES
        )));
    }
    String::from_utf8(bytes)
        .map_err(|e| format!("decode_verify_payload: invalid UTF-8: {e}").into())
}

/// Inspect a document ID without verifying the document.
///
/// Checks fields in priority order: `jacsDocumentId`, `document_id`, `id`.
///
/// SDK clients use this to build hosted verification URLs
/// (e.g. `https://hai.ai/verify/{id}`).
///
/// This function only performs bounded, strict JSON parsing. The returned ID
/// is attacker-controlled until the caller separately verifies the document;
/// never use it for authorization, key lookup, replay decisions, or trust.
pub fn extract_document_id(document: &str) -> Result<String, JacsError> {
    let value = parse_bounded_protocol_json(document, "extract_document_id")?;

    let doc_id = value
        .get("jacsDocumentId")
        .and_then(Value::as_str)
        .or_else(|| value.get("document_id").and_then(Value::as_str))
        .or_else(|| value.get("id").and_then(Value::as_str));

    doc_id.map(String::from).ok_or_else(|| {
        "extract_document_id: no ID field found (expected jacsDocumentId, document_id, or id)"
            .into()
    })
}

/// Unwrap a fully verified JACS-signed event.
///
/// This matches the behaviour of `unwrapSignedEvent` (Node) and
/// `unwrap_signed_event` (Python) in the HAI SDK.
///
/// This compatibility wrapper preserves the historical tuple shape, but it is
/// fail-closed: `Ok` is returned only for a fully verified v2 response and the
/// boolean is therefore always `true`. Unknown keys, legacy payload-only
/// signatures, and plain events are errors and never release data. New callers
/// should prefer [`verify_signed_event_strict`] and its provenance type.
///
/// # Arguments
///
/// * `agent`              -- an initialised JACS agent used for verification.
/// * `event`              -- the parsed JSON event to unwrap.
/// * `server_public_keys` -- map of `agent_id -> public_key_bytes`
///   (raw bytes, the same encoding that `KeyManager::verify_string` expects).
pub fn unwrap_signed_event(
    agent: &Agent,
    event: &Value,
    server_public_keys: &HashMap<String, Vec<u8>>,
) -> Result<(Value, bool), JacsError> {
    let verified = verify_signed_event_strict(agent, event, server_public_keys)?;
    Ok((verified.data, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- canonicalize_json tests ----

    #[test]
    fn canonicalize_sorts_keys() {
        let input = json!({"b": 2, "a": 1});
        let result = canonicalize_json(&input);
        assert_eq!(result, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonicalize_nested_objects() {
        let input = json!({"z": {"b": 2, "a": 1}, "a": 0});
        let result = canonicalize_json(&input);
        assert_eq!(result, r#"{"a":0,"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn canonicalize_null() {
        let input = json!(null);
        let result = canonicalize_json(&input);
        assert_eq!(result, "null");
    }

    #[test]
    fn canonicalize_empty_object() {
        let input = json!({});
        let result = canonicalize_json(&input);
        assert_eq!(result, "{}");
    }

    #[test]
    fn canonicalize_empty_array() {
        let input = json!([]);
        let result = canonicalize_json(&input);
        assert_eq!(result, "[]");
    }

    // ---- request-bound auth header tests ----

    /// Helper: create an ephemeral agent with keys for testing.
    fn make_test_agent() -> Agent {
        // These tests are algorithm-agnostic and use the default pq2025 path.
        let mut agent = Agent::ephemeral("pq2025").expect("Failed to create ephemeral agent");

        let agent_string = crate::create_minimal_blank_agent("ai".to_string(), None, None, None)
            .expect("Failed to create minimal agent JSON");

        agent
            .create_agent_and_load(&agent_string, true, Some("pq2025"))
            .expect("Failed to create and load agent");

        agent
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn request_auth_header_binds_complete_request_and_replay() {
        let mut agent = make_test_agent();
        let method = "POST";
        let url = "https://api.example.test/v1/jobs?mode=fast";
        let body = br#"{"task":"review"}"#;
        let audience = "hai-api";
        let header = build_request_auth_header(&mut agent, method, url, body, audience)
            .expect("build_request_auth_header failed");
        assert!(header.starts_with("JACS v2."));

        let key = agent.get_public_key().expect("public key");
        let key_id = agent.get_lookup_id().expect("key id");

        for (changed_method, changed_url, changed_body, changed_audience) in [
            ("GET", url, body.as_slice(), audience),
            (
                method,
                "https://api.example.test/v1/other?mode=fast",
                body.as_slice(),
                audience,
            ),
            (
                method,
                "https://api.example.test/v1/jobs?mode=slow",
                body.as_slice(),
                audience,
            ),
            (method, url, br#"{"task":"delete"}"#.as_slice(), audience),
            (method, url, body.as_slice(), "other-service"),
        ] {
            let result = verify_request_auth_header(
                &agent,
                &header,
                &key,
                &key_id,
                changed_method,
                changed_url,
                changed_body,
                changed_audience,
                300,
            );
            assert!(result.is_err(), "substituted request must fail");
        }

        let claims = verify_request_auth_header(
            &agent, &header, &key, &key_id, method, url, body, audience, 300,
        )
        .expect("bound request should verify");
        assert_eq!(claims.version, REQUEST_AUTH_VERSION);
        assert_eq!(claims.key_id, key_id);
        assert_eq!(claims.method, method);
        assert_eq!(claims.audience, audience);

        let replay = verify_request_auth_header(
            &agent, &header, &key, &key_id, method, url, body, audience, 300,
        );
        assert!(replay.is_err(), "the same nonce must be consumed once");
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn request_auth_signature_verification_leaves_replay_to_the_caller() {
        let mut signer = make_test_agent();
        let verifier = make_test_agent();
        let method = "PATCH";
        let url = "https://hai.ai/api/v1/agents/example?mode=strict";
        let body = br#"{"enabled":true}"#;
        let audience = "hai.ai";
        let header = build_request_auth_header(&mut signer, method, url, body, audience)
            .expect("request auth header");
        let key = signer.get_public_key().expect("public key");
        let key_id = signer.get_lookup_id().expect("key id");

        let inspected = inspect_unverified_request_auth_header(&header)
            .expect("well-formed claims may be inspected before key lookup");
        assert_eq!(inspected.key_id, key_id);

        for _ in 0..2 {
            let verified = verify_request_auth_header_without_replay(
                &verifier, &header, &key, &key_id, method, url, body, audience, 300,
            )
            .expect("signature/context verification must not consume process replay state");
            assert_eq!(verified.nonce, inspected.nonce);
        }

        let stateless = verify_request_auth_header_with_trusted_key_without_replay(
            &header, &key, &key_id, method, url, body, audience, 300,
        )
        .expect("trusted-key server verification must not require another identity");
        assert_eq!(stateless, inspected);

        verify_request_auth_header(
            &verifier, &header, &key, &key_id, method, url, body, audience, 300,
        )
        .expect("the full verifier consumes replay exactly once");
        assert!(
            verify_request_auth_header(
                &verifier, &header, &key, &key_id, method, url, body, audience, 300,
            )
            .is_err(),
            "the full verifier must still reject a replay"
        );
    }

    #[derive(Default)]
    struct RecordingReplayStore {
        ttls: std::sync::Mutex<Vec<std::time::Duration>>,
        keys: std::sync::Mutex<Vec<String>>,
    }

    impl crate::replay::ReplayStore for RecordingReplayStore {
        fn consume(&self, key: &str, ttl: std::time::Duration) -> Result<bool, JacsError> {
            self.keys
                .lock()
                .expect("key recording lock")
                .push(key.to_string());
            self.ttls.lock().expect("TTL recording lock").push(ttl);
            Ok(true)
        }

        fn name(&self) -> &'static str {
            "protocol-ttl-recording-test"
        }

        fn scope(&self) -> crate::replay::ReplayStoreScope {
            crate::replay::ReplayStoreScope::Shared
        }
    }

    fn rewrite_request_auth_issued_at(signer: &mut Agent, header: &str, issued_at: u64) -> String {
        let mut claims = parse_request_auth_header(header)
            .expect("parse request auth header")
            .claims;
        claims.issued_at = issued_at;
        let canonical = request_auth_claims_canonical(&claims).expect("canonical claims");
        let signature = signer
            .sign_string(&format!("{REQUEST_AUTH_DOMAIN}{canonical}"))
            .expect("resign claims");
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .expect("signature base64");
        format!(
            "JACS v2.{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        )
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn request_auth_replay_retention_matches_caller_max_age() {
        let recording = std::sync::Arc::new(RecordingReplayStore::default());
        let mut signer = make_test_agent();
        let verifier = make_test_agent();
        let method = "POST";
        let url = "https://hai.ai/api/v1/jobs";
        let body = br#"{"task":"review"}"#;
        let audience = "hai.ai";
        let header = build_request_auth_header(&mut signer, method, url, body, audience)
            .expect("request auth header");
        let key = signer.get_public_key().expect("public key");
        let key_id = signer.get_lookup_id().expect("key id");

        let previous = crate::replay::install_replay_store(recording.clone())
            .expect("install recording replay store");
        let result = verify_request_auth_header(
            &verifier, &header, &key, &key_id, method, url, body, audience, 937,
        );
        crate::replay::install_replay_store(previous).expect("restore replay store");
        result.expect("request auth should verify");

        let ttls = recording.ttls.lock().expect("TTL recording lock");
        assert_eq!(ttls.len(), 1);
        assert!(
            (937..=938).contains(&ttls[0].as_secs()),
            "inclusive absolute-expiry TTL should cover the caller max age: {:?}",
            ttls[0]
        );
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn request_auth_replay_retention_covers_accepted_future_clock_skew() {
        let recording = std::sync::Arc::new(RecordingReplayStore::default());
        let mut signer = make_test_agent();
        let verifier = make_test_agent();
        let method = "POST";
        let url = "https://hai.ai/api/v1/jobs";
        let body = br#"{"task":"review"}"#;
        let audience = "hai.ai";
        let header = build_request_auth_header(&mut signer, method, url, body, audience)
            .expect("request auth header");
        let future_header = rewrite_request_auth_issued_at(
            &mut signer,
            &header,
            current_unix_seconds("test clock").expect("clock") + 120,
        );
        let key = signer.get_public_key().expect("public key");
        let key_id = signer.get_lookup_id().expect("key id");
        let max_age = 60;

        let previous = crate::replay::install_replay_store(recording.clone())
            .expect("install recording replay store");
        let result = verify_request_auth_header(
            &verifier,
            &future_header,
            &key,
            &key_id,
            method,
            url,
            body,
            audience,
            max_age,
        );
        crate::replay::install_replay_store(previous).expect("restore replay store");
        result.expect("credential within accepted future skew should verify");

        let ttls = recording.ttls.lock().expect("TTL recording lock");
        assert_eq!(ttls.len(), 1);
        assert!(
            ttls[0] > Duration::from_secs(max_age),
            "future-dated credential replay TTL must outlive max_age: {:?}",
            ttls[0]
        );
        assert!(ttls[0] <= Duration::from_secs(max_age + 121));
    }

    #[test]
    fn request_auth_generic_signer_matches_agent_builder_contract() {
        let mut signer = make_test_agent();
        let verifier = make_test_agent();
        let key = signer.get_public_key().expect("public key");
        let key_id = signer.get_lookup_id().expect("key id");
        let algorithm = signer
            .get_key_algorithm()
            .cloned()
            .expect("signing algorithm");
        let key_hash = crate::crypt::hash::hash_public_key(&key);

        let header = build_request_auth_header_with_signer(
            &key_id,
            &algorithm,
            &key_hash,
            "POST",
            "https://hai.ai/api/v1/agents/hello",
            br#"{"include_test":false}"#,
            "hai.ai",
            |signing_input| signer.sign_string(signing_input),
        )
        .expect("generic request auth builder");

        verify_request_auth_header_without_replay(
            &verifier,
            &header,
            &key,
            &key_id,
            "POST",
            "https://hai.ai/api/v1/agents/hello",
            br#"{"include_test":false}"#,
            "hai.ai",
            300,
        )
        .expect("generic builder must emit the canonical JACS v2 contract");
    }

    #[test]
    fn request_auth_header_rejects_untrusted_key_and_tampered_claims() {
        let mut signer = make_test_agent();
        let verifier = make_test_agent();
        let header = build_request_auth_header(
            &mut signer,
            "POST",
            "https://api.example.test/v1/jobs",
            b"payload",
            "hai-api",
        )
        .expect("header");
        let signer_id = signer.get_lookup_id().expect("signer id");

        let wrong_key = verifier.get_public_key().expect("wrong key");
        assert!(
            verify_request_auth_header(
                &verifier,
                &header,
                &wrong_key,
                &signer_id,
                "POST",
                "https://api.example.test/v1/jobs",
                b"payload",
                "hai-api",
                300,
            )
            .is_err()
        );

        let mut segments: Vec<String> = header.split('.').map(str::to_string).collect();
        assert_eq!(segments.len(), 3);
        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&segments[1])
            .expect("claims base64url");
        let mut claims =
            jacs_core::strict_json::parse_strict_json_slice(&claims_bytes).expect("claims json");
        claims["audience"] = json!("attacker");
        segments[1] =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonicalize_json(&claims));
        let tampered = segments.join(".");
        let key = signer.get_public_key().expect("key");
        assert!(
            verify_request_auth_header(
                &verifier,
                &tampered,
                &key,
                &signer_id,
                "POST",
                "https://api.example.test/v1/jobs",
                b"payload",
                "attacker",
                300,
            )
            .is_err()
        );
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    #[allow(deprecated)]
    fn legacy_unbound_auth_remains_additive_and_can_be_rejected_by_policy() {
        let previous = std::env::var_os("JACS_REJECT_UNBOUND_AUTH_HEADER");
        // SAFETY: this test is serialized with the shared JACS environment lock.
        unsafe { std::env::remove_var("JACS_REJECT_UNBOUND_AUTH_HEADER") };
        let mut agent = make_test_agent();
        let legacy = build_auth_header(&mut agent).expect("legacy API remains source-compatible");
        assert!(legacy.starts_with("JACS "));

        // SAFETY: this test is serialized with the shared JACS environment lock.
        unsafe { std::env::set_var("JACS_REJECT_UNBOUND_AUTH_HEADER", "true") };
        let denied = build_auth_header(&mut agent);
        assert!(
            denied.is_err(),
            "strict deployments can reject unbound auth"
        );

        match previous {
            // SAFETY: restore the serialized process environment before return.
            Some(value) => unsafe { std::env::set_var("JACS_REJECT_UNBOUND_AUTH_HEADER", value) },
            // SAFETY: restore the serialized process environment before return.
            None => unsafe { std::env::remove_var("JACS_REJECT_UNBOUND_AUTH_HEADER") },
        }
    }

    // ---- sign_response tests ----

    #[test]
    fn response_signing_rejects_missing_algorithm_state() {
        let mut agent = Agent::new("v1", "v1", "v1").expect("empty agent");
        agent.config = None;
        let error = configured_agent_signing_algorithm(&agent, "response signing")
            .expect_err("missing algorithm must not silently become Ed25519");
        assert!(matches!(error, JacsError::SigningFailed { .. }));
        assert!(error.to_string().contains("configured signing algorithm"));
    }

    #[test]
    fn sign_response_has_required_top_level_keys() {
        let mut agent = make_test_agent();
        let payload = json!({"answer": 42});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");

        for key in &[
            "version",
            "document_type",
            "data",
            "metadata",
            "jacsSignature",
        ] {
            assert!(
                envelope.get(key).is_some(),
                "Envelope missing required key: {key}"
            );
        }
    }

    #[test]
    fn sign_response_version_and_document_type() {
        let mut agent = make_test_agent();
        let payload = json!({"foo": "bar"});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");

        assert_eq!(envelope["version"], "2.0.0");
        assert_eq!(envelope["document_type"], "job_response");
    }

    #[test]
    fn sign_response_metadata_has_required_fields() {
        let mut agent = make_test_agent();
        let payload = json!({"x": 1});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");
        let metadata = &envelope["metadata"];

        for key in &["issuer", "document_id", "created_at", "hash"] {
            assert!(
                metadata.get(key).is_some(),
                "metadata missing required field: {key}"
            );
        }

        // hash should be a non-empty hex string (64 hex chars for SHA-256)
        let hash = metadata["hash"].as_str().expect("hash should be string");
        assert_eq!(hash.len(), 64, "SHA-256 hex hash should be 64 chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash should be valid hex"
        );
    }

    #[test]
    fn sign_response_jacs_signature_has_required_fields() {
        let mut agent = make_test_agent();
        let payload = json!({"y": 2});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");
        let sig = &envelope["jacsSignature"];

        for key in &[
            "agentID",
            "date",
            "signature",
            "signingAlgorithm",
            "publicKeyHash",
            "signatureContentVersion",
        ] {
            assert!(
                sig.get(key).is_some(),
                "jacsSignature missing required field: {key}"
            );
        }

        let signature = sig["signature"]
            .as_str()
            .expect("signature should be string");
        assert!(!signature.is_empty(), "signature must not be empty");
        assert_eq!(sig["signatureContentVersion"], "jacs-response-v2");
    }

    #[test]
    fn response_verification_with_trusted_key_is_stateless() {
        let mut signer = make_test_agent();
        let payload = json!({"decision": "allow", "score": 0.99});
        let envelope = sign_response(&mut signer, &payload).expect("signed response");
        let key = signer.get_public_key().expect("public key");

        let verified = verify_response_envelope_with_trusted_key(&envelope, &key)
            .expect("explicit-key response verification must not require another agent");
        assert_eq!(verified, payload);

        let mut tampered = envelope;
        tampered["metadata"]["issuer"] = json!("attacker");
        assert!(verify_response_envelope_with_trusted_key(&tampered, &key).is_err());
    }

    // ---- encode/decode verify payload tests ----

    #[test]
    fn encode_verify_payload_uses_url_safe_base64_no_padding() {
        let encoded = encode_verify_payload(r#"{"k":">>>>"}"#);
        assert!(!encoded.contains('+'), "URL-safe base64 must not contain +");
        assert!(!encoded.contains('/'), "URL-safe base64 must not contain /");
        assert!(
            !encoded.contains('='),
            "URL-safe base64 must not contain = (no padding)"
        );
    }

    #[test]
    fn encode_decode_round_trips() {
        let original = r#"{"hello":"world","num":123}"#;
        let encoded = encode_verify_payload(original);
        let decoded = decode_verify_payload(&encoded).expect("should decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_verify_payload_rejects_oversized_encoded_input_before_decoding() {
        let oversized = "A".repeat(MAX_VERIFY_PAYLOAD_ENCODED_BYTES + 1);
        let error = decode_verify_payload(&oversized)
            .expect_err("oversized base64 input must fail before allocation");
        assert!(error.to_string().contains("encoded input exceeds"));
    }

    #[test]
    fn decode_verify_payload_rejects_decoded_data_over_the_document_limit() {
        let decodes_over_limit = "A".repeat(MAX_VERIFY_PAYLOAD_ENCODED_BYTES);
        let error = decode_verify_payload(&decodes_over_limit)
            .expect_err("decoded payload over the document limit must fail");
        assert!(error.to_string().contains("decoded payload exceeds"));
    }

    // ---- extract_document_id tests ----

    #[test]
    fn extract_id_prefers_jacs_document_id() {
        let doc = r#"{"jacsDocumentId":"preferred","document_id":"fallback","id":"last"}"#;
        let id = extract_document_id(doc).expect("should succeed");
        assert_eq!(id, "preferred");
    }

    #[test]
    fn extract_id_falls_back_to_document_id() {
        let doc = r#"{"document_id":"def-456"}"#;
        let id = extract_document_id(doc).expect("should succeed");
        assert_eq!(id, "def-456");
    }

    #[test]
    fn extract_id_falls_back_to_id() {
        let doc = r#"{"id":"ghi-789"}"#;
        let id = extract_document_id(doc).expect("should succeed");
        assert_eq!(id, "ghi-789");
    }

    #[test]
    fn extract_id_errors_when_no_id_field() {
        let doc = r#"{"name":"no-id-here"}"#;
        let result = extract_document_id(doc);
        assert!(result.is_err(), "Should error when no ID field is present");
    }

    #[test]
    fn raw_protocol_json_rejects_oversize_before_parsing() {
        let oversized = " ".repeat(crate::schema::utils::max_document_size() + 1);

        for error in [
            extract_document_id(&oversized)
                .expect_err("ID inspection must size-check before parsing"),
            verify_response_json_with_trusted_key(&oversized, b"unused")
                .expect_err("response verification must size-check before parsing"),
        ] {
            assert!(
                matches!(error, JacsError::DocumentTooLarge { .. }),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn extract_id_errors_on_invalid_json() {
        let result = extract_document_id("not json");
        assert!(result.is_err(), "Should error on invalid JSON input");
    }

    // ---- unwrap_signed_event tests ----

    #[test]
    fn unwrap_canonical_with_unknown_agent_fails_closed() {
        let agent = make_test_agent();
        let data = json!({"result": "hello"});
        let event = json!({
            "version": "1.0.0",
            "document_type": "job_response",
            "data": data,
            "metadata": {
                "issuer": "unknown-agent:v1",
                "document_id": "doc-1",
                "created_at": "2026-01-01T00:00:00Z",
                "hash": "abc123",
            },
            "jacsSignature": {
                "agentID": "unknown-agent:v1",
                "date": "2026-01-01T00:00:00Z",
                "signature": "fakesig",
            },
        });

        let keys: HashMap<String, Vec<u8>> = HashMap::new();
        let error = unwrap_signed_event(&agent, &event, &keys)
            .expect_err("unknown signer must not release event data");
        assert!(matches!(error, JacsError::SignerUnknown { .. }));
    }

    #[test]
    fn unwrap_legacy_payload_fails_closed() {
        let agent = make_test_agent();
        let payload = json!({"status": "ok", "items": [1, 2, 3]});
        let event = json!({
            "payload": payload,
            "signature": {
                "key_id": "some-key",
                "signature": "irrelevant",
            },
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
            },
        });

        let keys: HashMap<String, Vec<u8>> = HashMap::new();
        let error = unwrap_signed_event(&agent, &event, &keys)
            .expect_err("legacy payload must not be released as verified data");
        assert!(error.to_string().contains("not a fully signed v2 response"));
    }

    #[test]
    fn unwrap_plain_event_fails_closed() {
        let agent = make_test_agent();
        let event = json!({"type": "heartbeat", "ts": 12345});

        let keys: HashMap<String, Vec<u8>> = HashMap::new();
        let error = unwrap_signed_event(&agent, &event, &keys)
            .expect_err("plain event must not be released by a verification API");
        assert!(error.to_string().contains("not a fully signed v2 response"));
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn unwrap_canonical_with_known_key_verifies_signature() {
        // Create a test agent, sign a payload, then verify it via unwrap_signed_event
        let mut agent = make_test_agent();
        let payload = json!({"answer": 42});

        // Use sign_response to create a properly signed envelope
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");

        // Extract the agentID from the signed envelope
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID should be a string")
            .to_string();

        // Get the agent's public key (raw bytes)
        let public_key = agent
            .get_public_key()
            .expect("should be able to get public key");

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert(agent_id, public_key);

        let (result_data, verified) =
            unwrap_signed_event(&agent, &envelope, &keys).expect("should not error");

        // The data should be the canonicalized payload
        assert_eq!(result_data["answer"], 42);
        assert!(
            verified,
            "Known key with valid signature should return verified=true"
        );
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn unwrap_accepts_the_trusted_key_in_canonical_pem_form() {
        let mut agent = make_test_agent();
        let envelope = sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let raw_key = agent.get_public_key().expect("public key");
        let pem_key = crate::crypt::normalize_public_key_pem(&raw_key).into_bytes();
        let keys = HashMap::from([(agent_id, pem_key)]);

        let verified = verify_signed_event_strict(&agent, &envelope, &keys)
            .expect("PEM encoding of the trusted key should verify");
        assert_eq!(verified.data["answer"], 42);
    }

    #[test]
    fn live_signed_event_verification_consumes_signer_and_document_id_once() {
        let mut agent = make_test_agent();
        let envelope = sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = HashMap::from([(agent_id, agent.get_public_key().expect("public key"))]);
        let store =
            crate::replay::InMemoryReplayStore::new(std::time::Duration::from_secs(60), 100);

        verify_signed_event_with_replay_store(&envelope, &keys, &store, 300)
            .expect("first event delivery should verify");
        let duplicate = verify_signed_event_with_replay_store(&envelope, &keys, &store, 300)
            .expect_err("duplicate signed event must fail closed");
        assert!(duplicate.to_string().contains("Replay attack"));
    }

    #[test]
    fn contextual_response_preserves_frozen_family_and_requires_expected_recipient() {
        use jacs_core::response_context::{
            RequestBinding, ResponseData, ResponseExpectation, ResponseOperation,
        };
        let mut agent = make_test_agent();
        let key = agent.get_public_key().unwrap();
        let data = ResponseData::DirectResponse {
            request_id: "request-1".into(),
            request_binding: RequestBinding::RequestNonce("nonce-1".into()),
            audience: "recipient-1".into(),
            response_type: "job-result".into(),
            payload: json!({"answer":42}),
        };
        assert!(
            sign_response_with_context(&mut agent, &data, ResponseOperation::SignAsyncEvent)
                .is_err()
        );
        let envelope =
            sign_response_with_context(&mut agent, &data, ResponseOperation::SignBoundResponse)
                .unwrap();
        let expected = ResponseExpectation::ExactContext {
            value: data.operation_context().unwrap(),
        };
        let verified =
            verify_response_for_context_with_trusted_key(&envelope, &key, &expected).unwrap();
        assert_eq!(verified.payload()["answer"], 42);
        assert_eq!(envelope["version"], RESPONSE_ENVELOPE_VERSION);
        let mut wrong = data.operation_context().unwrap();
        wrong["audience"] = json!("recipient-2");
        assert!(
            verify_response_for_context_with_trusted_key(
                &envelope,
                &key,
                &ResponseExpectation::ExactContext { value: wrong }
            )
            .is_err()
        );
        let legacy = sign_response(&mut agent, &json!({"answer":42})).unwrap();
        assert!(verify_response_for_context_with_trusted_key(&legacy, &key, &expected).is_err());
        assert!(
            jacs_core::response_context::inspect_response_context(&legacy)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn contextual_event_metadata_is_signer_owned_and_exact() {
        use jacs_core::response_context::{
            EventCausation, EventTransport, ResponseData, ResponseOperation,
        };
        let mut agent = make_test_agent();
        let data = ResponseData::PrivateEvent {
            event_type: "heartbeat".into(),
            contract: "test.events".into(),
            contract_version: "2".into(),
            transport: EventTransport::Stream("stream-1".into()),
            issuer: "caller supplied".into(),
            tenant: "tenant-1".into(),
            audience: "recipient-1".into(),
            event_id: String::new(),
            emitted_at: String::new(),
            causation: EventCausation::None { id: () },
            payload: json!({"type":"heartbeat"}),
        };
        let envelope =
            sign_response_with_context(&mut agent, &data, ResponseOperation::SignAsyncEvent)
                .unwrap();
        let context = jacs_core::response_context::inspect_response_context(&envelope)
            .unwrap()
            .unwrap();
        assert_eq!(
            envelope["data"]["issuer"],
            envelope["jacsSignature"]["agentID"]
        );
        assert_eq!(
            envelope["data"]["eventId"],
            envelope["metadata"]["document_id"]
        );
        assert!(context.validate_envelope_metadata(&envelope).is_ok());
        let mut wrong = envelope;
        wrong["data"]["emittedAt"] = json!("2000-01-01T00:00:00Z");
        assert!(jacs_core::response_context::inspect_response_context(&wrong).is_err());
    }

    #[test]
    fn signed_event_replay_preparation_verifies_without_releasing_payload_or_consuming_store() {
        let mut agent = make_test_agent();
        let envelope = sign_response(&mut agent, &json!({"secret": "release only after replay"}))
            .expect("sign response");
        let event_json = serde_json::to_string_pretty(&envelope).expect("serialize signed event");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let document_id = envelope["metadata"]["document_id"]
            .as_str()
            .expect("document ID")
            .to_string();
        let keys = HashMap::from([(
            agent_id.clone(),
            agent.get_public_key().expect("public key"),
        )]);

        let prepared = prepare_signed_event_replay_json(&event_json, &keys, 300)
            .expect("valid signed event should prepare for an external replay store");
        let serialized = serde_json::to_value(&prepared).expect("serialize preparation claim");

        assert_eq!(serialized["contractVersion"], 1);
        assert_eq!(serialized["status"], "crypto_verified_replay_pending");
        assert_eq!(serialized["cryptographicallyVerified"], true);
        assert_eq!(serialized["freshnessVerified"], true);
        assert_eq!(serialized["replayConsumed"], false);
        assert_eq!(serialized["signerId"], agent_id);
        assert_eq!(serialized["documentId"], document_id);
        assert_eq!(
            serialized["eventSha256"],
            hex::encode(Sha256::digest(event_json.as_bytes()))
        );
        assert!(serialized["replayKey"].as_str().is_some_and(|key| {
            key.starts_with("jacs-replay-v1:") && key.ends_with(&document_id)
        }));
        assert!(
            serialized["replayTtlSeconds"]
                .as_u64()
                .is_some_and(|ttl| ttl > 0)
        );
        assert!(serialized["expiresAtUnixSeconds"].as_u64().is_some());
        for forbidden in ["data", "valid", "verified"] {
            assert!(
                serialized.get(forbidden).is_none(),
                "preparation must not release or ambiguously label payload data: {forbidden}"
            );
        }
    }

    #[test]
    fn signed_event_replay_preparation_uses_the_same_key_as_native_consumption() {
        let mut agent = make_test_agent();
        let envelope = sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let event_json = serde_json::to_string(&envelope).expect("serialize signed event");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = HashMap::from([(agent_id, agent.get_public_key().expect("public key"))]);
        let store = RecordingReplayStore::default();

        let prepared = prepare_signed_event_replay_json(&event_json, &keys, 300)
            .expect("prepare signed event replay claim");
        assert!(
            store.keys.lock().expect("key recording lock").is_empty(),
            "preparation must never consume an implicit replay store"
        );

        verify_signed_event_with_replay_store(&envelope, &keys, &store, 300)
            .expect("native replay verification");
        let recorded = store.keys.lock().expect("key recording lock");
        assert_eq!(recorded.as_slice(), [prepared.replay_key.as_str()]);
    }

    #[test]
    fn signed_event_replay_preparation_binds_the_exact_input_bytes() {
        let mut agent = make_test_agent();
        let envelope = sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let compact = serde_json::to_string(&envelope).expect("compact event");
        let pretty = serde_json::to_string_pretty(&envelope).expect("pretty event");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = HashMap::from([(agent_id, agent.get_public_key().expect("public key"))]);

        let compact_claim = prepare_signed_event_replay_json(&compact, &keys, 300)
            .expect("compact event preparation");
        let pretty_claim = prepare_signed_event_replay_json(&pretty, &keys, 300)
            .expect("pretty event preparation");

        assert_eq!(compact_claim.replay_key, pretty_claim.replay_key);
        assert_eq!(compact_claim.document_id, pretty_claim.document_id);
        assert_ne!(compact_claim.event_sha256, pretty_claim.event_sha256);
    }

    #[test]
    fn response_signing_rejects_integers_outside_the_i_json_safe_range() {
        let mut agent = make_test_agent();
        let error = sign_response(&mut agent, &json!({"attempt": 9_007_199_254_740_993_u64}))
            .expect_err("unsafe integers must not enter a cross-language signature");
        assert!(
            error.to_string().contains("safe integer"),
            "unexpected unsafe-number error: {error}"
        );
    }

    #[test]
    fn response_verification_rejects_an_unsafe_integer_canonicalization_collision() {
        let mut agent = make_test_agent();
        let mut envelope =
            sign_response(&mut agent, &json!({"attempt": 42})).expect("safe response");
        envelope["data"]["attempt"] = json!(9_007_199_254_740_992_u64);
        envelope["metadata"]["hash"] = json!(hex::encode(Sha256::digest(
            canonicalize_json(&envelope["data"]).as_bytes()
        )));

        // Construct one historical unsafe envelope through the low-level
        // infallible canonicalizer so the verifier regression remains capable
        // of testing old artifacts after signing starts rejecting them.
        let mut unsigned = envelope.clone();
        unsigned["jacsSignature"]
            .as_object_mut()
            .expect("signature object")
            .remove("signature");
        let signing_input = format!(
            "{}{}",
            RESPONSE_SIGNATURE_DOMAIN,
            canonicalize_json(&unsigned)
        );
        envelope["jacsSignature"]["signature"] = json!(
            agent
                .sign_string(&signing_input)
                .expect("legacy unsafe signature")
        );

        // 2^53 and 2^53+1 collapse to the same ECMAScript/JCS number. A
        // verifier must reject the non-I-JSON value before accepting that
        // signature for a different Rust integer.
        envelope["data"]["attempt"] = json!(9_007_199_254_740_993_u64);
        let public_key = agent.get_public_key().expect("public key");
        let error = verify_response_envelope_with_trusted_key(&envelope, &public_key)
            .expect_err("unsafe numeric collision must fail closed");
        assert!(
            error.to_string().contains("safe integer"),
            "unexpected unsafe-number verification error: {error}"
        );
    }

    #[test]
    fn concurrent_signed_event_delivery_releases_payload_exactly_once() {
        const WORKERS: usize = 64;
        let mut agent = make_test_agent();
        let envelope = std::sync::Arc::new(
            sign_response(&mut agent, &json!({"command": "run-once"})).expect("sign response"),
        );
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = std::sync::Arc::new(HashMap::from([(
            agent_id,
            agent.get_public_key().expect("public key"),
        )]));
        let store = std::sync::Arc::new(crate::replay::InMemoryReplayStore::new(
            Duration::from_secs(300),
            100,
        ));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(WORKERS));
        let mut workers = Vec::with_capacity(WORKERS);

        for _ in 0..WORKERS {
            let envelope = std::sync::Arc::clone(&envelope);
            let keys = std::sync::Arc::clone(&keys);
            let store = std::sync::Arc::clone(&store);
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                verify_signed_event_with_replay_store(
                    envelope.as_ref(),
                    keys.as_ref(),
                    store.as_ref(),
                    300,
                )
                .is_ok()
            }));
        }

        let accepted = workers
            .into_iter()
            .map(|worker| usize::from(worker.join().expect("verification worker")))
            .sum::<usize>();
        assert_eq!(
            accepted, 1,
            "only the atomic replay winner may release data"
        );
    }

    #[test]
    fn signed_event_replay_preparation_rejects_duplicate_json_before_any_claim_is_returned() {
        let duplicate = r#"{"data":{},"data":{"attacker":true}}"#;
        let error = prepare_signed_event_replay_json(duplicate, &HashMap::new(), 300)
            .expect_err("duplicate fields must fail strict parsing");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn raw_signed_event_verification_rejects_duplicate_json_before_releasing_payload() {
        let duplicate = r#"{"data":{"command":"safe"},"data":{"command":"attacker"}}"#;
        let error = verify_signed_event_json_with_trusted_keys(duplicate, &HashMap::new())
            .expect_err("duplicate fields must fail strict parsing");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn raw_signed_event_verification_returns_provenance_after_strict_parse() {
        let mut agent = make_test_agent();
        let envelope =
            sign_response(&mut agent, &json!({"command": "run-once"})).expect("sign response");
        let event_json = serde_json::to_string(&envelope).expect("serialize signed event");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let document_id = envelope["metadata"]["document_id"]
            .as_str()
            .expect("document ID")
            .to_string();
        let keys = HashMap::from([(
            agent_id.clone(),
            agent.get_public_key().expect("public key"),
        )]);

        let verified = verify_signed_event_json_with_trusted_keys(&event_json, &keys)
            .expect("strict raw event should verify");

        assert_eq!(verified.data["command"], "run-once");
        assert_eq!(verified.signer_id, agent_id);
        assert_eq!(verified.document_id, document_id);
        assert!(!verified.timestamp.is_empty());
        assert!(!verified.algorithm.is_empty());
    }

    #[test]
    fn signed_event_replay_retention_covers_accepted_future_clock_skew() {
        let mut agent = make_test_agent();
        let mut envelope =
            sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let future = (chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339();
        envelope["metadata"]["created_at"] = json!(future.clone());
        envelope["jacsSignature"]["date"] = json!(future);
        let signing_input = response_signing_input(&envelope).expect("response signing input");
        envelope["jacsSignature"]["signature"] = json!(
            agent
                .sign_string(&signing_input)
                .expect("re-sign future envelope")
        );
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = HashMap::from([(agent_id, agent.get_public_key().expect("public key"))]);
        let store = RecordingReplayStore::default();
        let max_age = 60;

        verify_signed_event_with_replay_store(&envelope, &keys, &store, max_age)
            .expect("event within accepted future skew should verify");
        let ttls = store.ttls.lock().expect("TTL recording lock");
        assert_eq!(ttls.len(), 1);
        assert!(
            ttls[0] > Duration::from_secs(max_age),
            "future-dated event replay TTL must outlive max_age: {:?}",
            ttls[0]
        );
        assert!(ttls[0] <= Duration::from_secs(max_age + 121));
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn default_live_signed_event_verification_is_replay_safe() {
        let mut agent = make_test_agent();
        let envelope = sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = HashMap::from([(agent_id, agent.get_public_key().expect("public key"))]);

        verify_signed_event_with_trusted_keys(&envelope, &keys)
            .expect("first event delivery should verify");
        let duplicate = verify_signed_event_with_trusted_keys(&envelope, &keys)
            .expect_err("secure default must reject duplicate delivery");
        assert!(duplicate.to_string().contains("Replay attack"));
    }

    #[test]
    fn live_signed_event_verification_rejects_stale_envelopes() {
        let mut agent = make_test_agent();
        let mut envelope =
            sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let stale = (chrono::Utc::now() - chrono::Duration::seconds(600)).to_rfc3339();
        envelope["metadata"]["created_at"] = json!(stale);
        envelope["jacsSignature"]["date"] = json!(stale);
        let signing_input = response_signing_input(&envelope).expect("response signing input");
        envelope["jacsSignature"]["signature"] = json!(
            agent
                .sign_string(&signing_input)
                .expect("re-sign stale envelope")
        );
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = HashMap::from([(agent_id, agent.get_public_key().expect("public key"))]);
        let store =
            crate::replay::InMemoryReplayStore::new(std::time::Duration::from_secs(60), 100);

        let error = verify_signed_event_with_replay_store(&envelope, &keys, &store, 300)
            .expect_err("stale signed event must fail closed");
        assert!(error.to_string().contains("too old"));
    }

    struct FailingReplayStore;

    impl crate::replay::ReplayStore for FailingReplayStore {
        fn consume(&self, _key: &str, _ttl: std::time::Duration) -> Result<bool, JacsError> {
            Err(JacsError::Internal {
                message: "shared signed-event replay store unavailable".to_string(),
            })
        }

        fn name(&self) -> &'static str {
            "signed-event-failing-test"
        }

        fn scope(&self) -> crate::replay::ReplayStoreScope {
            crate::replay::ReplayStoreScope::Shared
        }
    }

    #[test]
    fn live_signed_event_verification_fails_closed_when_replay_store_fails() {
        let mut agent = make_test_agent();
        let envelope = sign_response(&mut agent, &json!({"answer": 42})).expect("sign response");
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let keys = HashMap::from([(agent_id, agent.get_public_key().expect("public key"))]);

        let error =
            verify_signed_event_with_replay_store(&envelope, &keys, &FailingReplayStore, 300)
                .expect_err("store outage must reject an otherwise valid event");
        assert!(error.to_string().contains("unavailable"));
    }

    #[test]
    fn unwrap_rejects_independent_response_envelope_mutations() {
        let mut agent = make_test_agent();
        let envelope =
            sign_response(&mut agent, &json!({"decision": "allow"})).expect("sign_response failed");
        let real_agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID")
            .to_string();
        let public_key = agent.get_public_key().expect("public key");
        let mut keys = HashMap::new();
        keys.insert(real_agent_id, public_key.clone());
        keys.insert("attacker-alias".to_string(), public_key);

        let mut attacks = Vec::new();
        let mut mutate = |pointer: &str, value: Value| {
            let mut attacked = envelope.clone();
            *attacked.pointer_mut(pointer).expect("test pointer exists") = value;
            attacks.push(attacked);
        };
        mutate("/version", json!("9.9.9"));
        mutate("/document_type", json!("admin_command"));
        mutate("/metadata/issuer", json!("attacker-alias"));
        mutate("/metadata/document_id", json!(Uuid::new_v4().to_string()));
        mutate("/metadata/created_at", json!("2099-01-01T00:00:00Z"));
        mutate("/metadata/hash", json!("00".repeat(32)));
        mutate("/jacsSignature/agentID", json!("attacker-alias"));
        mutate("/jacsSignature/date", json!("2099-01-01T00:00:00Z"));
        mutate("/jacsSignature/signingAlgorithm", json!("ring-Ed25519"));
        let mut injected_key_hash = envelope.clone();
        injected_key_hash["jacsSignature"]["publicKeyHash"] = json!("attacker-key-hash");
        attacks.push(injected_key_hash);
        let mut injected_content_version = envelope.clone();
        injected_content_version["jacsSignature"]["signatureContentVersion"] =
            json!("payload-only");
        attacks.push(injected_content_version);
        let mut injected = envelope.clone();
        injected["routing_authority"] = json!("attacker");
        attacks.push(injected);

        for attack in attacks {
            assert!(
                unwrap_signed_event(&agent, &attack, &keys).is_err(),
                "mutated response envelope must fail closed: {}",
                canonicalize_json(&attack)
            );
        }
    }

    #[test]
    fn unwrap_canonical_with_known_key_and_bad_signature_errors() {
        let agent = make_test_agent();
        let data = json!({"result": "tampered"});
        let agent_id = "known-agent:v1".to_string();

        // Use the agent's real public key but a bogus signature
        let public_key = agent
            .get_public_key()
            .expect("should be able to get public key");

        let event = json!({
            "version": "1.0.0",
            "document_type": "job_response",
            "data": data,
            "metadata": {
                "issuer": agent_id,
                "document_id": "doc-bad",
                "created_at": "2026-01-01T00:00:00Z",
                "hash": "000",
            },
            "jacsSignature": {
                "agentID": agent_id,
                "date": "2026-01-01T00:00:00Z",
                "signature": "dGhpcyBpcyBub3QgYSB2YWxpZCBzaWduYXR1cmU=",
            },
        });

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert(agent_id, public_key);

        let result = unwrap_signed_event(&agent, &event, &keys);
        assert!(
            result.is_err(),
            "Known key with bad signature must return an error, not silent false"
        );
    }
}
