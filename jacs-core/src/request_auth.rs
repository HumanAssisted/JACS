//! Portable request-auth-v2 primitives, promoted from `jacs::protocol`.
//!
//! The native wire contract is unchanged: canonical camelCase claims, exact
//! entity-byte digest, normalized absolute HTTP URL, deployment-pinned audience,
//! UUID nonce, and `JACS-REQUEST-AUTH-V2\n` domain separation. No legacy fallback.
//! Verification is stateless: callers MUST atomically consume the verified nonce
//! in a shared replay store before granting access. Clocks are explicit in `_at`
//! construction and verification so browser and device adapters need no I/O.

use crate::canonical::canonicalize_json_try;
use crate::verify::{legacy_public_key_hash, verify_detached};
use crate::{CoreAgent, CoreError, SigningAlgorithm};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

pub const REQUEST_AUTH_VERSION: &str = "jacs-request-v2";
pub const REQUEST_AUTH_DOMAIN: &str = "JACS-REQUEST-AUTH-V2\n";
pub const MAX_REQUEST_AUTH_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_FUTURE_TIMESTAMP_SECONDS: u64 = 300;

/// Claims are authenticated only after verification against trusted request
/// context/key and a successful atomic replay-store consume.
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

fn malformed(message: impl Into<String>) -> CoreError {
    CoreError::MalformedDocument(message.into())
}
fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::SignatureInvalid(message.into())
}

impl CoreAgent {
    /// Sign a single final HTTP request. Transports must send the exact body
    /// bytes once without redirects; each retry needs a fresh header. Audience
    /// is deployment configuration, never remote discovery or an inferred host.
    pub fn build_request_auth_header(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
        audience: &str,
    ) -> Result<String, CoreError> {
        let now = u64::try_from(chrono::Utc::now().timestamp())
            .map_err(|_| malformed("system clock precedes Unix epoch"))?;
        build_request_auth_header_at(self, method, url, body, audience, now)
    }
}

/// Same request-auth-v2 constructor with an explicit Unix-seconds clock.
pub fn build_request_auth_header_at(
    agent: &CoreAgent,
    method: &str,
    url: &str,
    body: &[u8],
    audience: &str,
    now: u64,
) -> Result<String, CoreError> {
    let identity = agent.export_agent();
    let id = identity
        .get("jacsId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| malformed("missing agent jacsId"))?;
    let version = identity
        .get("jacsVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| malformed("missing agent jacsVersion"))?;
    if id.is_empty() || version.is_empty() || id.contains(':') || version.contains(':') {
        return Err(malformed("agent ID/version cannot be empty or contain ':'"));
    }
    let algorithm = match agent.algorithm() {
        // The native request-auth protocol emits this established wire spelling.
        SigningAlgorithm::Ed25519 => "ring-Ed25519",
        algorithm => algorithm.as_str(),
    };
    build_request_auth_header_with_signer_at(
        &format!("{id}:{version}"),
        algorithm,
        &legacy_public_key_hash(agent.public_key()),
        method,
        url,
        body,
        audience,
        now,
        &uuid::Uuid::new_v4().simple().to_string(),
        |input| {
            let signature = agent.sign_raw_bytes(input.as_bytes())?;
            // A platform callback may return bytes for a replaced key, corrupt
            // bytes, or an incorrect wire encoding. Fail before request send or
            // committing a metadata update authenticated with this header.
            verify_detached(
                agent.algorithm(),
                agent.public_key(),
                input.as_bytes(),
                &signature,
            )?;
            Ok(STANDARD.encode(signature))
        },
    )
}

/// Callback variant matching native `jacs::protocol` construction. The callback
/// returns standard-base64 signature bytes; key handling stays in the provider.
/// The caller supplies fresh UUIDv4 hex nonce and Unix-seconds timestamp.
#[allow(clippy::too_many_arguments)]
pub fn build_request_auth_header_with_signer_at(
    key_id: &str,
    signing_algorithm: &str,
    public_key_hash: &str,
    method: &str,
    url: &str,
    body: &[u8],
    audience: &str,
    issued_at: u64,
    nonce: &str,
    sign: impl FnOnce(&str) -> Result<String, CoreError>,
) -> Result<String, CoreError> {
    let (scheme, authority, target) = canonical_request_url_components(url)?;
    if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(malformed("request auth nonce must be a UUIDv4 hex value"));
    }
    let claims = RequestAuthClaims {
        version: REQUEST_AUTH_VERSION.into(),
        key_id: nonempty_request_auth_value(key_id, "key_id")?.into(),
        issued_at,
        nonce: nonce.into(),
        method: normalize_http_method(method)?,
        scheme,
        authority,
        target,
        content_digest: request_content_digest(body),
        audience: nonempty_request_auth_value(audience, "audience")?.into(),
        signing_algorithm: nonempty_request_auth_value(signing_algorithm, "signing_algorithm")?
            .into(),
        public_key_hash: nonempty_request_auth_value(public_key_hash, "public_key_hash")?.into(),
    };
    let canonical = request_auth_claims_canonical(&claims)?;
    let signature = sign(&format!("{REQUEST_AUTH_DOMAIN}{canonical}"))?;
    let bytes = STANDARD
        .decode(signature)
        .map_err(|_| invalid("request auth signer returned invalid base64"))?;
    if bytes.is_empty() {
        return Err(invalid("request auth signer returned empty signature"));
    }
    let header = format!(
        "JACS v2.{}.{}",
        URL_SAFE_NO_PAD.encode(canonical),
        URL_SAFE_NO_PAD.encode(bytes)
    );
    if header.len() > MAX_REQUEST_AUTH_HEADER_BYTES {
        return Err(malformed("request auth header exceeds 64 KiB"));
    }
    Ok(header)
}

struct ParsedRequestAuthHeader {
    claims: RequestAuthClaims,
    canonical: String,
    signature: Vec<u8>,
}

fn parse_request_auth_header(header: &str) -> Result<ParsedRequestAuthHeader, CoreError> {
    if header.len() > MAX_REQUEST_AUTH_HEADER_BYTES {
        return Err(malformed("request auth header exceeds 64 KiB"));
    }
    let token = header.strip_prefix("JACS v2.").ok_or_else(|| {
        invalid("unsupported Authorization header; expected request-bound JACS v2")
    })?;
    let (claims_segment, signature_segment) = token
        .split_once('.')
        .ok_or_else(|| malformed("JACS v2 header must contain claims and signature segments"))?;
    if claims_segment.is_empty() || signature_segment.is_empty() || signature_segment.contains('.')
    {
        return Err(malformed(
            "JACS v2 header contains an invalid segment count",
        ));
    }
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_segment)
        .map_err(|_| malformed("invalid base64url claims"))?;
    let claims: RequestAuthClaims =
        crate::strict_json::deserialize_strict_json_slice(&claims_bytes)?;
    let canonical = request_auth_claims_canonical(&claims)?;
    if canonical.as_bytes() != claims_bytes {
        return Err(malformed(
            "request auth claims must use canonical JSON encoding",
        ));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|_| malformed("invalid base64url signature"))?;
    Ok(ParsedRequestAuthHeader {
        claims,
        canonical,
        signature,
    })
}

/// Structural inspection for key lookup only; returned claims are untrusted.
pub fn inspect_unverified_request_auth_header(
    header: &str,
) -> Result<RequestAuthClaims, CoreError> {
    Ok(parse_request_auth_header(header)?.claims)
}

/// Verify against canonical raw public-key bytes and the actual HTTP request.
/// The expected key ID is the registry's exact `jacsId:jacsVersion` lookup ID.
/// Returned claims still require atomic nonce consumption in a shared store.
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
    now: u64,
) -> Result<RequestAuthClaims, CoreError> {
    if max_age_seconds == 0 {
        return Err(malformed(
            "request auth max_age_seconds must be greater than zero",
        ));
    }
    let parsed = parse_request_auth_header(header)?;
    let claims = &parsed.claims;
    if claims.version != REQUEST_AUTH_VERSION {
        return Err(invalid("unsupported request auth version"));
    }
    if claims.key_id != nonempty_request_auth_value(expected_key_id, "expected_key_id")? {
        return Err(invalid(
            "request auth key ID does not match the trusted signer",
        ));
    }
    if claims.method != normalize_http_method(expected_method)? {
        return Err(invalid(
            "request auth method does not match the actual request",
        ));
    }
    let (scheme, authority, target) = canonical_request_url_components(expected_url)?;
    if claims.scheme != scheme || claims.authority != authority || claims.target != target {
        return Err(invalid(
            "request auth target URI does not match the actual request",
        ));
    }
    if claims.content_digest != request_content_digest(expected_body) {
        return Err(invalid(
            "request auth content digest does not match the actual body",
        ));
    }
    if claims.audience != nonempty_request_auth_value(expected_audience, "expected_audience")? {
        return Err(invalid("request auth audience does not match this service"));
    }
    if claims.nonce.len() != 32 || !claims.nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(malformed("request auth nonce must be a UUIDv4 hex value"));
    }
    if claims.issued_at > now.saturating_add(MAX_FUTURE_TIMESTAMP_SECONDS) {
        return Err(invalid("request auth timestamp is too far in the future"));
    }
    if now.saturating_sub(claims.issued_at) > max_age_seconds {
        return Err(invalid("request auth credential has expired"));
    }
    if claims.public_key_hash != legacy_public_key_hash(public_key) {
        return Err(invalid(
            "request auth publicKeyHash does not match the trusted key",
        ));
    }
    let algorithm = SigningAlgorithm::from_wire_str(&claims.signing_algorithm)
        .ok_or_else(|| CoreError::UnsupportedAlgorithm(claims.signing_algorithm.clone()))?;
    crate::identity::canonical_key_id(algorithm.as_str(), public_key)?;
    verify_detached(
        algorithm,
        public_key,
        format!("{REQUEST_AUTH_DOMAIN}{}", parsed.canonical).as_bytes(),
        &parsed.signature,
    )?;
    Ok(parsed.claims)
}

/// Required nonce-retention seconds through inclusive absolute expiry. Use only
/// for already-verified claims. Future clock skew must extend replay retention.
pub fn request_auth_replay_ttl(
    verified_claims: &RequestAuthClaims,
    max_age_seconds: u64,
    now: u64,
) -> Result<u64, CoreError> {
    if max_age_seconds == 0 {
        return Err(malformed(
            "request auth max_age_seconds must be greater than zero",
        ));
    }
    verified_claims
        .issued_at
        .checked_add(max_age_seconds)
        .and_then(|expiry| expiry.checked_sub(now))
        .and_then(|remaining| remaining.checked_add(1))
        .ok_or_else(|| invalid("request auth credential expired or expiry exceeds timestamp range"))
}

fn request_auth_claims_canonical(claims: &RequestAuthClaims) -> Result<String, CoreError> {
    canonicalize_json_try(
        &serde_json::to_value(claims).map_err(|error| malformed(error.to_string()))?,
    )
}

/// URL normalization is identical to native JACS (`url::Url`): scheme/host
/// case, default ports, path and query handling are shared across targets.
pub fn canonical_request_url_components(
    request_url: &str,
) -> Result<(String, String, String), CoreError> {
    let parsed = Url::parse(request_url).map_err(|_| malformed("invalid absolute request URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(malformed("request URL scheme must be http or https"));
    }
    if parsed.fragment().is_some() {
        return Err(malformed("request URL must not contain a fragment"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(malformed("request URL must not contain userinfo"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| malformed("request URL must include an authority"))?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.into(),
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

pub fn request_content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

pub fn normalize_http_method(method: &str) -> Result<String, CoreError> {
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
        return Err(malformed("request method must be a non-empty HTTP token"));
    }
    Ok(method.to_ascii_uppercase())
}

fn nonempty_request_auth_value<'a>(value: &'a str, field: &str) -> Result<&'a str, CoreError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(malformed(format!("request auth {field} must be non-empty")));
    }
    Ok(value)
}
