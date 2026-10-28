//! Opt-in discovery of verification candidates, never enrollment or authorization.
//!
//! DNS fingerprints hash raw keys. Document references retain their existing
//! native/portable profiles, and registry transport hashes describe wire bytes.

use crate::agent::{Agent, boilerplate::BoilerPlate, loaders::FileLoader};
use crate::config::{KeyResolutionSource, get_key_resolution_order};
use crate::crypt::hash::{hash_bytes, hash_public_key};
use crate::error::JacsError;
use base64::Engine as _;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ResolvedVerificationKey {
    pub public_key: Vec<u8>,
    pub algorithm: String,
}

/// Recompute the signed reference without rewriting it. Only document v2 has
/// the existing portable raw-key alternative; legacy references stay frozen.
pub(crate) fn document_key_matches(document: &Value, key: &[u8]) -> bool {
    let signature = &document["jacsSignature"];
    let expected = signature["publicKeyHash"].as_str().unwrap_or_default();
    expected == hash_public_key(key)
        || (signature["signatureContentVersion"].as_str()
            == Some(jacs_core::verify::SIGNATURE_CONTENT_VERSION_V2)
            && expected == hash_bytes(key))
}

struct Request<'a> {
    document: &'a Value,
    id: &'a str,
    version: &'a str,
    hash: &'a str,
    algorithm: &'a str,
    domain: Option<&'a str>,
    dns_strict: Option<bool>,
    explicit_domain_only: bool,
}

impl<'a> Request<'a> {
    fn new(document: &'a Value) -> Result<Self, JacsError> {
        let signature = &document["jacsSignature"];
        let field = |name: &str| {
            signature[name]
                .as_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| JacsError::ValidationError(format!("Missing signature {name}")))
        };
        let request = Self {
            document,
            id: field("agentID")?,
            version: field("agentVersion")?,
            hash: field("publicKeyHash")?,
            algorithm: field("signingAlgorithm")?,
            dns_strict: None,
            explicit_domain_only: false,
            // Unauthenticated routing hint until the complete v2 signature is
            // checked. It never changes enrollment or trust policy.
            domain: (signature["signatureContentVersion"].as_str()
                == Some(jacs_core::verify::SIGNATURE_CONTENT_VERSION_V2))
            .then(|| signature["agentDomain"].as_str())
            .flatten(),
        };
        uuid::Uuid::parse_str(request.id).map_err(|e| JacsError::ValidationError(e.to_string()))?;
        uuid::Uuid::parse_str(request.version)
            .map_err(|e| JacsError::ValidationError(e.to_string()))?;
        if request.hash.len() != 64 || !request.hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(JacsError::ValidationError(
                "Invalid signed publicKeyHash".into(),
            ));
        }
        crate::verification::matching_algorithm(Some(request.algorithm), None)?;
        Ok(request)
    }

    fn validate(&self, key: ResolvedVerificationKey) -> Result<ResolvedVerificationKey, JacsError> {
        let algorithm =
            crate::verification::matching_algorithm(Some(self.algorithm), Some(&key.algorithm))?
                .ok_or_else(|| JacsError::ValidationError("Missing key algorithm".into()))?;
        jacs_core::identity::canonical_key_id(&algorithm, &key.public_key)?;
        if !document_key_matches(self.document, &key.public_key) {
            return Err(JacsError::SignatureVerificationFailed {
                reason: "Resolved key does not match the signed document reference".into(),
            });
        }
        Ok(ResolvedVerificationKey {
            public_key: key.public_key,
            algorithm,
        })
    }
}

/// Resolve a candidate for an exact signed identity/version/key reference.
/// Existing distrust/enrollment conflicts stop before any network access.
pub fn resolve_document_key(
    agent: &Agent,
    document: &Value,
) -> Result<ResolvedVerificationKey, JacsError> {
    let binding = crate::trust::verify_document_identity_binding(document)?;
    let request = Request::new(document)?;
    let sources = get_key_resolution_order();
    if sources.contains(&KeyResolutionSource::Local)
        && binding == crate::trust::IdentityBindingStatus::LocallyEnrolled
    {
        return enrolled_candidate(&request);
    }
    resolve_with_transport(agent, &request, &sources, &NetworkTransport)
}

/// Resolve only self/historical local material, regardless of network settings.
pub fn resolve_document_key_local(
    agent: &Agent,
    document: &Value,
) -> Result<ResolvedVerificationKey, JacsError> {
    let binding = crate::trust::verify_document_identity_binding(document)?;
    let request = Request::new(document)?;
    if binding == crate::trust::IdentityBindingStatus::LocallyEnrolled {
        return enrolled_candidate(&request);
    }
    resolve_with_transport(
        agent,
        &request,
        &[KeyResolutionSource::Local],
        &NetworkTransport,
    )
}

fn enrolled_candidate(request: &Request<'_>) -> Result<ResolvedVerificationKey, JacsError> {
    let public_key =
        crate::trust::get_trusted_public_key(&format!("{}:{}", request.id, request.version))?;
    request.validate(ResolvedVerificationKey {
        public_key,
        algorithm: request.algorithm.into(),
    })
}

/// Resolve using an explicitly selected DNS publisher without changing signed bytes.
pub fn resolve_document_key_for_domain(
    agent: &Agent,
    document: &Value,
    domain: &str,
    require_secure: bool,
) -> Result<ResolvedVerificationKey, JacsError> {
    crate::trust::verify_document_identity_binding(document)?;
    let mut request = Request::new(document)?;
    request.domain = Some(domain);
    request.dns_strict = Some(require_secure);
    request.explicit_domain_only = true;
    resolve_dns(agent, &request, &NetworkTransport)
}

trait DiscoveryTransport {
    fn registry(&self, id: &str, version: &str) -> Result<ResolvedVerificationKey, JacsError>;
    fn dns(
        &self,
        domain: &str,
        id: &str,
        strict: bool,
    ) -> Result<Vec<crate::dns::bootstrap::AgentTxtFields>, JacsError>;
    fn json(&self, uri: &str) -> Result<Value, JacsError>;
}

struct NetworkTransport;
impl DiscoveryTransport for NetworkTransport {
    fn registry(&self, id: &str, version: &str) -> Result<ResolvedVerificationKey, JacsError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let key = crate::agent::loaders::fetch_remote_public_key(id, version)?;
            Ok(ResolvedVerificationKey {
                public_key: key.public_key,
                algorithm: key.algorithm,
            })
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (id, version);
            Err(JacsError::NetworkError(
                "Native key discovery unavailable on wasm32".into(),
            ))
        }
    }
    fn dns(
        &self,
        domain: &str,
        id: &str,
        strict: bool,
    ) -> Result<Vec<crate::dns::bootstrap::AgentTxtFields>, JacsError> {
        crate::dns::bootstrap::resolve_agent_txt_records(domain, id, strict)
    }
    fn json(&self, uri: &str) -> Result<Value, JacsError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::config::ensure_network_access(crate::config::NetworkCapability::RemoteKeyFetch)?;
            let policy = crate::secure_fetch::SecureFetchPolicy::new(
                "DNS key discovery",
                64 * 1024,
                &["application/json"],
            )
            .max_redirects(2)
            .timeouts(
                std::time::Duration::from_secs(10),
                std::time::Duration::from_secs(3),
                std::time::Duration::from_secs(2),
            );
            // No loopback exception for attacker-controlled TXT URIs.
            let response = crate::secure_fetch::secure_get(uri, "application/json", &policy)?;
            if response.status == reqwest::StatusCode::GONE {
                return Err(JacsError::TrustError(
                    "Discovery key revoked or withdrawn (HTTP 410)".into(),
                ));
            }
            if !response.status.is_success() {
                return Err(JacsError::NetworkError(format!(
                    "Key discovery returned {}",
                    response.status
                )));
            }
            jacs_core::strict_json::parse_strict_json_slice(&response.body).map_err(Into::into)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = uri;
            Err(JacsError::NetworkError(
                "Native key discovery unavailable on wasm32".into(),
            ))
        }
    }
}

fn resolve_with_transport(
    agent: &Agent,
    request: &Request<'_>,
    sources: &[KeyResolutionSource],
    transport: &dyn DiscoveryTransport,
) -> Result<ResolvedVerificationKey, JacsError> {
    // Same UUID alone is insufficient after rotation: require the signed key
    // reference and algorithm, otherwise continue to exact historical lookup.
    if agent.get_id().ok().as_deref() == Some(request.id)
        && let Ok(key) = agent.get_public_key()
        && document_key_matches(request.document, &key)
    {
        return request.validate(ResolvedVerificationKey {
            public_key: key,
            algorithm: agent
                .get_key_algorithm()
                .cloned()
                .unwrap_or_else(|| request.algorithm.into()),
        });
    }
    let mut last_error = JacsError::KeyNotFound {
        path: "No configured key source resolved the exact signer".into(),
    };
    for source in sources {
        let result = match source {
            KeyResolutionSource::Local => {
                agent
                    .fs_load_public_key(request.hash)
                    .and_then(|public_key| {
                        let algorithm = agent.fs_load_public_key_type(request.hash)?;
                        request.validate(ResolvedVerificationKey {
                            public_key,
                            algorithm: algorithm.trim().into(),
                        })
                    })
            }
            KeyResolutionSource::Registry => transport
                .registry(request.id, request.version)
                .and_then(|key| request.validate(key)),
            KeyResolutionSource::Dns => match resolve_dns(agent, request, transport) {
                Ok(key) => Ok(key),
                // Missing publisher/unavailable network can try another configured
                // source. Contradictory authenticated evidence cannot downgrade.
                Err(error @ JacsError::KeyNotFound { .. })
                    if !request
                        .dns_strict
                        .unwrap_or(agent.key_discovery_dns_strict()) =>
                {
                    Err(error)
                }
                Err(error @ JacsError::NetworkError(_))
                    if !request
                        .dns_strict
                        .unwrap_or(agent.key_discovery_dns_strict()) =>
                {
                    Err(error)
                }
                Err(error) => return Err(error),
            },
        };
        match result {
            Ok(key) => return Ok(key),
            Err(error @ JacsError::TrustError(_)) => return Err(error),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn resolve_dns(
    agent: &Agent,
    request: &Request<'_>,
    transport: &dyn DiscoveryTransport,
) -> Result<ResolvedVerificationKey, JacsError> {
    let strict = request
        .dns_strict
        .unwrap_or(agent.key_discovery_dns_strict());
    let mut domains = request
        .domain
        .map(str::to_string)
        .into_iter()
        .collect::<Vec<_>>();
    if !request.explicit_domain_only
        && let Ok(configured) = std::env::var("JACS_DNS_KEY_DOMAINS")
    {
        domains.extend(
            configured
                .split(',')
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(str::to_string),
        );
    }
    let mut contradiction = None;
    let mut attempts = 0;
    for domain in domains.into_iter().take(16) {
        let base = validated_domain_origin(&domain)?;
        let records = match transport.dns(base.host_str().unwrap(), request.id, strict) {
            Ok(records) => records
                .into_iter()
                .filter(|record| record.jacs_agent_id == request.id)
                .collect::<Vec<_>>(),
            Err(error) if strict => return Err(error),
            Err(JacsError::DnsLookupFailed { .. } | JacsError::DnsRecordMissing { .. }) => continue,
            Err(error) => return Err(error),
        };
        if records.len() > 16 {
            return Err(JacsError::ValidationError(
                "Too many DNS key candidates".into(),
            ));
        }
        let mut urls = std::collections::HashSet::new();
        for record in &records {
            let uri = record.uri.clone().unwrap_or_else(|| {
                format!(
                    "{}/.well-known/jacs-pubkey.json",
                    base.origin().ascii_serialization()
                )
            });
            validate_discovery_uri(&base, &uri, request)?;
            if !urls.insert(uri.clone()) {
                continue;
            }
            attempts += 1;
            if attempts > 16 {
                return Err(JacsError::ValidationError(
                    "Too many HTTPS key candidates".into(),
                ));
            }
            let value = match transport.json(&uri) {
                Ok(value) => value,
                Err(error @ JacsError::NetworkError(_)) => {
                    let _ = error;
                    continue;
                }
                Err(error) => {
                    contradiction = Some(error);
                    continue;
                }
            };
            match decode_discovery_document(&value, request) {
                Ok(key) => {
                    // Rotation overlap may publish several digests for one URI.
                    // Match the candidate against the entire eligible RRset.
                    if records.iter().any(|pin| {
                        crate::dns::bootstrap::record_matches_public_key(pin, &key.public_key)
                    }) {
                        return Ok(key);
                    }
                    contradiction = Some(JacsError::SignatureVerificationFailed {
                        reason: "DNS raw public-key digest mismatch".into(),
                    });
                }
                Err(error) => contradiction = Some(error),
            }
        }
    }
    Err(contradiction.unwrap_or_else(|| JacsError::KeyNotFound {
        path: "No matching DNS/HTTPS key candidate".into(),
    }))
}

fn validate_discovery_uri(
    base: &url::Url,
    uri: &str,
    request: &Request<'_>,
) -> Result<(), JacsError> {
    let url = url::Url::parse(uri).map_err(|e| JacsError::ValidationError(e.to_string()))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().ends_with("/keys")
        || url.path().ends_with("/latest")
    {
        return Err(JacsError::ValidationError(
            "DNS key URI requires public HTTPS and an exact key resource".into(),
        ));
    }
    if url.origin() == base.origin() {
        return Ok(());
    }
    let registry = std::env::var("JACS_KEYS_BASE_URL")
        .or_else(|_| std::env::var("HAI_KEYS_BASE_URL"))
        .ok()
        .and_then(|value| url::Url::parse(&value).ok());
    if registry
        .as_ref()
        .is_some_and(|registry| registry.scheme() == "https" && registry.origin() == url.origin())
        && url.path() == format!("/jacs/v1/agents/{}/keys/{}", request.id, request.version)
    {
        return Ok(());
    }
    Err(JacsError::ValidationError("DNS URI must use the publisher origin or an explicitly configured registry's exact version endpoint".into()))
}

fn validated_domain_origin(domain: &str) -> Result<url::Url, JacsError> {
    let domain = domain.trim();
    let url = url::Url::parse(&format!("https://{domain}/"))
        .map_err(|e| JacsError::ValidationError(e.to_string()))?;
    if domain.is_empty()
        || domain.len() > 253
        || domain.contains('/')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.host(), Some(url::Host::Domain(_)))
        || !url
            .host_str()
            .unwrap_or_default()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(domain.trim_end_matches('.'))
    {
        return Err(JacsError::ValidationError(
            "agentDomain must be a bare DNS domain".into(),
        ));
    }
    Ok(url)
}

fn decode_discovery_document(
    value: &Value,
    request: &Request<'_>,
) -> Result<ResolvedVerificationKey, JacsError> {
    if value.get("publicKey").is_some() {
        if value["agentId"].as_str() != Some(request.id)
            || value["agentVersion"].as_str() != Some(request.version)
        {
            return Err(JacsError::ValidationError(
                "Discovery document signer identity/version mismatch".into(),
            ));
        }
        let algorithm = value["algorithm"]
            .as_str()
            .ok_or_else(|| JacsError::ValidationError("Missing discovery algorithm".into()))?;
        let key = decode_key_representation(
            value["publicKey"]
                .as_str()
                .ok_or_else(|| JacsError::ValidationError("Missing discovery publicKey".into()))?,
            algorithm,
        )?;
        // This endpoint's exporter explicitly uses the frozen native alias.
        if value["publicKeyHash"].as_str() != Some(hash_public_key(&key).as_str()) {
            return Err(JacsError::ValidationError(
                "Discovery publicKeyHash mismatch".into(),
            ));
        }
        request.validate(ResolvedVerificationKey {
            public_key: key,
            algorithm: algorithm.into(),
        })
    } else {
        if value
            .get("jacs_id")
            .is_some_and(|id| id.as_str() != Some(request.id))
            || value
                .get("version")
                .is_some_and(|version| version.as_str() != Some(request.version))
        {
            return Err(JacsError::ValidationError(
                "Registry pointer response identity/version mismatch".into(),
            ));
        }
        let key = crate::agent::loaders::decode_remote_key_response(value)?;
        request.validate(ResolvedVerificationKey {
            public_key: key.public_key,
            algorithm: key.algorithm,
        })
    }
}

/// Decode historical raw-key armor or standard algorithm-specific SPKI, then
/// validate the exact canonical raw shape. Armor is not itself key material.
pub(crate) fn decode_key_representation(
    representation: &str,
    algorithm: &str,
) -> Result<Vec<u8>, JacsError> {
    let algorithm = crate::verification::matching_algorithm(Some(algorithm), None)?
        .ok_or_else(|| JacsError::ValidationError("Missing key algorithm".into()))?;
    let bytes = if representation.trim_start().starts_with("-----BEGIN") {
        let blocks =
            pem::parse_many(representation).map_err(|e| JacsError::CryptoError(e.to_string()))?;
        if blocks.len() != 1 || blocks[0].tag() != "PUBLIC KEY" {
            return Err(JacsError::CryptoError(
                "Expected one PUBLIC KEY PEM block".into(),
            ));
        }
        blocks[0].contents().to_vec()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(representation.trim())
            .map_err(|e| JacsError::CryptoError(e.to_string()))?
    };
    let ed_spki = hex::decode("302a300506032b6570032100").expect("constant DER");
    let pq_spki =
        hex::decode("30820a32300b060960864801650304031303820a2100").expect("constant DER");
    let raw = match algorithm.as_str() {
        "ring-Ed25519" if bytes.len() == ed_spki.len() + 32 && bytes.starts_with(&ed_spki) => {
            bytes[ed_spki.len()..].to_vec()
        }
        "pq2025" if bytes.len() == pq_spki.len() + 2592 && bytes.starts_with(&pq_spki) => {
            bytes[pq_spki.len()..].to_vec()
        }
        "es256" if bytes.len() != 65 => {
            use p256::elliptic_curve::sec1::ToSec1Point;
            use p256::pkcs8::DecodePublicKey;
            p256::PublicKey::from_public_key_der(&bytes)
                .map_err(|error| JacsError::CryptoError(error.to_string()))?
                .to_sec1_point(false)
                .as_bytes()
                .to_vec()
        }
        _ => bytes,
    };
    jacs_core::identity::canonical_key_id(&algorithm, &raw)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::bootstrap::{
        AgentTxtFields, DigestEncoding, build_agent_dns_txt, parse_agent_txt, pubkey_digest_b64,
    };
    use std::cell::{Cell, RefCell};

    const ID: &str = "11111111-1111-4111-8111-111111111111";
    const VERSION: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER_ID: &str = "33333333-3333-4333-8333-333333333333";
    fn key() -> Vec<u8> {
        vec![0x80; 2592]
    }
    fn document(raw_reference: bool) -> Value {
        serde_json::json!({"jacsSignature": {
            "agentID": ID, "agentVersion": VERSION, "signingAlgorithm": "pq2025",
            "publicKeyHash": if raw_reference { hash_bytes(&key()) } else { hash_public_key(&key()) },
            "signatureContentVersion": jacs_core::verify::SIGNATURE_CONTENT_VERSION_V2,
            "agentDomain": "publisher.example"
        }})
    }
    fn published() -> Value {
        serde_json::json!({"agentId": ID,"agentVersion": VERSION,"algorithm":"pq2025",
            "publicKey": base64::engine::general_purpose::STANDARD.encode(key()), "publicKeyHash":hash_public_key(&key())})
    }
    fn record(id: &str, raw: &[u8]) -> AgentTxtFields {
        parse_agent_txt(&build_agent_dns_txt(
            id,
            &pubkey_digest_b64(raw),
            DigestEncoding::Base64,
        ))
        .unwrap()
    }
    struct MockTransport {
        records: Vec<AgentTxtFields>,
        value: Value,
        registry_calls: Cell<usize>,
        requests: RefCell<Vec<String>>,
        fetch_error: bool,
    }
    impl DiscoveryTransport for MockTransport {
        fn registry(&self, id: &str, version: &str) -> Result<ResolvedVerificationKey, JacsError> {
            assert_eq!((id, version), (ID, VERSION));
            self.registry_calls.set(self.registry_calls.get() + 1);
            Ok(ResolvedVerificationKey {
                public_key: key(),
                algorithm: "pq2025".into(),
            })
        }
        fn dns(
            &self,
            domain: &str,
            id: &str,
            _strict: bool,
        ) -> Result<Vec<AgentTxtFields>, JacsError> {
            assert_eq!((domain, id), ("publisher.example", ID));
            Ok(self.records.clone())
        }
        fn json(&self, uri: &str) -> Result<Value, JacsError> {
            self.requests.borrow_mut().push(uri.into());
            if self.fetch_error {
                return Err(JacsError::NetworkError("Mock endpoint unavailable".into()));
            }
            Ok(self.value.clone())
        }
    }
    fn transport(records: Vec<AgentTxtFields>) -> MockTransport {
        MockTransport {
            records,
            value: published(),
            registry_calls: Cell::new(0),
            requests: RefCell::new(vec![]),
            fetch_error: false,
        }
    }
    fn verifier() -> Agent {
        Agent::new("v1", "v1", "v1").unwrap()
    }

    #[test]
    fn dns_raw_digest_supports_both_existing_document_reference_profiles() {
        assert_ne!(hash_bytes(&key()), hash_public_key(&key()));
        for raw in [false, true] {
            let document = document(raw);
            let request = Request::new(&document).unwrap();
            let transport = transport(vec![record(ID, &key())]);
            let result = resolve_with_transport(
                &verifier(),
                &request,
                &[KeyResolutionSource::Dns],
                &transport,
            )
            .unwrap();
            assert_eq!(result.public_key, key());
            assert_eq!(
                *transport.requests.borrow(),
                ["https://publisher.example/.well-known/jacs-pubkey.json"]
            );
        }
    }

    #[test]
    fn rotation_overlap_matches_whole_rrset_and_fetches_shared_uri_once() {
        let document = document(true);
        let request = Request::new(&document).unwrap();
        let old = vec![0x81; 2592];
        for records in [
            vec![record(ID, &old), record(ID, &key())],
            vec![record(ID, &key()), record(ID, &old)],
        ] {
            let transport = transport(records);
            assert!(
                resolve_with_transport(
                    &verifier(),
                    &request,
                    &[KeyResolutionSource::Dns, KeyResolutionSource::Registry],
                    &transport
                )
                .is_ok()
            );
            assert_eq!(transport.requests.borrow().len(), 1);
            assert_eq!(transport.registry_calls.get(), 0);
        }
    }

    #[test]
    fn contradictory_dns_pin_cannot_be_replaced_by_registry_or_other_agent_pin() {
        let document = document(false);
        let request = Request::new(&document).unwrap();
        let transport = transport(vec![record(ID, &[0x81; 2592]), record(OTHER_ID, &key())]);
        assert!(
            resolve_with_transport(
                &verifier(),
                &request,
                &[KeyResolutionSource::Dns, KeyResolutionSource::Registry],
                &transport
            )
            .is_err()
        );
        assert_eq!(transport.registry_calls.get(), 0);
    }

    #[test]
    fn wrong_response_version_algorithm_and_hash_fail_before_registry_fallback() {
        let document = document(false);
        let request = Request::new(&document).unwrap();
        for (field, value) in [
            ("agentVersion", Value::String(OTHER_ID.into())),
            ("algorithm", Value::String("ed25519".into())),
            ("publicKeyHash", Value::String("0".repeat(64))),
        ] {
            let mut transport = transport(vec![record(ID, &key())]);
            transport.value[field] = value;
            assert!(
                resolve_with_transport(
                    &verifier(),
                    &request,
                    &[KeyResolutionSource::Dns, KeyResolutionSource::Registry],
                    &transport
                )
                .is_err()
            );
            assert_eq!(transport.registry_calls.get(), 0);
        }
    }

    #[test]
    fn registry_requires_exact_version_and_document_key_reference() {
        let document = document(true);
        let request = Request::new(&document).unwrap();
        let transport = transport(vec![]);
        assert!(
            resolve_with_transport(
                &verifier(),
                &request,
                &[KeyResolutionSource::Registry],
                &transport
            )
            .is_ok()
        );
        assert_eq!(transport.registry_calls.get(), 1);
        let mut missing_version = document.clone();
        missing_version["jacsSignature"]
            .as_object_mut()
            .unwrap()
            .remove("agentVersion");
        assert!(Request::new(&missing_version).is_err());
        let mut latest = document.clone();
        latest["jacsSignature"]["agentVersion"] = "latest".into();
        assert!(Request::new(&latest).is_err());
        let mut wrong = document.clone();
        wrong["jacsSignature"]["publicKeyHash"] = "0".repeat(64).into();
        assert!(
            Request::new(&wrong)
                .unwrap()
                .validate(ResolvedVerificationKey {
                    public_key: key(),
                    algorithm: "pq2025".into()
                })
                .is_err()
        );
    }

    #[test]
    fn dns_pointer_is_rejected_before_fetch_for_other_origin_collection_or_http() {
        let document = document(false);
        let request = Request::new(&document).unwrap();
        for uri in [
            "https://other.example/key",
            "http://127.0.0.1/key",
            "https://publisher.example/keys",
            "https://publisher.example/latest",
            "https://publisher.example/key?secret=1",
        ] {
            let mut record = record(ID, &key());
            record.uri = Some(uri.into());
            let transport = transport(vec![record]);
            assert!(
                resolve_with_transport(
                    &verifier(),
                    &request,
                    &[KeyResolutionSource::Dns],
                    &transport
                )
                .is_err()
            );
            assert!(transport.requests.borrow().is_empty());
        }
    }

    #[test]
    fn strict_dns_unreachable_pinned_key_cannot_downgrade_to_registry() {
        let document = document(false);
        let mut request = Request::new(&document).unwrap();
        request.dns_strict = Some(true);
        let mut transport = transport(vec![record(ID, &key())]);
        transport.fetch_error = true;
        assert!(
            resolve_with_transport(
                &verifier(),
                &request,
                &[KeyResolutionSource::Dns, KeyResolutionSource::Registry],
                &transport
            )
            .is_err()
        );
        assert_eq!(transport.registry_calls.get(), 0);
        request.dns_strict = Some(false);
        assert!(
            resolve_with_transport(
                &verifier(),
                &request,
                &[KeyResolutionSource::Dns, KeyResolutionSource::Registry],
                &transport
            )
            .is_ok()
        );
        assert_eq!(transport.registry_calls.get(), 1);
    }

    #[test]
    fn local_only_resolution_never_calls_transport() {
        let document = document(false);
        let request = Request::new(&document).unwrap();
        let transport = transport(vec![]);
        assert!(
            resolve_with_transport(
                &verifier(),
                &request,
                &[KeyResolutionSource::Local],
                &transport
            )
            .is_err()
        );
        assert_eq!(transport.registry_calls.get(), 0);
        assert!(transport.requests.borrow().is_empty());
    }

    #[test]
    fn standard_spki_and_historical_raw_armor_decode_to_same_exact_key() {
        let raw = key();
        let mut der = hex::decode("30820a32300b060960864801650304031303820a2100").unwrap();
        der.extend_from_slice(&raw);
        for bytes in [raw.clone(), der] {
            let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", bytes));
            assert_eq!(decode_key_representation(&pem, "pq2025").unwrap(), raw);
            assert!(decode_key_representation(&pem, "ed25519").is_err());
        }
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn configured_network_sources_stay_off_without_capability_grants() {
        struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in self.0.drain(..) {
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(key, value),
                            None => std::env::remove_var(key),
                        }
                    }
                }
            }
        }
        let names = [
            "JACS_ALLOW_NETWORK",
            "JACS_ALLOW_DNS",
            "JACS_ALLOW_REMOTE_KEY_FETCH",
            "JACS_KEYS_BASE_URL",
        ];
        let _restore = Restore(
            names
                .iter()
                .map(|key| (*key, std::env::var_os(key)))
                .collect(),
        );
        unsafe {
            for key in &names[..3] {
                std::env::set_var(key, "false");
            }
            std::env::set_var("JACS_KEYS_BASE_URL", "https://registry.example");
        }
        let registry_error = NetworkTransport
            .registry(ID, VERSION)
            .unwrap_err()
            .to_string();
        assert!(
            registry_error.contains("disabled by default"),
            "{registry_error}"
        );
        let dns_error = NetworkTransport
            .dns("publisher.example", ID, false)
            .unwrap_err()
            .to_string();
        assert!(dns_error.contains("disabled by default"), "{dns_error}");
        let http_error = NetworkTransport
            .json("https://publisher.example/.well-known/jacs-pubkey.json")
            .unwrap_err()
            .to_string();
        assert!(http_error.contains("disabled by default"), "{http_error}");
    }

    #[test]
    fn registry_checks_exact_wire_hash_and_all_expanded_representations() {
        let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", key()));
        let mut response = serde_json::json!({"public_key":pem,"algorithm":"pq2025","public_key_hash":format!("sha256:{}",hash_bytes(pem.as_bytes())),
            "jacs_id":ID,"version":VERSION,"public_key_b64":base64::engine::general_purpose::STANDARD.encode(pem.as_bytes()),
            "public_key_raw_b64":base64::engine::general_purpose::STANDARD.encode(key()),"status":"active"});
        assert_eq!(
            crate::agent::loaders::decode_remote_key_response(&response)
                .unwrap()
                .public_key,
            key()
        );
        let valid = response.clone();
        response["public_key_hash"] = format!("sha256:{}", hash_bytes(&key())).into();
        assert!(
            crate::agent::loaders::decode_remote_key_response(&response).is_err(),
            "prefix does not license raw-hash fallback"
        );
        response = valid.clone();
        response["public_key_raw_b64"] = base64::engine::general_purpose::STANDARD
            .encode([0x81; 2592])
            .into();
        assert!(crate::agent::loaders::decode_remote_key_response(&response).is_err());
        response = valid.clone();
        response["public_key_hash"] = hash_bytes(&key()).into();
        assert!(
            crate::agent::loaders::decode_remote_key_response(&response).is_ok(),
            "expanded bare checksum is raw"
        );
        response["public_key_hash"] = hash_public_key(&key()).into();
        assert!(
            crate::agent::loaders::decode_remote_key_response(&response).is_err(),
            "expanded response cannot select legacy hash fallback"
        );
        response = valid;
        response["status"] = "revoked".into();
        assert!(crate::agent::loaders::decode_remote_key_response(&response).is_err());
    }
}
