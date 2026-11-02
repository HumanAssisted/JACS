use crate::config::{NetworkCapability, ensure_network_access};
use crate::crypt::hash::{hash_bytes_raw, hash_public_key};
use crate::error::JacsError;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub owner: String,
    pub ttl: u32,
    pub txt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Provider {
    Plain,
    Aws,
    Azure,
    Cloudflare,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DigestEncoding {
    Base64,
    Hex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTxtFields {
    pub v: String,
    pub jacs_agent_id: String,
    pub alg: String,
    pub enc: DigestEncoding,
    pub digest: String,
    /// Optional HTTPS discovery location. Fetch policy still restricts origins and addresses.
    pub uri: Option<String>,
}

pub fn pubkey_digest_sha256_bytes(pubkey: &[u8]) -> [u8; 32] {
    hash_bytes_raw(pubkey)
}

pub fn pubkey_digest_b64(pubkey: &[u8]) -> String {
    let bytes = pubkey_digest_sha256_bytes(pubkey);
    B64.encode(bytes)
}

pub fn pubkey_digest_hex(pubkey: &[u8]) -> String {
    let bytes = pubkey_digest_sha256_bytes(pubkey);
    hex::encode(bytes)
}

pub fn build_agent_dns_txt(agent_id: &str, digest: &str, enc: DigestEncoding) -> String {
    let enc_str = match enc {
        DigestEncoding::Base64 => "base64",
        DigestEncoding::Hex => "hex",
    };
    format!(
        "v=jacs; jacs_agent_id={}; alg=SHA-256; enc={}; jac_public_key_hash={}",
        agent_id, enc_str, digest
    )
}

pub fn build_agent_dns_txt_with_uri(
    agent_id: &str,
    digest: &str,
    enc: DigestEncoding,
    uri: Option<&str>,
) -> Result<String, JacsError> {
    let mut record = build_agent_dns_txt(agent_id, digest, enc);
    if let Some(uri) = uri {
        record.push_str("; uri=");
        record.push_str(uri);
    }
    parse_agent_txt(&record)?;
    Ok(record)
}

pub fn parse_agent_txt(txt: &str) -> Result<AgentTxtFields, JacsError> {
    let invalid = |reason: &str| JacsError::DnsRecordInvalid {
        domain: String::new(),
        reason: reason.to_string(),
    };
    if txt.len() > 4096 || txt.chars().any(char::is_control) {
        return Err(invalid("Invalid TXT record length or control character"));
    }
    let parts: Vec<&str> = txt.split(';').map(|s| s.trim()).collect();
    let mut map = std::collections::HashMap::new();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        let (k, value) = p
            .split_once('=')
            .ok_or_else(|| invalid("Malformed TXT field"))?;
        if k.trim().is_empty() || value.trim().is_empty() {
            return Err(invalid("Empty TXT field name or value"));
        }
        if map
            .insert(k.trim().to_string(), value.trim().to_string())
            .is_some()
        {
            return Err(JacsError::DnsRecordInvalid {
                domain: String::new(),
                reason: format!("Duplicate {} field in TXT record", k.trim()),
            });
        }
    }
    let missing = |field: &str| JacsError::DnsRecordInvalid {
        domain: String::new(),
        reason: format!("Missing {} field in TXT record", field),
    };
    let v = map.get("v").cloned().ok_or_else(|| missing("v"))?;
    let jacs_agent_id = map
        .get("jacs_agent_id")
        .cloned()
        .ok_or_else(|| missing("jacs_agent_id"))?;
    let alg = map.get("alg").cloned().ok_or_else(|| missing("alg"))?;
    if v != "jacs" || alg != "SHA-256" {
        return Err(invalid("TXT record requires v=jacs and alg=SHA-256"));
    }
    if jacs_agent_id.len() > 256 || jacs_agent_id.chars().any(char::is_whitespace) {
        return Err(invalid("Invalid jacs_agent_id"));
    }
    let enc_val = map.get("enc").cloned().ok_or_else(|| missing("enc"))?;
    let enc = match enc_val.as_str() {
        "base64" => DigestEncoding::Base64,
        "hex" => DigestEncoding::Hex,
        _ => {
            return Err(JacsError::DnsRecordInvalid {
                domain: String::new(),
                reason: format!("Unsupported encoding: {}", enc_val),
            });
        }
    };
    let digest = map
        .get("jac_public_key_hash")
        .cloned()
        .ok_or_else(|| missing("jac_public_key_hash"))?;
    decode_dns_digest(&digest, &enc)?;
    let uri = map.get("uri").cloned();
    if let Some(uri) = uri.as_deref() {
        let parsed = url::Url::parse(uri).map_err(|_| invalid("Invalid DNS key URI"))?;
        if uri.len() > 2048
            || uri.chars().any(char::is_whitespace)
            || parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(invalid(
                "DNS key URI must be HTTPS without credentials or fragment",
            ));
        }
    }
    Ok(AgentTxtFields {
        v,
        jacs_agent_id,
        alg,
        enc,
        digest,
        uri,
    })
}

fn decode_dns_digest(digest: &str, encoding: &DigestEncoding) -> Result<[u8; 32], JacsError> {
    let invalid = || JacsError::DnsRecordInvalid {
        domain: String::new(),
        reason: "DNS fingerprint must encode exactly 32 SHA-256 bytes".to_string(),
    };
    let bytes = match encoding {
        DigestEncoding::Base64 => {
            let bytes = B64.decode(digest).map_err(|_| invalid())?;
            if B64.encode(&bytes) != digest {
                return Err(invalid());
            }
            bytes
        }
        DigestEncoding::Hex => hex::decode(digest).map_err(|_| invalid())?,
    };
    bytes.try_into().map_err(|_| invalid())
}

pub fn record_matches_public_key(fields: &AgentTxtFields, key: &[u8]) -> bool {
    fields.v == "jacs"
        && fields.alg == "SHA-256"
        && decode_dns_digest(&fields.digest, &fields.enc)
            .is_ok_and(|digest| digest == pubkey_digest_sha256_bytes(key))
}

fn is_jacs_record(record: &str) -> bool {
    record
        .split(';')
        .next()
        .is_some_and(|tag| tag.trim() == "v=jacs")
}

/// Select one agent's complete rotation set; unrelated agents do not create ambiguity.
pub fn select_agent_txt_records(
    records: &[String],
    domain: &str,
    agent_id: &str,
) -> Result<Vec<AgentTxtFields>, JacsError> {
    let mut selected = Vec::new();
    for record in records.iter().filter(|r| is_jacs_record(r)) {
        // Unrelated publishers sharing an owner must not block this identity.
        // Parse every record claiming the requested ID in full, including duplicate
        // ID tags, so malformed or contradictory evidence cannot be skipped.
        let claims_agent = record.split(';').any(|part| {
            part.split_once('=').is_some_and(|(name, value)| {
                name.trim() == "jacs_agent_id" && value.trim() == agent_id
            })
        });
        if claims_agent {
            selected.push(parse_agent_txt(record)?);
        }
    }
    if selected.is_empty() {
        return Err(JacsError::DnsRecordMissing {
            domain: domain.to_string(),
        });
    }
    // A single content address must not send different clients to different locations.
    for (index, record) in selected.iter().enumerate() {
        let digest = decode_dns_digest(&record.digest, &record.enc)?;
        if selected[..index].iter().any(|other| {
            decode_dns_digest(&other.digest, &other.enc).ok() == Some(digest)
                && other.uri != record.uri
        }) {
            return Err(JacsError::DnsRecordInvalid {
                domain: domain.to_string(),
                reason: "Conflicting DNS key URIs for the same agent and fingerprint".into(),
            });
        }
    }
    Ok(selected)
}

pub fn match_agent_txt_record(
    records: &[String],
    domain: &str,
    agent_id: &str,
    key: &[u8],
) -> Result<AgentTxtFields, JacsError> {
    select_agent_txt_records(records, domain, agent_id)?
        .into_iter()
        .find(|record| record_matches_public_key(record, key))
        .ok_or_else(|| JacsError::DnsRecordInvalid {
            domain: domain.into(),
            reason: "DNS fingerprint does not match candidate public key".into(),
        })
}

pub fn record_owner(domain: &str) -> String {
    format!("_v1.agent.jacs.{}.", domain.trim_end_matches('.'))
}

/// Existing configuration accepts service origins and local development hosts.
/// Emit only a DNS hostname usable for HTTPS discovery. Keep local/HTTP origins
/// working without a discovery hint, and never rewrite the configured origin.
pub(crate) fn signing_agent_domain(configured: &str) -> Result<Option<String>, JacsError> {
    let invalid = || {
        JacsError::ValidationError(
            "Agent discovery domain requires a bare hostname or HTTP(S) origin".into(),
        )
    };
    if configured
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
        || configured.contains('\\')
    {
        return Err(invalid());
    }
    let domain = if configured.starts_with("https://") || configured.starts_with("http://") {
        let origin = url::Url::parse(configured).map_err(|_| invalid())?;
        if !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(invalid());
        }
        let host = origin.host_str().ok_or_else(invalid)?;
        if matches!(origin.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))) {
            return Ok(None);
        }
        validate_agent_domain(host)?;
        if origin.scheme() == "http" {
            return Ok(None);
        }
        host.to_string()
    } else {
        // Preserve valid bare IP dev configuration without advertising it as DNS.
        let address = configured
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(configured);
        if address.parse::<std::net::IpAddr>().is_ok() {
            return Ok(None);
        }
        configured.to_string()
    };
    validate_agent_domain(&domain)?;
    let bare = domain.trim_end_matches('.').to_ascii_lowercase();
    if !bare.contains('.') || bare.ends_with(".localhost") || bare.ends_with(".local") {
        return Ok(None);
    }
    Ok(Some(domain))
}

/// Validate a bare DNS domain hint, without performing I/O or granting trust.
pub fn validate_agent_domain(domain: &str) -> Result<(), JacsError> {
    let bare = domain.strip_suffix('.').unwrap_or(domain);
    if bare.is_empty()
        || bare.parse::<std::net::IpAddr>().is_ok()
        || bare.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(JacsError::DnsRecordInvalid {
            domain: domain.into(),
            reason: "agentDomain must be a bare DNS hostname".into(),
        });
    }
    validate_dns_owner(&record_owner(domain))
}

/// Reject DNS owner names that exceed RFC 1035 limits before they reach the
/// resolver. Defense-in-depth for RUSTSEC-2026-0119 (hickory-proto O(n²) name
/// compression in BinEncoder): bounding the encoder input also bounds the
/// worst-case CPU cost. The real fix is hickory-resolver 0.26 (separate PR).
fn validate_dns_owner(owner: &str) -> Result<(), JacsError> {
    // RFC 1035: full domain name <= 255 octets on the wire (253 in
    // dotted-string form before the implicit trailing dot).
    const MAX_DOMAIN_BYTES: usize = 253;
    const MAX_LABEL_BYTES: usize = 63;

    let trimmed = owner.trim_end_matches('.');
    if trimmed.len() > MAX_DOMAIN_BYTES {
        return Err(JacsError::DnsRecordInvalid {
            domain: owner.to_string(),
            reason: format!(
                "Domain exceeds {} bytes (RFC 1035 limit; rejected to bound encoder cost)",
                MAX_DOMAIN_BYTES
            ),
        });
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(JacsError::DnsRecordInvalid {
                domain: owner.to_string(),
                reason: "Empty DNS label".to_string(),
            });
        }
        if label.len() > MAX_LABEL_BYTES {
            return Err(JacsError::DnsRecordInvalid {
                domain: owner.to_string(),
                reason: format!(
                    "DNS label exceeds {} bytes (RFC 1035 limit)",
                    MAX_LABEL_BYTES
                ),
            });
        }
    }
    Ok(())
}

pub fn build_dns_record(
    domain: &str,
    ttl: u32,
    agent_id: &str,
    digest: &str,
    enc: DigestEncoding,
) -> DnsRecord {
    let owner = record_owner(domain);
    let txt = build_agent_dns_txt(agent_id, digest, enc);
    DnsRecord { owner, ttl, txt }
}

pub fn emit_plain_bind(rr: &DnsRecord) -> String {
    format!("{} {} IN TXT \"{}\"", rr.owner, rr.ttl, rr.txt)
}

pub fn emit_route53_change_batch(rr: &DnsRecord) -> String {
    // Inner value must be quoted and escaped for JSON
    let val = format!("\\\"{}\\\"", rr.txt);
    format!(
        r#"{{
  "Comment": "UPSERT JACS agent TXT",
  "Changes": [{{
    "Action": "UPSERT",
    "ResourceRecordSet": {{
      "Name": "{}",
      "Type": "TXT",
      "TTL": {},
      "ResourceRecords": [{{ "Value": "{}" }}]
    }}
  }}]
}}"#,
        rr.owner, rr.ttl, val
    )
}

pub fn emit_gcloud_dns(rr: &DnsRecord, zone: &str) -> String {
    format!(
        "gcloud dns record-sets transaction start --zone {zone}\n\
gcloud dns record-sets transaction add --zone {zone} \\\n+  --name {owner} --ttl {ttl} --type TXT \\\n+  --txt-data \"{txt}\"\n\
gcloud dns record-sets transaction execute --zone {zone}",
        zone = zone,
        owner = rr.owner,
        ttl = rr.ttl,
        txt = rr.txt
    )
}

pub fn emit_azure_cli(
    rr: &DnsRecord,
    resource_group: &str,
    dns_zone: &str,
    short_name: &str,
) -> String {
    format!(
        "az network dns record-set txt create -g {rg} -z {zone} -n {short} --ttl {ttl}\n\
az network dns record-set txt add-record -g {rg} -z {zone} -n {short} \\\n+  --value \"{txt}\"",
        rg = resource_group,
        zone = dns_zone,
        short = short_name,
        ttl = rr.ttl,
        txt = rr.txt
    )
}

pub fn emit_cloudflare_curl(rr: &DnsRecord, zone_id_hint: &str) -> String {
    let owner_no_dot = rr.owner.trim_end_matches('.');
    format!(
        "curl -X POST \"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records\" \\n+  -H \"Authorization: Bearer ${{API_TOKEN}}\" -H \"Content-Type: application/json\" \\\n+  --data '{{\n    \"type\":\"TXT\",\n    \"name\":\"{name}\",\n    \"content\":\"{content}\",\n    \"ttl\":{ttl},\n    \"proxied\":false\n  }}'",
        zone_id = zone_id_hint,
        name = owner_no_dot,
        content = rr.txt,
        ttl = rr.ttl
    )
}

/// Find the unique JACS-formatted TXT record from individual TXT record strings.
///
/// DNS lookups may return multiple TXT records (SPF, DKIM, DMARC, etc.) at the same
/// domain name. This function filters for the record starting with `v=jacs` and ignores
/// all others, preventing non-JACS records from corrupting the parsed result.
///
/// Returns `Err(JacsError::DnsRecordInvalid)` if no JACS record is found.
pub fn find_jacs_txt_record(records: Vec<String>, domain: &str) -> Result<String, JacsError> {
    let mut selected = None;
    for record in records {
        if is_jacs_record(&record) {
            if selected.is_some() {
                return Err(JacsError::DnsRecordInvalid {
                    domain: domain.to_string(),
                    reason: "Multiple JACS TXT records are ambiguous".to_string(),
                });
            }
            selected = Some(record);
        }
    }
    selected.ok_or_else(|| JacsError::DnsRecordInvalid {
        domain: domain.to_string(),
        reason: "No v=jacs TXT record found at this domain".to_string(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn run_dns_future<F, T>(future: F) -> Result<T, String>
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    let run = move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Tokio runtime init failed: {e}"))?;
        Ok(runtime.block_on(future))
    };

    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|scope| {
            scope
                .spawn(run)
                .join()
                .map_err(|_| "DNS runtime thread panicked".to_string())?
        })
    } else {
        run()
    }
}

pub fn resolve_txt_dnssec(owner: &str) -> Result<String, JacsError> {
    resolve_txt(owner, true)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_txt_insecure(owner: &str) -> Result<String, JacsError> {
    resolve_txt(owner, false)
}

fn resolver_from_config(
    config: hickory_resolver::config::ResolverConfig,
    mut options: hickory_resolver::config::ResolverOpts,
    require_secure: bool,
    owner: &str,
) -> Result<hickory_resolver::TokioResolver, JacsError> {
    use hickory_resolver::Resolver;
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    if config.name_servers().is_empty() {
        return Err(JacsError::DnsLookupFailed {
            domain: owner.to_string(),
            reason: "DNS resolver configuration contains no name servers".to_string(),
        });
    }
    options.validate = require_secure;
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()
        .map_err(|error| JacsError::DnsLookupFailed {
            domain: owner.to_string(),
            reason: format!("Resolver init failed: {error}"),
        })
}

fn resolve_txt(owner: &str, require_secure: bool) -> Result<String, JacsError> {
    find_jacs_txt_record(resolve_txt_records(owner, require_secure)?, owner)
}

pub fn resolve_agent_txt_records(
    domain: &str,
    agent_id: &str,
    require_secure: bool,
) -> Result<Vec<AgentTxtFields>, JacsError> {
    validate_agent_domain(domain)?;
    let owner = record_owner(domain);
    select_agent_txt_records(
        &resolve_txt_records(&owner, require_secure)?,
        domain,
        agent_id,
    )
}

pub fn resolve_txt_records(owner: &str, require_secure: bool) -> Result<Vec<String>, JacsError> {
    validate_dns_owner(owner)?;
    ensure_network_access(NetworkCapability::DnsLookup)?;
    let (config, options) = hickory_resolver::system_conf::read_system_conf().map_err(|error| {
        JacsError::DnsLookupFailed {
            domain: owner.to_string(),
            reason: format!("System resolver configuration failed: {error}"),
        }
    })?;
    let resolver = resolver_from_config(config, options, require_secure, owner)?;
    let resp = run_dns_future(resolver.txt_lookup(owner))
        .map_err(|e| JacsError::DnsLookupFailed {
            domain: owner.to_string(),
            reason: e,
        })?
        .map_err(|e| JacsError::DnsLookupFailed {
            domain: owner.to_string(),
            reason: format!("DNS lookup failed: {e}"),
        })?;
    txt_records_from_answers(resp.answers(), owner, require_secure)
}

#[cfg(test)]
fn txt_from_answers(
    answers: &[hickory_resolver::proto::rr::Record],
    owner: &str,
    require_secure: bool,
) -> Result<String, JacsError> {
    find_jacs_txt_record(
        txt_records_from_answers(answers, owner, require_secure)?,
        owner,
    )
}

fn txt_records_from_answers(
    answers: &[hickory_resolver::proto::rr::Record],
    owner: &str,
    require_secure: bool,
) -> Result<Vec<String>, JacsError> {
    let mut records = Vec::new();
    for rr in answers {
        let hickory_resolver::proto::rr::RData::TXT(txt) = &rr.data else {
            continue;
        };
        if require_secure && !rr.proof.is_secure() {
            tracing::warn!(event = "dnssec_proof_rejected", domain = owner, proof = ?rr.proof,
                "DNS TXT answer lacks a Secure DNSSEC proof");
            return Err(JacsError::DnsRecordInvalid {
                domain: owner.to_string(),
                reason: "DNS TXT answer requires a Secure DNSSEC proof".to_string(),
            });
        }
        let mut record = String::new();
        for part in txt.txt_data.iter() {
            record.push_str(&String::from_utf8(part.to_vec()).map_err(|e| {
                JacsError::DnsRecordInvalid {
                    domain: owner.to_string(),
                    reason: format!("UTF-8 decode failed: {e}"),
                }
            })?);
        }
        records.push(record);
    }
    Ok(records)
}

pub fn verify_pubkey_via_dns_or_embedded(
    agent_public_key: &[u8],
    agent_id: &str,
    jacs_agent_domain: Option<&str>,
    embedded_fingerprint: Option<&str>,
    strict_dns: bool,
) -> Result<(), JacsError> {
    let local_b64 = pubkey_digest_b64(agent_public_key);
    let local_hex = pubkey_digest_hex(agent_public_key);

    if let Some(domain) = jacs_agent_domain {
        let owner = record_owner(domain);
        let lookup = resolve_txt_records(&owner, strict_dns).and_then(|records| {
            if records.iter().any(|record| is_jacs_record(record)) {
                Ok(records)
            } else {
                Err(JacsError::DnsRecordMissing {
                    domain: domain.to_string(),
                })
            }
        });
        match lookup {
            Ok(records) => {
                match_agent_txt_record(&records, domain, agent_id, agent_public_key)?;
                return Ok(());
            }
            Err(error) => {
                if strict_dns {
                    return Err(error);
                }
                // Fallback to embedded if provided
                if let Some(embed) = embedded_fingerprint {
                    // Accept either the new byte-based digest or the legacy normalized-string hex
                    let legacy_hex = hash_public_key(agent_public_key);
                    if embed == local_b64
                        || embed.eq_ignore_ascii_case(&local_hex)
                        || embed.eq_ignore_ascii_case(&legacy_hex)
                    {
                        return Ok(());
                    }
                    return Err(JacsError::DnsRecordInvalid {
                        domain: domain.to_string(),
                        reason: "Embedded fingerprint mismatch: does not match local public key"
                            .to_string(),
                    });
                }
                return Err(JacsError::DnsRecordMissing {
                    domain: domain.to_string(),
                });
            }
        }
    }

    if let Some(embed) = embedded_fingerprint {
        let legacy_hex = hash_public_key(agent_public_key);
        if embed == local_b64
            || embed.eq_ignore_ascii_case(&local_hex)
            || embed.eq_ignore_ascii_case(&legacy_hex)
        {
            return Ok(());
        }
        return Err(JacsError::SignatureVerificationFailed {
            reason:
                "embedded fingerprint mismatch (embedded present but does not match local public key)"
                    .to_string(),
        });
    }

    Err(JacsError::DnsRecordMissing {
        domain: "unknown".to_string(),
    })
}

// =============================================================================
// Registry Registration Verification
// =============================================================================

/// Information about an agent's registry registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryRegistration {
    /// Whether the agent is verified by the registry
    pub verified: bool,
    /// ISO 8601 timestamp of when the agent was verified
    pub verified_at: Option<String>,
    /// Type of registration (e.g., "agent", "organization")
    pub registration_type: String,
    /// The agent ID as registered with the registry
    pub agent_id: String,
    /// The public key hash registered with the registry
    pub public_key_hash: String,
}

/// Response from registry API for agent lookup
#[derive(Clone, Debug, Deserialize)]
struct RegistryApiResponse {
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    verified_at: Option<String>,
    #[serde(default)]
    registration_type: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    public_key_hash: Option<String>,
}

#[cfg(not(target_arch = "wasm32"))]
const MAX_REGISTRY_RESPONSE_BYTES: usize = 64 * 1024;

/// Check if an agent is registered with a registry.
///
/// This function queries the registry API to verify that an agent claiming
/// "verified-registry" status is actually registered.
///
/// # Arguments
///
/// * `agent_id` - The JACS agent ID (UUID format)
/// * `public_key_hash` - The SHA-256 hash of the agent's public key (hex encoded)
///
/// # Returns
///
/// * `Ok(RegistryRegistration)` - Agent is registered and public key matches
/// * `Err(JacsError)` - Verification failed with reason
///
/// # Environment Variables
///
/// * `JACS_REGISTRY_URL` - Registry API URL. No default -- returns an error if not configured.
///
/// # Errors
///
/// This function returns an error if:
/// - No registry URL is configured
/// - Registry API is unreachable (network error)
/// - Agent is not registered with the registry
/// - Public key hash doesn't match the registered key
///
/// # Example
///
/// ```rust,ignore
/// use jacs::dns::bootstrap::verify_registry_registration_sync;
///
/// let result = verify_registry_registration_sync(
///     "550e8400-e29b-41d4-a716-446655440000",
///     "sha256-hash-of-public-key"
/// );
///
/// match result {
///     Ok(reg) => println!("Agent verified at: {:?}", reg.verified_at),
///     Err(e) => println!("Verification failed: {}", e),
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_registry_registration_sync(
    agent_id: &str,
    public_key_hash: &str,
) -> Result<RegistryRegistration, JacsError> {
    // Validate agent_id is a valid UUID to prevent URL path traversal
    uuid::Uuid::parse_str(agent_id).map_err(|e| {
        JacsError::ValidationError(format!(
            "Invalid agent_id '{}' for registry registration: must be a valid UUID. {}",
            agent_id, e
        ))
    })?;

    // Registry API endpoint for agent verification
    let api_url = std::env::var("JACS_REGISTRY_URL").map_err(|_| {
        JacsError::ConfigError(
            "No registry URL configured. Set JACS_REGISTRY_URL to enable registry verification."
                .to_string(),
        )
    })?;
    let parsed = url::Url::parse(&api_url)
        .map_err(|e| JacsError::ConfigError(format!("Invalid JACS_REGISTRY_URL: {}", e)))?;
    let allow_loopback = crate::secure_fetch::is_exact_textual_loopback_endpoint(&api_url);
    crate::secure_fetch::validate_transport_url(&parsed, allow_loopback, "registry API")
        .map_err(|_| {
            JacsError::ConfigError(
                "JACS_REGISTRY_URL must use HTTPS. Only an exact textual loopback endpoint is allowed over HTTP for testing, and credentials/fragments are forbidden."
                    .to_string(),
            )
        })?;
    ensure_network_access(NetworkCapability::RegistryLookup)?;
    let url = format!("{}/v1/agents/{}", api_url.trim_end_matches('/'), agent_id);

    let policy = crate::secure_fetch::SecureFetchPolicy::new(
        "registry API",
        MAX_REGISTRY_RESPONSE_BYTES,
        &["application/json"],
    )
    .allow_exact_loopback(allow_loopback);
    let response =
        crate::secure_fetch::secure_get(&url, "application/json", &policy).map_err(|e| {
            JacsError::NetworkError(format!(
                "Registry verification failed: unable to reach configured API: {}",
                e
            ))
        })?;

    // Check response status
    if response.status == reqwest::StatusCode::NOT_FOUND {
        return Err(JacsError::RegistrationFailed {
            reason: format!(
                "Agent '{}' is not registered with the registry. \
                Agents claiming 'verified-registry' must be registered with a JACS registry.",
                agent_id
            ),
        });
    }

    if !response.status.is_success() {
        return Err(JacsError::NetworkError(format!(
            "Registry API returned error status {}: agent verification failed",
            response.status
        )));
    }

    // Parse response
    let api_response: RegistryApiResponse =
        jacs_core::strict_json::deserialize_strict_json_slice(&response.body).map_err(|e| {
            JacsError::NetworkError(format!("Failed to parse registry API response: {}", e))
        })?;

    // Verify the agent is actually verified
    if !api_response.verified {
        return Err(JacsError::RegistrationFailed {
            reason: format!(
                "Agent '{}' is registered with the registry but not yet verified. \
                Complete the verification process with your registry provider.",
                agent_id
            ),
        });
    }

    // Verify public key hash matches
    let registered_hash = api_response.public_key_hash.as_deref().unwrap_or("");
    if !registered_hash.eq_ignore_ascii_case(public_key_hash) {
        return Err(JacsError::RegistrationFailed {
            reason: format!(
                "Public key mismatch: agent '{}' is registered with the registry \
                but with a different public key. Expected hash '{}', got '{}'",
                agent_id,
                &public_key_hash[..public_key_hash.len().min(16)],
                &registered_hash[..registered_hash.len().min(16)]
            ),
        });
    }

    Ok(RegistryRegistration {
        verified: true,
        verified_at: api_response.verified_at,
        registration_type: api_response
            .registration_type
            .unwrap_or_else(|| "agent".to_string()),
        agent_id: api_response
            .agent_id
            .unwrap_or_else(|| agent_id.to_string()),
        public_key_hash: registered_hash.to_string(),
    })
}

pub fn dnssec_guidance(provider: &str) -> &'static str {
    match provider {
        "aws" | "route53" => {
            "Enable DNSSEC signing in Route53 hosted zone settings, then publish the DS record at your registrar."
        }
        "cloudflare" => {
            "DNSSEC is one-click in the Cloudflare dashboard under DNS > Settings. Copy the DS record to your registrar."
        }
        "azure" => {
            "Enable DNSSEC signing on the Azure DNS zone, then publish the DS record at your registrar."
        }
        "gcloud" | "google" => {
            "Enable DNSSEC on the Cloud DNS zone (gcloud dns managed-zones update --dnssec-state on), then publish DS at registrar."
        }
        _ => {
            "Enable DNSSEC zone signing with your DNS provider, then publish the DS record at your domain registrar."
        }
    }
}

/// Document integrity and DNS fingerprint agreement, not independent identity authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsVerificationResult {
    /// True only when the document signature and a matching raw-key DNS fingerprint verify.
    pub verified: bool,
    pub agent_id: String,
    pub domain: String,
    /// The signed document reference, which may use the frozen native legacy hash profile.
    pub document_hash: String,
    /// The separate raw-key SHA-256 fingerprint in its DNS-declared encoding.
    pub dns_hash: String,
    pub message: String,
}

fn dns_verification_input(
    agent_json: &str,
    domain: &str,
) -> Result<(serde_json::Value, DnsVerificationResult), JacsError> {
    let parsed = jacs_core::strict_json::parse_strict_json(agent_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "agent_json".into(),
            reason: format!("Invalid agent JSON: {e}"),
        }
    })?;
    let sig = parsed
        .get("jacsSignature")
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature".into(),
            reason: "Missing jacsSignature in agent document".into(),
        })?;
    let result = DnsVerificationResult {
        verified: false,
        agent_id: sig["agentID"].as_str().unwrap_or_default().into(),
        domain: domain.into(),
        document_hash: sig["publicKeyHash"].as_str().unwrap_or_default().into(),
        dns_hash: String::new(),
        message: String::new(),
    };
    Ok((parsed, result))
}

/// Resolve an exact-version public key from this DNS publisher, then verify the
/// document and raw-key DNS fingerprint separately. Network access remains opt-in;
/// configured DNSSEC strictness applies. Lookup failures produce `verified: false`.
/// This does not authorize the signer identity. Legacy v1 signatures are not
/// accepted by this integrity API and never authenticate an `agentDomain` hint.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_agent_dns(
    agent_json: &str,
    domain: &str,
) -> Result<DnsVerificationResult, JacsError> {
    let (parsed, mut result) = dns_verification_input(agent_json, domain)?;
    if result.document_hash.is_empty() {
        result.message = "Agent document has no publicKeyHash".into();
        return Ok(result);
    }
    let attempt = (|| {
        let agent = crate::agent::Agent::new("v1", "v1", "v1")?;
        let require_secure = agent.key_discovery_dns_strict();
        let key = crate::key_resolution::resolve_document_key_for_domain(
            &agent,
            &parsed,
            domain,
            require_secure,
        )?;
        verify_agent_dns_with_key(
            agent_json,
            domain,
            &key.public_key,
            &key.algorithm,
            require_secure,
        )
    })();
    match attempt {
        Ok(verified) => Ok(verified),
        Err(error) => {
            result.message = format!("DNS key discovery or verification failed: {error}");
            Ok(result)
        }
    }
}

/// Check a caller-selected raw public key against a signed v2 document and this
/// DNS publisher. `require_secure` requires locally validated DNSSEC proofs.
/// The document's legacy key reference is never used as the DNS fingerprint.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_agent_dns_with_key(
    agent_json: &str,
    domain: &str,
    public_key: &[u8],
    algorithm: &str,
    require_secure: bool,
) -> Result<DnsVerificationResult, JacsError> {
    verify_agent_dns_with_records(agent_json, domain, public_key, algorithm, |agent_id| {
        resolve_agent_txt_records(domain, agent_id, require_secure)
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_agent_dns_with_records(
    agent_json: &str,
    domain: &str,
    public_key: &[u8],
    algorithm: &str,
    records: impl FnOnce(&str) -> Result<Vec<AgentTxtFields>, JacsError>,
) -> Result<DnsVerificationResult, JacsError> {
    let (_, mut result) = dns_verification_input(agent_json, domain)?;
    let attempt = (|| {
        validate_agent_domain(domain)?;
        let report = crate::verification::NonSigningVerifier::new()?
            .verify_with_key(agent_json, public_key, algorithm, None)?;
        if !report.integrity_valid {
            return Err(JacsError::SignatureVerificationFailed {
                reason: format!("Document integrity failed: {}", report.errors.join("; ")),
            });
        }
        records(&result.agent_id)?
            .into_iter()
            .find(|record| {
                record.jacs_agent_id == result.agent_id
                    && record_matches_public_key(record, public_key)
            })
            .ok_or_else(|| JacsError::DnsRecordInvalid {
                domain: domain.into(),
                reason: "DNS fingerprint does not match the verified public key".into(),
            })
    })();
    match attempt {
        Ok(record) => {
            result.verified = true;
            result.dns_hash = record.digest;
            result.message = "Document signature and raw public-key DNS fingerprint verified; identity authorization is separate".into();
        }
        Err(error) => result.message = format!("DNS key verification failed: {error}"),
    }
    Ok(result)
}

pub fn tld_requirement_text() -> &'static str {
    "You must own a registered domain (TLD or subdomain of a TLD you control). Example: example.com or agents.example.com. The JACS TXT record is placed at _v1.agent.jacs.{your-domain}."
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[derive(Clone, Copy)]
    enum StubReply {
        Unsigned { forged_ad: bool },
        WrongQuestion,
        Malformed,
    }

    /// Only the local UDP socket is configured; never query public DNS.
    fn lookup_against_udp_stub(reply: StubReply, require_secure: bool) -> Result<String, String> {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
        use hickory_resolver::proto::op::{Message, OpCode, Query};
        use hickory_resolver::proto::rr::{Name, RData, Record, RecordType, rdata::TXT};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::Duration;

        let owner = "_v1.agent.jacs.example.test.";
        let text = build_agent_dns_txt("stub-agent", "stub-digest", DigestEncoding::Hex);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = stopped.clone();
        let observed = requests.clone();
        let expected = text.clone();
        let server = std::thread::spawn(move || {
            let mut packet = [0u8; 2048];
            while !stop.load(Ordering::Relaxed) {
                let Ok((length, peer)) = socket.recv_from(&mut packet) else {
                    continue;
                };
                observed.fetch_add(1, Ordering::Relaxed);
                let query = Message::from_vec(&packet[..length]).unwrap();
                if matches!(reply, StubReply::Malformed) {
                    socket.send_to(&[0, 1, 2], peer).unwrap();
                    continue;
                }
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.metadata.recursion_available = true;
                response.metadata.recursion_desired = query.metadata.recursion_desired;
                response.metadata.authentic_data =
                    matches!(reply, StubReply::Unsigned { forged_ad: true });
                if matches!(reply, StubReply::WrongQuestion) {
                    response.add_query(Query::query(
                        Name::from_ascii("different.test.").unwrap(),
                        RecordType::TXT,
                    ));
                } else {
                    response.add_queries(query.queries.clone());
                }
                // One logical TXT record with two wire chunks must concatenate.
                response.add_answer(Record::from_rdata(
                    Name::from_ascii(owner).unwrap(),
                    60,
                    RData::TXT(TXT::new(vec![
                        expected[..7].to_string(),
                        expected[7..].to_string(),
                    ])),
                ));
                socket.send_to(&response.to_vec().unwrap(), peer).unwrap();
            }
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let mut nameserver = NameServerConfig::udp(address.ip());
            nameserver.connections[0].port = address.port();
            let config = ResolverConfig::from_parts(None, vec![], vec![nameserver]);
            let mut options = ResolverOpts::default();
            options.timeout = Duration::from_millis(150);
            options.attempts = 1;
            options.try_tcp_on_error = false;
            options.case_randomization = false;
            let resolver = resolver_from_config(config, options, require_secure, owner).unwrap();
            match tokio::time::timeout(Duration::from_secs(2), resolver.txt_lookup(owner)).await {
                Ok(Ok(answer)) => txt_from_answers(answer.answers(), owner, require_secure)
                    .map_err(|e| e.to_string()),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("bounded loopback lookup timed out".to_string()),
            }
        });
        stopped.store(true, Ordering::Relaxed);
        server.join().unwrap();
        assert!(
            requests.load(Ordering::Relaxed) > 0,
            "must exercise actual UDP resolution"
        );
        result
    }

    #[test]
    fn actual_udp_lookup_rejects_unsigned_txt_even_with_forged_ad_bit() {
        let expected = build_agent_dns_txt("stub-agent", "stub-digest", DigestEncoding::Hex);
        for forged_ad in [false, true] {
            let reply = StubReply::Unsigned { forged_ad };
            assert_eq!(lookup_against_udp_stub(reply, false).unwrap(), expected);
            assert!(
                lookup_against_udp_stub(reply, true).is_err(),
                "AD is not a DNSSEC proof"
            );
        }
    }

    #[test]
    fn actual_udp_lookup_rejects_wrong_question_and_malformed_response() {
        for reply in [StubReply::WrongQuestion, StubReply::Malformed] {
            assert!(lookup_against_udp_stub(reply, false).is_err());
        }
    }

    #[test]
    fn resolver_requires_configured_name_servers_without_network_io() {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
        assert!(
            resolver_from_config(
                ResolverConfig::default(),
                ResolverOpts::default(),
                true,
                "example.test."
            )
            .is_err()
        );
        let configured = || {
            ResolverConfig::from_parts(
                None,
                vec![],
                vec![NameServerConfig::udp(
                    "127.0.0.1".parse().expect("loopback"),
                )],
            )
        };
        for require_secure in [false, true] {
            resolver_from_config(
                configured(),
                ResolverOpts::default(),
                require_secure,
                "example.test.",
            )
            .expect("configured resolver can be constructed without making a query");
        }
    }

    #[test]
    fn txt_answers_require_secure_proof_and_unambiguous_records() {
        use hickory_resolver::proto::dnssec::Proof;
        use hickory_resolver::proto::rr::{Name, RData, Record, rdata::TXT};
        let owner = "_v1.agent.jacs.example.test.";
        let text = build_agent_dns_txt("sample-agent", "sample-digest", DigestEncoding::Hex);
        let mut answer = Record::from_rdata(
            Name::from_ascii(owner).expect("owner"),
            60,
            RData::TXT(TXT::new(vec![text.clone()])),
        );
        answer.proof = Proof::Secure;
        assert_eq!(
            txt_from_answers(&[answer.clone()], owner, true).expect("secure TXT candidate"),
            text
        );
        assert!(txt_from_answers(&[answer.clone(), answer.clone()], owner, true).is_err());
        for proof in [Proof::Insecure, Proof::Bogus, Proof::Indeterminate] {
            answer.proof = proof;
            assert!(txt_from_answers(&[answer.clone()], owner, true).is_err());
        }
        assert_eq!(
            txt_from_answers(&[answer], owner, false).expect("explicit insecure discovery"),
            text
        );
    }

    #[test]
    fn rrset_preserves_chunk_boundaries_and_dnssec_for_every_record() {
        use hickory_resolver::proto::dnssec::Proof;
        use hickory_resolver::proto::rr::{Name, RData, Record, rdata::TXT};
        let owner = "_v1.agent.jacs.example.test.";
        let text = build_agent_dns_txt("agent", &pubkey_digest_b64(b"old"), DigestEncoding::Base64);
        let other = build_agent_dns_txt("agent", &pubkey_digest_hex(b"new"), DigestEncoding::Hex);
        let mut first = Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            60,
            RData::TXT(TXT::new(vec![
                text[..20].to_string(),
                text[20..].to_string(),
            ])),
        );
        let mut second = Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            60,
            RData::TXT(TXT::new(vec![other.clone()])),
        );
        first.proof = Proof::Secure;
        second.proof = Proof::Secure;
        assert_eq!(
            txt_records_from_answers(&[first.clone(), second.clone()], owner, true).unwrap(),
            vec![text, other]
        );
        second.proof = Proof::Bogus;
        assert!(txt_records_from_answers(&[first, second], owner, true).is_err());
    }

    #[test]
    fn signed_domain_and_dns_fingerprint_are_independent_verified_inputs() {
        use crate::simple::SimpleAgent;
        use serde_json::{Value, json};
        let (signer, info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let no_domain = signer
            .sign_message(&json!({"message": "no discovery hint"}))
            .unwrap();
        let old: Value = serde_json::from_str(&no_domain.raw).unwrap();
        assert!(old["jacsSignature"].get("agentDomain").is_none());
        {
            let mut agent = signer.agent.lock().unwrap();
            agent.config = Some(
                crate::config::Config::builder()
                    .key_algorithm("ring-Ed25519")
                    .default_storage("memory")
                    .agent_domain("https://keys.example.test/")
                    .build(),
            );
        }
        let signed = signer
            .sign_message(&json!({"message": "signed discovery hint"}))
            .unwrap();
        let mut document: Value = serde_json::from_str(&signed.raw).unwrap();
        assert_eq!(
            document["jacsSignature"]["agentDomain"],
            "keys.example.test"
        );
        let key = signer.get_public_key().unwrap();
        for source in [
            include_str!("../../schemas/components/signature/v1/signature.schema.json"),
            jacs_core::schema::EmbeddedSchemaResolver::lookup(
                "schemas/components/signature/v1/signature.schema.json",
            )
            .unwrap(),
        ] {
            let schema: Value = serde_json::from_str(source).unwrap();
            let validator = jsonschema::validator_for(&schema).unwrap();
            assert!(validator.is_valid(&old["jacsSignature"]));
            assert!(validator.is_valid(&document["jacsSignature"]));
        }
        assert!(
            jacs_core::verify::verify_document(
                &document,
                &key,
                jacs_core::sign::SigningAlgorithm::Ed25519,
                "jacsSignature"
            )
            .unwrap()
            .valid
        );
        let verifier = crate::verification::NonSigningVerifier::new().unwrap();
        assert!(
            verifier
                .verify_with_key(&no_domain.raw, &key, "ed25519", None)
                .unwrap()
                .integrity_valid
        );
        assert!(
            verifier
                .verify_with_key(&signed.raw, &key, "ed25519", None)
                .unwrap()
                .integrity_valid
        );
        for encoding in [DigestEncoding::Base64, DigestEncoding::Hex] {
            let digest = match encoding {
                DigestEncoding::Base64 => pubkey_digest_b64(&key),
                DigestEncoding::Hex => pubkey_digest_hex(&key),
            };
            let fields =
                parse_agent_txt(&build_agent_dns_txt(&info.agent_id, &digest, encoding)).unwrap();
            let result = verify_agent_dns_with_records(
                &signed.raw,
                "keys.example.test",
                &key,
                "ed25519",
                |_| Ok(vec![fields]),
            )
            .unwrap();
            assert!(result.verified, "{}", result.message);
            assert_eq!(result.dns_hash, digest);
            assert_eq!(result.document_hash, hash_public_key(&key));
        }
        let wrong_record = parse_agent_txt(&build_agent_dns_txt(
            &info.agent_id,
            &pubkey_digest_b64(b"wrong key"),
            DigestEncoding::Base64,
        ))
        .unwrap();
        assert!(
            !verify_agent_dns_with_records(
                &signed.raw,
                "keys.example.test",
                &key,
                "ed25519",
                |_| Ok(vec![wrong_record])
            )
            .unwrap()
            .verified
        );
        document["jacsSignature"]["agentDomain"] = json!("attacker.example.test");
        let tampered = serde_json::to_string(&document).unwrap();
        assert!(
            !verifier
                .verify_with_key(&tampered, &key, "ed25519", None)
                .unwrap()
                .signature_valid
        );
        let failed =
            verify_agent_dns_with_records(&tampered, "keys.example.test", &key, "ed25519", |_| {
                panic!("tampered signature must fail before DNS")
            });
        assert!(!failed.unwrap().verified);
        // A legacy profile never upgrades this metadata into an authenticated hint.
        document["jacsSignature"]["signatureContentVersion"] = json!("jacs-signature-v1");
        assert!(
            !verifier
                .verify_with_key(&document.to_string(), &key, "ed25519", None)
                .unwrap()
                .integrity_valid
        );
        for local in ["localhost", "http://127.0.0.1:8080/", "https://[::1]:8443/"] {
            signer.agent.lock().unwrap().config = Some(
                crate::config::Config::builder()
                    .key_algorithm("ring-Ed25519")
                    .default_storage("memory")
                    .agent_domain(local)
                    .build(),
            );
            let signed = signer
                .sign_message(&json!({"message": "local signing"}))
                .unwrap();
            let document: Value = serde_json::from_str(&signed.raw).unwrap();
            assert!(document["jacsSignature"].get("agentDomain").is_none());
            assert!(
                verifier
                    .verify_with_key(&signed.raw, &key, "ed25519", None)
                    .unwrap()
                    .integrity_valid
            );
        }
    }

    #[test]
    fn domain_hints_are_bare_bounded_hostnames() {
        assert_eq!(
            signing_agent_domain("https://keys.example.test/").unwrap(),
            Some("keys.example.test".into())
        );
        assert_eq!(
            signing_agent_domain("keys.example.test").unwrap(),
            Some("keys.example.test".into())
        );
        for origin in [
            "https://user@keys.example.test/",
            "https://keys.example.test/path",
            "https://keys.example.test/?x=1",
            "https://keys.example.test/#fragment",
            "https://keys.example.test/\0",
            "https://keys.example.test\\",
        ] {
            assert!(signing_agent_domain(origin).is_err(), "{origin}");
        }
        for local in [
            "localhost",
            "dev.localhost",
            "service.local",
            "127.0.0.1",
            "[::1]",
            "http://localhost:8080/",
            "https://127.0.0.1:8443/",
            "https://[::1]/",
            "http://keys.example.test/",
        ] {
            assert_eq!(signing_agent_domain(local).unwrap(), None, "{local}");
        }
        for domain in [
            "example.test",
            "keys.example.test.",
            "xn--bcher-kva.example",
        ] {
            assert!(validate_agent_domain(domain).is_ok(), "{domain}");
        }
        for domain in [
            "",
            "https://example.test",
            "example.test/path",
            "127.0.0.1",
            "[::1]",
            "-bad.example",
            "bad-.example",
            "a..example",
            "example.test..",
            "_bad.example",
        ] {
            assert!(validate_agent_domain(domain).is_err(), "{domain}");
        }
    }

    #[test]
    fn dns_txt_rejects_duplicate_fields() {
        let text = build_agent_dns_txt("sample-agent", "sample-digest", DigestEncoding::Hex);
        assert!(parse_agent_txt(&format!("{text}; alg=SHA-256")).is_err());
    }

    #[test]
    fn validate_dns_owner_accepts_normal_domain() {
        assert!(validate_dns_owner("_v1.agent.jacs.example.com.").is_ok());
        assert!(validate_dns_owner("example.com").is_ok());
    }

    #[test]
    fn validate_dns_owner_rejects_oversized_domain() {
        let label = "a".repeat(63);
        // Build a name with enough labels to exceed 253 bytes
        let oversized = format!("{0}.{0}.{0}.{0}.{0}", label);
        assert!(oversized.len() > 253);
        let err = validate_dns_owner(&oversized).unwrap_err().to_string();
        assert!(
            err.contains("exceeds 253 bytes"),
            "expected length-bound error, got: {err}"
        );
    }

    #[test]
    fn validate_dns_owner_rejects_oversized_label() {
        let label = "a".repeat(64);
        let bad = format!("{label}.example.com");
        let err = validate_dns_owner(&bad).unwrap_err().to_string();
        assert!(
            err.contains("label exceeds 63 bytes"),
            "expected label-bound error, got: {err}"
        );
    }

    #[test]
    fn validate_dns_owner_rejects_empty_label() {
        let err = validate_dns_owner("foo..bar").unwrap_err().to_string();
        assert!(
            err.contains("Empty DNS label"),
            "expected empty-label error, got: {err}"
        );
    }

    #[test]
    fn test_verify_agent_dns_invalid_json() {
        let result = verify_agent_dns("not json", "example.com");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid agent JSON"),
            "Expected 'Invalid agent JSON', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_verify_agent_dns_missing_signature() {
        let result = verify_agent_dns(r#"{"hello":"world"}"#, "example.com");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("jacsSignature"),
            "Expected 'jacsSignature' mention, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_verify_agent_dns_empty_hash() {
        let agent = r#"{"jacsSignature":{"agentID":"test-id","publicKeyHash":""}}"#;
        let result = verify_agent_dns(agent, "example.com").unwrap();
        assert!(!result.verified);
        assert_eq!(result.agent_id, "test-id");
        assert!(result.message.contains("no publicKeyHash"));
    }

    #[test]
    fn test_verify_agent_dns_invalid_identity_fails_without_lookup() {
        // An incomplete identity cannot trigger discovery or claim a hash match.
        let agent = r#"{"jacsSignature":{"agentID":"test-id","publicKeyHash":"abc123"}}"#;
        let result = verify_agent_dns(agent, "example.com").unwrap();
        assert!(!result.verified);
        assert_eq!(result.domain, "example.com");
        assert!(
            result
                .message
                .contains("DNS key discovery or verification failed"),
            "Expected DNS lookup failure, got: {}",
            result.message
        );
    }

    #[test]
    fn test_dnssec_guidance_known_providers() {
        for provider in &["aws", "route53", "cloudflare", "azure", "gcloud", "google"] {
            let text = dnssec_guidance(provider);
            assert!(
                !text.is_empty(),
                "guidance for {} should be non-empty",
                provider
            );
            assert!(
                text.contains("DNSSEC"),
                "guidance for {} should contain 'DNSSEC', got: {}",
                provider,
                text
            );
        }
    }

    #[test]
    fn test_dnssec_guidance_unknown_provider() {
        let text = dnssec_guidance("unknown-provider");
        assert!(text.contains("DNSSEC"));
        assert!(text.contains("DNS provider"));
    }

    #[test]
    fn test_tld_requirement_text() {
        let text = tld_requirement_text();
        assert!(!text.is_empty());
        assert!(text.contains("_v1.agent.jacs"));
    }

    // --- Task 010: DNS format is registry-agnostic ---

    #[test]
    fn test_build_agent_dns_txt_uses_jacs_version_tag() {
        let txt = build_agent_dns_txt("agent-123", "digest-abc", DigestEncoding::Base64);
        assert!(
            txt.starts_with("v=jacs;"),
            "TXT record must use v=jacs, got: {}",
            txt
        );
    }

    #[test]
    fn test_parse_agent_txt_accepts_jacs_version() {
        let txt = build_agent_dns_txt("a1", &pubkey_digest_b64(b"key"), DigestEncoding::Base64);
        let result = parse_agent_txt(&txt).unwrap();
        assert_eq!(result.v, "jacs");
    }

    #[test]
    fn test_parse_agent_txt_rejects_hai_ai_version() {
        // "hai.ai" is no longer accepted as a version tag in DNS TXT records
        let pubkey = b"test-public-key-bytes-for-digest";
        let digest = pubkey_digest_b64(pubkey);
        let agent_id = "test-agent-id";

        let txt = format!(
            "v=hai.ai; jacs_agent_id={}; alg=SHA-256; enc=base64; jac_public_key_hash={}",
            agent_id, digest
        );

        assert!(parse_agent_txt(&txt).is_err());
    }

    #[test]
    fn test_record_owner_uses_jacs_namespace() {
        let owner = record_owner("example.com");
        assert_eq!(owner, "_v1.agent.jacs.example.com.");
        assert!(
            !owner.contains("hai"),
            "DNS record owner must not contain hai references"
        );
    }

    #[test]
    fn test_dns_code_no_hai_references_in_txt_format() {
        // Verify the TXT record format is completely generic
        let txt = build_agent_dns_txt("my-agent", "my-digest", DigestEncoding::Hex);
        assert!(
            !txt.to_lowercase().contains("hai"),
            "TXT format must not contain hai references, got: {}",
            txt
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn test_registry_verification_requires_jacs_registry_url() {
        // Ensure HAI_API_URL is NOT used as a fallback
        // SAFETY: test-only env var manipulation; tests run serially for env var tests
        unsafe {
            std::env::remove_var("JACS_REGISTRY_URL");
            std::env::remove_var("HAI_API_URL");

            // Set only HAI_API_URL -- should NOT be picked up
            std::env::set_var("HAI_API_URL", "https://api.hai.ai");
        }

        let result =
            verify_registry_registration_sync("550e8400-e29b-41d4-a716-446655440000", "some-hash");
        assert!(result.is_err(), "Should fail without JACS_REGISTRY_URL");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("JACS_REGISTRY_URL"),
            "Error should mention JACS_REGISTRY_URL, got: {}",
            err_msg
        );

        // Cleanup
        unsafe {
            std::env::remove_var("HAI_API_URL");
        }
    }

    // --- H1 fix: find_jacs_txt_record filters non-JACS TXT records ---

    #[test]
    fn test_find_jacs_txt_record_mixed_spf_and_jacs() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "v=jacs; jacs_agent_id=a1; alg=SHA-256; enc=base64; jac_public_key_hash=abc"
                .to_string(),
        ];
        let result = find_jacs_txt_record(records, "example.com").unwrap();
        assert!(
            result.starts_with("v=jacs"),
            "Should return JACS record, got: {}",
            result
        );
        assert!(
            result.contains("jacs_agent_id=a1"),
            "Should contain agent ID, got: {}",
            result
        );
    }

    #[test]
    fn test_find_jacs_txt_record_no_jacs_record() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "google-site-verification=abc123".to_string(),
        ];
        let result = find_jacs_txt_record(records, "example.com");
        assert!(result.is_err(), "Should return error when no JACS record");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No v=jacs TXT record"),
            "Error should mention 'No v=jacs TXT record', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_find_jacs_txt_record_empty_records() {
        let records: Vec<String> = vec![];
        let result = find_jacs_txt_record(records, "example.com");
        assert!(result.is_err(), "Should return error for empty records");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No v=jacs TXT record"),
            "Error should mention 'No v=jacs TXT record', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_find_jacs_txt_record_jacs_among_garbage() {
        // JACS record between other unrelated TXT records
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "google-site-verification=abc123".to_string(),
            "v=jacs; jacs_agent_id=agent-42; alg=SHA-256; enc=hex; jac_public_key_hash=deadbeef"
                .to_string(),
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string(),
        ];
        let result = find_jacs_txt_record(records, "example.com").unwrap();
        assert!(
            result.contains("jacs_agent_id=agent-42"),
            "Should extract the JACS record, got: {}",
            result
        );
    }

    #[test]
    fn test_verify_pubkey_embedded_fallback_no_hai_references() {
        // Test that embedded fingerprint verification works without any hai.ai involvement
        let pubkey = b"test-key-for-embedded-verification";
        let digest = pubkey_digest_b64(pubkey);

        let result = verify_pubkey_via_dns_or_embedded(
            pubkey,
            "agent-123",
            None,          // no domain
            Some(&digest), // embedded fingerprint
            false,         // not strict
        );
        assert!(
            result.is_ok(),
            "Embedded verification should succeed: {:?}",
            result
        );
    }
}
