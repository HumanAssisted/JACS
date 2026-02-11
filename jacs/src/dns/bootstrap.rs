use crate::crypt::hash::{hash_bytes_raw, hash_public_key};
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
        "v=hai.ai; jacs_agent_id={}; alg=SHA-256; enc={}; jac_public_key_hash={}",
        agent_id, enc_str, digest
    )
}

pub fn parse_agent_txt(txt: &str) -> Result<AgentTxtFields, String> {
    let parts: Vec<&str> = txt.split(';').map(|s| s.trim()).collect();
    let mut map = std::collections::HashMap::new();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        if let Some((k, v)) = p.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let v = map.get("v").cloned().ok_or("Missing v field")?;
    let jacs_agent_id = map
        .get("jacs_agent_id")
        .cloned()
        .ok_or("Missing jacs_agent_id field")?;
    let alg = map.get("alg").cloned().ok_or("Missing alg field")?;
    let enc_val = map.get("enc").cloned().ok_or("Missing enc field")?;
    let enc = match enc_val.as_str() {
        "base64" => DigestEncoding::Base64,
        "hex" => DigestEncoding::Hex,
        _ => return Err(format!("Unsupported encoding: {}", enc_val)),
    };
    let digest = map
        .get("jac_public_key_hash")
        .cloned()
        .ok_or("Missing jac_public_key_hash field")?;
    Ok(AgentTxtFields {
        v,
        jacs_agent_id,
        alg,
        enc,
        digest,
    })
}

pub fn record_owner(domain: &str) -> String {
    format!("_v1.agent.jacs.{}.", domain.trim_end_matches('.'))
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

#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_txt_dnssec(owner: &str) -> Result<String, String> {
    use hickory_resolver::Resolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    let resolver = Resolver::new(ResolverConfig::default(), opts)
        .map_err(|e| format!("Resolver init failed: {e}"))?;
    let resp = resolver
        .txt_lookup(owner)
        .map_err(|e| format!("DNS lookup failed: {e}"))?;
    let mut s = String::new();
    for rr in resp.iter() {
        for part in rr.txt_data() {
            s.push_str(
                &String::from_utf8(part.to_vec())
                    .map_err(|e| format!("UTF-8 decode failed: {e}"))?,
            );
        }
    }
    Ok(s)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_txt_insecure(owner: &str) -> Result<String, String> {
    use hickory_resolver::Resolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    let mut opts = ResolverOpts::default();
    opts.validate = false; // allow unsigned answers
    let resolver = Resolver::new(ResolverConfig::default(), opts)
        .map_err(|e| format!("Resolver init failed: {e}"))?;
    let resp = resolver
        .txt_lookup(owner)
        .map_err(|e| format!("DNS lookup failed: {e}"))?;
    let mut s = String::new();
    for rr in resp.iter() {
        for part in rr.txt_data() {
            s.push_str(
                &String::from_utf8(part.to_vec())
                    .map_err(|e| format!("UTF-8 decode failed: {e}"))?,
            );
        }
    }
    Ok(s)
}

pub fn verify_pubkey_via_dns_or_embedded(
    agent_public_key: &[u8],
    agent_id: &str,
    jacs_agent_domain: Option<&str>,
    embedded_fingerprint: Option<&str>,
    strict_dns: bool,
) -> Result<(), String> {
    let local_b64 = pubkey_digest_b64(agent_public_key);
    let local_hex = pubkey_digest_hex(agent_public_key);

    if let Some(domain) = jacs_agent_domain {
        let owner = record_owner(domain);
        let lookup = if strict_dns {
            resolve_txt_dnssec(&owner)
        } else {
            resolve_txt_insecure(&owner)
        };
        match lookup {
            Ok(txt) => {
                let f = parse_agent_txt(&txt)?;
                if f.v != "hai.ai" {
                    return Err(format!("Unexpected v field: {}", f.v));
                }
                if f.jacs_agent_id != agent_id {
                    return Err("Agent ID mismatch".to_string());
                }
                let ok = match f.enc {
                    DigestEncoding::Base64 => f.digest == local_b64,
                    DigestEncoding::Hex => f.digest.eq_ignore_ascii_case(&local_hex),
                };
                if ok {
                    return Ok(());
                } else {
                    return Err(
                        "DNS fingerprint mismatch: digest does not match local public key"
                            .to_string(),
                    );
                }
            }
            Err(_e) => {
                // Fallback to embedded if provided
                if let Some(embed) = embedded_fingerprint {
                    // Accept either the new byte-based digest or the legacy normalized-string hex
                    let legacy_hex = hash_public_key(agent_public_key.to_vec());
                    if embed == local_b64
                        || embed.eq_ignore_ascii_case(&local_hex)
                        || embed.eq_ignore_ascii_case(&legacy_hex)
                    {
                        return Ok(());
                    }
                    return Err(
                        "Embedded fingerprint mismatch: does not match local public key"
                            .to_string(),
                    );
                }
                // Neither DNS nor embedded available
                if strict_dns {
                    return Err(format!(
                        "Strict DNSSEC validation failed for {}: TXT not authenticated. Enable DNSSEC and publish DS at registrar",
                        owner
                    ));
                } else {
                    return Err(format!(
                        "DNS TXT lookup failed for {}: record missing or not yet propagated",
                        owner
                    ));
                }
            }
        }
    }

    if let Some(embed) = embedded_fingerprint {
        let legacy_hex = hash_public_key(agent_public_key.to_vec());
        if embed == local_b64
            || embed.eq_ignore_ascii_case(&local_hex)
            || embed.eq_ignore_ascii_case(&legacy_hex)
        {
            return Ok(());
        }
        return Err(
            "embedded fingerprint mismatch (embedded present but does not match local public key)"
                .to_string(),
        );
    }

    Err("DNS TXT lookup required: domain configured or provide embedded fingerprint".to_string())
}

// =============================================================================
// HAI.ai Registration Verification
// =============================================================================

/// Information about an agent's HAI.ai registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaiRegistration {
    /// Whether the agent is verified by HAI.ai
    pub verified: bool,
    /// ISO 8601 timestamp of when the agent was verified
    pub verified_at: Option<String>,
    /// Type of registration (e.g., "agent", "organization")
    pub registration_type: String,
    /// The agent ID as registered with HAI.ai
    pub agent_id: String,
    /// The public key hash registered with HAI.ai
    pub public_key_hash: String,
}

/// Response from HAI.ai API for agent lookup
#[derive(Clone, Debug, Deserialize)]
struct HaiApiResponse {
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

/// Check if an agent is registered with HAI.ai.
///
/// This function queries the HAI.ai API to verify that an agent claiming
/// "verified-hai.ai" status is actually registered.
///
/// # Arguments
///
/// * `agent_id` - The JACS agent ID (UUID format)
/// * `public_key_hash` - The SHA-256 hash of the agent's public key (hex encoded)
///
/// # Returns
///
/// * `Ok(HaiRegistration)` - Agent is registered and public key matches
/// * `Err(String)` - Verification failed with reason
///
/// # Errors
///
/// This function returns an error if:
/// - HAI.ai API is unreachable (network error)
/// - Agent is not registered with HAI.ai
/// - Public key hash doesn't match the registered key
///
/// # Example
///
/// ```rust,ignore
/// use jacs::dns::bootstrap::verify_hai_registration_sync;
///
/// let result = verify_hai_registration_sync(
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
pub fn verify_hai_registration_sync(
    agent_id: &str,
    public_key_hash: &str,
) -> Result<HaiRegistration, String> {
    // Validate agent_id is a valid UUID to prevent URL path traversal
    uuid::Uuid::parse_str(agent_id).map_err(|e| {
        format!(
            "Invalid agent_id '{}' for HAI registration: must be a valid UUID. {}",
            agent_id, e
        )
    })?;

    // HAI.ai API endpoint for agent verification
    let api_url = std::env::var("HAI_API_URL").unwrap_or_else(|_| "https://api.hai.ai".to_string());
    let parsed = url::Url::parse(&api_url)
        .map_err(|e| format!("Invalid HAI_API_URL '{}': {}", api_url, e))?;
    let host = parsed.host_str().unwrap_or_default();
    let http_localhost = parsed.scheme() == "http"
        && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1");
    if parsed.scheme() != "https" && !http_localhost {
        return Err(format!(
            "HAI_API_URL must use HTTPS (got '{}'). Only localhost URLs are allowed over HTTP for testing.",
            api_url
        ));
    }
    let url = format!("{}/v1/agents/{}", api_url.trim_end_matches('/'), agent_id);

    // Build blocking HTTP client with TLS
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    // Make request to HAI.ai API
    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| {
            format!(
                "HAI.ai verification failed: unable to reach API at {}: {}",
                url, e
            )
        })?;

    // Check response status
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "Agent '{}' is not registered with HAI.ai. \
            Agents claiming 'verified-hai.ai' must be registered at https://hai.ai",
            agent_id
        ));
    }

    if !response.status().is_success() {
        return Err(format!(
            "HAI.ai API returned error status {}: agent verification failed",
            response.status()
        ));
    }

    // Parse response
    let api_response: HaiApiResponse = response
        .json()
        .map_err(|e| format!("Failed to parse HAI.ai API response: {}", e))?;

    // Verify the agent is actually verified
    if !api_response.verified {
        return Err(format!(
            "Agent '{}' is registered with HAI.ai but not yet verified. \
            Complete the verification process at https://hai.ai",
            agent_id
        ));
    }

    // Verify public key hash matches
    let registered_hash = api_response.public_key_hash.as_deref().unwrap_or("");
    if !registered_hash.eq_ignore_ascii_case(public_key_hash) {
        return Err(format!(
            "Public key mismatch: agent '{}' is registered with HAI.ai \
            but with a different public key. Expected hash '{}', got '{}'",
            agent_id,
            &public_key_hash[..public_key_hash.len().min(16)],
            &registered_hash[..registered_hash.len().min(16)]
        ));
    }

    Ok(HaiRegistration {
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
        "aws" | "route53" => "Enable DNSSEC signing in Route53 hosted zone settings, then publish the DS record at your registrar.",
        "cloudflare" => "DNSSEC is one-click in the Cloudflare dashboard under DNS > Settings. Copy the DS record to your registrar.",
        "azure" => "Enable DNSSEC signing on the Azure DNS zone, then publish the DS record at your registrar.",
        "gcloud" | "google" => "Enable DNSSEC on the Cloud DNS zone (gcloud dns managed-zones update --dnssec-state on), then publish DS at registrar.",
        _ => "Enable DNSSEC zone signing with your DNS provider, then publish the DS record at your domain registrar.",
    }
}

/// Result of verifying an agent's identity via DNS TXT record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsVerificationResult {
    /// Whether the DNS record matches the agent's public key hash.
    pub verified: bool,
    /// The agent ID extracted from the agent document.
    pub agent_id: String,
    /// The domain that was checked.
    pub domain: String,
    /// The public key hash from the agent document.
    pub document_hash: String,
    /// The public key hash from the DNS TXT record (empty if lookup failed).
    pub dns_hash: String,
    /// Human-readable status message.
    pub message: String,
}

/// Verify an agent's DNS TXT record matches its public key hash.
///
/// Parses the agent JSON to extract `jacsSignature.publicKeyHash` and `jacsSignature.agentID`,
/// then looks up the DNS TXT record at `_v1.agent.jacs.{domain}` and compares the hashes.
///
/// # Arguments
/// * `agent_json` - Full agent JSON document string
/// * `domain` - Domain to check (e.g., "example.com")
///
/// # Returns
/// `Ok(DnsVerificationResult)` with match status. Never returns `Err` for DNS failures;
/// those are reported via `verified: false` in the result.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_agent_dns(agent_json: &str, domain: &str) -> Result<DnsVerificationResult, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(agent_json).map_err(|e| format!("Invalid agent JSON: {}", e))?;

    let sig = parsed.get("jacsSignature").ok_or("Missing jacsSignature in agent document")?;
    let agent_id = sig
        .get("agentID")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let doc_hash = sig
        .get("publicKeyHash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if doc_hash.is_empty() {
        return Ok(DnsVerificationResult {
            verified: false,
            agent_id,
            domain: domain.to_string(),
            document_hash: doc_hash,
            dns_hash: String::new(),
            message: "Agent document has no publicKeyHash".to_string(),
        });
    }

    let owner = record_owner(domain);
    let txt = match resolve_txt_insecure(&owner) {
        Ok(t) => t,
        Err(e) => {
            return Ok(DnsVerificationResult {
                verified: false,
                agent_id,
                domain: domain.to_string(),
                document_hash: doc_hash,
                dns_hash: String::new(),
                message: format!("DNS lookup failed for {}: {}", owner, e),
            });
        }
    };

    let fields = match parse_agent_txt(&txt) {
        Ok(f) => f,
        Err(e) => {
            return Ok(DnsVerificationResult {
                verified: false,
                agent_id,
                domain: domain.to_string(),
                document_hash: doc_hash,
                dns_hash: String::new(),
                message: format!("Failed to parse DNS TXT record: {}", e),
            });
        }
    };

    // Compare agent IDs
    if !agent_id.is_empty() && fields.jacs_agent_id != agent_id {
        let msg = format!(
            "Agent ID mismatch: document={}, dns={}",
            agent_id, fields.jacs_agent_id
        );
        return Ok(DnsVerificationResult {
            verified: false,
            agent_id,
            domain: domain.to_string(),
            document_hash: doc_hash,
            dns_hash: fields.digest.clone(),
            message: msg,
        });
    }

    // Compare hashes (support both base64 and hex encodings)
    let matched = match fields.enc {
        DigestEncoding::Base64 => fields.digest == doc_hash,
        DigestEncoding::Hex => fields.digest.eq_ignore_ascii_case(&doc_hash),
    };

    Ok(DnsVerificationResult {
        verified: matched,
        agent_id,
        domain: domain.to_string(),
        document_hash: doc_hash,
        dns_hash: fields.digest,
        message: if matched {
            "DNS public key hash matches agent document".to_string()
        } else {
            "DNS public key hash does NOT match agent document".to_string()
        },
    })
}

pub fn tld_requirement_text() -> &'static str {
    "You must own a registered domain (TLD or subdomain of a TLD you control). Example: example.com or agents.example.com. The JACS TXT record is placed at _v1.agent.jacs.{your-domain}."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_agent_dns_invalid_json() {
        let result = verify_agent_dns("not json", "example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid agent JSON"));
    }

    #[test]
    fn test_verify_agent_dns_missing_signature() {
        let result = verify_agent_dns(r#"{"hello":"world"}"#, "example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing jacsSignature"));
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
    fn test_verify_agent_dns_no_record() {
        // example.com won't have a JACS TXT record
        let agent = r#"{"jacsSignature":{"agentID":"test-id","publicKeyHash":"abc123"}}"#;
        let result = verify_agent_dns(agent, "example.com").unwrap();
        assert!(!result.verified);
        assert_eq!(result.domain, "example.com");
        assert!(
            result.message.contains("DNS lookup failed"),
            "Expected DNS lookup failure, got: {}",
            result.message
        );
    }

    #[test]
    fn test_dnssec_guidance_known_providers() {
        for provider in &["aws", "route53", "cloudflare", "azure", "gcloud", "google"] {
            let text = dnssec_guidance(provider);
            assert!(!text.is_empty(), "guidance for {} should be non-empty", provider);
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
}
