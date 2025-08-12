use crate::crypt::hash::hash_public_key;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sha2::{Digest, Sha256};

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
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
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
    let v = map.get("v").cloned().ok_or("missing v field")?;
    let jacs_agent_id = map
        .get("jacs_agent_id")
        .cloned()
        .ok_or("missing jacs_agent_id")?;
    let alg = map.get("alg").cloned().ok_or("missing alg")?;
    let enc_val = map.get("enc").cloned().ok_or("missing enc")?;
    let enc = match enc_val.as_str() {
        "base64" => DigestEncoding::Base64,
        "hex" => DigestEncoding::Hex,
        _ => return Err(format!("unsupported enc: {}", enc_val)),
    };
    let digest = map
        .get("jac_public_key_hash")
        .cloned()
        .ok_or("missing jac_public_key_hash")?;
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
        .map_err(|e| format!("resolver init: {e}"))?;
    let resp = resolver
        .txt_lookup(owner)
        .map_err(|e| format!("lookup: {e}"))?;
    let mut s = String::new();
    for rr in resp.iter() {
        for part in rr.txt_data() {
            s.push_str(&String::from_utf8(part.to_vec()).map_err(|e| format!("utf8: {e}"))?);
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
        .map_err(|e| format!("resolver init: {e}"))?;
    let resp = resolver
        .txt_lookup(owner)
        .map_err(|e| format!("lookup: {e}"))?;
    let mut s = String::new();
    for rr in resp.iter() {
        for part in rr.txt_data() {
            s.push_str(&String::from_utf8(part.to_vec()).map_err(|e| format!("utf8: {e}"))?);
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
                    return Err(format!("unexpected v field: {}", f.v));
                }
                if f.jacs_agent_id != agent_id {
                    return Err("agent id mismatch".to_string());
                }
                let ok = match f.enc {
                    DigestEncoding::Base64 => f.digest == local_b64,
                    DigestEncoding::Hex => f.digest.eq_ignore_ascii_case(&local_hex),
                };
                if ok {
                    return Ok(());
                } else {
                    return Err("DNS fingerprint mismatch".to_string());
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
                    return Err("embedded fingerprint mismatch (embedded present but does not match local public key)".to_string());
                }
                // Neither DNS nor embedded available
                if strict_dns {
                    return Err(format!(
                        "strict DNSSEC validation failed for {} (TXT not authenticated). Enable DNSSEC and publish DS at registrar",
                        owner
                    ));
                } else {
                    return Err(format!(
                        "DNS TXT lookup failed for {} (record missing or not yet propagated)",
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

    Err("DNS TXT lookup required (domain configured) or provide embedded fingerprint".to_string())
}
