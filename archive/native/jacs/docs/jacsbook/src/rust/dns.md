# DNS-Based Agent Verification

JACS compares an agent's public-key fingerprint with a TXT record at
`_v1.agent.jacs.<domain>`. Strict mode also validates DNSSEC. Domain control,
cryptographic integrity and application trust are separate decisions.

## Publishing Agent Identity

### Generate DNS Commands

```bash
# Generate DNS TXT record commands for your agent
jacs-compat agent dns --domain myagent.example.com

# Specify agent ID explicitly
jacs-compat agent dns --domain myagent.example.com --agent-id 550e8400-e29b-41d4-a716-446655440000

# Use hex encoding instead of base64
jacs-compat agent dns --domain myagent.example.com --encoding hex

# Set custom TTL (time-to-live)
jacs-compat agent dns --domain myagent.example.com --ttl 7200
```

### Provider-Specific Formats

JACS can generate DNS commands for various providers:

```bash
# Plain text format (default)
jacs-compat agent dns --domain myagent.example.com --provider plain

# AWS Route 53 format
jacs-compat agent dns --domain myagent.example.com --provider aws

# Azure DNS format
jacs-compat agent dns --domain myagent.example.com --provider azure

# Cloudflare DNS format
jacs-compat agent dns --domain myagent.example.com --provider cloudflare
```

### DNS Record Structure

The DNS TXT record follows this format:
```
_v1.agent.jacs.myagent.example.com. 3600 IN TXT "v=jacs; jacs_agent_id=<agent-uuid>; alg=SHA-256; enc=base64; jac_public_key_hash=<digest>"
```

Where:
- `_v1.agent.jacs.` is the JACS-specific subdomain prefix
- `<digest>` is standard Base64 of SHA-256 over the raw public-key bytes
- `jacs_agent_id` must match the agent ID; for hex use `enc=hex`
- Do not substitute a JWK thumbprint or the native legacy signature key hash

### Setting Up with Route 53 (AWS)

1. Generate the record and Route 53 change-batch JSON:

```bash
jacs-compat agent dns --domain myagent.example.com --provider aws
```

2. Save only the JSON following `Route53 change-batch JSON:` to `change-batch.json`, inspect its identity/domain/fingerprint, then apply it to your hosted zone:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id YOUR_ZONE_ID --change-batch file://change-batch.json
```

The JACS output also includes headings and a BIND record; it is not an executable shell script or a raw JSON file. Do not pipe it to `eval`.

### Setting Up with Cloudflare

1. Generate the Cloudflare-formatted command:
```bash
jacs-compat agent dns --domain myagent.example.com --provider cloudflare
```

2. Or add manually in the Cloudflare dashboard:
   - Type: `TXT`
   - Name: `_v1.agent.jacs`
   - Content: `v=jacs; jacs_agent_id=<agent-uuid>; alg=SHA-256; enc=base64; jac_public_key_hash=<digest>`
   - TTL: 3600

### Setting Up with Azure DNS

1. Generate the Azure-formatted command:
```bash
jacs-compat agent dns --domain myagent.example.com --provider azure
```

2. Inspect the Azure command and supply your resource group and DNS zone before running it. The output also contains headings and a BIND record.

## Verifying Agents with DNS

### Look Up Another Agent

```bash
# Look up an agent by their domain
jacs-compat agent lookup other-agent.example.com

# With strict DNSSEC validation
jacs-compat agent lookup other-agent.example.com --strict

# Skip DNS verification (not recommended)
jacs-compat agent lookup other-agent.example.com --no-dns
```

### Verify Agent with DNS

When verifying an agent, you can specify DNS requirements:

```bash
# Default: persisted DNS settings, otherwise defaults follow domain presence
jacs-compat agent verify

# Require DNS validation (non-strict)
jacs-compat agent verify --require-dns

# Require strict DNSSEC validation
jacs-compat agent verify --require-strict-dns

# Attempt DNS, with an embedded-fingerprint fallback
jacs-compat agent verify --no-dns

# Disable DNS checks entirely
jacs-compat agent verify --ignore-dns
```

These `agent verify` commands load the identity selected by the native config.
Verified claims force strict, required DNS validation. The lookup command has
its own `--no-dns` option; do not confuse it with the agent-verification modes.

## DNS Validation Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Default | (none) | Use persisted settings; otherwise a domain enables and requires DNS |
| Require DNS | `--require-dns` | Fail if DNS record not found (DNSSEC not required) |
| Require Strict | `--require-strict-dns` | Fail if DNSSEC validation fails |
| Optional DNS | `--no-dns` | Attempt DNS; allow embedded-fingerprint fallback |
| Ignore DNS | `--ignore-dns` | Skip DNS validation entirely |

## Agent Domain Configuration

Agents can specify their domain in their agent document:

```json
{
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsAgentType": "ai",
  "jacsAgentDomain": "myagent.example.com"
}
```

The `jacsAgentDomain` field is optional but enables DNS-based verification.

## DNSSEC Requirements

For maximum security, enable DNSSEC on your domain:

1. **Enable DNSSEC at your registrar**: Most registrars support DNSSEC
2. **Configure your DNS provider**: Ensure your DNS provider signs zones
3. **Use `--require-strict-dns`**: Enforce DNSSEC validation

### Checking DNSSEC Status

You can verify DNSSEC is working using standard tools:

```bash
# Check if DNSSEC is enabled
dig +dnssec _v1.agent.jacs.myagent.example.com TXT

# Verify DNSSEC validation
delv @8.8.8.8 _v1.agent.jacs.myagent.example.com TXT
```

## Security Considerations

### Trust Model

- **With DNSSEC**: Full cryptographic chain of trust from root DNS servers
- **Without DNSSEC**: Trust depends on DNS infrastructure security
- **Local Only**: Trust is limited to having the correct public key

### Best Practices

1. **Always enable DNSSEC** for production agents
2. **Use strict validation** when verifying unknown agents
3. **Rotate keys carefully** - update DNS records before key changes
4. **Monitor DNS records** for unauthorized changes
5. **Use short TTLs during transitions** then increase for stability

### Caching

DNS responses are cached based on TTL. Consider:
- **Short TTL (300-600s)**: Better for development or key rotation
- **Long TTL (3600-86400s)**: Better for production stability

## Troubleshooting

### "DNS record not found"

1. Verify the record exists:
```bash
dig _v1.agent.jacs.myagent.example.com TXT
```

2. Check DNS propagation (may take up to 48 hours for new records)

3. Verify the domain in the agent document matches

### "DNSSEC validation failed"

1. Check DNSSEC is enabled:
```bash
dig +dnssec myagent.example.com
```

2. Verify DS records at registrar

3. Use `--require-dns` instead of `--require-strict-dns` if DNSSEC isn't available

### "Fingerprint mismatch"

1. The public key may have changed - regenerate DNS record:
```bash
jacs-compat agent dns --domain myagent.example.com
```

2. Update the DNS TXT record with the new fingerprint

3. Wait for DNS propagation

## Integration with CI/CD

Generate the provider output from the configured agent, inspect it, then apply
it using your DNS provider's authenticated tooling:

```bash
jacs-compat agent dns --domain "$AGENT_DOMAIN" --provider aws
```

The command prints explanatory text, the BIND record and provider data; its
stdout is not an executable shell script. Copy the Route 53 change-batch JSON
into a reviewed `dns-change.json`, then submit it explicitly:

```bash
aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch file://dns-change.json
jacs-compat agent verify --require-strict-dns
```

Account for DNS TTL and propagation before switching a trusted key. Exactly one
JACS TXT record is supported at a discovery name; duplicate matching records
are rejected. Historical key evidence belongs in the versioned trust store.

## Next Steps

- [Creating an Agent](agent.md) - Set up agents with DNS domains
- [Security Model](../advanced/security.md) - Deep dive into JACS security
- [Agreements](agreements.md) - Use DNS-verified agents in agreements
