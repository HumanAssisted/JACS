# DNS-Based Agent Verification

JACS supports DNS-based agent verification using DNS TXT records and DNSSEC. This allows agents to publish their identity in a decentralized, verifiable way that doesn't require a central authority.

## Overview

DNS verification in JACS works by:
1. Publishing an agent's public key fingerprint as a DNS TXT record
2. Using DNSSEC to cryptographically verify the DNS response
3. Comparing the fingerprint from DNS with the agent's actual public key

This provides a secure, decentralized way to verify agent identity across the internet.

## Why DNS Verification?

- **Decentralized**: No central authority required
- **Existing Infrastructure**: Uses established DNS infrastructure
- **DNSSEC Security**: Cryptographic verification of DNS responses
- **Human-Readable**: Agents can be identified by domain names
- **Widely Supported**: Works with any DNS provider

## Publishing Agent Identity

### Generate DNS Commands

```bash
# Generate DNS TXT record commands for your agent
jacs agent dns --domain myagent.example.com

# Specify agent ID explicitly
jacs agent dns --domain myagent.example.com --agent-id 550e8400-e29b-41d4-a716-446655440000

# Use hex encoding instead of base64
jacs agent dns --domain myagent.example.com --encoding hex

# Set custom TTL (time-to-live)
jacs agent dns --domain myagent.example.com --ttl 7200
```

### Provider-Specific Formats

JACS can generate DNS commands for various providers:

```bash
# Plain text format (default)
jacs agent dns --domain myagent.example.com --provider plain

# AWS Route 53 format
jacs agent dns --domain myagent.example.com --provider aws

# Azure DNS format
jacs agent dns --domain myagent.example.com --provider azure

# Cloudflare DNS format
jacs agent dns --domain myagent.example.com --provider cloudflare
```

### DNS Record Structure

The DNS TXT record follows this format:
```
_v1.agent.jacs.myagent.example.com. 3600 IN TXT "jacs-agent-fingerprint=<fingerprint>"
```

Where:
- `_v1.agent.jacs.` is the JACS-specific subdomain prefix
- `<fingerprint>` is the base64-encoded hash of the agent's public key

### Setting Up with Route 53 (AWS)

1. Generate the AWS-formatted command:
```bash
jacs agent dns --domain myagent.example.com --provider aws
```

2. The output will include an AWS CLI command like:
```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id YOUR_ZONE_ID \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "_v1.agent.jacs.myagent.example.com",
        "Type": "TXT",
        "TTL": 3600,
        "ResourceRecords": [{"Value": "\"jacs-agent-fingerprint=...\""}]
      }
    }]
  }'
```

3. Replace `YOUR_ZONE_ID` with your actual Route 53 hosted zone ID.

### Setting Up with Cloudflare

1. Generate the Cloudflare-formatted command:
```bash
jacs agent dns --domain myagent.example.com --provider cloudflare
```

2. Or add manually in the Cloudflare dashboard:
   - Type: `TXT`
   - Name: `_v1.agent.jacs`
   - Content: `jacs-agent-fingerprint=<your-fingerprint>`
   - TTL: 3600

### Setting Up with Azure DNS

1. Generate the Azure-formatted command:
```bash
jacs agent dns --domain myagent.example.com --provider azure
```

2. The output will include an Azure CLI command that you can run directly.

## Verifying Agents with DNS

### Look Up Another Agent

```bash
# Look up an agent by their domain
jacs agent lookup other-agent.example.com

# With strict DNSSEC validation
jacs agent lookup other-agent.example.com --strict

# Skip DNS verification (not recommended)
jacs agent lookup other-agent.example.com --no-dns
```

### Verify Agent with DNS

When verifying an agent, you can specify DNS requirements:

```bash
# Default: Use DNS if available, but don't require it
jacs agent verify -a ./agent.json

# Require DNS validation (non-strict)
jacs agent verify -a ./agent.json --require-dns

# Require strict DNSSEC validation
jacs agent verify -a ./agent.json --require-strict-dns

# Disable DNS validation entirely
jacs agent verify -a ./agent.json --no-dns

# Ignore DNS (won't fail if DNS unavailable)
jacs agent verify -a ./agent.json --ignore-dns
```

## DNS Validation Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Default | (none) | Use DNS if available, fall back to local verification |
| Require DNS | `--require-dns` | Fail if DNS record not found (DNSSEC not required) |
| Require Strict | `--require-strict-dns` | Fail if DNSSEC validation fails |
| No DNS | `--no-dns` | Skip DNS validation entirely |
| Ignore DNS | `--ignore-dns` | Don't fail on DNS errors, just warn |

## Agent Domain Configuration

Agents can specify their domain in their agent document:

```json
{
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsAgentType": "ai",
  "jacsAgentDomain": "myagent.example.com",
  "jacsServices": [...]
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
jacs agent dns --domain myagent.example.com
```

2. Update the DNS TXT record with the new fingerprint

3. Wait for DNS propagation

## Integration with CI/CD

Automate DNS updates in your deployment pipeline:

```bash
#!/bin/bash
# deploy-agent.sh

# 1. Create new agent keys
jacs agent create --create-keys true

# 2. Generate DNS update command
DNS_CMD=$(jacs agent dns --domain $AGENT_DOMAIN --provider aws)

# 3. Execute DNS update
eval $DNS_CMD

# 4. Wait for propagation
sleep 60

# 5. Verify DNS is working
jacs agent verify --require-dns
```

## Next Steps

- [Creating an Agent](agent.md) - Set up agents with DNS domains
- [Security Model](../advanced/security.md) - Deep dive into JACS security
- [Agreements](agreements.md) - Use DNS-verified agents in agreements
