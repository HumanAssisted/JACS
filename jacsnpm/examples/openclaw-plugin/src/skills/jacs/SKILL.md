---
name: jacs
description: Cryptographic document signing and verification with JACS
user-invocable: true
metadata: {"openclaw":{"requires":{"config":["plugins.entries.jacs.enabled"]}}}
---

# JACS Cryptographic Provenance

Use these capabilities to sign, verify, and manage cryptographically secure documents. All signatures use post-quantum cryptography by default.

## Available Tools

| Tool | Purpose |
|------|---------|
| `jacs_sign` | Sign a document with your JACS identity |
| `jacs_verify` | Verify a signed document's authenticity (self-signed) |
| `jacs_verify_auto` | **Seamlessly verify any signed document** (auto-fetches keys) |
| `jacs_fetch_pubkey` | Fetch another agent's public key from their domain |
| `jacs_verify_with_key` | Verify a document using a specific public key |
| `jacs_dns_lookup` | Look up an agent's DNS TXT record for verification |
| `jacs_lookup_agent` | Get complete info about an agent (DNS + public key) |
| `jacs_create_agreement` | Create multi-party signing agreements |
| `jacs_sign_agreement` | Add your signature to an agreement |
| `jacs_check_agreement` | Check which parties have signed |
| `jacs_hash` | Create a cryptographic hash of content |
| `jacs_identity` | Get your JACS identity information |

## Usage Examples

### Sign a document

```
Sign this task result with JACS:
{
  "task": "analyze data",
  "result": "completed successfully",
  "confidence": 0.95
}
```

### Verify your own document

```
Verify this signed document is authentic:
{paste signed JSON document}
```

### Verify a document from another agent

```
Fetch the public key for agent.example.com and verify this document they sent:
{paste signed JSON document from other agent}
```

This will:
1. Fetch the public key from https://agent.example.com/.well-known/jacs-pubkey.json
2. Verify the document signature using that key

### Create a multi-party agreement

```
Create an agreement for these agents to sign:
- agent1-id
- agent2-id

Document: {the document requiring signatures}
Question: "Do you approve this proposal?"
```

### Get my identity

```
What is my JACS identity?
```

## Security Notes

- All signatures use post-quantum cryptography (ML-DSA-87/pq2025) by default
- Private keys are encrypted at rest with AES-256-GCM using PBKDF2 key derivation
- Chain of custody is maintained for multi-agent workflows
- Documents include version UUIDs and timestamps to prevent replay attacks

## CLI Commands

You can also use these commands directly:

- `openclaw jacs init` - Initialize JACS with key generation
- `openclaw jacs sign <file>` - Sign a document file
- `openclaw jacs verify <file>` - Verify a signed document
- `openclaw jacs status` - Show agent status
- `openclaw jacs hash <string>` - Hash a string
- `openclaw jacs dns-record <domain>` - Generate DNS TXT record
- `openclaw jacs lookup <domain>` - Look up another agent's public key and DNS info

The standalone JACS CLI also supports lookup:
- `jacs agent lookup <domain>` - Look up agent info (with `--strict` for DNSSEC validation)

## Public Endpoints

Your agent exposes these well-known endpoints:

- `/.well-known/jacs-pubkey.json` - Your public key (for verification)
- `/jacs/status` - Health check endpoint
- `/jacs/verify` - Public verification endpoint
- `/jacs/sign` - Authenticated signing endpoint

Other agents can discover you by looking up your DNS TXT record at `_v1.agent.jacs.{your-domain}`
