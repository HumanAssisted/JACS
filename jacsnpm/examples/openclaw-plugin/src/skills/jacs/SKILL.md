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
| `jacs_verify` | Verify a signed document's authenticity |
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

### Verify a document

```
Verify this signed document is authentic:
{paste signed JSON document}
```

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

## Public Endpoints

Your agent exposes these well-known endpoints:

- `/.well-known/jacs-pubkey.json` - Your public key (for verification)
- `/jacs/status` - Health check endpoint
- `/jacs/verify` - Public verification endpoint
- `/jacs/sign` - Authenticated signing endpoint

Other agents can discover you by looking up your DNS TXT record at `_v1.agent.jacs.{your-domain}`
