# Agent Schema

The Agent Schema defines signed identity documents for entities that can sign and verify JACS documents. Agents are cryptographic identities, not catalogs of services or contact records.

## Schema Location

```text
https://hai.ai/schemas/agent/v1/agent.schema.json
```

## Overview

Agent documents describe:

- Identity and versioning
- Agent type
- Optional DNS-based verification domain
- Public-key and signature metadata

Capabilities for A2A interoperability are represented in A2A Agent Cards instead of the JACS identity schema.

## Agent Types

The `jacsAgentType` field classifies the agent:

| Type | Description |
|------|-------------|
| `human` | Individual person |
| `human-org` | Organization or group |
| `hybrid` | Combination of human and AI components |
| `ai` | Fully artificial intelligence |

## Agent Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jacsId` | string (UUID) | Yes | Unique agent identifier |
| `jacsVersion` | string (UUID) | Yes | Current version identifier |
| `jacsVersionDate` | string (date-time) | Yes | Version timestamp |
| `jacsType` | string | Yes | Set to `agent` |
| `jacsOriginalVersion` | string (UUID) | Yes | First version identifier |
| `jacsOriginalDate` | string (date-time) | Yes | Creation timestamp |
| `jacsLevel` | string | Yes | Document level |
| `jacsAgentType` | string | Yes | Agent classification |
| `jacsAgentDomain` | string | No | Domain for DNS verification |
| `jacsSignature` | object | No | Cryptographic signature |
| `jacsSha256` | string | No | Content hash |

## DNS Verification

Agents can link to a domain for DNSSEC-validated verification:

```json
{
  "jacsAgentDomain": "example.com"
}
```

The domain should have a DNS TXT record at `_v1.agent.jacs.example.com.` containing the agent's public key fingerprint.

## Example

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsType": "agent",
  "jacsOriginalVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsOriginalDate": "2024-01-15T10:30:00Z",
  "jacsLevel": "artifact",
  "jacsAgentType": "ai",
  "jacsAgentDomain": "agent.example.com",
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "date": "2024-01-15T10:30:00Z",
    "signature": "base64-encoded-signature...",
    "publicKeyHash": "sha256-hash-of-public-key",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsId", "jacsVersion", "jacsAgentType", "jacsAgentDomain"]
  },
  "jacsSha256": "document-hash..."
}
```

## See Also

- [Document Schema](document.md)
- [DNS-Based Verification](../rust/dns.md)
- [A2A Interoperability](../integrations/a2a.md)
