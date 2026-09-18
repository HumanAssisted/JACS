# Document Schema

The Document Schema is the generic header/signature wrapper for JACS documents. It is intentionally payload-agnostic: applications can sign arbitrary JSON content while preserving the same hashing, signature, agreement, and verification contracts across languages.

## Schema Location

```text
https://hai.ai/schemas/header/v1/header.schema.json
```

## Overview

The header schema provides:

- Unique document and version identifiers
- Version history through previous-version references
- Cryptographic signatures and hashes
- Optional file attachments
- Optional multi-party agreements

## Core Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `$schema` | string | Yes | Schema URL for validation |
| `jacsId` | string (UUID) | Yes | Unique document identifier |
| `jacsType` | string | Yes | Document type, commonly `document` for generic payloads |
| `jacsVersion` | string (UUID) | Yes | Current version identifier |
| `jacsVersionDate` | string (date-time) | Yes | Version creation timestamp |
| `jacsOriginalVersion` | string (UUID) | Yes | First version identifier |
| `jacsOriginalDate` | string (date-time) | Yes | Document creation timestamp |
| `jacsLevel` | string | Yes | Intended document level |
| `jacsSignature` | object | No | Creator signature |
| `jacsSha256` | string | No | Canonical content hash |

## Document Level

| Level | Description |
|-------|-------------|
| `raw` | Raw data that should not change |
| `config` | Configuration meant to be updated |
| `artifact` | Generated content that may be updated |
| `derived` | Computed from other documents |

## Signatures

`jacsSignature` contains the signing agent, timestamp, algorithm, public key hash, fields signed, and signature bytes.

```json
{
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "date": "2024-01-15T10:30:00Z",
    "signature": "base64-encoded-signature-string",
    "publicKeyHash": "sha256-hash-of-public-key",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsId", "jacsVersion", "jacsType", "content"]
  }
}
```

## Agreements

Any signed document can include `jacsAgreement` for multi-party approval.

```json
{
  "jacsAgreement": {
    "agentIDs": [
      "agent-1-uuid",
      "agent-2-uuid"
    ],
    "question": "Do you approve this payload?",
    "context": "Deployment approval",
    "quorum": 2,
    "signatures": []
  },
  "jacsAgreementHash": "hash-of-content-at-agreement-time"
}
```

## File Attachments

Documents can include file attachments using `jacsFiles`:

```json
{
  "jacsFiles": [
    {
      "mimetype": "application/pdf",
      "path": "./documents/contract.pdf",
      "embed": false,
      "sha256": "file-content-hash"
    }
  ]
}
```

## Complete Example

```json
{
  "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsType": "document",
  "jacsVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsOriginalVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsOriginalDate": "2024-01-15T10:30:00Z",
  "jacsLevel": "artifact",
  "content": {
    "title": "Sample Document",
    "body": "This is arbitrary signed JSON content."
  },
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "date": "2024-01-15T10:30:00Z",
    "signature": "signature-base64...",
    "publicKeyHash": "public-key-hash...",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["$schema", "jacsId", "jacsType", "jacsVersion", "content"]
  },
  "jacsSha256": "document-hash..."
}
```
