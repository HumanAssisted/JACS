# Core Concepts

JACS is a portable signing and verification system for JSON documents. Its main primitive is a verifiable JSON envelope: canonical bytes, schema-declared structure, content hash, signer identity, signing algorithm, and cryptographic signature.

## Agents

An **Agent** is an identity that can create, sign, and verify documents.

```json
{
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "123e4567-e89b-12d3-a456-426614174000",
  "jacsType": "agent",
  "jacsAgentType": "ai",
  "jacsAgentDomain": "agent.example.com"
}
```

Agents have stable IDs, versioned identity documents, and cryptographic keys. A2A capabilities are represented through A2A Agent Cards.

## Documents

A **Document** is any JSON object signed with the JACS header/signature wrapper.

```json
{
  "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
  "jacsId": "doc-uuid-here",
  "jacsVersion": "version-uuid-here",
  "jacsType": "document",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsLevel": "artifact",
  "content": {
    "title": "Analyze Q4 Sales Data",
    "description": "Generate insights from sales data"
  },
  "jacsSha256": "hash-of-document-content",
  "jacsSignature": {
    "agentID": "agent-uuid",
    "agentVersion": "agent-version-uuid",
    "signature": "base64-signature",
    "signingAlgorithm": "ring-Ed25519",
    "publicKeyHash": "hash-of-public-key",
    "date": "2024-01-15T10:30:00Z",
    "fields": ["$schema", "jacsId", "jacsVersion", "jacsType", "content"]
  }
}
```

Application-specific meaning belongs inside the payload or in a custom schema that extends the header.

## Agreements

Agreements collect multiple signatures over the same document payload.

```json
{
  "jacsAgreement": {
    "agentIDs": ["agent-1-uuid", "agent-2-uuid"],
    "question": "Do you approve this change?",
    "context": "Deployment approval",
    "quorum": 2,
    "signatures": []
  },
  "jacsAgreementHash": "hash-of-agreement-content"
}
```

An agreement is complete when the required signatures and quorum rules are satisfied.

## Verification

When consuming signed documents, verify in one of two ways:

- With a loaded agent: call `verify(signedDocument)` using the configured trust store and key resolution.
- Without loading an agent: call `verify_standalone(signedDocument, options)` with explicit key-resolution options.

## Cryptographic Security

JACS signs canonical JSON bytes. Verification checks the content hash, signature fields, signer identity, algorithm, and public key.

Supported algorithms:

| Algorithm | Description |
|-----------|-------------|
| `ring-Ed25519` | Fast elliptic curve signatures |
| `pq2025` | Post-quantum ML-DSA-87 signatures |
