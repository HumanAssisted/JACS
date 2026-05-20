# JSON Schemas

JACS schemas now describe a small portable signing surface instead of many narrow workflow document types. The core model is a generic signed JSON document: canonical JSON bytes, a common header, cryptographic signatures, signer identity, hashes, optional files, and optional multi-party agreements.

Application-specific payloads belong in the document body or in a custom schema layered on top of the header schema.

## Preserved Schemas

### Document and Agent Schemas

| Schema | Purpose |
|--------|---------|
| `header/v1/header.schema.json` | Generic signature wrapper for signed JSON documents |
| `agent/v1/agent.schema.json` | Agent identity and public signing metadata |
| `a2a-verification-result.schema.json` | Cross-language A2A artifact verification result |

### Component Schemas

| Schema | Purpose |
|--------|---------|
| `components/signature/v1/signature.schema.json` | Cryptographic signatures |
| `components/agreement/v1/agreement.schema.json` | Multi-party agreement metadata and co-signatures |
| `components/files/v1/files.schema.json` | File attachments and content hashes |

### Configuration Schema

| Schema | Purpose |
|--------|---------|
| `jacs.config.schema.json` | Agent configuration file format |

## Schema Locations

Schemas are available as HTTPS URLs and local files:

```text
https://hai.ai/schemas/header/v1/header.schema.json
https://hai.ai/schemas/agent/v1/agent.schema.json
https://hai.ai/schemas/components/signature/v1/signature.schema.json
https://hai.ai/schemas/components/agreement/v1/agreement.schema.json
https://hai.ai/schemas/components/files/v1/files.schema.json
https://hai.ai/schemas/jacs.config.schema.json
```

## Generic Signed Documents

Every signed document includes a `$schema` field. Generic payloads use the header schema directly:

```json
{
  "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsType": "document",
  "jacsLevel": "artifact",
  "content": {
    "invoice_id": "INV-001",
    "amount": 100.0
  }
}
```

Custom schemas may extend the header when an integration needs stronger payload validation:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/schemas/invoice.schema.json",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "content": {
          "type": "object",
          "required": ["invoice_id", "amount"]
        }
      }
    }
  ]
}
```

## Agreements

Use `jacsAgreement` on any generic signed document when multiple agents need to approve the same payload. Agreement metadata records the required signers, quorum, deadline, algorithm requirements, and collected signatures.

## HAI Extensions

JACS schemas include a custom `hai` property that categorizes fields:

| Value | Description |
|-------|-------------|
| `meta` | Metadata fields such as IDs, timestamps, and versions |
| `base` | Core cryptographic fields such as hashes and signatures |
| `agent` | Agent-controlled content fields |

These categories help determine which fields participate in hashing and signing.
