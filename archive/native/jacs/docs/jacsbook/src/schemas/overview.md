# JSON Schemas

JACS schemas now describe a small portable signing surface instead of many narrow workflow document types. The core model is a generic signed JSON document: canonical JSON bytes, a common header, cryptographic signatures, signer identity, hashes, optional files, and optional agreement semantics.

Application-specific payloads belong in the document body or in a custom schema layered on top of the header schema.

## Preserved Schemas

### Document and Agent Schemas

| Schema | Purpose |
|--------|---------|
| `header/v1/header.schema.json` | Generic signature wrapper for signed JSON documents |
| `agent/v1/agent.schema.json` | Agent identity and public signing metadata |
| `agreement/v2/agreement.schema.json` | Standalone compatibility agreement document for signature inspection |
| `a2a-verification-result.schema.json` | Cross-language A2A artifact verification result |

### Component Schemas

| Schema | Purpose |
|--------|---------|
| `components/signature/v1/signature.schema.json` | Cryptographic signatures |
| `components/agreement/v1/agreement.schema.json` | Legacy sidecar agreement metadata and co-signatures |
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
https://hai.ai/schemas/agreement/v2/agreement.schema.json
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

Native Agreement v2 represents standalone terms, parties and signature records, but its verifier reports mathematical checks only: `valid=false`, `policyAccepted=false`, `overallScope=consent_signatures_only`. Legacy `jacsAgreement` v1 countersignatures likewise do not authenticate participant, role, quorum, question or context policy.

For authenticated portable consent policy, use [Agreement v3](https://github.com/HumanAssisted/JACS/blob/main/jacs-core/README.md). Application authorization remains separate. The [native agreement reference](../rust/agreements.md) documents compatibility inspection.

## HAI Extensions

The schema's custom `hai` property categorizes fields as `meta`, `base` or `agent`. These annotations participate in native schema-driven hashing; they do not supply an authorization policy.
