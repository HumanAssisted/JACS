# JSON Schemas

JACS uses JSON Schema (Draft-07) to define the structure and validation rules for all documents in the system. These schemas ensure consistency, enable validation, and provide a contract for interoperability between agents.

## Schema Architecture

JACS schemas follow a hierarchical composition pattern:

```
┌─────────────────────────────────────────────────────────┐
│                    Document Schemas                      │
│  (agent.schema.json, task.schema.json, message.schema.json)  │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Header Schema                          │
│              (header.schema.json)                        │
│  Base fields: jacsId, jacsVersion, jacsSignature, etc.  │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                 Component Schemas                        │
│   signature.schema.json, agreement.schema.json,         │
│   files.schema.json, embedding.schema.json, etc.        │
└─────────────────────────────────────────────────────────┘
```

## Schema Categories

### Configuration Schema

| Schema | Purpose |
|--------|---------|
| `jacs.config.schema.json` | Agent configuration file format |

### Document Schemas

| Schema | Purpose |
|--------|---------|
| `header/v1/header.schema.json` | Base fields for all JACS documents |
| `agent/v1/agent.schema.json` | Agent identity and capabilities |
| `task/v1/task.schema.json` | Task workflow and state management |
| `message/v1/message.schema.json` | Inter-agent messages |
| `node/v1/node.schema.json` | Graph node representation |
| `program/v1/program.schema.json` | Executable program definitions |
| `eval/v1/eval.schema.json` | Evaluation and assessment records |
| `agentstate/v1/agentstate.schema.json` | Signed agent state files (memory, skills, plans, configs, hooks, other) |

### Component Schemas

| Schema | Purpose |
|--------|---------|
| `signature/v1/signature.schema.json` | Cryptographic signatures |
| `agreement/v1/agreement.schema.json` | Multi-party agreements |
| `files/v1/files.schema.json` | File attachments |
| `embedding/v1/embedding.schema.json` | Vector embeddings |
| `contact/v1/contact.schema.json` | Contact information |
| `service/v1/service.schema.json` | Service definitions |
| `tool/v1/tool.schema.json` | Tool capabilities |
| `action/v1/action.schema.json` | Action definitions |
| `unit/v1/unit.schema.json` | Unit of measurement |

## Schema Locations

Schemas are available at:

- **HTTPS URLs**: `https://hai.ai/schemas/...`
- **Local files**: `jacs/schemas/...`

Example schema URLs:
```
https://hai.ai/schemas/jacs.config.schema.json
https://hai.ai/schemas/header/v1/header.schema.json
https://hai.ai/schemas/agent/v1/agent.schema.json
https://hai.ai/schemas/components/signature/v1/signature.schema.json
```

## Using Schemas

### In Documents

Every JACS document must include a `$schema` field:

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsType": "agent",
  ...
}
```

### In Configuration Files

Reference the config schema for IDE support:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  ...
}
```

### Custom Schema Validation

Validate documents against custom schemas:

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create document with custom schema
doc = agent.create_document(
    json.dumps({'invoice_id': 'INV-001', 'amount': 100.00}),
    custom_schema='./schemas/invoice.schema.json'
)
```

```javascript
import { JacsAgent } from 'jacsnpm';

const agent = new JacsAgent();
agent.load('./jacs.config.json');

// Create document with custom schema
const doc = agent.createDocument(
  JSON.stringify({ invoice_id: 'INV-001', amount: 100.00 }),
  './schemas/invoice.schema.json'
);
```

## HAI Extensions

JACS schemas include a custom `hai` property that categorizes fields:

| Value | Description |
|-------|-------------|
| `meta` | Metadata fields (IDs, dates, versions) |
| `base` | Core cryptographic fields (hashes, signatures) |
| `agent` | Agent-controlled content fields |

This categorization helps determine which fields should be included in hash calculations and signature operations.

## Versioning

Schemas are versioned using directory paths:

```
schemas/
├── header/
│   └── v1/
│       └── header.schema.json
├── agent/
│   └── v1/
│       └── agent.schema.json
└── components/
    └── signature/
        └── v1/
            └── signature.schema.json
```

Configuration options allow specifying schema versions:

```json
{
  "jacs_agent_schema_version": "v1",
  "jacs_header_schema_version": "v1",
  "jacs_signature_schema_version": "v1"
}
```

## Schema Composition

Document schemas use JSON Schema's `allOf` to compose the header with type-specific fields:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "jacsAgentType": { ... },
        "jacsServices": { ... }
      }
    }
  ]
}
```

This ensures all documents share common header fields while allowing type-specific extensions.

## Creating Custom Schemas

Create custom schemas that extend JACS schemas:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/schemas/invoice.schema.json",
  "title": "Invoice",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "invoiceNumber": {
          "type": "string",
          "description": "Unique invoice identifier"
        },
        "amount": {
          "type": "number",
          "minimum": 0,
          "description": "Invoice amount"
        },
        "currency": {
          "type": "string",
          "enum": ["USD", "EUR", "GBP"],
          "default": "USD"
        },
        "lineItems": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "description": { "type": "string" },
              "quantity": { "type": "integer", "minimum": 1 },
              "unitPrice": { "type": "number", "minimum": 0 }
            },
            "required": ["description", "quantity", "unitPrice"]
          }
        }
      },
      "required": ["invoiceNumber", "amount"]
    }
  ]
}
```

## Validation Rules

### Required Fields

All JACS documents require these header fields:
- `jacsId` - Unique document identifier (UUID v4)
- `jacsType` - Document type identifier
- `jacsVersion` - Version identifier (UUID v4)
- `jacsVersionDate` - Version timestamp (ISO 8601)
- `jacsOriginalVersion` - First version identifier
- `jacsOriginalDate` - Creation timestamp
- `jacsLevel` - Document level (raw, config, artifact, derived)
- `$schema` - Schema reference URL

### Format Validation

Fields use JSON Schema format keywords:
- `uuid` - UUID v4 format
- `date-time` - ISO 8601 date-time format
- `uri` - Valid URI format

### Enum Constraints

Many fields have enumerated valid values:

```json
{
  "jacsLevel": {
    "enum": ["raw", "config", "artifact", "derived"]
  },
  "jacsAgentType": {
    "enum": ["human", "human-org", "hybrid", "ai"]
  },
  "jacs_agent_key_algorithm": {
    "enum": ["RSA-PSS", "ring-Ed25519", "pq-dilithium", "pq2025"]
  }
}
```

## Schema Reference

For detailed documentation on specific schemas:

- [Agent Schema](agent.md) - Agent identity and capabilities
- [Document Schema](document.md) - Document header and structure
- [Task Schema](task.md) - Task workflow management
- [Agent State Schema](agentstate.md) - Signed agent state documents
- [Configuration](configuration.md) - Configuration file format

## See Also

- [Custom Schemas](../advanced/custom-schemas.md) - Creating custom document types
- [Security Model](../advanced/security.md) - How schemas relate to security
- [API Reference](../python/api.md) - Using schemas in code
