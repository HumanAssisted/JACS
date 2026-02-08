# Document Schema

The Document Schema (Header Schema) defines the base structure for all JACS documents. Every JACS document type (agents, tasks, messages, etc.) extends this schema.

## Schema Location

```
https://hai.ai/schemas/header/v1/header.schema.json
```

## Overview

The header schema provides:
- **Unique Identification**: Every document has a unique ID and version
- **Version Tracking**: Full history with previous version references
- **Cryptographic Integrity**: Signatures and hashes for verification
- **File Attachments**: Support for embedded or linked files
- **Vector Embeddings**: Pre-computed embeddings for semantic search
- **Agreements**: Multi-party signature support

## Core Fields

### Identification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `$schema` | string | Yes | Schema URL for validation |
| `jacsId` | string (UUID) | Yes | Unique document identifier |
| `jacsType` | string | Yes | Document type (agent, task, etc.) |

```json
{
  "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsType": "document"
}
```

### Versioning

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jacsVersion` | string (UUID) | Yes | Current version identifier |
| `jacsVersionDate` | string (date-time) | Yes | Version creation timestamp |
| `jacsPreviousVersion` | string (UUID) | No | Previous version (if not first) |
| `jacsOriginalVersion` | string (UUID) | Yes | First version identifier |
| `jacsOriginalDate` | string (date-time) | Yes | Document creation timestamp |
| `jacsBranch` | string (UUID) | No | Branch identifier for JACS databases |

```json
{
  "jacsVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsPreviousVersion": "e36ac10b-58cc-4372-a567-0e02b2c3d478",
  "jacsOriginalVersion": "a47ac10b-58cc-4372-a567-0e02b2c3d476",
  "jacsOriginalDate": "2024-01-01T09:00:00Z"
}
```

### Document Level

The `jacsLevel` field indicates the intended use:

| Level | Description |
|-------|-------------|
| `raw` | Raw data that should not change |
| `config` | Configuration meant to be updated |
| `artifact` | Generated content that may be updated |
| `derived` | Computed from other documents |

```json
{
  "jacsLevel": "artifact"
}
```

## Cryptographic Fields

### Signature

The `jacsSignature` field contains the creator's cryptographic signature:

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

#### Signature Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agentID` | string (UUID) | Yes | Signing agent's ID |
| `agentVersion` | string (UUID) | Yes | Signing agent's version |
| `date` | string (date-time) | Yes | Signing timestamp |
| `signature` | string | Yes | Base64-encoded signature |
| `publicKeyHash` | string | Yes | Hash of public key used |
| `signingAlgorithm` | string | No | Algorithm used (ring-Ed25519, RSA-PSS, pq-dilithium) |
| `fields` | array | Yes | Fields included in signature |
| `response` | string | No | Text response with signature |
| `responseType` | string | No | agree, disagree, or reject |

### Registration

The `jacsRegistration` field contains a signature from a registration authority:

```json
{
  "jacsRegistration": {
    "agentID": "registrar-agent-id",
    "agentVersion": "registrar-version",
    "date": "2024-01-15T10:35:00Z",
    "signature": "registrar-signature",
    "publicKeyHash": "registrar-key-hash",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsId", "jacsSignature"]
  }
}
```

### Hash

The `jacsSha256` field contains a SHA-256 hash of all document content (excluding this field):

```json
{
  "jacsSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

## Agreements

Documents can include multi-party agreements using `jacsAgreement`:

```json
{
  "jacsAgreement": {
    "agentIDs": [
      "agent-1-uuid",
      "agent-2-uuid",
      "agent-3-uuid"
    ],
    "question": "Do you agree to these terms?",
    "context": "Q1 2024 Service Agreement",
    "signatures": [
      {
        "agentID": "agent-1-uuid",
        "signature": "...",
        "responseType": "agree",
        "date": "2024-01-15T11:00:00Z"
      }
    ]
  },
  "jacsAgreementHash": "hash-of-content-at-agreement-time"
}
```

### Agreement Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agentIDs` | array | Yes | Required signers |
| `question` | string | No | What parties are agreeing to |
| `context` | string | No | Additional context |
| `signatures` | array | No | Collected signatures |

## File Attachments

Documents can include file attachments using `jacsFiles`:

```json
{
  "jacsFiles": [
    {
      "mimetype": "application/pdf",
      "path": "./documents/contract.pdf",
      "embed": true,
      "contents": "base64-encoded-file-contents",
      "sha256": "file-content-hash"
    },
    {
      "mimetype": "image/png",
      "path": "./images/diagram.png",
      "embed": false,
      "sha256": "file-content-hash"
    }
  ]
}
```

### File Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mimetype` | string | Yes | MIME type of the file |
| `path` | string | Yes | File location (local path) |
| `embed` | boolean | Yes | Whether to embed contents |
| `contents` | string | No | Base64-encoded file contents |
| `sha256` | string | No | Hash for content verification |

## Vector Embeddings

Documents can include pre-computed embeddings for semantic search:

```json
{
  "jacsEmbedding": [
    {
      "llm": "text-embedding-ada-002",
      "vector": [0.0023, -0.0089, 0.0156, ...]
    }
  ]
}
```

### Embedding Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `llm` | string | Yes | Model used for embedding |
| `vector` | array | Yes | Vector of numbers |

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

  "title": "Sample Document",
  "content": "This is the document content.",

  "jacsFiles": [
    {
      "mimetype": "application/pdf",
      "path": "./attachment.pdf",
      "embed": false,
      "sha256": "abc123..."
    }
  ],

  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "date": "2024-01-15T10:30:00Z",
    "signature": "signature-base64...",
    "publicKeyHash": "key-hash...",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsId", "jacsVersion", "title", "content"]
  },

  "jacsSha256": "document-hash..."
}
```

## HAI Field Categories

Fields include a `hai` property indicating their category:

| Category | Description | Examples |
|----------|-------------|----------|
| `meta` | Metadata (IDs, dates) | jacsId, jacsVersion, jacsVersionDate |
| `base` | Cryptographic data | jacsSha256, signature |
| `agent` | Agent-controlled content | Custom content fields |

This categorization determines which fields are included in hash and signature calculations.

## Working with Documents

### Creating Documents

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create a basic document
doc = agent.create_document(json.dumps({
    'title': 'My Document',
    'content': 'Document content here'
}))
```

```javascript
import { JacsAgent } from '@hai-ai/jacs';

const agent = new JacsAgent();
agent.load('./jacs.config.json');

const doc = agent.createDocument(JSON.stringify({
  title: 'My Document',
  content: 'Document content here'
}));
```

### Verifying Documents

```python
is_valid = agent.verify_document(doc_json)
```

```javascript
const isValid = agent.verifyDocument(docJson);
```

### Updating Documents

```python
doc = json.loads(signed_doc)
document_key = f"{doc['jacsId']}:{doc['jacsVersion']}"

updated = agent.update_document(
    document_key,
    json.dumps({**doc, 'content': 'Updated content'})
)
```

```javascript
const doc = JSON.parse(signedDoc);
const documentKey = `${doc.jacsId}:${doc.jacsVersion}`;

const updated = agent.updateDocument(
  documentKey,
  JSON.stringify({...doc, content: 'Updated content'})
);
```

### Adding Attachments

```python
doc = agent.create_document(
    json.dumps({'title': 'Report'}),
    attachments='./report.pdf',
    embed=True
)
```

```javascript
const doc = agent.createDocument(
  JSON.stringify({ title: 'Report' }),
  null,    // custom_schema
  null,    // output_filename
  false,   // no_save
  './report.pdf',  // attachments
  true     // embed
);
```

## Version History

Documents maintain a version chain:

```
Original (v1) ← Previous (v2) ← Current (v3)
     │
     └── jacsOriginalVersion points here for all versions
```

Each version:
- Has its own `jacsVersion` UUID
- References `jacsPreviousVersion` (except the first)
- All share the same `jacsId` and `jacsOriginalVersion`

## See Also

- [Agent Schema](agent.md) - Agent document structure
- [Task Schema](task.md) - Task document structure
- [Working with Documents](../rust/documents.md) - Document operations guide
- [Agreements](../rust/agreements.md) - Multi-party agreements
