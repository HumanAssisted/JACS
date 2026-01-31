# Working with Documents

Documents are the core data structure in JACS. Any JSON object can become a JACS document by adding the required header fields and a cryptographic signature.

## What is a JACS Document?

A JACS document is a JSON object that includes:
- **Identity**: Unique ID and version tracking
- **Metadata**: Type, timestamps, and origin information
- **Signature**: Cryptographic proof of authenticity
- **Hash**: Integrity verification

## Creating Documents

### From a JSON File

Create a simple JSON document (`my-document.json`):

```json
{
  "title": "Project Proposal",
  "description": "Q1 development plan",
  "budget": 50000,
  "deadline": "2024-03-31"
}
```

Sign it with JACS:

```bash
jacs document create -f my-document.json
```

This adds JACS headers and signature, producing a signed document.

### From a Directory

Process multiple documents at once:

```bash
jacs document create -d ./documents/
```

### With Custom Schema

Validate against a custom JSON schema:

```bash
jacs document create -f my-document.json -s ./schemas/proposal.schema.json
```

### Output Options

```bash
# Save to specific file
jacs document create -f my-document.json -o ./output/signed-doc.json

# Print to stdout instead of saving
jacs document create -f my-document.json --no-save

# Verbose output
jacs document create -f my-document.json -v
```

## Document Structure

After signing, a document looks like:

```json
{
  "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
  "jacsId": "doc-uuid-here",
  "jacsVersion": "version-uuid-here",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsOriginalVersion": "version-uuid-here",
  "jacsOriginalDate": "2024-01-15T10:30:00Z",
  "jacsType": "document",
  "jacsLevel": "artifact",

  "title": "Project Proposal",
  "description": "Q1 development plan",
  "budget": 50000,
  "deadline": "2024-03-31",

  "jacsSha256": "a1b2c3d4...",
  "jacsSignature": {
    "agentID": "agent-uuid",
    "agentVersion": "agent-version-uuid",
    "signature": "base64-signature",
    "signingAlgorithm": "ring-Ed25519",
    "publicKeyHash": "hash-of-public-key",
    "date": "2024-01-15T10:30:00Z",
    "fields": ["jacsId", "title", "description", "budget", "deadline"]
  }
}
```

## Required Header Fields

| Field | Description | Auto-generated |
|-------|-------------|----------------|
| `$schema` | JSON Schema reference | Yes |
| `jacsId` | Permanent document UUID | Yes |
| `jacsVersion` | Version UUID (changes on update) | Yes |
| `jacsVersionDate` | When this version was created | Yes |
| `jacsOriginalVersion` | First version UUID | Yes |
| `jacsOriginalDate` | Original creation timestamp | Yes |
| `jacsType` | Document type | Yes |
| `jacsLevel` | Data level (raw, config, artifact, derived) | Yes |

## Document Levels

The `jacsLevel` field indicates the document's purpose:

| Level | Description | Use Case |
|-------|-------------|----------|
| `raw` | Original data, should not change | Source documents |
| `config` | Configuration, meant to be updated | Agent definitions, settings |
| `artifact` | Generated output | Reports, summaries |
| `derived` | Computed from other documents | Analysis results |

## File Attachments

### Attach Files

```bash
# Attach a single file
jacs document create -f my-document.json --attach ./report.pdf

# Attach a directory of files
jacs document create -f my-document.json --attach ./attachments/
```

### Embed vs. Reference

```bash
# Embed files directly in the document (larger document, self-contained)
jacs document create -f my-document.json --attach ./files/ --embed true

# Reference files (smaller document, files stored separately)
jacs document create -f my-document.json --attach ./files/ --embed false
```

### Attachment Structure

Embedded attachments appear in the `jacsFiles` field:

```json
{
  "jacsFiles": [
    {
      "jacsFileName": "report.pdf",
      "jacsFileMimeType": "application/pdf",
      "jacsFileSha256": "file-hash",
      "jacsFileContent": "base64-encoded-content"
    }
  ]
}
```

## Verifying Documents

### Basic Verification

```bash
jacs document verify -f ./signed-document.json
```

Verification checks:
1. Hash integrity (document hasn't been modified)
2. Signature validity (signature matches content)
3. Schema compliance (if schema specified)

### Verify with Schema

```bash
jacs document verify -f ./document.json -s ./schema.json
```

### Verify Directory

```bash
jacs document verify -d ./documents/
```

### Verbose Output

```bash
jacs document verify -f ./document.json -v
```

## Updating Documents

Updates create a new version while maintaining the same `jacsId`:

```bash
jacs document update -f ./original.json -n ./modified.json
```

The update process:
1. Reads the original document
2. Applies changes from the modified file
3. Increments `jacsVersion`
4. Links to previous version via `jacsPreviousVersion`
5. Re-signs with agent's key

### Update with Attachments

```bash
jacs document update -f ./original.json -n ./modified.json --attach ./new-file.pdf
```

## Extracting Embedded Content

Extract attachments from a document:

```bash
jacs document extract -f ./document-with-attachments.json
```

Extract from multiple documents:

```bash
jacs document extract -d ./documents/
```

## Document Types

### Task Documents

Tasks are specialized documents for work tracking:

```bash
jacs task create -n "Code Review" -d "Review PR #123"
```

See [Task Schema](../schemas/task.md) for details.

### Message Documents

Messages for agent communication:

```json
{
  "$schema": "https://hai.ai/schemas/message/v1/message.schema.json",
  "jacsType": "message",
  "jacsMessageContent": "Hello, I've completed the task.",
  "jacsMessageReplyTo": "previous-message-uuid"
}
```

### Custom Documents

Any JSON can be a JACS document. Create custom schemas:

```json
{
  "$schema": "https://example.com/schemas/invoice.schema.json",
  "jacsType": "invoice",
  "invoiceNumber": "INV-001",
  "amount": 1000,
  "currency": "USD"
}
```

## Version History

JACS tracks document history through version chains:

```
Version 1 (jacsOriginalVersion)
    ↓
Version 2 (jacsPreviousVersion → Version 1)
    ↓
Version 3 (jacsPreviousVersion → Version 2)
    ↓
Current Version
```

Each version is a complete document that can be independently verified.

## Working with Multiple Agents

### Different Agent Signs Document

```bash
# Use a specific agent's keys
jacs document create -f ./document.json -a ./other-agent.json
```

### Verify Document from Unknown Agent

```bash
# Verify with strict DNS requirement
jacs document verify -f ./document.json --require-strict-dns
```

## Best Practices

### Document Design

1. **Use appropriate levels**: Match `jacsLevel` to document purpose
2. **Include context**: Add descriptive fields for human readability
3. **Version control**: Keep source files in git alongside JACS documents

### Security

1. **Verify before trusting**: Always verify signatures
2. **Check agent identity**: Verify the signing agent
3. **Validate schemas**: Use custom schemas for strict validation

### Performance

1. **External attachments**: Use `--embed false` for large files
2. **Batch processing**: Use directory mode for multiple documents
3. **Selective verification**: Verify only when needed

## Common Workflows

### Create and Share Document

```bash
# 1. Create document
jacs document create -f ./proposal.json -o ./signed-proposal.json

# 2. Share the signed document
# The recipient can verify it:
jacs document verify -f ./signed-proposal.json
```

### Track Document Changes

```bash
# 1. Create initial version
jacs document create -f ./contract-v1.json

# 2. Make changes and update
jacs document update -f ./contract-v1.json -n ./contract-v2.json

# 3. Continue updating
jacs document update -f ./contract-v2.json -n ./contract-v3.json
```

### Process Multiple Documents

```bash
# Create all documents in a directory
jacs document create -d ./input-docs/

# Verify all documents
jacs document verify -d ./signed-docs/
```

## Next Steps

- [Agreements](agreements.md) - Multi-agent consent
- [Task Schema](../schemas/task.md) - Task document structure
- [Custom Schemas](../advanced/custom-schemas.md) - Create your own schemas
