# Agent State Schema

The Agent State Schema defines the structure for signed agent state documents in JACS. Agent state documents wrap and cryptographically sign any agent configuration file -- memory files, skills, plans, configs, hooks, or any other document an agent wants to verify.

## Schema Location

```
https://hai.ai/schemas/agentstate/v1/agentstate.schema.json
```

## Overview

Agent state documents provide:
- **Signed state files**: Cryptographically sign MEMORY.md, skill files, plans, configs, hooks, or any file
- **File integrity**: SHA-256 hashes verify file contents haven't been tampered with
- **Origin tracking**: Record whether state was authored, adopted, generated, or imported
- **Framework tagging**: Identify which agent framework (claude-code, langchain, etc.) the state belongs to
- **General-purpose signing**: Use type `other` to sign any document an agent wants to verify

All documents are stored within the JACS data directory for security.

## Schema Structure

The agent state schema extends the [Header Schema](document.md):

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "title": "Agent State Document",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" }
  ],
  "properties": {
    "jacsAgentStateType": {
      "type": "string",
      "enum": ["memory", "skill", "plan", "config", "hook", "other"]
    },
    "jacsAgentStateName": { "type": "string" }
  },
  "required": ["jacsAgentStateType", "jacsAgentStateName"]
}
```

## State Types

| Type | Description | Example |
|------|-------------|---------|
| `memory` | Agent memory/knowledge files | MEMORY.md, context files |
| `skill` | Agent skill definitions | Coding patterns, domain knowledge |
| `plan` | Agent plans and strategies | Implementation plans, workflows |
| `config` | Agent configuration files | Settings, preferences |
| `hook` | Agent hooks and triggers (always embedded) | Pre-commit hooks, event handlers |
| `other` | Any document the agent wants to sign and verify | Reports, artifacts, custom files |

## Properties

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacsAgentStateType` | string (enum) | Type of agent state: memory, skill, plan, config, hook, other |
| `jacsAgentStateName` | string | Human-readable name for this state document |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacsAgentStateDescription` | string | Description of what this state contains |
| `jacsAgentStateFramework` | string | Agent framework (e.g., "claude-code", "langchain") |
| `jacsAgentStateVersion` | string | Content version (distinct from `jacsVersion`) |
| `jacsAgentStateContentType` | string | MIME type (text/markdown, application/json, etc.) |
| `jacsAgentStateContent` | string | Inline content (used when embedding) |
| `jacsAgentStateTags` | string[] | Tags for categorization and search |
| `jacsAgentStateOrigin` | string (enum) | How created: authored, adopted, generated, imported |
| `jacsAgentStateSourceUrl` | string (uri) | Where content was obtained from |

## Origin Tracking

Every agent state document can track its provenance:

| Origin | Meaning |
|--------|---------|
| `authored` | Created by the signing agent |
| `adopted` | Found unsigned, signed by adopting agent |
| `generated` | Produced by AI/automation |
| `imported` | Brought from another JACS installation |

## File References

Agent state documents can reference external files using `jacsFiles`:

```json
{
  "jacsFiles": [
    {
      "mimetype": "text/markdown",
      "path": "MEMORY.md",
      "embed": true,
      "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      "contents": "base64-encoded-gzipped-content"
    }
  ]
}
```

When `embed` is `true`, the file content is stored inline in the document. **Hook-type documents always embed content** for security (prevents time-of-check/time-of-use attacks).

## Examples

### Minimal Agent State

```json
{
  "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "jacsAgentStateType": "memory",
  "jacsAgentStateName": "Project Memory",
  "jacsType": "agentstate",
  "jacsLevel": "config"
}
```

### Memory File with Embedding

```json
{
  "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "jacsAgentStateType": "memory",
  "jacsAgentStateName": "JACS Project Memory",
  "jacsAgentStateDescription": "Agent memory for the JACS project workspace",
  "jacsAgentStateFramework": "claude-code",
  "jacsAgentStateOrigin": "authored",
  "jacsAgentStateContentType": "text/markdown",
  "jacsAgentStateContent": "# MEMORY.md\n\n## Project: JACS\n- Location: /home/agent/jacs\n- Rust library for cryptographic signing\n",
  "jacsAgentStateTags": ["jacs", "rust", "crypto"],
  "jacsType": "agentstate",
  "jacsLevel": "config"
}
```

### Adopted Skill

```json
{
  "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "jacsAgentStateType": "skill",
  "jacsAgentStateName": "JSON Schema Validation",
  "jacsAgentStateOrigin": "adopted",
  "jacsAgentStateSourceUrl": "https://agentskills.io/skills/json-schema",
  "jacsAgentStateVersion": "2.1.0",
  "jacsType": "agentstate",
  "jacsLevel": "config"
}
```

### General-Purpose Signed Document

Use type `other` to sign any document:

```json
{
  "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "jacsAgentStateType": "other",
  "jacsAgentStateName": "Q1 Financial Report",
  "jacsAgentStateDescription": "Quarterly financial summary for verification",
  "jacsAgentStateContentType": "application/json",
  "jacsAgentStateContent": "{\"revenue\": 150000, \"expenses\": 120000}",
  "jacsType": "agentstate",
  "jacsLevel": "config"
}
```

## Rust API

### Creating Agent State Documents

```rust
use jacs::schema::agentstate_crud::*;

// Minimal state
let doc = create_minimal_agentstate("memory", "Project Memory", Some("Agent memory file"))?;

// With file reference
let doc = create_agentstate_with_file("skill", "Rust Patterns", "./skills/rust.md", true)?;

// With inline content
let doc = create_agentstate_with_content(
    "config",
    "Agent Settings",
    "{\"theme\": \"dark\"}",
    "application/json"
)?;

// General-purpose signing
let doc = create_agentstate_with_content(
    "other",
    "Audit Report",
    "Report contents here...",
    "text/plain"
)?;

// Set metadata
let mut doc = create_minimal_agentstate("memory", "My Memory", None)?;
set_agentstate_framework(&mut doc, "claude-code")?;
set_agentstate_origin(&mut doc, "authored", None)?;
set_agentstate_tags(&mut doc, vec!["project", "notes"])?;
set_agentstate_version(&mut doc, "1.0.0")?;
```

### Signing and Verification

```rust
// Create, sign, and store
let doc_string = serde_json::to_string(&doc)?;
let signed_doc = agent.create_document_and_load(&doc_string, None, None)?;

// Verify file integrity
let hash_valid = verify_agentstate_file_hash(&doc)?;
```

## MCP Tools

Six MCP tools are available for agent state operations:

| Tool | Description |
|------|-------------|
| `jacs_sign_state` | Create and sign a new agent state document |
| `jacs_verify_state` | Verify an existing agent state document's signature |
| `jacs_load_state` | Load an agent state document by key |
| `jacs_update_state` | Update and re-sign an agent state document |
| `jacs_list_state` | List all agent state documents |
| `jacs_adopt_state` | Adopt an external file as a signed agent state |

### MCP Example: Sign a Memory File

```json
{
  "tool": "jacs_sign_state",
  "arguments": {
    "state_type": "memory",
    "name": "Project Memory",
    "content": "# My Agent Memory\n\nKey facts about the project...",
    "content_type": "text/markdown",
    "framework": "claude-code",
    "tags": ["project", "memory"]
  }
}
```

### MCP Example: Sign Any Document

```json
{
  "tool": "jacs_sign_state",
  "arguments": {
    "state_type": "other",
    "name": "Verification Report",
    "content": "{\"status\": \"passed\", \"checks\": 42}",
    "content_type": "application/json"
  }
}
```

## Security Notes

- All agent state documents are stored within the JACS data directory for security
- Hook-type documents always embed content to prevent TOCTOU attacks
- File hashes (SHA-256) are verified on load to detect tampering
- Origin tracking provides provenance auditing
- Documents are signed with the agent's private key, providing non-repudiation

## See Also

- [JSON Schemas](overview.md) - Schema architecture overview
- [Working with Documents](../rust/documents.md) - General document operations
- [MCP Integration](../integrations/mcp.md) - MCP server setup
- [Security Model](../advanced/security.md) - Cryptographic details
