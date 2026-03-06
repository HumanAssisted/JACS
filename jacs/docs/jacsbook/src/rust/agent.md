# Creating an Agent

An agent is the fundamental identity in JACS - an autonomous entity that can create, sign, and verify documents. This guide covers creating and managing agents.

## What is an Agent?

A JACS agent is:
- A unique identity with a UUID that never changes
- A holder of cryptographic keys for signing
- A provider of services defined in the agent document
- Self-signed to prove authenticity

## Creating Your First Agent

### Quick Method (Recommended)

```bash
# Initialize JACS (creates config and agent)
jacs init
```

This creates:
- Configuration file
- Cryptographic key pair
- Initial agent document

### Manual Method

```bash
# 1. Create configuration
jacs config create

# 2. Create agent with new keys
jacs agent create --create-keys true
```

### With Custom Agent Definition

Create an agent definition file (`my-agent.json`):

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsAgentType": "ai",
  "jacsAgentDomain": "myagent.example.com",
  "name": "Content Creation Agent",
  "description": "AI agent specialized in content creation",
  "jacsServices": [
    {
      "name": "content-generation",
      "serviceDescription": "Generate high-quality content",
      "successDescription": "Engaging, accurate content delivered",
      "failureDescription": "Unable to generate requested content"
    }
  ]
}
```

Then create the agent:

```bash
jacs agent create --create-keys true -f my-agent.json
```

## Agent Types

JACS supports four agent types:

| Type | Description | Contacts Required |
|------|-------------|-------------------|
| `ai` | Fully artificial intelligence | No |
| `human` | Individual person | Yes |
| `human-org` | Group of people (organization) | Yes |
| `hybrid` | Human-AI combination | Yes |

### AI Agent Example

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsAgentType": "ai",
  "name": "DataBot",
  "description": "Data processing agent",
  "jacsServices": [
    {
      "name": "data-processing",
      "serviceDescription": "Process and transform data",
      "successDescription": "Data transformed successfully",
      "failureDescription": "Input data could not be processed"
    }
  ]
}
```

### Human Agent Example

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsAgentType": "human",
  "name": "John Smith",
  "description": "Software engineer",
  "jacsContacts": [
    {
      "firstName": "John",
      "lastName": "Smith",
      "email": "john@example.com",
      "isPrimary": true
    }
  ],
  "jacsServices": [
    {
      "name": "code-review",
      "serviceDescription": "Review code for quality and security",
      "successDescription": "Actionable review delivered",
      "failureDescription": "Could not complete review"
    }
  ]
}
```

## Agent Services

Services define what an agent can do. Each service has:

```json
{
  "name": "service-identifier",
  "serviceDescription": "What the service does",
  "successDescription": "Definition of successful completion",
  "failureDescription": "What constitutes failure"
}
```

### Detailed Service Example

```json
{
  "name": "document-processing",
  "serviceDescription": "Process and analyze documents",
  "successDescription": "Documents processed accurately",
  "failureDescription": "Unable to process one or more documents",
  "costDescription": "Usage-based pricing",
  "privacyPolicy": "https://example.com/privacy",
  "termsOfService": "https://example.com/terms"
}
```

## Agent Contacts

For human and hybrid agents, contacts are required:

```json
{
  "jacsContacts": [
    {
      "firstName": "Example",
      "lastName": "Agent",
      "email": "agent@example.com",
      "phone": "+1-555-0123",
      "isPrimary": true
    }
  ]
}
```

## Cryptographic Keys

### Key Algorithms

JACS supports multiple cryptographic algorithms:

| Algorithm | Description | Recommended For |
|-----------|-------------|-----------------|
| `ring-Ed25519` | Fast elliptic curve signatures | General use (default) |
| `RSA-PSS` | Traditional RSA signatures | Legacy compatibility |
| `pq2025` | Post-quantum ML-DSA-87 signatures | Future-proof security |
| `pq-dilithium` | Legacy post-quantum signatures | Backward compatibility only (deprecated) |

### Configure Key Algorithm

In `jacs.config.json`:

```json
{
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

Or via environment variable:

```bash
JACS_AGENT_KEY_ALGORITHM=ring-Ed25519 jacs agent create --create-keys true
```

### Key Storage

Keys are stored in the key directory (default: `./jacs_keys`):

```
jacs_keys/
├── private_key.pem    # Private key (keep secure!)
└── public_key.pem     # Public key (can be shared)
```

## Verifying Agents

### Verify Your Own Agent

```bash
jacs agent verify
```

### Verify a Specific Agent File

```bash
jacs agent verify -a ./path/to/agent.json
```

### With DNS Verification

```bash
# Require DNS validation
jacs agent verify --require-dns

# Require strict DNSSEC
jacs agent verify --require-strict-dns
```

## Updating Agents

Agent updates create a new version while maintaining the same `jacsId`:

1. Modify the agent document
2. Re-sign with the agent's keys

The `jacsVersion` changes but `jacsId` remains constant.

## Agent Document Structure

A complete agent document looks like:

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "123e4567-e89b-12d3-a456-426614174000",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsOriginalVersion": "123e4567-e89b-12d3-a456-426614174000",
  "jacsOriginalDate": "2024-01-15T10:30:00Z",
  "jacsType": "agent",
  "jacsLevel": "config",

  "jacsAgentType": "ai",
  "jacsAgentDomain": "myagent.example.com",
  "name": "Content Creation Agent",
  "description": "AI agent for content generation",

  "jacsServices": [
    {
      "name": "content-generation",
      "serviceDescription": "Generate high-quality content",
      "successDescription": "High-quality content generated",
      "failureDescription": "Unable to generate requested content"
    }
  ],

  "jacsSha256": "hash-of-document",
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "123e4567-e89b-12d3-a456-426614174000",
    "signature": "base64-encoded-signature",
    "signingAlgorithm": "ring-Ed25519",
    "publicKeyHash": "hash-of-public-key",
    "date": "2024-01-15T10:30:00Z",
    "fields": ["jacsId", "jacsVersion", "jacsAgentType", "name", "jacsServices"]
  }
}
```

## Best Practices

### Security

1. **Protect private keys**: Never share or commit private keys
2. **Use strong algorithms**: Prefer Ed25519 or post-quantum
3. **Enable DNS verification**: For production agents
4. **Regular key rotation**: Update keys periodically

### Agent Design

1. **Clear service definitions**: Be specific about capabilities
2. **Meaningful names**: Use descriptive agent names
3. **Contact information**: Include for human agents
4. **Version control**: Track agent document changes

### Operations

1. **Backup keys**: Keep secure backups of private keys
2. **Monitor signatures**: Watch for unauthorized signing
3. **Document services**: Keep service definitions current

## Next Steps

- [Working with Documents](documents.md) - Create signed documents
- [Agreements](agreements.md) - Multi-agent coordination
- [DNS Verification](dns.md) - Publish agent identity
