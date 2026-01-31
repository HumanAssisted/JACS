# Agent Schema

The Agent Schema defines the structure for agent identity documents in JACS. Agents represent entities that can sign documents, participate in agreements, and provide services.

## Schema Location

```
https://hai.ai/schemas/agent/v1/agent.schema.json
```

## Overview

Agent documents describe:
- **Identity**: Unique identifiers and versioning
- **Type**: Human, organizational, hybrid, or AI classification
- **Services**: Capabilities the agent offers
- **Contacts**: How to reach human or hybrid agents
- **Domain**: Optional DNS-based verification

## Schema Structure

The agent schema extends the [Header Schema](document.md) using JSON Schema composition:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "title": "Agent",
  "description": "General schema for human, hybrid, and AI agents",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    { "type": "object", "properties": { ... } }
  ]
}
```

## Agent Types

The `jacsAgentType` field classifies the agent:

| Type | Description |
|------|-------------|
| `human` | A biological entity (individual person) |
| `human-org` | A group of people (organization, company) |
| `hybrid` | Combination of human and AI components |
| `ai` | Fully artificial intelligence |

```json
{
  "jacsAgentType": {
    "type": "string",
    "enum": ["human", "human-org", "hybrid", "ai"]
  }
}
```

### Contact Requirements

Human and hybrid agents must provide contact information:

```json
{
  "if": {
    "properties": {
      "jacsAgentType": { "enum": ["human", "human-org", "hybrid"] }
    }
  },
  "then": {
    "required": ["jacsContacts"]
  }
}
```

## Agent Properties

### Core Fields (from Header)

All agents inherit these header fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jacsId` | string (UUID) | Yes | Unique agent identifier |
| `jacsVersion` | string (UUID) | Yes | Current version identifier |
| `jacsVersionDate` | string (date-time) | Yes | Version timestamp |
| `jacsType` | string | Yes | Set to "agent" |
| `jacsOriginalVersion` | string (UUID) | Yes | First version identifier |
| `jacsOriginalDate` | string (date-time) | Yes | Creation timestamp |
| `jacsLevel` | string | Yes | Document level |
| `jacsSignature` | object | No | Cryptographic signature |
| `jacsSha256` | string | No | Content hash |

### Agent-Specific Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jacsAgentType` | string | Yes | Agent classification |
| `jacsAgentDomain` | string | No | Domain for DNS verification |
| `jacsServices` | array | Yes | Services the agent provides |
| `jacsContacts` | array | Conditional | Contact information (required for human/hybrid) |

## Services

Services describe capabilities the agent offers:

```json
{
  "jacsServices": [{
    "name": "Document Signing Service",
    "serviceDescription": "Sign and verify JACS documents",
    "successDescription": "Documents are signed with valid signatures",
    "failureDescription": "Invalid documents or signing errors",
    "costDescription": "Free for basic usage, paid tiers available",
    "idealCustomerDescription": "Developers building secure agent systems",
    "termsOfService": "https://example.com/tos",
    "privacyPolicy": "https://example.com/privacy",
    "isDev": false,
    "tools": [...]
  }]
}
```

### Service Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Service name |
| `serviceDescription` | string | Yes | What the service does |
| `successDescription` | string | Yes | What success looks like |
| `failureDescription` | string | Yes | What failure looks like |
| `costDescription` | string | No | Pricing information |
| `idealCustomerDescription` | string | No | Target customer profile |
| `termsOfService` | string | No | Legal terms URL or text |
| `privacyPolicy` | string | No | Privacy policy URL or text |
| `copyright` | string | No | Usage rights for provided data |
| `eula` | string | No | End-user license agreement |
| `isDev` | boolean | No | Whether this is a dev/test service |
| `tools` | array | No | Tool definitions |
| `piiDesired` | array | No | Types of sensitive data needed |

### PII Types

Services can declare what personally identifiable information they need:

```json
{
  "piiDesired": ["email", "phone", "address"]
}
```

Valid PII types:
- `signature` - Digital signatures
- `cryptoaddress` - Cryptocurrency addresses
- `creditcard` - Payment card numbers
- `govid` - Government identification
- `social` - Social security numbers
- `email` - Email addresses
- `phone` - Phone numbers
- `address` - Physical addresses
- `zip` - Postal codes
- `PHI` - Protected health information
- `MHI` - Mental health information
- `identity` - Identity documents
- `political` - Political affiliation
- `bankaddress` - Banking information
- `income` - Income data

## Contacts

Contact information for human and hybrid agents:

```json
{
  "jacsContacts": [{
    "firstName": "Jane",
    "lastName": "Smith",
    "email": "jane@example.com",
    "phone": "+1-555-0123",
    "isPrimary": true,
    "mailAddress": "123 Main St",
    "mailState": "CA",
    "mailZip": "94102",
    "mailCountry": "USA"
  }]
}
```

### Contact Schema Fields

| Field | Type | Description |
|-------|------|-------------|
| `firstName` | string | First name |
| `lastName` | string | Last name |
| `addressName` | string | Location name |
| `phone` | string | Phone number |
| `email` | string (email) | Email address |
| `mailName` | string | Name at address |
| `mailAddress` | string | Street address |
| `mailAddressTwo` | string | Address line 2 |
| `mailState` | string | State/province |
| `mailZip` | string | Postal code |
| `mailCountry` | string | Country |
| `isPrimary` | boolean | Primary contact flag |

## DNS Verification

Agents can link to a domain for DNSSEC-validated verification:

```json
{
  "jacsAgentDomain": "example.com"
}
```

The domain should have a DNS TXT record at `_v1.agent.jacs.example.com.` containing the agent's public key fingerprint.

See the [DNS chapter](../dns.md) for complete setup instructions.

## Complete Example

### AI Agent

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
  "jacsServices": [{
    "name": "Code Review Service",
    "serviceDescription": "Automated code review and analysis",
    "successDescription": "Review completed with actionable feedback",
    "failureDescription": "Unable to process or analyze code",
    "isDev": false
  }],
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "date": "2024-01-15T10:30:00Z",
    "signature": "base64-encoded-signature...",
    "publicKeyHash": "sha256-hash-of-public-key",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsId", "jacsVersion", "jacsAgentType", "jacsServices"]
  },
  "jacsSha256": "document-hash..."
}
```

### Human Agent

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsId": "660e8400-e29b-41d4-a716-446655440001",
  "jacsVersion": "a47ac10b-58cc-4372-a567-0e02b2c3d480",
  "jacsVersionDate": "2024-01-15T11:00:00Z",
  "jacsType": "agent",
  "jacsOriginalVersion": "a47ac10b-58cc-4372-a567-0e02b2c3d480",
  "jacsOriginalDate": "2024-01-15T11:00:00Z",
  "jacsLevel": "artifact",
  "jacsAgentType": "human",
  "jacsAgentDomain": "smith.example.com",
  "jacsServices": [{
    "name": "Consulting",
    "serviceDescription": "Technical consulting services",
    "successDescription": "Project goals achieved",
    "failureDescription": "Unable to meet requirements",
    "termsOfService": "https://smith.example.com/tos"
  }],
  "jacsContacts": [{
    "firstName": "John",
    "lastName": "Smith",
    "email": "john@smith.example.com",
    "isPrimary": true
  }]
}
```

### Organization Agent

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsId": "770e8400-e29b-41d4-a716-446655440002",
  "jacsVersion": "b47ac10b-58cc-4372-a567-0e02b2c3d481",
  "jacsVersionDate": "2024-01-15T12:00:00Z",
  "jacsType": "agent",
  "jacsOriginalVersion": "b47ac10b-58cc-4372-a567-0e02b2c3d481",
  "jacsOriginalDate": "2024-01-15T12:00:00Z",
  "jacsLevel": "artifact",
  "jacsAgentType": "human-org",
  "jacsAgentDomain": "acme.com",
  "jacsServices": [{
    "name": "Enterprise Software",
    "serviceDescription": "Enterprise software solutions",
    "successDescription": "Software deployed and operational",
    "failureDescription": "Deployment or integration failure",
    "privacyPolicy": "https://acme.com/privacy",
    "piiDesired": ["email", "phone"]
  }],
  "jacsContacts": [{
    "addressName": "Acme Corporation",
    "email": "contact@acme.com",
    "phone": "+1-800-555-ACME",
    "mailAddress": "1 Corporate Plaza",
    "mailState": "NY",
    "mailZip": "10001",
    "mailCountry": "USA",
    "isPrimary": true
  }]
}
```

## Creating Agents

### Python

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# The agent is created during configuration setup
# Agent document is available after loading
agent_json = agent.load('./jacs.config.json')
agent_doc = json.loads(agent_json)

print(f"Agent ID: {agent_doc['jacsId']}")
print(f"Agent Type: {agent_doc['jacsAgentType']}")
```

### Node.js

```javascript
import { JacsAgent } from 'jacsnpm';

const agent = new JacsAgent();
const agentJson = agent.load('./jacs.config.json');
const agentDoc = JSON.parse(agentJson);

console.log(`Agent ID: ${agentDoc.jacsId}`);
console.log(`Agent Type: ${agentDoc.jacsAgentType}`);
```

### CLI

```bash
# Create a new agent
jacs agent create

# View agent details
jacs agent show
```

## Verifying Agents

```python
# Verify the loaded agent
is_valid = agent.verify_agent()

# Verify another agent file
is_valid = agent.verify_agent('./other-agent.json')
```

```javascript
// Verify the loaded agent
const isValid = agent.verifyAgent();

// Verify another agent file
const isOtherValid = agent.verifyAgent('./other-agent.json');
```

## See Also

- [Document Schema](document.md) - Header fields documentation
- [Task Schema](task.md) - Task workflow schema
- [DNS Verification](../dns.md) - Setting up domain verification
- [Creating an Agent](../rust/agent.md) - Agent creation guide
