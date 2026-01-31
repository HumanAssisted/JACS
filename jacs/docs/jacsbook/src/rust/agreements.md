# Creating and Using Agreements

Agreements enable multi-party consent in JACS. They allow multiple agents to cryptographically sign a document, creating binding commitments between parties.

## What is an Agreement?

An agreement is a mechanism for:
- **Collecting signatures** from multiple agents
- **Tracking consent** from required parties
- **Enforcing completion** before proceeding
- **Creating audit trails** of who agreed and when

## Agreement Lifecycle

```
1. Create Agreement → 2. Distribute → 3. Agents Sign → 4. Verify Complete
```

1. **Create**: Initial agent creates agreement with required participants
2. **Distribute**: Agreement document shared with all parties
3. **Sign**: Each agent reviews and adds their signature
4. **Verify**: Check that all required parties have signed

## Creating Agreements

### Basic Agreement

```bash
# Create agreement requiring signatures from two agents
jacs document create-agreement \
  -f ./document.json \
  -i agent1-uuid,agent2-uuid
```

### With Context

Include a question and context for clarity:

```json
{
  "jacsAgreement": {
    "jacsAgreementQuestion": "Do you agree to the terms of this contract?",
    "jacsAgreementContext": "Service agreement for Q1 2024",
    "jacsAgreementAgents": ["agent1-uuid", "agent2-uuid"]
  }
}
```

## Signing Agreements

### Sign as Current Agent

```bash
jacs document sign-agreement -f ./document-with-agreement.json
```

### Sign as Different Agent

```bash
# Use a different configuration/agent
JACS_CONFIG_PATH=./agent2.config.json jacs document sign-agreement -f ./document.json
```

### Sign with Response

When signing, agents can include a response:

```json
{
  "jacsAgreement": {
    "signatures": {
      "agent1-uuid": {
        "agentID": "agent1-uuid",
        "signature": "base64-signature",
        "date": "2024-01-15T10:30:00Z",
        "response": "Agreed with minor reservation about timeline",
        "responseType": "agree"
      }
    }
  }
}
```

Response types:
- `agree` - Agent consents
- `disagree` - Agent does not consent
- `reject` - Agent considers the question invalid or irrelevant

## Checking Agreement Status

### Check if Complete

```bash
jacs document check-agreement -f ./document.json
```

This shows:
- Which agents have signed
- Which agents still need to sign
- Whether the agreement is complete

## Agreement Structure

A document with an agreement includes:

```json
{
  "jacsId": "doc-uuid",
  "jacsType": "contract",

  "jacsAgreement": {
    "jacsAgreementQuestion": "Do you agree to these terms?",
    "jacsAgreementContext": "Annual service contract",
    "jacsAgreementAgents": [
      "550e8400-e29b-41d4-a716-446655440000",
      "123e4567-e89b-12d3-a456-426614174000"
    ],
    "signatures": {
      "550e8400-e29b-41d4-a716-446655440000": {
        "agentID": "550e8400-e29b-41d4-a716-446655440000",
        "agentVersion": "version-uuid",
        "signature": "base64-signature",
        "signingAlgorithm": "ring-Ed25519",
        "publicKeyHash": "hash",
        "date": "2024-01-15T10:30:00Z",
        "responseType": "agree",
        "fields": ["jacsId", "jacsAgreement"]
      }
    }
  },

  "jacsAgreementHash": "hash-of-agreement-content"
}
```

## Task Agreements

Tasks have built-in support for start and end agreements:

```json
{
  "jacsType": "task",
  "jacsTaskName": "Code Review",

  "jacsStartAgreement": {
    "jacsAgreementQuestion": "Do you agree to start this task?",
    "jacsAgreementAgents": ["customer-uuid", "provider-uuid"]
  },

  "jacsEndAgreement": {
    "jacsAgreementQuestion": "Do you agree the task is complete?",
    "jacsAgreementAgents": ["customer-uuid", "provider-uuid"]
  }
}
```

## Multi-Agent Workflow Example

```bash
# 1. Agent A creates a task
jacs task create -n "Write Report" -d "Quarterly sales report"

# 2. Agent A adds agreement requiring both agents
jacs document create-agreement \
  -f ./task.json \
  -i agent-a-uuid,agent-b-uuid

# 3. Agent A signs the agreement
jacs document sign-agreement -f ./task.json

# 4. Agent B signs the agreement
JACS_CONFIG_PATH=./agent-b.config.json \
  jacs document sign-agreement -f ./task.json

# 5. Check agreement is complete
jacs document check-agreement -f ./task.json
```

## Agreement Hash

The `jacsAgreementHash` ensures all agents agree to the same content:

1. Hash is computed from the agreement content
2. Each signature includes the hash
3. If content changes, hash changes, invalidating existing signatures

This prevents modifications after some parties have signed.

## Best Practices

1. **Verify before signing**: Always review documents before signing
2. **Check agent identities**: Verify who you're agreeing with (use DNS)
3. **Include context**: Make the agreement purpose clear
4. **Handle disagreement**: Have a process for when agents disagree

## Next Steps

- [DNS Verification](dns.md) - Verify agent identities
- [Task Schema](../schemas/task.md) - Task-specific agreements
- [Security Model](../advanced/security.md) - Agreement security
