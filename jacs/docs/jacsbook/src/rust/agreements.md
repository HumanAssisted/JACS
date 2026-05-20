# Creating and Using Agreements

Agreements enable multi-party consent in JACS. Any signed document can carry agreement metadata so multiple agents can approve the same payload.

## What is an Agreement?

An agreement:

- Lists required signers
- Records collected signatures
- Supports quorum rules
- Optionally constrains signing algorithms
- Preserves the hash of the content being approved

## Agreement Lifecycle

```text
1. Create agreement -> 2. Share document -> 3. Agents sign -> 4. Verify status
```

## Creating Agreements

```bash
jacs document create-agreement \
  -f ./document.json \
  -i agent1-uuid,agent2-uuid
```

Include a question and context when the payload needs human-readable review:

```json
{
  "jacsAgreement": {
    "question": "Do you approve deploying this configuration?",
    "context": "Production rollout",
    "agentIDs": ["agent1-uuid", "agent2-uuid"]
  }
}
```

## Signing Agreements

```bash
jacs document sign-agreement -f ./document-with-agreement.json
```

Use a different configuration to sign as another agent:

```bash
JACS_CONFIG_PATH=./agent2.config.json jacs document sign-agreement -f ./document.json
```

## Checking Agreement Status

```bash
jacs document check-agreement -f ./document.json
```

This reports which agents signed, which signatures are still required, and whether quorum has been met.

## Agreement Structure

```json
{
  "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
  "jacsId": "doc-uuid",
  "jacsType": "document",
  "content": {
    "change": "Deploy model v2"
  },
  "jacsAgreement": {
    "question": "Do you approve this payload?",
    "context": "Deployment approval",
    "agentIDs": [
      "550e8400-e29b-41d4-a716-446655440000",
      "123e4567-e89b-12d3-a456-426614174000"
    ],
    "quorum": 2,
    "signatures": []
  },
  "jacsAgreementHash": "hash-of-agreement-content"
}
```

## Agreement Options

### Timeout

```python
agreement = client.create_agreement(
    document=proposal,
    agent_ids=[alice.agent_id, bob.agent_id],
    timeout="2025-12-31T23:59:59Z"
)
```

### Quorum

```python
agreement = client.create_agreement(
    document=proposal,
    agent_ids=[alice.agent_id, bob.agent_id, carol.agent_id],
    quorum=2
)
```

### Algorithm Constraints

```python
agreement = client.create_agreement(
    document=proposal,
    agent_ids=agent_ids,
    required_algorithms=["pq2025"],
    minimum_strength="post-quantum"
)
```

## See Also

- [Working with Documents](documents.md)
- [Multi-Agent Agreements](../getting-started/multi-agent-agreement.md)
