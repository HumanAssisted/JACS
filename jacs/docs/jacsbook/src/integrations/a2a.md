# A2A Interoperability

Use A2A when your agent needs to be discoverable and verifiable by another service, team, or organization. This is the cross-boundary story; MCP is the inside-the-app story.

## What JACS Adds To A2A

- **Agent Cards** with JACS provenance metadata
- **Signed artifacts** such as `a2a-task` or `a2a-message`
- **Trust policy** for deciding whether another agent is acceptable
- **Chain of custody** via parent signatures

## The Core Flow

### 1. Export An Agent Card

Python:

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
card = client.export_agent_card(url="http://localhost:8080")
```

Node.js:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});

const card = client.exportAgentCard();
```

### 2. Serve Discovery Documents

Python has the strongest first-class server helpers today.

Quick demo server:

```python
from jacs.a2a import JACSA2AIntegration

JACSA2AIntegration.quickstart(
    name="my-agent",
    domain="my-agent.example.com",
    url="http://localhost:8080",
).serve(port=8080)
```

Production FastAPI mounting:

```python
from jacs.a2a_server import create_a2a_app, jacs_a2a_routes

app = create_a2a_app(client, title="My A2A Agent")
# or:
# app.include_router(jacs_a2a_routes(client))
```

Node.js has two discovery helpers:

- `client.getA2A().listen(port)` for a minimal demo server
- `jacsA2AMiddleware(client, options)` for mounting discovery routes in an existing Express app

```typescript
import express from 'express';
import { jacsA2AMiddleware } from '@hai.ai/jacs/a2a-server';

const app = express();
app.use(jacsA2AMiddleware(client, { url: 'http://localhost:3000' }));
app.listen(3000);
```

### 3. Sign And Verify Artifacts

Python:

```python
signed = client.sign_artifact({"taskId": "t-1", "operation": "classify"}, "task")
result = client.get_a2a().verify_wrapped_artifact(signed)
assert result["valid"]
```

Node.js:

```typescript
const signed = await client.signArtifact(
  { taskId: 't-1', operation: 'classify' },
  'task',
);

const result = await client.verifyArtifact(signed);
console.log(result.valid);
```

## Trust Policies

Trust policy answers a different question from cryptographic verification.

- **Trust policy**: should this remote agent be admitted?
- **Artifact verification**: is this specific signed payload valid?

The current policy meanings are:

{{#include ../_snippets/a2a-trust-policies.md}}

That means `verified` is about **JACS provenance on the Agent Card**, not about a promise that every foreign key has already been resolved.

### Python

```python
a2a = client.get_a2a()
assessment = a2a.assess_remote_agent(remote_card_json, policy="strict")

if assessment["allowed"]:
    result = a2a.verify_wrapped_artifact(artifact, assess_trust=True)
```

### Node.js

```typescript
const a2a = client.getA2A();
const assessment = a2a.assessRemoteAgent(remoteCardJson);

if (assessment.allowed) {
  const result = await a2a.verifyWrappedArtifact(signedArtifact);
}
```

## Bootstrap Patterns

Use the trust store when you want explicit admission:

- Export the agent document with `share_agent()` / `shareAgent()`
- Exchange the public key with `share_public_key()` / `getPublicKey()`
- Add the remote agent with `trust_agent_with_key()` / `trustAgentWithKey()`

This is the cleanest path into `strict` policy.

## Current Runtime Differences

- **Python**: `jacs.a2a_server` is the clearest full discovery story.
- **Node.js**: `jacsA2AMiddleware()` serves five `.well-known` routes from Express, but the generated `jwks.json` and `jacs-pubkey.json` payloads are still placeholder metadata. `listen()` is intentionally smaller and only suitable for demos.

Those gaps are tracked outside the book in `docs/missing-features.md`.

## Example Paths In This Repo

- `jacs-mcp/README.md`
- `jacspy/tests/test_a2a_server.py`
- `jacsnpm/src/a2a-server.js`
- `jacsnpm/examples/a2a-agent-example.js`
- `jacs/tests/a2a_cross_language_tests.rs`
