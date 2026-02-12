# JACS A2A Quick Start (5 Minutes)

JACS extends the A2A (Agent-to-Agent) protocol with cryptographic document provenance. Every JACS agent is automatically an A2A agent -- zero additional configuration.

> **Deep dive:** See the [A2A Quickstart Guide](./jacs/docs/jacsbook/src/guides/a2a-quickstart.md) in the jacsbook for tabbed step-by-step walkthroughs, or the [A2A Interoperability Reference](./jacs/docs/jacsbook/src/integrations/a2a.md) for the full API.

## What JACS Adds to A2A

- **Document signatures** that persist with data (not just transport security)
- **Post-quantum cryptography** for future-proof security
- **Chain of custody** tracking for multi-agent workflows
- **Self-verifying artifacts** that work offline
- **Trust policies** (open / verified / strict) for controlling foreign agent access

## Install

```bash
pip install jacs                    # Python
pip install jacs[a2a-server]        # Python + discovery server (FastAPI + uvicorn)
npm install @hai.ai/jacs            # Node.js
cargo install jacs --features cli   # Rust CLI
```

## The 10-Line Journey

### Python

```python
from jacs.client import JacsClient

client = JacsClient.quickstart()                                          # 1. Create agent
card = client.export_agent_card(url="https://myagent.example.com")        # 2. Export Agent Card
signed = client.sign_artifact({"action": "classify"}, "task")             # 3. Sign an artifact
result = client.verify_artifact(signed)                                   # 4. Verify it
print(f"Valid: {result['valid']}, Signer: {result['signer_id']}")

a2a = client.get_a2a(url="http://localhost:8080")                         # 5. Get A2A integration
a2a.serve(port=8080)                                                      # 6. Serve discovery endpoints
```

### Node.js

```javascript
const { JacsClient } = require('@hai.ai/jacs/client');

const client = await JacsClient.quickstart();                              // 1. Create agent
const card = client.exportAgentCard();                                     // 2. Export Agent Card
const signed = await client.signArtifact({ action: 'classify' }, 'task');  // 3. Sign an artifact
const result = await client.verifyArtifact(signed);                        // 4. Verify it
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);

const a2a = client.getA2A();                                               // 5. Get A2A integration
const server = await a2a.listen({ port: 8080 });                           // 6. Serve discovery endpoints
```

### Rust CLI

```bash
jacs quickstart                                        # 1. Create agent
jacs a2a export-card                                   # 2. Export Agent Card
echo '{"action":"classify"}' | jacs a2a sign --type task  # 3. Sign an artifact
jacs a2a serve --port 8080                             # 4. Serve discovery endpoints
```

## Discover and Assess Remote Agents

```python
from jacs.a2a_discovery import discover_and_assess_sync

result = discover_and_assess_sync("https://agent.example.com")
print(f"Agent: {result['card']['name']}")
print(f"JACS registered: {result['jacs_registered']}")
print(f"Trust level: {result['trust_level']}")  # trusted / jacs_registered / untrusted
```

```javascript
const { discoverAndAssess } = require('@hai.ai/jacs/a2a-discovery');

const result = await discoverAndAssess('https://agent.example.com');
console.log(`Agent: ${result.card.name}`);
console.log(`JACS registered: ${result.jacsRegistered}`);
console.log(`Trust level: ${result.trustLevel}`);
```

## Chain of Custody

Track provenance across multi-agent workflows:

```python
step1 = client_a.sign_artifact({"step": 1, "data": "raw"}, "message")
step2 = client_b.sign_artifact({"step": 2, "data": "processed"}, "message", parent_signatures=[step1])
```

```javascript
const step1 = await clientA.signArtifact({ step: 1, data: 'raw' }, 'message');
const step2 = await clientB.signArtifact({ step: 2, data: 'processed' }, 'message', [step1]);
```

## Trust Policies

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `open` | Accept all agents | Development, testing |
| `verified` | Require JACS extension in agent card | **Default** -- production use |
| `strict` | Require agent in local trust store | High-security environments |

```python
from jacs.a2a import JACSA2AIntegration
a2a = JACSA2AIntegration(client, trust_policy="strict")
assessment = a2a.assess_remote_agent(remote_card_json)
```

```javascript
const { JACSA2AIntegration } = require('@hai.ai/jacs/a2a');
const a2a = new JACSA2AIntegration(client, 'strict');
const assessment = a2a.assessRemoteAgent(remoteCardJson);
```

## Well-Known Endpoints

JACS serves five endpoints for A2A discovery:

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/agent-card.json` | A2A Agent Card |
| `/.well-known/jwks.json` | JWK set for verifying signatures |
| `/.well-known/jacs-agent.json` | JACS agent descriptor |
| `/.well-known/jacs-pubkey.json` | JACS public key |
| `/.well-known/jacs-extension.json` | JACS provenance extension descriptor |

## JACS Extension in Agent Cards

JACS agents declare the `urn:hai.ai:jacs-provenance-v1` extension in their Agent Card so other JACS agents can identify them:

```json
{
  "capabilities": {
    "extensions": [{
      "uri": "urn:hai.ai:jacs-provenance-v1",
      "description": "JACS cryptographic document signing",
      "required": false
    }]
  }
}
```

## Next Steps

- **[A2A Quickstart Guide](./jacs/docs/jacsbook/src/guides/a2a-quickstart.md)** -- Hub page with "JACS for A2A Developers" and troubleshooting FAQ
  - [Serve Your Agent Card](./jacs/docs/jacsbook/src/guides/a2a-serve.md) -- Publish discovery endpoints
  - [Discover & Trust](./jacs/docs/jacsbook/src/guides/a2a-discover.md) -- Find and assess remote agents
  - [Exchange Artifacts](./jacs/docs/jacsbook/src/guides/a2a-exchange.md) -- Sign, verify, chain of custody
- **[A2A Interoperability Reference](./jacs/docs/jacsbook/src/integrations/a2a.md)** -- Full API reference, MCP integration, framework adapters
- **[Trust Store](./jacs/docs/jacsbook/src/advanced/trust-store.md)** -- Managing trusted agents
- **[Framework Adapters](./jacs/docs/jacsbook/src/python/adapters.md)** -- Auto-sign with LangChain, FastAPI, CrewAI
- **[Express Middleware](./jacs/docs/jacsbook/src/nodejs/express.md)** -- Add A2A to Express apps
- **[Hero Demo (Python)](./examples/a2a_trust_demo.py)** -- 3-agent trust verification example
- **[Hero Demo (Node.js)](./examples/a2a_trust_demo.ts)** -- Same demo in TypeScript
