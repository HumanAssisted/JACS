# Serve Your Agent Card

{{#include ../_snippets/node-registry-status.md}}

Make your JACS agent discoverable by other A2A agents.

> **Prerequisites:** `pip install jacs[a2a-server]` (Python) or `npm install @hai.ai/jacs express` (Node.js).

<div class="tabs">
<div class="tab">
<input type="radio" id="serve-python" name="serve-group" checked>
<label for="serve-python">Python</label>
<div class="content">

```python
from jacs.a2a import JACSA2AIntegration

JACSA2AIntegration.quickstart(url="http://localhost:8080").serve(port=8080)
```

Your agent is now discoverable at `http://localhost:8080/.well-known/agent-card.json`.

### Production: Mount into Your Own FastAPI App

```python
from fastapi import FastAPI
from jacs.client import JacsClient
from jacs.a2a_server import jacs_a2a_routes

app = FastAPI()
client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
router = jacs_a2a_routes(client)
app.include_router(router)
```

</div>
</div>

<div class="tab">
<input type="radio" id="serve-nodejs" name="serve-group">
<label for="serve-nodejs">Node.js (Express)</label>
<div class="content">

```javascript
const express = require('express');
const { JacsClient } = require('@hai.ai/jacs/client');
const { jacsA2AMiddleware } = require('@hai.ai/jacs/a2a-server');

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});
const app = express();
app.use(jacsA2AMiddleware(client));
app.listen(8080);
```

Your agent is now discoverable at `http://localhost:8080/.well-known/agent-card.json`.

</div>
</div>
</div>

## What Gets Served

The native generator serves six `.well-known` endpoints automatically:

{{#include ../_snippets/a2a-well-known-docs.md}}

The Agent Card includes the `urn:jacs:provenance-v1` extension in `capabilities.extensions`, signaling to other JACS agents that your agent supports cryptographic provenance.

The card and JWKS reuse the persisted ES256 compatibility key across calls and
restarts. The card references
`/.well-known/jacs-compat-binding.json` by both fixed path and content hash;
strict verification checks that native-root-signed artifact before treating the
card as the explicitly trusted JACS identity. Existing pre-compatibility agents
must run `jacs agent add-compat-key` once before serving. Local loopback trust
tests additionally require `JACS_ALLOW_PRIVATE_JWKS=true`; private-address JWKS
fetching is otherwise denied.

Strict verifiers accept a compatibility binding for at most seven days after
its signed `issuedAt`, with five minutes of future clock skew. Generating the
well-known set refreshes an authentic binding after six days under the shared
issuance lock, preserving its scopes and any explicit `expiresAt`.

## Next Steps

- **[Discover & Trust Remote Agents](a2a-discover.md)** -- Find other agents and assess their trustworthiness
- **[Exchange Signed Artifacts](a2a-exchange.md)** -- Sign and verify A2A artifacts
- **[A2A Interoperability Reference](../integrations/a2a.md)** -- Full API reference
