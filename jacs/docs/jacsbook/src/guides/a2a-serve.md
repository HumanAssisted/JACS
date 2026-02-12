# Serve Your Agent Card

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
client = JacsClient.quickstart()
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

const client = await JacsClient.quickstart();
const app = express();
app.use(jacsA2AMiddleware(client));
app.listen(8080);
```

Your agent is now discoverable at `http://localhost:8080/.well-known/agent-card.json`.

</div>
</div>
</div>

## What Gets Served

All five `.well-known` endpoints are served automatically:

{{#include ../_snippets/a2a-well-known-docs.md}}

The Agent Card includes the `urn:hai.ai:jacs-provenance-v1` extension in `capabilities.extensions`, signaling to other JACS agents that your agent supports cryptographic provenance.

## Next Steps

- **[Discover & Trust Remote Agents](a2a-discover.md)** -- Find other agents and assess their trustworthiness
- **[Exchange Signed Artifacts](a2a-exchange.md)** -- Sign and verify A2A artifacts
- **[A2A Interoperability Reference](../integrations/a2a.md)** -- Full API reference
