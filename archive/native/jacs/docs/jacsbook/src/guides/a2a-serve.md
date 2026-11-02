# Serve Your Agent Card

By default, these discovery helpers export the legacy A2A `0.4.0` card shape. For the
explicit A2A 1.0 options and their limits, see the
[current quickstart](https://github.com/HumanAssisted/JACS/blob/main/A2A_QUICKSTART.md).

{{#include ../_snippets/node-registry-status.md}}

Make your JACS agent discoverable by other A2A agents.

These helpers serve discovery documents only. They do not implement message/task
handlers or the legacy optional `/jacs/sign` and `/jacs/verify` host examples in
the extension descriptor. Configure the signed public interface for a service
your host actually implements; a local discovery listener does not create that
service or grant remote signing access.

> **Prerequisites:** The current-source PQ examples require [source-built bindings](https://humanassisted.github.io/JACS/a2a.html#build-this-checkout), plus Python's `a2a-server` extra or Express for Node.js. Registry installation alone does not establish that these newer exports are available. Node.js snippets below run inside an async function.

<div class="tabs">
<div class="tab">
<input type="radio" id="serve-python" name="serve-group" checked>
<label for="serve-python">Python</label>
<div class="content">

```python
from jacs.a2a import JACSA2AIntegration

JACSA2AIntegration.quickstart(name="my-agent", domain="my-agent.example.com").serve(port=8080)
```

Your agent is now discoverable at `http://localhost:8080/.well-known/agent-card.json`.

This local listener does not rewrite the card's signed public interface URL.

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

The native generator returns five public discovery documents by default.
Explicit ES256 compatibility adds the sixth, a delegated-key binding:

{{#include ../_snippets/a2a-well-known-docs.md}}

The Agent Card includes the `urn:jacs:provenance-v1` extension in `capabilities.extensions`, signaling to other JACS agents that your agent supports cryptographic provenance.

Current source signs the card with the persisted ML-DSA-87 root and publishes
its AKP JWK. The key remains stable across calls and restarts; randomized
signatures can differ. This path needs no compatibility key or binding.
For a peer requiring ES256, select `a2a_algorithm="ES256"` in the Python
`jacs_a2a_routes` / `create_a2a_app` options or `a2aAlgorithm: "ES256"` in
Node's `jacsA2AMiddleware` options. The existing compatibility path uses a
persisted ES256 key and a native-root-signed binding. Provision that key with
`jacs-compat agent add-compat-key` when needed; loading alone never creates it.

Strict verification of a direct root card requires the exact explicitly trusted
native key. For ES256 it additionally verifies the scoped compatibility binding
referenced by fixed path and content hash. Local loopback trust tests require
`JACS_ALLOW_PRIVATE_JWKS=true`; private-address JWKS fetching is otherwise denied.

Mounted routers refresh complete snapshots lazily after six days: measured from
local generation for direct root cards, or signed `issuedAt` for ES256 bindings.
The seven-day snapshot serving limit for a direct root card is a local cache
policy, not a signed expiry or revocation signal. For ES256, strict verifiers
accept a binding for at most seven days after `issuedAt`, with five minutes of
future skew. Generation refreshes an authentic binding after six days while
preserving its scopes and explicit `expiresAt`.

HTTP freshness ends by renewal or earlier expiry; failed renewal can serve a
still-valid snapshot with `no-store`, while hard expiry returns 503. An explicit
binding expiry requires renewed authorization and remounting. Separate resource
fetches can straddle replacement; verify related documents together and refetch
if their references differ.

## Next Steps

- **[Discover & Trust Remote Agents](a2a-discover.md)** -- Find other agents and assess their trustworthiness
- **[Exchange Signed Artifacts](a2a-exchange.md)** -- Sign and verify A2A artifacts
- **[A2A Interoperability Reference](../integrations/a2a.md)** -- Full API reference
