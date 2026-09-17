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
signed = client.sign_artifact({"artifactId": "a-1", "operation": "classify"}, "artifact")
result = client.get_a2a().verify_wrapped_artifact(signed)
assert result["valid"]
```

Node.js:

```typescript
const signed = await client.signArtifact(
  { artifactId: 'a-1', operation: 'classify' },
  'artifact',
);

const result = await client.verifyArtifact(signed);
console.log(result.valid);
```

Both SDKs require the canonical native A2A verifier for an affirmative result.
The generic `verify_response()` / `verifyResponse()` document API is not an A2A
fallback: even a literal success boolean yields an invalid result with blank
signer, version, type, timestamp, and payload provenance, and cannot elevate
trust. This prevents parsed attacker-controlled wrapper fields from being
presented as authenticated A2A evidence.

The Node signing wrapper also validates the native return contract before
releasing it: the document must carry complete portable-v2 signature metadata,
its payload and type must match the request, and its ordered parent chain must
exactly match the caller's input. If no parents were requested, only an absent
or empty returned chain is accepted. This prevents a malformed native result
from injecting, dropping, reordering, or changing chain-of-custody evidence.

## Trust Policies

Trust policy answers a different question from cryptographic verification.

- **Trust policy**: should this remote agent be admitted?
- **Artifact verification**: is this specific signed payload valid?

The current policy meanings are:

{{#include ../_snippets/a2a-trust-policies.md}}

`verified` means the card signature and a durable same-origin key pin verified.
It proves origin/key continuity, not that the self-asserted `jacsId` is a
real-world or explicitly trusted identity. `strict` is the identity-bound mode.

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

## ES256-Signed Agent Cards (P2)

Agent cards can also be exported with an ES256 signature from the agent's
compatibility key (`export_a2a_agent_card` in the Rust core and bindings,
feature `a2a`). This is a card-typed exporter, not a generic JWS API:

- The JWS protected header is pinned to `{"alg": "ES256", "typ": "JOSE",
  "kid": "<compat-key kid>"}` — `typ` is `JOSE`, not `JWT`.
- The export is gated by the `a2a-agent-card` scope of the native-root-signed
  compatibility key binding (an identity scope, granted by default).
- The card's `metadata` carries `jacsCompatKid`,
  `jacsCompatBindingHash`, and the fixed same-origin
  `jacsCompatBindingPath` (`/.well-known/jacs-compat-binding.json`).

A stock JOSE verifier can check the ES256 signature against the agent's
JWKS (`jacs agent export-jwks`), but that proves possession of the
compatibility key only. Tracing the card to the agent's native root requires
verifying the native-root-signed compatibility key binding
(`jacs agent export-compat-binding`). Native `generate_well_known_documents`
publishes the binding at the fixed path and reuses the same persisted ES256 key
across calls and restarts. An obsolete explicit `ring-Ed25519` discovery-key
choice is rejected rather than silently ignored — see the
[Security Model](../advanced/security.md#compatibility-key-binding-p2).

Under `strict`, the verifier checks the trusted native root signature, expected
`jacsId` and `jacsVersion`, binding content hash, compatibility `kid` and JWK,
the `a2a-agent-card` scope, expiry, and a signed `issuedAt` no more than seven
days old or five minutes in the future. This absolute freshness check applies
on first contact; local discovery generation refreshes an authentic binding at
six days while preserving its scopes and explicit expiry. A self-advertised
JWKS key by itself can never establish the claimed JACS identity.

## Current Runtime Differences

- **Python**: `jacs.a2a_server` is the clearest full discovery story.
- **Node.js**: `jacsA2AMiddleware()` serves five `.well-known` routes from Express, but the generated `jwks.json` and `jacs-pubkey.json` payloads are still placeholder metadata. `listen()` is intentionally smaller and only suitable for demos.

## Example Paths In This Repo

- `jacspy/tests/test_a2a_server.py`
- `jacsnpm/src/a2a-server.js`
- `jacsnpm/examples/a2a-agent-example.js`
- `jacs/tests/a2a_cross_language_tests.rs`
