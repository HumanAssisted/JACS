# HTTP Signing and Verification

{{#include ../_snippets/node-registry-status.md}}

HTTP integration has two separate jobs: verifying signed documents and
binding authorization to the actual request. The maintained
[Express](express.md) and [Koa](koa.md) adapters verify document bodies and
optionally sign responses. They do not implement request-bound authorization.
The old `@hai.ai/jacs/http` adapter calls removed root-module helpers; migrate
to those framework adapters instead.

## Request-bound credentials

Use the synchronous `JacsSimpleAgent` instance API. Run this client as an ES
module (`.mjs`), with an existing client configuration and a trusted server-key
map provisioned independently of the response:

```javascript
import { readFile } from 'node:fs/promises';
import { JacsSimpleAgent } from '@hai.ai/jacs';

const agent = JacsSimpleAgent.load('./client/jacs.config.json');
const serverKeysJson = await readFile('./trusted-server-keys.json', 'utf8');
const url = 'https://api.example.com/v1/jobs?mode=strict';
const body = JSON.stringify({ action: 'inspect', jobId: '42' });
const authorization = agent.buildRequestAuthHeader('POST', url, body, 'jobs-api');

const response = await fetch(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: authorization },
  body,
});
if (!response.ok) throw new Error(`HTTP ${response.status}`);
const event = JSON.parse(agent.unwrapSignedEvent(await response.text(), serverKeysJson));
console.log(event.data);
```

The key map is a JSON object mapping expected server agent IDs to trusted PEM
public keys. Do not construct it from an unverified response. The credential
binds method, absolute URL including query, exact body bytes, audience,
signer/key, issue time, and nonce. Send the final body unchanged.

The server must verify the same request context with a trusted key, enforce
its caller policy, and atomically consume the nonce before executing work.
Neither a generic signed body nor the legacy `buildAuthHeader()` provides
that binding. See [request-bound HTTP authorization](../advanced/security.md#request-bound-http-authorization)
for the server contract.

## Signed response events

A server with an initialized `JacsSimpleAgent` creates the v2 envelope with:

```javascript
const envelope = agent.signResponse(JSON.stringify({ result: 42 }));
```

`unwrapSignedEvent(envelope, serverKeysJson)` verifies the complete envelope,
including payload and metadata. It throws on unsigned input, legacy
payload-only envelopes, unknown signers, and mutations. Its result contains
`verified`, `data`, `signerId`, `timestamp`, `algorithm`, and `documentId`.
Verification alone does not consume an event for replay prevention or bind it
to an outstanding request; enforce those application constraints before use.

A signature proves possession of the selected key and integrity of the signed
scope. Real-world identity, authorization, freshness, and permitted use come
from the verifier's trust and application policies. Signatures do not encrypt
the payload; use HTTPS for transport confidentiality.

## Signed document bodies

For document exchange, use `JacsClient.signMessage()` and `verify()` or the
framework adapters. Configure sender trust and route authorization separately.
Express's `authReplay` and Koa's matching option add freshness and in-process
deduplication for signed bodies; they do not bind method, URL, or audience.

- [Express middleware](express.md): `jacsMiddleware` and `req.jacsPayload`
- [Koa middleware](koa.md): `jacsKoaMiddleware` and `ctx.state.jacsPayload`
- [MCP integration](mcp.md): signed messages between configured peers
- [Simplified API](simple-api.md): documents and transport helper reference
