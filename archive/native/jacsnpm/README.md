# JACS for Node.js

Cryptographic identity, signing, and verification for AI agents from Node.js.

> **Published 0.15.0:** `@hai.ai/jacs` remains a supported native Node.js library.
> Installed-package checks and provenance are recorded in the
> [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md). Its source lives in the
> separate native workspace; MCP remains the primary integration guide.

```bash
npm install --save-exact @hai.ai/jacs@0.15.0
```

Prebuilt native bindings are included. A normal install does not require compiling Rust.

### Install-time CLI download

Installation optionally downloads a checksummed CLI from the matching GitHub
release into a cache keyed by version and platform. Use
`npm install --ignore-scripts` to skip it; library APIs remain available if the
download fails. No musl CLI asset is published. Run `npx jacs-cli --diagnose`
to inspect the optional CLI, or install it with `cargo install jacs-cli`.

> **Building for the browser?** Use the published
> [`@hai.ai/jacs-wasm`](https://github.com/HumanAssisted/JACS/blob/main/jacs-wasm/README.md) package, also at 0.15.0.
> `@hai.ai/jacs` ships a `.node` native module that does not load in a browser.
> Browser WASM provides the portable crypto and encrypted-storage surface;
> it does not expose every native integration.

[Full documentation](https://humanassisted.github.io/JACS/) | [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Quick start

```javascript
import * as jacs from '@hai.ai/jacs/simple';

await jacs.quickstart({ name: 'my-agent', domain: 'agent.example.com' });
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

Run this example as an ES module (`.mjs`). Simple signing and I/O methods are
async; selected operations also have a `Sync` variant, such as
`signMessageSync`. `verifyStandalone`, trust helpers and the low-level
`JacsSimpleAgent` transport helpers shown below are synchronous.

## Core operations

| Function | Description |
|----------|-------------|
| `quickstart(options)` | Create or load a persistent agent |
| `load(configPath)` | Load an agent from config |
| `signMessage(data)` | Sign JSON data |
| `signFile(path, embed)` | Sign a file |
| `verify(doc)` | Verify a signed document |
| `verifyStandalone(doc, opts)` | Verify without loading an agent |
| `createAgreementV2(input)` | Create a standalone Agreement v2 document |
| `signAgreementV2(doc, role)` | Sign as `signer`, `witness`, or `notary` |
| `verifyAgreementV2(doc)` | Inspect Agreement v2 hashes, signatures and claimed status |
| `audit()` | Run a security audit |

## Public human-approved document verification

`verifyHumanApprovedDocument` requires a native `human-approval` build.
`npm run build` enables vendored OpenSSL; `build:slim` and `build:debug` omit it.
The installed addon supports Node 20+; see
[source build requirements](https://humanassisted.github.io/JACS/native/nodejs/installation.html#requirements).
This build configuration does not establish availability in older releases.
Browser WASM does not provide this verifier.

```javascript
const { JacsSimpleAgent } = require('@hai.ai/jacs');

if (!JacsSimpleAgent.verifyHumanApprovedDocument) {
  throw new Error('This native build requires the human-approval feature');
}
const report = JSON.parse(JacsSimpleAgent.verifyHumanApprovedDocument(
  bundleJson, expectedJson, authorityJson, provenanceJson,
));
```

This static method needs no agent, signing key, configuration, or network
lookup. All four arguments are JSON strings. Read stored public evidence into
`bundleJson`; select the expected human/action/credential and the two public
key pins from your application's trusted state, not from the bundle. The
complete report is returned as JSON. Success confirms retained proof and
document integrity, **not** permission to execute now: `current` remains
`not_evaluated`. Live authorization, revocation and one-use checks stay with
the relying application.

## Request authentication and signed events

Use the instance-based `JacsSimpleAgent` for the transport protocol helpers.
Its methods are synchronous; the JSON strings and body string below are the
exact values passed to the native binding:

```javascript
const { JacsSimpleAgent } = require('@hai.ai/jacs');

const agent = JacsSimpleAgent.ephemeral('ed25519');
const body = '{"action":"approve"}';
const authorization = agent.buildRequestAuthHeader(
  'POST',
  'https://api.example.com/v1/jobs?mode=strict',
  body,
  'jobs-api',
);
if (!authorization.startsWith('JACS v2.')) throw new Error('unexpected auth version');

const envelope = agent.signResponse(JSON.stringify({ decision: 'allow' }));
const signerId = JSON.parse(envelope).jacsSignature.agentID;
const serverKeys = JSON.stringify({ [signerId]: agent.getPublicKeyPem() });
const verified = JSON.parse(agent.unwrapSignedEvent(envelope, serverKeys));
if (!verified.verified || verified.data.decision !== 'allow') {
  throw new Error('response verification failed');
}
```

`buildRequestAuthHeader()` accepts `Buffer`, `Uint8Array`, or a string (encoded as
UTF-8), and binds the exact body bytes with method, absolute URL including
query, audience, signer/key, issue time, and nonce. Do not stringify or
otherwise transform the request body again afterward. `signResponse()` emits a
`2.0.0` envelope whose `jacs-response-v2` signature covers the payload and all
metadata. `unwrapSignedEvent()` is fail-closed: it throws for plain events,
legacy payload-only envelopes, unknown signers, and any mutation.

The `serverKeys` object must come from the application's configured trust
policy. A valid signature proves possession of the corresponding private key;
it does not independently establish a person's, organization's, or domain's
real-world identity.

The old no-argument `buildAuthHeader()` remains available for source
compatibility and emits a WARN because it does not bind the request. Migrate
both peers to `JACS v2`; strict deployments can reject the legacy method with
`JACS_REJECT_UNBOUND_AUTH_HEADER=true`.

## Text and image provenance

Node exposes the same inline text and image signing surface as the CLI:

```typescript
import * as jacs from '@hai.ai/jacs/simple';

await jacs.load('./jacs.config.json');

// Markdown/text: append and verify an inline signature block.
await jacs.signText('README.md');
const text = await jacs.verifyText('README.md');
console.log(text.status);  // 'signed' | 'missing_signature' | 'malformed'

try {
  await jacs.verifyText('README.md', { strict: true });
} catch (err) {
  if (/MissingSignature/.test(err.message)) {
    console.log('not signed');
  } else {
    throw err;
  }
}

await jacs.verifyText('README.md', { keyDir: './trusted-keys/' });

// Images: embed and verify a signature in PNG, JPEG, or WebP metadata.
await jacs.signImage('photo.png', 'signed.png');
const image = await jacs.verifyImage('signed.png');
console.log(image.status);  // 'valid'

const payload = await jacs.extractMediaSignature('signed.png');
```

The same methods are available on the instance-based `JacsClient` for multi-agent processes. These signatures prove that an agent signed specific canonical bytes at its claimed time; they do not prove first creation or legal ownership.

## Verify without an agent

```typescript
import { verifyStandalone } from '@hai.ai/jacs/simple';

const result = verifyStandalone(signedJson, { keyDirectory: './keys/' });
```

JACS uses a shared signed-document format across bindings. See the
[release evidence](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
for installed-consumer checks and their limits.

## Agreement v2

Use Agreement v2 to inspect native compatibility agreement documents:

```typescript
import { JacsSimpleAgent } from '@hai.ai/jacs';

const agent = JacsSimpleAgent.ephemeral('ed25519');
const agentId = agent.getAgentId();

const agreement = await agent.createAgreementV2(JSON.stringify({
  title: 'Refund approval',
  description: 'Approval for a bounded refund.',
  terms: 'Refund up to $25 for order 123.',
  status: 'proposed',
  parties: [{ agentId, agentType: 'ai', role: 'signer' }],
  signaturePolicy: { partyQuorum: 'all', witnessRequired: 0, notaryRequired: 0 },
  controllers: [agentId],
}));

const signed = await agent.signAgreementV2(agreement, 'signer');
const report = await agent.verifyAgreementV2(signed);
```

Agreement v2 inspection checks mathematical signatures and claimed status;
`valid` and `policyAccepted` remain false. Application policy acceptance and
permission to execute are separate decisions.

The older `createAgreement()` / `signAgreement()` / `checkAgreement()` methods remain for simple `jacsAgreement` sidecars on existing documents.

## Framework adapters

Adapters are available for [Express](https://humanassisted.github.io/JACS/native/nodejs/express.html),
[Koa](https://humanassisted.github.io/JACS/native/nodejs/koa.html),
[LangChain.js](https://humanassisted.github.io/JACS/native/nodejs/langchain.html),
[Vercel AI SDK](https://humanassisted.github.io/JACS/native/nodejs/vercel-ai.html)
and [MCP](https://humanassisted.github.io/JACS/native/nodejs/mcp.html).
Framework dependencies are optional peers. Signing fails closed: unsigned
output is withheld unless an explicit compatibility escape hatch permits it.
Do not enable those options when signed output is required.

MCP transport verification must also identify the intended peer. Configure
`expectedPeerAgentId` or `allowedPeerAgentIds`, optionally with an independently
obtained public-key-hash pin. Signature validity alone is not endpoint
authentication; see the MCP guide for transport setup and replay handling.

Current-source [A2A discovery](https://humanassisted.github.io/JACS/native/guides/a2a-serve.html)
serves five direct-root documents, or six for explicit ES256 compatibility.
Verify the card/JWKS and any root-signed compatibility binding against your
trust policy; discovery and cache freshness do not establish identity or
authority. New source behavior is not evidence of a new published release.
See the [A2A guide](https://humanassisted.github.io/JACS/native/integrations/a2a.html)
for signed artifacts, parent chains and trust assessment.

## Instance-based API

For multiple agents in one process:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({ name: 'my-agent', domain: 'example.com' });
const signed = await client.signMessage({ action: 'approve' });
```

See the [API reference](https://humanassisted.github.io/JACS/native/nodejs/api.html)
and [native development guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md).

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsnpm/examples)
