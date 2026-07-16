# JACS for Node.js

Cryptographic identity, signing, and verification for AI agents from Node.js.

> **Registry status (observed 2026-07-11):** npm still serves
> `@hai.ai/jacs@0.10.1`. This README describes source `0.11.4`; Agreement v2 and
> other newer methods are unavailable from the current registry package. Pin a
> version and inspect its exported methods until a coordinated release closes
> the gap.

```bash
npm install @hai.ai/jacs
```

Prebuilt native bindings are included. A normal install does not require compiling Rust.

### Install-time CLI download

The npm `postinstall` script makes an optional network request to the matching
`cli/vX.Y.Z` GitHub Release. It validates `sha256sums.txt` (with a validated
per-asset checksum fallback) before downloading the archive, bounds redirects,
time, bytes, members, and extraction expansion, and installs only a regular
executable. Remote HTTPS downloads cannot redirect into local HTTP services.

The executable is cached by the exact package version and release platform at
`$XDG_CACHE_HOME/jacs/bin/<version>/<platform>/` (or the platform cache-home
equivalent), not inside `node_modules`. Shared package stores therefore cannot
silently reuse a macOS, Windows, Linux, or older-version binary. Linux musl is
rejected because no musl CLI asset is published. Unsafe cache symlinks,
permissions, and pre-existing executable paths fail closed. Library APIs remain
usable if the platform or network is unsupported; the warning is written to
stderr.

Use `npm install --ignore-scripts` when install-time network access is not
allowed. In that mode no CLI is downloaded. Check the optional binary with:

```bash
npx jacs-cli --diagnose
```

For a standalone CLI, use `cargo install jacs-cli`.

> **Building for the browser?** Use the source-built
> [`@jacs/wasm`](../jacs-wasm/README.md) package instead. It is not yet
> published on npm. `@hai.ai/jacs` ships a `.node` native module that does not
> load in a browser context; `@jacs/wasm` is the WebAssembly build with the
> browser protocol surface (sign / verify / agreements / localStorage).

[Full documentation](https://humanassisted.github.io/JACS/) | [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Quick start

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.quickstart({ name: 'my-agent', domain: 'agent.example.com' });
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

All operations are async by default. Sync variants are available with a `Sync` suffix, for example `signMessageSync`.

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
| `verifyAgreementV2(doc)` | Verify Agreement v2 hash, policy, transcript, and status |
| `audit()` | Run a security audit |

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

Cross-language interop is tested on every commit. Documents signed in Rust or Python verify in Node.js, and Node-signed documents verify in the other bindings.

## Agreement v2

Use Agreement v2 for new multi-agent consent workflows:

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

The older `createAgreement()` / `signAgreement()` / `checkAgreement()` methods remain for simple `jacsAgreement` sidecars on existing documents.

## Framework adapters

Adapters for Vercel AI SDK, Express, Koa, LangChain.js, and MCP are available. Framework dependencies are optional peer dependencies.

Signing adapters fail closed: if signing is enabled and the signer fails or
returns no portable `raw` document, the original output is withheld. Express
and Koa sign JSON scalar responses as well as objects. LangChain rejects
unexpected tool-output shapes instead of silently returning them. The MCP
transport signs JSON-RPC error responses as well as successful responses.

Vercel AI generation provenance includes `signedDocument`, the full portable
JACS document binding `{ output, metadata }`. Streaming output is buffered up
to 1 MiB by default and is released only after signing succeeds; configure
`maxBufferedStreamBytes` (maximum 16 MiB) for a different bounded limit.
With `a2a: true`, `providerMetadata.jacs.a2a.signedDocument` separately binds
the exact emitted `agentCard`, and is constructed before buffered output is
released. That card is the signer's cryptographic self-assertion; configured
trust and real-world identity still require independent verification.

The escape hatches `allowUnsignedOutput: true`, MCP's
`allowUnsignedFallback: true`, and Vercel's `allowPostHocStreaming: true` are
dangerous compatibility options. They must be literal booleans; `strict: true`
overrides unsigned-output opt-ins, and post-hoc streaming additionally requires
`allowUnsignedOutput: true`.
MCP transports normally deliver parsed JSON-RPC objects. Signed traffic therefore
uses the schema-valid reserved `notifications/jacs/signed` carrier (wire version
`1`) whose `params.envelope` contains the portable JACS document. The receiver
strictly validates the carrier, verifies the envelope, and schema-validates the
recovered JSON-RPC payload before dispatch. Ordinary parsed objects fail closed
unless `allowUnsignedFallback: true` is explicitly enabled.

MCP signature validity alone proves possession of some resolvable signing key;
it does not identify the intended endpoint. Configure the peer's exact stable
`jacsSignature.agentID` on both sides. An optional public-key-hash pin binds one
key version more tightly:

```typescript
import { JacsAgent } from '@hai.ai/jacs';
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const localAgent = new JacsAgent();
await localAgent.load('./jacs.config.json');
const secureTransport = createJACSTransportProxy(
  baseTransport,
  localAgent,
  'client',
  {
    expectedPeerAgentId: '4d177fb9-84e0-421c-a52f-e33dca51e720',
    expectedPeerPublicKeyHash: '<exact hash obtained out of band>',
  },
);
```

Use `allowedPeerAgentIds: [...]` for an intentional multi-peer transport. With
neither option, authenticated input is rejected before `onmessage`.
`dangerouslyAllowAnyValidSigner: true` is a literal-only migration escape hatch:
it accepts any cryptographically valid signer known to JACS and therefore
provides proof of key possession, not MCP endpoint authentication. It cannot be
combined with an identity policy. Signed-carrier failures never fall through to
the unsigned compatibility path.

Every outbound JSON-RPC request is assigned a cryptographically random wire ID.
The proxy restores the caller's local ID only for the matching response and
consumes the mapping once; unknown, expired, replayed, or cross-session response
IDs fail closed. Pending correlations are bounded and cleared when the transport
closes.

`JACSA2AIntegration.quickstart({ skills })` retains its source-compatible type
but non-empty wrapper-supplied skills now fail immediately. Agent Card skills
are identity-bearing signed data; persist them through the native agent/card
configuration before generating or serving discovery documents.

`signArtifact()` uses the native canonical A2A signer and returns the direct
`a2a-*` document; it never wraps the result in a generic `jacs_payload` header
or falls back to `signRequest()`. It rejects incomplete or legacy-v1 signature
metadata and requires the returned parent chain to exactly match the caller's
ordered input; when no parents were requested, only an absent or empty chain is
accepted. `verifyWrappedArtifact(artifact)` proves the
artifact signature and parent chain. Pass the real identity-bound Agent Card as
the second argument when trust-policy assessment is also required; JACS never
synthesizes an Agent Card from unauthenticated artifact claims. Affirmative A2A
verification requires the native `verifyA2aArtifactSync()` contract. The
generic `verifyResponse()` method is never used as an A2A fallback: even a
literal `true` yields a stable invalid result with blank provenance and cannot
elevate trust.

## Instance-based API

For multiple agents in one process:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({ name: 'my-agent', domain: 'example.com' });
const signed = await client.signMessage({ action: 'approve' });
```

See [DEVELOPMENT.md](https://github.com/HumanAssisted/JACS/blob/main/DEVELOPMENT.md) for the full API reference, advanced usage, framework adapter examples, and testing utilities.

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](./examples/)
