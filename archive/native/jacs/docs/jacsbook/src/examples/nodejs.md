# Node.js Examples

{{#include ../_snippets/node-registry-status.md}}

These examples use the native `@hai.ai/jacs` library. Run JavaScript snippets
with top-level `await` as ES modules (`.mjs`). Signing and document I/O offer
async methods; trust helpers and `JacsSimpleAgent` methods are synchronous.

```bash
npm install @hai.ai/jacs
```

## Create, verify, and update a document

Quickstart creates a persistent identity or loads the config that already
exists. Set `JACS_PRIVATE_KEY_PASSWORD` securely in the process environment
for an identity you must reopen; do not put the password in source or command
arguments. See [quickstart persistence](../nodejs/simple-api.md#quickstartoptions).

```javascript
import * as jacs from '@hai.ai/jacs/simple';

await jacs.quickstart({
  name: 'invoice-agent', domain: 'billing.example.com',
  configPath: './invoice-agent/jacs.config.json',
});
const original = await jacs.signMessage({
  invoiceNumber: 'INV-001', amount: 1500, status: 'pending',
});
const result = await jacs.verify(original.raw);
if (!result.valid) throw new Error(result.errors.join(', '));
console.log(result.signerId, result.data);

// Update the full stored envelope, addressed by BOTH ID and version.
const envelope = JSON.parse(original.raw);
const key = `${envelope.jacsId}:${envelope.jacsVersion}`;
envelope.content.status = 'paid';
const updated = await jacs.updateDocument(key, envelope);
console.log(updated.documentId, JSON.parse(updated.raw).jacsVersion);
```

`SignedDocument.documentId` contains only `jacsId`. It is not the versioned
key accepted by `updateDocument()`. Passing a bare ID, the original JSON string
as the key, or a partial envelope does not implement a valid update.

## Low-level document operations

Use `JacsAgent` when you need custom schemas, attachments, or explicit storage
control. This snippet loads the identity created above:

```javascript
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();
await agent.load('./invoice-agent/jacs.config.json');
const signed = await agent.createDocument(JSON.stringify({
  title: 'Meeting notes', content: 'Review the quarterly budget.',
}));
try {
  await agent.verifyDocument(signed);
  console.log('Signature verified');
} catch (error) {
  console.error('Verification failed:', error.message);
  throw error;
}

const document = JSON.parse(signed);
const key = `${document.jacsId}:${document.jacsVersion}`;
document.title = 'Updated meeting notes';
const updated = await agent.updateDocument(key, JSON.stringify(document));
```

The native `verifyDocument()` can reject on invalid signatures. The simplified
`verify()` instead returns `valid: false` for document verification failures;
loading or initialization failures can still throw.

## Sign and verify a file

With the simplified module initialized:

```javascript
const signedFile = await jacs.signFile('./contract.pdf', true);
const verification = await jacs.verify(signedFile.raw);
if (!verification.valid) throw new Error(verification.errors.join(', '));
```

`true` embeds the attachment; `false` records a reference/hash. A portable
signature does not make referenced bytes available to another verifier.

For inline text/image signatures, see [the simplified API](../nodejs/simple-api.md#signtextpath-options).
Extraction alone does not verify embedded media:

```javascript
const payloadJson = await jacs.extractMediaSignature('./signed.png');
if (payloadJson !== null) console.log(JSON.parse(payloadJson));
const image = await jacs.verifyImage('./signed.png', { strict: true });
if (image.status !== 'valid') throw new Error('Image verification failed');
```

## Express document exchange

Install Express, then run this as a separate server module:

```javascript
import express from 'express';
import { JacsClient } from '@hai.ai/jacs/client';
import { jacsMiddleware } from '@hai.ai/jacs/express';

const client = await JacsClient.quickstart({
  name: 'echo-server', domain: 'echo.example.com',
  configPath: './echo-server/jacs.config.json',
});
const app = express();
app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.use('/api', express.text({ type: 'application/json' }));
app.use('/api', jacsMiddleware({ client, verify: true, sign: true }));
app.post('/api/echo', (req, res) => {
  if (req.jacsPayload === undefined) return res.sendStatus(400);
  res.json({ echo: req.jacsPayload });
});
app.listen(3000);
```

Provision signer verification keys on the receiving side. This example
verifies document bodies and signs `res.json()` output; it does not authenticate
an HTTP request's method, URL or audience or grant access to a route. For that
boundary, use [request-bound HTTP authorization](../nodejs/http.md) with caller
policy and atomic nonce consumption. The old `/http` adapter is not used by
this flow.

## MCP

The [Node MCP guide](../nodejs/mcp.md) contains a complete stdio server using
real SDK request schemas. It shows both signed tool outputs for ordinary MCP
clients and signed transport between two JACS peers.

For signed transport, each peer needs its own identity/configuration,
locally provisioned verification keys, and `expectedPeerAgentId` or
`allowedPeerAgentIds`. Both ends need the wrapper. Signatures do not encrypt
MCP messages, and an output signature alone does not authorize tool execution.

## Agreement signature inspection

This example uses the legacy sidecar API with a real local signer ID. Continue
from the initialized simplified API in the first example:

```javascript
const signerId = jacs.getAgentInfo().agentId;
const proposal = await jacs.signMessage({ task: 'review release notes' });
const agreement = await jacs.createAgreement(
  proposal.raw, [signerId], 'Have you reviewed these notes?',
  'Signature inspection example',
);
const signed = await jacs.signAgreement(agreement.raw);
const report = await jacs.checkAgreement(signed.raw);
console.log(report.signers, report.pending);
console.log(report.complete); // false: no authenticated agreement policy
```

The report can inspect mathematical signatures but keeps `complete`,
`policy_authenticated`, and `policy_accepted` false. It cannot establish
participant, role, quorum or consent policy. [Agreement v2](../guides/agreement-v2.md)
is also inspection-only; an application must make its own acceptance and
execution decisions from trusted policy.

## Store portable evidence

Store the complete signed document, not just an ID or a `valid` boolean:

```javascript
import { writeFile, readFile } from 'node:fs/promises';

const signed = await jacs.signMessage({ title: 'Meeting notes' });
await writeFile('./meeting-notes.jacs.json', signed.raw, { flag: 'wx' });
const stored = await readFile('./meeting-notes.jacs.json', 'utf8');
const verification = await jacs.verify(stored);
if (!verification.valid) throw new Error(verification.errors.join(', '));
console.log(verification.data);
```

A storage filename or database row is not a trust decision. Select keys and
expected signer policy independently, verify before use, and retain external
attachments if your application needs them later.

## Test tamper detection without disk configuration

This uses Node's built-in test runner and a disposable in-memory identity.
Save it as `jacs.test.mjs` and run `node --test jacs.test.mjs`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { JacsClient } from '@hai.ai/jacs/client';

test('verifies its own document and rejects changed contents', async () => {
  const client = await JacsClient.ephemeral(); // pq2025
  const signed = await client.signMessage({ value: 42 });
  const valid = await client.verify(signed.raw);
  assert.equal(valid.valid, true);

  const changed = JSON.parse(signed.raw);
  changed.content.value = 99;
  const invalid = await client.verify(JSON.stringify(changed));
  assert.equal(invalid.valid, false);
});
```

A config file without generated keys and an agent document cannot be loaded
as a test identity. Use ephemeral agents or quickstart with a unique temporary
configuration directory.

## Related references

- [Installation](../nodejs/installation.md)
- [API reference](../nodejs/api.md)
- [MCP integration](../nodejs/mcp.md)
- [A2A integration](../integrations/a2a.md)
