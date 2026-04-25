# JACS for Node.js

Cryptographic identity, signing, and verification for AI agents — from Node.js.

```bash
npm install @hai.ai/jacs
```

Prebuilt native bindings. No Rust compilation during install.

[Full documentation](https://humanassisted.github.io/JACS/) | [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Quick start

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.quickstart({ name: 'my-agent', domain: 'agent.example.com' });
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

All operations are async by default. Sync variants available with a `Sync` suffix (e.g. `signMessageSync`).

## Core operations

| Function | Description |
|----------|-------------|
| `quickstart(options)` | Create a persistent agent with keys — zero config |
| `load(configPath)` | Load agent from config file |
| `signMessage(data)` | Sign any JSON data |
| `signFile(path, embed)` | Sign a file |
| `verify(doc)` | Verify signed document |
| `verifyStandalone(doc, opts)` | Verify without loading an agent |
| `audit()` | Run a security audit |

## What's new in 0.11.0

*Why this matters:* shared markdown that multiple agents review and counter-sign, plus signed images for AI-era provenance, are now first-class — the signature is embedded in the artifact, no sidecar JSON required.

```typescript
import * as jacs from '@hai.ai/jacs/simple';

await jacs.load('./jacs.config.json');

// Text — permissive verify (default)
await jacs.signText('README.md');
const result = await jacs.verifyText('README.md');
console.log(result.status);  // 'signed' | 'missing_signature' | 'malformed'

// Hard-fail if the file isn't signed — Promise rejects with MissingSignature error
try {
  await jacs.verifyText('README.md', { strict: true });
} catch (err) {
  if (/MissingSignature/.test(err.message)) {
    console.log('not signed');
  } else {
    throw err;
  }
}

// Override trust store with a directory of <signer_id>.public.pem files
await jacs.verifyText('README.md', { keyDir: './trusted-keys/' });

// Images
await jacs.signImage('photo.png', 'signed.png');
const v = await jacs.verifyImage('signed.png');
console.log(v.status);  // 'valid'

// Extract the embedded provenance payload (decoded JSON by default)
const payload = await jacs.extractMediaSignature('signed.png');
```

The same five methods are available on the instance-based `JacsClient` for multi-agent processes. All operations return Promises (async-first since v0.7.0).

A JACS inline signature proves "agent X signed these canonical bytes at their claimed time." It does not prove first creation or legal ownership.

## Verify without an agent

```typescript
import { verifyStandalone } from '@hai.ai/jacs/simple';

const result = verifyStandalone(signedJson, { keyDirectory: './keys/' });
```

Cross-language interop tested on every commit — documents signed in Rust or Python verify identically in Node.js.

## Framework adapters

Adapters for Vercel AI SDK, Express, Koa, LangChain.js, and MCP. All framework dependencies are optional peer deps.

## Instance-based API

For multiple agents in one process:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({ name: 'my-agent', domain: 'example.com' });
const signed = await client.signMessage({ action: 'approve' });
```

See [DEVELOPMENT.md](https://github.com/HumanAssisted/JACS/blob/main/DEVELOPMENT.md) for the full API reference, advanced usage (agreements, A2A, attestation, headless loading), framework adapter examples, and testing utilities.

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](./examples/)
