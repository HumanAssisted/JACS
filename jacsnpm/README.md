# JACS for Node.js

Cryptographic identity, signing, and verification for AI agents from Node.js.

```bash
npm install @hai.ai/jacs
```

Prebuilt native bindings are included. A normal install does not require compiling Rust.

> **Building for the browser?** Use [`@jacs/wasm`](https://www.npmjs.com/package/@jacs/wasm)
> instead. `jacsnpm` ships a `.node` native module that does not load in a
> browser context; `@jacs/wasm` is the WebAssembly build with the same
> JACS protocol surface (sign / verify / agreements / localStorage).

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
| `audit()` | Run a security audit |

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

## Framework adapters

Adapters for Vercel AI SDK, Express, Koa, LangChain.js, and MCP are available. Framework dependencies are optional peer dependencies.

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
