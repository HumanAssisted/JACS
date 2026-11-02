# Node.js Installation

{{#include ../_snippets/node-registry-status.md}}

`@hai.ai/jacs` is a native Node.js package. Browser applications use
[`@hai.ai/jacs-wasm`](../wasm/building.md).

## Requirements

- Node.js 20 or newer.
- Published addons: macOS x64/arm64 and Linux x64/arm64 for glibc and musl.
  No native Windows addon is published; WSL needs a matching Linux build.
- Source builds with NAPI-RS CLI 3: Node `^20.17.0`, `^22.13.0` or `>=23.5.0`,
  plus Rust 1.97 and a platform C toolchain.

## Installation

```bash
npm install --save-exact @hai.ai/jacs@0.15.0
```

The package includes prebuilt bindings. Its optional install script downloads a
checksummed portable CLI; `npm install --ignore-scripts` skips that download.
The library remains usable without the CLI. See the
[package README](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsnpm/README.md#install-time-cli-download)
for details.

## Verify Installation

Save as `test.mjs` and run `node test.mjs`:

```javascript
import * as jacs from '@hai.ai/jacs/simple';

await jacs.quickstart({ name: 'my-agent', domain: 'my-agent.example.com' });
const signed = await jacs.signMessage({ hello: 'world' });
const result = await jacs.verify(signed.raw);
if (!result.valid) throw new Error('signature verification failed');
console.log('Verified signer:', result.signerId);
```

{{#include ../_snippets/quickstart-persistent-agent.md}}

New identities default to `pq2025` (ML-DSA-87), without classical fallback.
Ed25519 is an explicit compatibility choice.

## Package Structure

TypeScript declarations are included. Choose the API for your application:

| Import | Use |
| --- | --- |
| `@hai.ai/jacs/simple` | One process-wide signing session |
| `@hai.ai/jacs/client` | Independent `JacsClient` instances |
| `@hai.ai/jacs` | Lower-level `JacsAgent` and `JacsSimpleAgent` APIs |
| `@hai.ai/jacs/mcp` | Signed MCP transports and tool registration |
| `@hai.ai/jacs/express`, `@hai.ai/jacs/koa` | HTTP framework middleware |

See the [simple API](simple-api.md), [instance usage](basic-usage.md) and
[API reference](api.md) for method signatures and async/sync variants.

## Configuration and storage

Use `quickstart()` to create a persistent identity, or `load(configPath)` for
an existing one. See [configuration](../reference/configuration.md) for paths,
password sources and environment settings, and [storage](../advanced/storage.md)
for backends. Selecting a backend in config does not add a missing build feature;
AWS/S3 requires a custom source build with the Rust `s3` feature enabled.

## Troubleshooting

- Check `node --version` and match the addon's OS, architecture and libc.
  `npm rebuild` cannot supply an unpublished target. For a custom build, use
  `make build-jacsnpm` from the repository root; see the
  [native development guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md).
- Keep config and key directories private and writable by the signing user.
  For decryption errors, check the password source before replacing keys.
- Use `.mjs` or `"type": "module"` for examples with `import` and top-level
  `await`. Type declarations ship with the package; use a module-resolution
  mode compatible with your Node/TypeScript toolchain.

## Next Steps

- [MCP integration](mcp.md)
- [Express](express.md), [Koa](koa.md), [LangChain.js](langchain.md) and [Vercel AI SDK](vercel-ai.md)
- [Examples](../examples/nodejs.md)
