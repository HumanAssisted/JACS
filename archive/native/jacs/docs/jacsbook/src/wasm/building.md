# Browser WASM Package

`@hai.ai/jacs-wasm` is the browser WebAssembly package for JACS. Use it when a
web page needs to create a browser-local JACS agent, sign JSON, verify
signed JACS documents, or collect multi-party agreement signatures
without calling a backend service.

> **Published 0.15.0:** See the [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
> for provenance and installed-browser checks. Later source APIs require a
> separate release record; use a local build for current checkout behavior.

For Node.js server applications, use the native `@hai.ai/jacs` package
instead. `@hai.ai/jacs-wasm` is browser-only: no filesystem access, no DNS
trust lookup, no MCP server, and no CLI process.

## Install

```sh
npm install --save-exact @hai.ai/jacs-wasm@0.15.0
```

To build this checkout instead:

```sh
git clone https://github.com/HumanAssisted/JACS.git
cd JACS
make build-wasm
# From your consuming project:
npm install /absolute/path/to/JACS/jacs-wasm/pkg
```

Bundlers must be able to load an ES module plus the generated
`jacs_wasm_bg.wasm` asset. The source package is smoke-tested with Vite and
Chromium.

## Quick Start

```ts
import { createEphemeral, initJacsWasm } from "@hai.ai/jacs-wasm";

await initJacsWasm();

const agent = await createEphemeral(); // pq2025; no classical fallback
const signed = agent.signMessageJson(JSON.stringify({ hello: "world" }));
const result = JSON.parse(agent.verifyJson(signed));

console.log(result.valid); // true
```

`initJacsWasm()` is idempotent. The async constructors also initialize
the module, so applications can call `createEphemeral`,
`importEncryptedAgent`, `importEncryptedAgentFiles`, or `createVerifier`
directly.

## Public API

Constructors:

```ts
createEphemeral(algorithm?: "ed25519" | "pq2025" | "es256"): Promise<CoreAgentHandle>
importEncryptedAgent(materialJson: string, password: string): Promise<CoreAgentHandle>
importEncryptedAgentFiles(files: EncryptedAgentFiles, password: string): Promise<CoreAgentHandle>
createVerifier(publicKeyBase64: string, algorithm: "ed25519" | "pq2025" | "es256"): Promise<CoreAgentHandle>
```

`importEncryptedAgentFiles` is shaped for browser file pickers:

```ts
type EncryptedAgentFiles = {
  configText: string;
  agentText: string;
  publicKeyBytes: Uint8Array;
  encryptedPrivateKeyBytes: Uint8Array;
};
```

The wrapper infers the algorithm from the raw public key length: 32 bytes
for `ed25519`, 2592 bytes for `pq2025`, and 65-byte uncompressed SEC1 for
explicit ES256 compatibility. New identities default to `pq2025`.

Core handle methods:

```ts
agent.signMessageJson(dataJson: string): string
agent.verifyJson(signedJson: string): string
agent.verifyWithKeyJson(
  signedJson: string,
  publicKeyBase64: string,
  algorithm: "ed25519" | "pq2025" | "es256",
): string
agent.exportAgent(): string
agent.getPublicKeyBase64(): string
agent.algorithm(): "ed25519" | "pq2025" | "es256"
agent.isUnlocked(): boolean
agent.clearSecrets(): void
agent.metrics(): string
```

`clearSecrets()` zeroes the in-memory private key. Signing then fails
with a `Locked` error, while verification continues to work.

## Agreement signature inspection

Browser callers can collect and inspect v1 sidecar signatures. This local
example constructs both handles and pins their actual IDs and keys before
receiving an agreement. In an application, obtain the signer-key mapping
through independently trusted enrollment, never from the submitted document.

```ts
import { createEphemeral, createVerifier, createAgreementJson } from "@hai.ai/jacs-wasm";

const alice = await createEphemeral();
const bob = await createEphemeral();
const aliceId = JSON.parse(alice.exportAgent()).jacsId;
const bobId = JSON.parse(bob.exportAgent()).jacsId;
const trustedSigners = [
  { agentId: aliceId, publicKeyBase64: alice.getPublicKeyBase64(), algorithm: alice.algorithm() },
  { agentId: bobId, publicKeyBase64: bob.getPublicKeyBase64(), algorithm: bob.algorithm() },
];
const verifier = await createVerifier(alice.getPublicKeyBase64(), alice.algorithm());
const agreement = createAgreementJson(
  JSON.stringify({ action: "review", version: "1.2.3" }),
  JSON.stringify([aliceId, bobId]),
  "Have you reviewed this release?",
  "Signature inspection example",
);
const signedByAlice = alice.signAgreementJson(agreement, "reviewer");
const signedByBoth = bob.signAgreementJson(signedByAlice, "reviewer");
const outcome = JSON.parse(
  verifier.verifyAgreementJson(signedByBoth, JSON.stringify(trustedSigners)),
);
console.log(outcome);
```

The v1 signature does not authenticate participant, role or quorum policy;
`role` can be edited without invalidating its signature. The report's
mathematical outcomes are not consent, policy acceptance or permission to
execute. Missing signer keys are reported per signer. Keep application
acceptance policy separate from these inspection results.

## Browser Persistence

`localStore` wraps `window.localStorage` and stores values under the
`jacs:` namespace.

```ts
import { localStore } from "@hai.ai/jacs-wasm";

localStore.saveEncryptedAgent("alice", encryptedMaterialJson);
localStore.saveDocument("doc-1", signed);

const restored = localStore.loadEncryptedAgent("alice");
const keys = localStore.listKeys();

localStore.remove("doc-1");
localStore.clearAll();
```

`saveEncryptedAgent` refuses obvious plaintext secrets, top-level or
nested password-like fields, and raw private-key-shaped payloads. The
browser package should persist encrypted agent material and signed
documents only.

## Workers

Post-quantum key generation can block the main thread. The worker
subpath moves key generation and signing to a Web Worker:

```ts
import {
  createEphemeralInWorker,
} from "@hai.ai/jacs-wasm/worker";

const workerAgent = await createEphemeralInWorker("pq2025");
const signed = await workerAgent.signMessage(JSON.stringify({ hello: "world" }));
```

## Observability

Browsers do not expose stdout or a Prometheus endpoint for package code.
`@hai.ai/jacs-wasm` exposes per-handle counters instead:

```ts
const snapshot = JSON.parse(agent.metrics());
// { signCount, verifyCount, lastSignDurationMs, lastVerifyDurationMs }
```

For local debugging, set `globalThis.JACS_WASM_DEBUG = true` before a
sign, verify, or `clearSecrets` call. Debug logging is off by default.

## Security Notes

WebAssembly memory is visible to JavaScript running on the same page.
That means any XSS, compromised dependency, malicious browser extension,
or third-party script on the origin can potentially inspect key material
while an agent is unlocked.

Use `@hai.ai/jacs-wasm` for browser-local signing when that risk is acceptable.
For hardware-backed or high-assurance signing, use a hardware key,
secure-enclave-backed WebCrypto flow, or server-side signer. Call
`clearSecrets()` as soon as the user is done signing.

## Local Build and Chromium Smoke Test

Install the Rust WASM target once:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

Build the package and run the browser smoke fixture:

```sh
make build-wasm

cd jacs-wasm/examples/vite-smoke
npm install
npx playwright install chromium
npx playwright test --project=chromium
```

The Chromium smoke test builds the Vite app, serves the static output,
loads it in Chromium, creates an ephemeral `@hai.ai/jacs-wasm` agent, signs a
JSON payload, verifies it, and waits for `SMOKE OK` in the page output.

CI runs the same browser path in the WASM PR and release workflows.
