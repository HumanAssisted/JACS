# Browser WASM Package

`@jacs/wasm` is the browser WebAssembly package for JACS. Use it when a
web page needs to create a browser-local JACS agent, sign JSON, verify
signed JACS documents, or collect multi-party agreement signatures
without calling a backend service.

For Node.js server applications, use the native `@hai.ai/jacs` package
instead. `@jacs/wasm` is browser-only: no filesystem access, no DNS
trust lookup, no MCP server, and no CLI process.

## Install

```sh
npm install @jacs/wasm
```

Bundlers must be able to load an ES module plus the generated
`jacs_wasm_bg.wasm` asset. Vite works with the package as published.

## Quick Start

```ts
import { createEphemeral, initJacsWasm } from "@jacs/wasm";

await initJacsWasm();

const agent = await createEphemeral("ed25519");
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
createEphemeral(algorithm: "ed25519" | "pq2025"): Promise<CoreAgentHandle>
importEncryptedAgent(materialJson: string, password: string): Promise<CoreAgentHandle>
importEncryptedAgentFiles(files: EncryptedAgentFiles, password: string): Promise<CoreAgentHandle>
createVerifier(publicKeyBase64: string, algorithm: "ed25519" | "pq2025"): Promise<CoreAgentHandle>
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
for `ed25519` and 2592 bytes for `pq2025`.

Core handle methods:

```ts
agent.signMessageJson(dataJson: string): string
agent.verifyJson(signedJson: string): string
agent.verifyWithKeyJson(
  signedJson: string,
  publicKeyBase64: string,
  algorithm: "ed25519" | "pq2025",
): string
agent.exportAgent(): string
agent.getPublicKeyBase64(): string
agent.algorithm(): "ed25519" | "pq2025"
agent.isUnlocked(): boolean
agent.clearSecrets(): void
agent.metrics(): string
```

`clearSecrets()` zeroes the in-memory private key. Signing then fails
with a `Locked` error, while verification continues to work.

## Multi-Party Agreements

Browser callers can build, sign, and verify agreement documents:

```ts
import { createAgreementJson } from "@jacs/wasm";

const documentJson = JSON.stringify({ action: "deploy", version: "1.2.3" });
const agentIdsJson = JSON.stringify(["alice", "bob"]);
const agreement = createAgreementJson(
  documentJson,
  agentIdsJson,
  "Ship this release?",
  "Production release vote",
);

const signedByAlice = alice.signAgreementJson(agreement, "approver");
const outcome = JSON.parse(
  verifier.verifyAgreementJson(
    signedByAlice,
    JSON.stringify([
      {
        agentId: "alice",
        publicKeyBase64: alice.getPublicKeyBase64(),
        algorithm: alice.algorithm(),
      },
    ]),
  ),
);
```

## Browser Persistence

`localStore` wraps `window.localStorage` and stores values under the
`jacs:` namespace.

```ts
import { localStore } from "@jacs/wasm";

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
  signMessageInWorker,
} from "@jacs/wasm/worker";

const workerAgent = await createEphemeralInWorker("pq2025");
const signed = await signMessageInWorker(
  workerAgent,
  JSON.stringify({ hello: "world" }),
);
```

## Observability

Browsers do not expose stdout or a Prometheus endpoint for package code.
`@jacs/wasm` exposes per-handle counters instead:

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

Use `@jacs/wasm` for browser-local signing when that risk is acceptable.
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
wasm-pack build jacs-wasm --target web --out-dir pkg
jacs-wasm/scripts/finalize-pkg.sh

cd jacs-wasm/examples/vite-smoke
npm install
npx playwright install chromium
npx playwright test --project=chromium
```

The Chromium smoke test builds the Vite app, serves the static output,
loads it in Chromium, creates an ephemeral `@jacs/wasm` agent, signs a
JSON payload, verifies it, and waits for `SMOKE OK` in the page output.

CI runs the same browser path in the WASM PR and release workflows.
