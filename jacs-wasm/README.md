# @jacs/wasm

**JACS sign + verify in the browser. No backend required.**

`@jacs/wasm` is the WebAssembly bindings for [JACS](https://github.com/HumanAssisted/JACS).
Install one package, await one init call, and you can create JACS agents,
sign messages, verify signed documents, and run multi-party agreements
entirely client-side.

## Install

```sh
npm install @jacs/wasm
```

## Quick start

```ts
import { initJacsWasm, createEphemeral } from "@jacs/wasm";

await initJacsWasm();

const agent = await createEphemeral("pq2025");
const signed = agent.signMessageJson(JSON.stringify({ hello: "world" }));
const result = JSON.parse(agent.verifyJson(signed));
console.log(result.valid); // true
```

## API

### Lifecycle

- `initJacsWasm(): Promise<void>` — wire up the panic hook. Idempotent.
  Safe to call multiple times.

### Constructors

- `createEphemeral(algorithm: "ed25519" | "pq2025"): Promise<CoreAgentHandle>` —
  generate a fresh keypair. Public key is wrapped in a minimal agent
  document (`jacsId`, `jacsVersion`, `name`, `algorithm`).
- `importEncryptedAgent(materialJson: string, password: string): Promise<CoreAgentHandle>` —
  unlock an `AgentMaterial` bundle produced by `localStore.saveEncryptedAgent`
  or the native `jacs` CLI.
- `importEncryptedAgentFiles(args, password): Promise<CoreAgentHandle>` —
  same as `importEncryptedAgent` but takes the four constituent files
  separately (matches the shape browser file pickers hand you).
- `createVerifier(publicKeyBase64: string, algorithm: "ed25519" | "pq2025"): Promise<CoreAgentHandle>` —
  build a verify-only handle. Sign attempts return `{ code: "Locked" }`.

### Instance methods on `CoreAgentHandle`

- `signMessageJson(dataJson: string): string` — JSON in, signed JACS
  document (also JSON) out.
- `verifyJson(signed: string): string` — verify with this handle's
  algorithm + key. Returns a JSON `VerificationOutcome`
  (`{ valid, signer_id, timestamp, data, errors }`).
- `verifyWithKeyJson(signed, publicKeyBase64, algorithm): string` —
  static verify path. Useful when the verifier doesn't hold any private
  key (e.g. dashboard pages).
- `exportAgent(): string` — JSON string of the agent document.
- `getPublicKeyBase64(): string` — raw public-key bytes, base64-encoded.
- `algorithm(): "ed25519" | "pq2025"` — algorithm tag.
- `isUnlocked(): boolean` — whether the handle still holds a private key.
- `clearSecrets(): void` — zero the in-memory private key. Subsequent
  `signMessageJson` calls throw `{ code: "Locked" }`; verify methods
  continue to work.

### Error codes

Every fallible call throws a `JacsWasmError` whose `message` is a
JSON-shaped `{ code, message, details? }` payload. The `code` field is
the stable wire identifier — match on that, not on the human-readable
message:

| Code | Meaning |
|------|---------|
| `InvalidPassword` | Password did not unlock the encrypted private key. |
| `Locked` | `clearSecrets()` was called or this is a verifier-only handle. Sign refused. |
| `AlgorithmMismatch` | The document was signed under a different algorithm than this handle's. |
| `UnsupportedAlgorithm` | Requested algorithm is not one of `"ed25519"` / `"pq2025"`. |
| `MalformedDocument` | The signed payload is structurally invalid. |
| `MalformedKey` | The supplied public/private key is the wrong length or format. |
| `MalformedEnvelope` | The encrypted key envelope is short, missing fields, or has wrong magic. |
| `SignatureInvalid` | The cryptographic signature did not verify. |
| `EncryptionFailed` | AEAD encryption failed (rare). |
| `DecryptionFailed` | AEAD decryption failed for a reason other than wrong password. |
| `SchemaInvalid` | JSON-schema validation failed. |
| `AgreementFailed` | A multi-party agreement payload was missing or malformed. |

```ts
try {
  const result = JSON.parse(agent.verifyJson(signed));
  if (!result.valid) console.warn("did not verify:", result.errors);
} catch (e) {
  const { code, message } = JSON.parse((e as Error).message);
  switch (code) {
    case "AlgorithmMismatch": /* surface algo mismatch */; break;
    case "Locked": /* re-prompt for password */; break;
    default: console.error(code, message);
  }
}
```

## Security caveats — read this section

**Browser WebAssembly memory is JavaScript-visible by design.** Any code
running on the page — including third-party libraries, advertising
scripts, or browser extensions injected via Manifest V3 — can read the
WebAssembly module's linear memory through JS `Memory.buffer`. There is
no isolation boundary between the private key bytes that
`createEphemeral` or `importEncryptedAgent` materializes and the rest of
the page's JS.

### What this means in practice

- **`@jacs/wasm` is not a replacement for a hardware-backed signing
  service.** If the threat model includes XSS, malicious extensions, or
  hostile third-party JS on the same origin, the keys are reachable from
  that JS. Use a hardware key, a secure-enclave-backed
  WebCrypto `CryptoKey`, or a server-side signing endpoint instead.
- **Persist nothing plaintext.** `localStore` (below) refuses to write
  raw private keys, PEM `BEGIN PRIVATE KEY` blocks, or top-level
  `password` fields. Only the AES-256-GCM/Argon2id encrypted envelope
  hits `localStorage`.
- **Treat `clearSecrets()` as a "logout" primitive.** Call it as soon as
  the user is done signing. It zeroes the in-memory private key;
  subsequent sign calls throw `{ code: "Locked" }`. Verification
  continues to work.
- **Tab isolation is not a security boundary.** Two tabs on the same
  origin share `localStorage`. Set short-lived passwords + force
  re-unlock between tab visits if you need stronger separation.

The full background — including the cross-platform compile audit, the
`forbidden-deps` enforcement, and the deliberate decision to defer a
WebCrypto-backed `DetachedSigner` to V2 — lives in
[`WASM_FINDINGS.md`](../docs/jacs/WASM_FINDINGS.md) (HAI internal repo)
and the [`JACS_WASM_PRD.md`](../docs/jacs/JACS_WASM_PRD.md).

## `localStore` (browser persistence)

`localStore` is a synchronous wrapper around `window.localStorage` that
namespaces every key under `jacs:` and refuses plaintext-secret payloads:

```ts
import { localStore } from "@jacs/wasm";

localStore.saveEncryptedAgent("alice", agent.exportAgent()); // OK — encrypted material
localStore.saveDocument("doc-1", signed);                    // OK — signed JACS document
const restored = localStore.loadEncryptedAgent("alice");
localStore.listKeys("doc-");
localStore.remove("doc-1");
localStore.clearAll();                                       // only removes `jacs:`-prefixed keys
```

## Workers (`@jacs/wasm/worker`)

Long-running ops like pq2025 key generation block the main thread for
hundreds of milliseconds. The worker subpath lets you push them
off-thread:

```ts
import { createEphemeralInWorker, signMessageInWorker } from "@jacs/wasm/worker";

const agent = await createEphemeralInWorker("pq2025");
const signed = await signMessageInWorker(agent, JSON.stringify({ hello: "world" }));
```

## Differences from `jacsnpm`

If you reached this README looking for the Node.js native bindings, you
want a different package: [`jacsnpm`](https://www.npmjs.com/package/jacsnpm)
is the napi-rs build with the full native JACS surface (storage backends,
DNS, observability, MCP). `@jacs/wasm` is browser-only — no filesystem,
no DNS, no MCP — and ships a wasm artifact, not a `.node` binary.

| | `@jacs/wasm` | `jacsnpm` |
|---|---|---|
| Runtime | Browser | Node.js native |
| Install | `npm install @jacs/wasm` | `npm install jacsnpm` |
| Build artifact | `.wasm` + `.js` | `.node` (per platform) |
| Sign / verify | Yes | Yes |
| Filesystem / DNS | No | Yes |
| MCP server / CLI | No | Yes |

## License

Apache-2.0. See [`LICENSE-APACHE`](../LICENSE-APACHE).
