# @hai.ai/jacs-wasm

**JACS sign + verify in the browser. No backend required.**

> **Published 0.15.0:** npm artifacts, provenance and installed-browser checks
> are recorded in [release status](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md). This README also
> describes the current source API; later changes in this checkout are not
> evidence of a new published release.

`@hai.ai/jacs-wasm` is the WebAssembly bindings for [JACS](https://github.com/HumanAssisted/JACS).
Await one init call and you can create JACS
agents, sign messages, verify signed documents, and run multi-party agreements
entirely client-side.

**New identities use post-quantum ML-DSA-87 (`pq2025`) by default**, in both
the main-thread and worker APIs. Use `createEphemeral()` or
`createEphemeralInWorker()`; neither falls back to a classical algorithm.
Ed25519 and ES256 remain explicit compatibility choices for existing identities
or platform integrations. Imports retain and verify their declared algorithm.

## Install

```sh
npm install --save-exact @hai.ai/jacs-wasm@0.15.0
```

For the current source API, follow the
[local build guide](https://humanassisted.github.io/JACS/native/wasm/building.html#local-build-and-chromium-smoke-test).

## Quick start

```ts
import { initJacsWasm, createEphemeral } from "@hai.ai/jacs-wasm";

await initJacsWasm();

const agent = await createEphemeral(); // pq2025; no classical fallback
const signed = agent.signMessageJson(JSON.stringify({ hello: "world" }));
const result = JSON.parse(agent.verifyJson(signed));
console.log(result.valid); // true
```

## API

### Lifecycle

- `initJacsWasm(): Promise<void>` — load WASM and install the panic hook;
  safe to call multiple times.

### Constructors

- `createEphemeral(algorithm?: "pq2025" | "ed25519" | "es256"): Promise<CoreAgentHandle>` —
  generate a fresh keypair and a self-signed agent document; defaults to
  `pq2025`. The raw wasm-bindgen constructor requires an explicit algorithm.
- `importEncryptedAgent(materialJson: string, password: string): Promise<CoreAgentHandle>` —
  unlock an `AgentMaterial` bundle produced by `exportEncryptedAgent(password)`
  or the native `jacs` CLI, including a value loaded from
  `localStore.loadEncryptedAgent`.
- `importEncryptedAgentFiles(args, password): Promise<CoreAgentHandle>` —
  same as `importEncryptedAgent` but takes the four constituent files
  separately (matches the shape browser file pickers hand you).
- `createVerifier(publicKeyBase64: string, algorithm: "ed25519" | "pq2025" | "es256"): Promise<CoreAgentHandle>` —
  build a verify-only handle. Sign attempts return `{ code: "Locked" }`.

### Instance methods on `CoreAgentHandle`

- `signMessageJson(dataJson: string): string` — JSON in, signed JACS
  document (also JSON) out.
- `signString(message: string): string` / `signRawBytesBase64(bytes: Uint8Array): string` —
  detached signature over the exact UTF-8 string or bytes, standard base64
  encoded.
- `buildRequestAuthHeader(method, url, body: Uint8Array, audience): string` —
  construct a request-auth-v2 credential bound to the exact HTTP request.
  Send the same body bytes without reserialization; HAI requires this request
  context rather than an unbound timestamp signature.
- `updateAgentJson(updatesJson: string): string` — merge identity metadata,
  advance the version, and self-sign with the current key. Core rejects edits
  to protected identity/key fields. An unchanged exported document plus edited
  metadata may be supplied as well.
- `prepareAgentUpdateJson(updatesJson: string): string` — sign a candidate
  successor without changing the current handle. Authenticate its registration
  request with the handle's current version, then call
  `commitAgentUpdateJson(preparedJson: string): string` after registration
  succeeds. A failed registration leaves the handle's existing identity usable.
- `verifyJson(signed: string): string` — verify with this handle's
  algorithm + key. Returns a JSON `VerificationOutcome`
  (`{ valid, signer_id, timestamp, data, errors }`).
- `verifyWithKeyJson(signed, publicKeyBase64, algorithm): string` —
  verify using the supplied key without unlocking this handle.
- `exportAgent(): string` — JSON string of the public agent document. It does
  not contain private-key material and cannot be used to restore a signing
  handle.
- `exportEncryptedAgent(password: string): string` — JSON `AgentMaterial`
  bundle whose private key is encrypted with the current V2 Argon2id +
  AES-256-GCM envelope. Pass this result to
  `localStore.saveEncryptedAgent`; restore it with `importEncryptedAgent`.
- `getPublicKeyBase64(): string` — raw public-key bytes, base64-encoded.
- `getPublicKeyHash(): string` — SHA-256 of raw public-key bytes, lowercase hex.
- `getPublicKeyPem(): string` / `getPublicKeyPemBase64(): string` —
  native-compatible public PEM or base64 of its UTF-8 bytes for HAI registration.
- `algorithm(): "ed25519" | "pq2025" | "es256"` — algorithm tag. ES256 uses a
  65-byte uncompressed SEC1 public key and a 64-byte low-S P1363 signature.
- `isUnlocked(): boolean` — whether the handle still holds a private key.
- `clearSecrets(): void` — zero the in-memory private key. Subsequent
  `signMessageJson` calls throw `{ code: "Locked" }`; verify methods
  continue to work.

### Encrypted device transfer

`generateTransferCode(): Promise<string>` generates six independent random
words (66 bits). Display it only on the sending device; the relay receives
only `exportEncryptedAgent(code)`. It must never receive the code.

On the receiving device, obtain the expected agent ID, public key, and
algorithm from an authenticated registration independently of the blob:

```ts
import { reencryptTransferredAgent, localStore, importEncryptedAgent } from "@hai.ai/jacs-wasm";

// Inputs: ciphertext from the link relay, the code entered by the user,
// independently authenticated registration, and a distinct local secret.
const stored = await reencryptTransferredAgent(
  ciphertext, code, registration.agentId, registration.publicKeyBase64,
  registration.algorithm, browserSecret,
);
localStore.saveEncryptedAgent(registration.agentId, stored);
const agent = await importEncryptedAgent(stored, browserSecret);
```

`reencryptTransferredAgent` validates the self-signed identity and all three
pins, unlocks, re-encrypts using the local secret, and clears the temporary
agent. The local secret must differ from the transfer code. `browserSecret`
can be a user password or an encoded passkey PRF output obtained by the host;
this library does not implement passkey enrollment or recovery.

For an explicitly managed unlocked handle, use
`importEncryptedAgentPinned(materialJson, code, expectedAgentId,
expectedPublicKeyBase64, expectedAlgorithm)` and call `clearSecrets()` in a
`finally` block. Plain `importEncryptedAgent` verifies the self-signature but
does not provide an independent registration trust check. Unsigned legacy
identity bundles must be migrated before browser import.

The worker entry point exports `generateTransferCodeInWorker`,
`importEncryptedAgentPinnedInWorker`, and `reencryptTransferredAgentInWorker`
with the same positional arguments, plus an optional `{ workerUrl }`.
Worker handles also expose `signString`, `getPublicKeyHash`, `exportAgent`,
`updateAgentJson`, and `exportEncryptedAgent` as async methods.

One-shot delivery, authenticated sessions, and relay expiry remain transport
responsibilities. JavaScript owns copies of strings passed through the API;
Rust can wipe its own secret buffers, not the host's string copies.

### Error codes

Main-thread WASM calls throw a `JacsWasmError` whose `message` is a
JSON-shaped `{ code, message, details? }` payload. The `code` field is
the stable wire identifier — match on that, not on the human-readable
message. Worker calls instead reject with a structured `{ code, message, details? }`
object; read its `code` directly, without parsing `message` as JSON.

| Code | Meaning |
|------|---------|
| `InvalidPassword` | Password did not unlock the encrypted private key. |
| `Locked` | `clearSecrets()` was called or this is a verifier-only handle. Sign refused. |
| `AlgorithmMismatch` | The document was signed under a different algorithm than this handle's. |
| `UnsupportedAlgorithm` | Requested algorithm is not `"ed25519"`, `"pq2025"`, or `"es256"`. |
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

- **Unlocked keys are visible to same-page JavaScript.** WASM is not a key
  isolation boundary against XSS, malicious dependencies or injected scripts.
  Use a separate trusted signing boundary when those threats must be isolated.
- **Persist encrypted `AgentMaterial` only.** `localStore` validates the envelope
  shape and rejects obvious plaintext secrets; it is not a general secret scanner.
- **Clear handles after signing.** `clearSecrets()` wipes Rust-owned key material
  and locks signing while preserving verification. It cannot erase JavaScript
  copies of passwords or other strings.
- **Same-origin tabs share storage.** Re-unlock deliberately and limit secret
  lifetime. Passkey/PRF enrollment and recovery belong to the host application.

## `localStore` (browser persistence)

`localStore` is a synchronous wrapper around `window.localStorage` that
namespaces every key under `jacs:` and refuses plaintext-secret payloads:

```ts
import { importEncryptedAgent, localStore } from "@hai.ai/jacs-wasm";

const password = prompt("Protect this signing key with a strong password")!;
const encryptedMaterial = agent.exportEncryptedAgent(password);
localStore.saveEncryptedAgent("alice", encryptedMaterial);
localStore.saveDocument("doc-1", signed);                    // OK — signed JACS document
const storedMaterial = localStore.loadEncryptedAgent("alice");
if (!storedMaterial) throw new Error("saved agent not found");
const restoredAgent = await importEncryptedAgent(storedMaterial, password);
localStore.listKeys("doc-");
localStore.remove("doc-1");
localStore.clearAll();                                       // only removes `jacs:`-prefixed keys
```

## Observability (`metrics()` + `JACS_WASM_DEBUG`)

`JSON.parse(agent.metrics())` returns per-handle signing/verification counts and
last-call timings. Set `globalThis.JACS_WASM_DEBUG = true` for `console.debug`
events around sign, verify and lock operations; logging is off by default.

## Workers (`@hai.ai/jacs-wasm/worker`)

Long-running ops like pq2025 key generation block the main thread for
hundreds of milliseconds. The worker subpath lets you push them
off-thread:

```ts
import { createEphemeralInWorker } from "@hai.ai/jacs-wasm/worker";

const agent = await createEphemeralInWorker(); // pq2025; keeps key generation off the UI thread
const signed = await agent.signMessage(JSON.stringify({ hello: "world" }));
```

## Native compatibility

For Node.js use [`@hai.ai/jacs`](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsnpm/README.md);
for React Native use the [mobile bindings and vaults](https://github.com/HumanAssisted/JACS/blob/main/jacs-mobile/README.md).

## Human creation and generated-code recovery

Use `await createHuman()` or `await createHumanInWorker()` for a first-version,
self-signed human identity (ML-DSA-87 only). Existing `createEphemeral` behavior
is unchanged. `handle.exportRecovery()` returns a JSON string containing
`{ code, materialJson }`; `WorkerAgentHandle.exportRecovery()` returns that
object directly. The code contains 128 generated bits in eight hexadecimal
groups. Show it only after an explicit recovery action and never send it to the
backup service. The ciphertext uses the existing `AgentMaterial` wire shape.

`await importRecovery(materialJson, code, expectedAgentId,
expectedPublicKeyBase64, expectedAlgorithm)` and `importRecoveryInWorker(...)`
restore with independently authenticated registration pins. Spaces/hyphens and
case are normalized; short transfer codes are rejected. Errors keep core codes,
including `InvalidPasswordFormat`, `InvalidPassword`, `MalformedKey`,
`MalformedEnvelope` and `Locked`. A failed import leaves other handles intact.
After completing work, call `clearSecrets()`/`drop()`; discard late results after
background/cancel/account change and erase displayed code copies in the host.
The worker provides responsiveness, not protection against same-origin scripts.

`verifyRecovery(...)` / `verifyRecoveryInWorker(...)` return signed public identity
JSON without a retained handle or storage mutation. Check the returned version
against current authenticated registration as well as the supplied ID/key pins.
`normalizeRecoveryCode(...)` / `normalizeRecoveryCodeInWorker(...)` validate pasted
syntax without KDF work. Backup read-back and save acknowledgment remain separate.

`handle.signDocumentJson(contentJson)` / `workerHandle.signDocument(contentJson)`
create complete JACS documents: exact JSON content, fresh signed root IDs/dates and
standard checksum. Existing message methods are unchanged. The host still owns
review, authorization and suppression of results arriving after cancellation.

When the server has already prepared the complete unsigned document, use
`handle.signPreparedDocument(preparedJson)` or
`workerHandle.signPreparedDocument(preparedJson)`. The input is serialized
`jacs_core::PreparedDocumentV2`, including its complete unsigned `envelope`, frozen
signature input and request context. JACS validates these against the handle's
owned identity/key before signing, then returns the full signed envelope. Only
the signature value and derived checksum change; no IDs or timestamps are
regenerated. The host must independently bind the prepared document to the
reviewed action. This method does not turn content JSON into a new document.

## Staged rotation in the worker

`handle.prepareKeyRotation(storagePassword)` returns encrypted candidate
`AgentMaterial` JSON and leaves the current handle active. Persist it beside the
old material before registration. There is no second candidate-handle registry:
`signRotationDocument(materialJson,password,dataJson)` and
`exportRotationRecovery(materialJson,password)` validate and reopen the stage
inside the worker, then drop the candidate signer. The latter returns the same
`{code,materialJson}` recovery shape as `exportRecovery`. The document's `content`
is the exact candidate possession challenge; old-key authorization uses the
existing `handle.signDocument`.

Reopen the old encrypted handle after interruption and reuse the same stage.
Before `commitKeyRotation(materialJson,password,acceptedIdentityJson,
acceptedPublicKeyBase64)`, reconcile authenticated registry acceptance of those
exact pins and any required saved successor backup. Commit is idempotent and
updates handle public-key metadata. The host owns atomic browser persistence and
must retain both encrypted copies until promotion is durable. Discard only an
authoritatively unaccepted stage; never regenerate/delete after a timeout without
reconciliation. The main-thread WASM handle provides the same methods.
Candidate public-key PEM can be obtained through the existing verification-only
`(await createVerifier(candidate.public_key, candidate.algorithm)).getPublicKeyPem()`;
this needs no candidate private-key handle.

## License

Apache-2.0. See [LICENSE-APACHE](https://github.com/HumanAssisted/JACS/blob/main/LICENSE-APACHE).
