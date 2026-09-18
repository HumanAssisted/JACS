// `@jacs/wasm` main entry point. Hand-written wrapper around the
// wasm-bindgen output (Issues 002 / 007 / Tasks 027 / 032). The wasm-
// bindgen functions are imported under `_*Raw` aliases; the *public*
// names re-exported below are PRD §4.3-shaped:
//
// - All constructors are `async` and return `Promise<CoreAgentHandle>`.
// - `importEncryptedAgentFiles` takes an *object* of files + a password
//   (no positional `algorithm` parameter — the algorithm is derived
//   from `publicKeyBytes.length`).
// - A `localStore` object aggregates the camelCase free functions
//   exposed by the wasm module.

/* eslint-disable @typescript-eslint/no-explicit-any */

import __wbg_init, {
  CoreAgentHandle,
  createAgreementJson,
  createEphemeral as _createEphemeralRaw,
  createHuman as _createHumanRaw,
  importRecovery as _importRecoveryRaw,
  generateRecoveryCode as _generateRecoveryCodeRaw,
  createVerifier as _createVerifierRaw,
  importEncryptedAgent as _importEncryptedAgentRaw,
  importEncryptedAgentPinned as _importEncryptedAgentPinnedRaw,
  generateTransferCode as _generateTransferCodeRaw,
  reencryptTransferredAgent as _reencryptTransferredAgentRaw,
  importEncryptedAgentFiles as _importEncryptedAgentFilesRaw,
  initJacsWasm as initJacsWasmInner,
  localStoreClearAll,
  localStoreListKeys,
  localStoreLoadDocument,
  localStoreLoadEncryptedAgent,
  localStoreRemove,
  localStoreSaveDocument,
  localStoreSaveEncryptedAgent,
} from "./jacs_wasm.js";

let initPromise: Promise<void> | null = null;

/**
 * Initialize the wasm runtime. Idempotent — subsequent calls return
 * the same resolved promise. Pass `module_or_path` to override the
 * default bundler-friendly URL (`new URL("./jacs_wasm_bg.wasm",
 * import.meta.url)`).
 */
export async function initJacsWasm(
  module_or_path?:
    | RequestInfo
    | URL
    | Response
    | BufferSource
    | WebAssembly.Module,
): Promise<void> {
  if (!initPromise) {
    initPromise = (async () => {
      const target =
        module_or_path ?? new URL("./jacs_wasm_bg.wasm", import.meta.url);
      await __wbg_init(target as any);
      initJacsWasmInner();
    })();
  }
  return initPromise;
}

/** JS-facing algorithm tag. */
export type Algorithm = "ed25519" | "pq2025" | "es256";

/**
 * Stable wire shape of every error thrown by `@jacs/wasm`. The `code`
 * is the load-bearing discriminator; `message` is human-readable but
 * not stable across releases.
 */
export interface JacsWasmError {
  code: string;
  message: string;
  details?: unknown;
}

/** Argument shape of `importEncryptedAgentFiles`. */
export interface EncryptedAgentFiles {
  configText: string;
  agentText: string;
  publicKeyBytes: Uint8Array;
  encryptedPrivateKeyBytes: Uint8Array;
}

// ---------------------------------------------------------------------------
// Re-export the CoreAgentHandle type and helpers that don't need
// reshaping. `createAgreementJson` is a free helper (matches PRD §4.3
// for the optional skeleton-builder), and `CoreAgentHandle` is the
// instance type returned by every constructor.
// ---------------------------------------------------------------------------

export { CoreAgentHandle, createAgreementJson };

// ---------------------------------------------------------------------------
// PRD §4.3 constructors — async wrappers that initialize wasm first
// (idempotent) and return Promise<CoreAgentHandle>. Each one awaits
// `initJacsWasm()` so callers can use any constructor before explicitly
// initializing (matching the "no global agent state, init is idempotent"
// guarantee in PRD §3.1).
// ---------------------------------------------------------------------------

/** Generate a fresh agent with ML-DSA-87 (pq2025) by default. Classical
 * algorithms require an explicit compatibility choice; failures never fall back. */
export async function createEphemeral(
  algorithm: Algorithm = "pq2025",
): Promise<CoreAgentHandle> {
  await initJacsWasm();
  return _createEphemeralRaw(algorithm);
}

/** Create a human identity in its first signed version, ML-DSA-87 only. */
export async function createHuman(): Promise<CoreAgentHandle> {
  await initJacsWasm();
  return _createHumanRaw();
}

/** Generate 128 random recovery bits. Never persist/upload the plaintext code. */
export async function generateRecoveryCode(): Promise<string> {
  await initJacsWasm();
  return _generateRecoveryCodeRaw();
}

/** Durable recovery with independent identity/key pins; accepts grouped pasted codes. */
export async function importRecovery(
  materialJson: string, code: string, expectedAgentId: string,
  expectedPublicKeyBase64: string, expectedAlgorithm: Algorithm,
): Promise<CoreAgentHandle> {
  await initJacsWasm();
  return _importRecoveryRaw(materialJson, code, expectedAgentId, expectedPublicKeyBase64, expectedAlgorithm);
}

/** Import an encrypted agent from a JSON-serialized `AgentMaterial`
 * blob + password. */
export async function importEncryptedAgent(
  materialJson: string,
  password: string,
): Promise<CoreAgentHandle> {
  await initJacsWasm();
  return _importEncryptedAgentRaw(materialJson, password);
}

/** Generate a transfer secret on the sending device. Never send this code
 * to the relay or derive it from user-selected words. */
export async function generateTransferCode(): Promise<string> {
  await initJacsWasm();
  return _generateTransferCodeRaw();
}

/** Verify independently trusted identity/key/algorithm pins before unlocking
 * a received transfer. Pins must come from an authenticated key registry. */
export async function importEncryptedAgentPinned(
  materialJson: string,
  password: string,
  expectedAgentId: string,
  expectedPublicKeyBase64: string,
  expectedAlgorithm: Algorithm,
): Promise<CoreAgentHandle> {
  await initJacsWasm();
  return _importEncryptedAgentPinnedRaw(
    materialJson, password, expectedAgentId, expectedPublicKeyBase64, expectedAlgorithm,
  );
}

/** Validate, unlock, and immediately rewrap a transfer using a fresh local
 * secret (password or encoded passkey PRF output), clearing the temporary key. */
export async function reencryptTransferredAgent(
  materialJson: string,
  code: string,
  expectedAgentId: string,
  expectedPublicKeyBase64: string,
  expectedAlgorithm: Algorithm,
  storagePassword: string,
): Promise<string> {
  await initJacsWasm();
  return _reencryptTransferredAgentRaw(
    materialJson, code, expectedAgentId, expectedPublicKeyBase64,
    expectedAlgorithm, storagePassword,
  );
}

/**
 * Import an encrypted agent from four separate file-shaped buffers
 * (browser file pickers). The algorithm is derived from
 * `publicKeyBytes.length` (32 → ed25519, 65 → es256, 2592 → pq2025).
 *
 * PRD §4.3 declares the surface as `(files, password)` — no positional
 * algorithm parameter — so the algorithm is inferred from the key
 * shape. A bad / unknown size throws a `JacsWasmError` with code
 * `UnsupportedAlgorithm` *before* dispatching to the wasm layer so the
 * error is observable on the JS side without round-tripping through
 * Rust.
 */
export async function importEncryptedAgentFiles(
  files: EncryptedAgentFiles,
  password: string,
): Promise<CoreAgentHandle> {
  await initJacsWasm();
  const algorithm = algorithmFromPublicKeyLength(files.publicKeyBytes.length);
  return _importEncryptedAgentFilesRaw(
    files.configText,
    files.agentText,
    files.publicKeyBytes,
    files.encryptedPrivateKeyBytes,
    password,
    algorithm,
  );
}

/** Build a verify-only handle from a base64 public key. */
export async function createVerifier(
  publicKeyBase64: string,
  algorithm: Algorithm,
): Promise<CoreAgentHandle> {
  await initJacsWasm();
  return _createVerifierRaw(publicKeyBase64, algorithm);
}

/** Map raw public-key length to the algorithm tag. Ed25519 keys are
 * 32 bytes; canonical uncompressed SEC1 P-256 keys are 65 bytes; ML-DSA-87 (pq2025)
 * public keys are 2592 bytes. Any other length is unknown.
 *
 * Throws a `JacsWasmError`-shaped Error before crossing the wasm
 * boundary so callers get a typed error without a Rust round-trip.
 *
 * @internal exported for tests.
 */
export function algorithmFromPublicKeyLength(length: number): Algorithm {
  // 32-byte ed25519 public key (raw, no SPKI wrapper).
  if (length === 32) return "ed25519";
  // Canonical SEC1 uncompressed P-256 public keys (es256).
  if (length === 65) return "es256";
  // 2592-byte ML-DSA-87 public key (pq2025).
  if (length === 2592) return "pq2025";
  const err: JacsWasmError = {
    code: "UnsupportedAlgorithm",
    message: `cannot infer signing algorithm from public-key length ${length} (expected 32 for ed25519, 65 for es256, or 2592 for pq2025)`,
  };
  // `JacsWasmError` is the wire shape; throw a plain Error whose
  // message is the JSON form so callers can parse it the same way they
  // do every other error from this package.
  throw Object.assign(new Error(JSON.stringify(err)), err);
}

// ---------------------------------------------------------------------------
// localStore — wrapped around the wasm-bindgen free functions so JS
// callers write `localStore.saveDocument(...)` per PRD §4.3.
// ---------------------------------------------------------------------------

/**
 * Persistent storage helpers. Wraps `window.localStorage` with a
 * strict policy: every key is namespaced with `jacs:` internally;
 * payloads containing PEM private blocks, top-level `password` fields,
 * or invalid encrypted-envelope shapes are refused (Task 029 / Issue
 * 004).
 *
 * See PRD §3.1 / §5.4. The load-bearing guarantee is the secret-leak
 * walk test exercised in CI.
 */
export const localStore = {
  /** Persist an encrypted-agent material blob under `key`. Refuses
   * payloads carrying obvious plaintext secrets. */
  saveEncryptedAgent(key: string, materialJson: string): void {
    localStoreSaveEncryptedAgent(key, materialJson);
  },
  /** Load an encrypted-agent material blob, or `null` if not present. */
  loadEncryptedAgent(key: string): string | null {
    const v = localStoreLoadEncryptedAgent(key);
    return v ?? null;
  },
  /** Persist a signed JACS document under `key`. Refuses plaintext-
   * secret payloads (defense-in-depth). */
  saveDocument(key: string, signedJson: string): void {
    localStoreSaveDocument(key, signedJson);
  },
  /** Load a signed JACS document, or `null` if not present. */
  loadDocument(key: string): string | null {
    const v = localStoreLoadDocument(key);
    return v ?? null;
  },
  /** List JS-facing keys in the `jacs:` namespace. */
  listKeys(prefix?: string): string[] {
    return localStoreListKeys(prefix);
  },
  /** Remove the entry stored under `key`. Throws `KeyNotFound` if the
   * entry was not present. */
  remove(key: string): void {
    localStoreRemove(key);
  },
  /** Remove every entry in the `jacs:` namespace. Keys outside the
   * namespace are left untouched. */
  clearAll(): void {
    localStoreClearAll();
  },
};
