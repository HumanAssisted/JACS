// `@jacs/wasm` main entry point. Hand-written wrapper around the
// wasm-bindgen output. Adds:
//
// - A `localStore` object that assembles the camelCase free functions
//   exposed by the wasm module (PRD §4.3).
// - JSDoc + named re-exports for IDE completion.
// - `initJacsWasm` accepts an optional `module_or_path` like the
//   generated default; if omitted, falls back to the bundler-friendly
//   `new URL("./jacs_wasm_bg.wasm", import.meta.url)`.

/* eslint-disable @typescript-eslint/no-explicit-any */

import __wbg_init, {
  CoreAgentHandle,
  createAgreementJson,
  createEphemeral,
  createVerifier,
  importEncryptedAgent,
  importEncryptedAgentFiles,
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
  module_or_path?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
): Promise<void> {
  if (!initPromise) {
    initPromise = (async () => {
      const target = module_or_path ?? new URL("./jacs_wasm_bg.wasm", import.meta.url);
      await __wbg_init(target as any);
      initJacsWasmInner();
    })();
  }
  return initPromise;
}

// Re-export the wasm-bindgen handle + constructors verbatim.
export {
  CoreAgentHandle,
  createAgreementJson,
  createEphemeral,
  createVerifier,
  importEncryptedAgent,
  importEncryptedAgentFiles,
};

export type Algorithm = "ed25519" | "pq2025";

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

/**
 * Persistent storage helpers. Wraps `window.localStorage` with a
 * strict policy: every key is namespaced with `jacs:` internally;
 * payloads containing PEM private blocks or top-level `password`
 * fields are refused.
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
