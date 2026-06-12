// Checked-in declaration stub for `@jacs/wasm` source-tree TypeScript
// validation (Issue 007 / Task 032).
//
// The hand-written wrappers in `index.ts` and `worker/jacs-worker.ts`
// import from `./jacs_wasm.js` / `../jacs_wasm.js` because that is the
// filename layout *inside* the published `pkg/` directory after
// `wasm-pack build`. From a fresh source-tree checkout no `pkg/` exists
// yet (it is gitignored), so `tsc --noEmit -p jacs-wasm/tsconfig.json`
// has nothing to resolve those imports against.
//
// This file mirrors the wasm-bindgen public surface declared in
// `pkg/jacs_wasm.d.ts`. The duplication is intentional and load-bearing:
// `finalize-pkg.sh` *does not* ship this file in the npm artifact (only
// the real `pkg/jacs_wasm.d.ts` is published). It exists solely for
// IDE + `tsc --noEmit` smoke validation in CI.
//
// When the wasm-bindgen surface grows, regenerate this stub by copying
// the matching declarations from a fresh `wasm-pack build --target web
// --release jacs-wasm` and committing the diff. CI catches drift via
// `tsc --noEmit` (Task 028 makes the check release-blocking).
//
// Source of truth at build time: `jacs-wasm/pkg/jacs_wasm.d.ts`.

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Handle for a CoreAgent. See `pkg/jacs_wasm.d.ts` for full docs. */
export class CoreAgentHandle {
  private constructor();
  free(): void;
  algorithm(): string;
  clearSecrets(): void;
  exportAgent(): string;
  getPublicKeyBase64(): string;
  isUnlocked(): boolean;
  signMessageJson(data_json: string): string;
  verifyJson(signed_json: string): string;
  verifyWithKeyJson(
    signed_json: string,
    public_key_base64: string,
    algorithm: string,
  ): string;
  signAgreementJson(agreement_json: string, role: string): string;
  verifyAgreementJson(agreement_json: string, signers_json: string): string;
  createAgreementV2Json(input_json: string): string;
  applyAgreementV2Json(agreement_json: string, mutation_json: string): string;
  signAgreementV2Json(agreement_json: string, role: string): string;
  verifyAgreementV2Json(agreement_json: string, signers_json: string): string;
  detectAgreementV2BranchConflictJson(
    base_json: string,
    left_json: string,
    right_json: string,
  ): string;
  mergeAgreementV2TranscriptBranchesJson(
    base_json: string,
    left_json: string,
    right_json: string,
  ): string;
  resolveAgreementV2BranchConflictJson(
    base_json: string,
    previous_json: string,
    side_json: string,
    mutation_json: string,
  ): string;
  /**
   * In-memory snapshot of `{ signCount, verifyCount,
   * lastSignDurationMs, lastVerifyDurationMs }` as a JSON string
   * (PRD §10.2). Per-handle.
   */
  metrics(): string;
}

export function createEphemeral(algorithm: string): CoreAgentHandle;

export function createVerifier(
  public_key_base64: string,
  algorithm: string,
): CoreAgentHandle;

export function importEncryptedAgent(
  material_json: string,
  password: string,
): CoreAgentHandle;

export function importEncryptedAgentFiles(
  config_text: string,
  agent_text: string,
  public_key_bytes: Uint8Array,
  encrypted_private_key_bytes: Uint8Array,
  password: string,
  algorithm: string,
): CoreAgentHandle;

export function createAgreementJson(
  document_json: string,
  agent_ids_json: string,
  question?: string | null,
  context?: string | null,
): string;

export function initJacsWasm(): void;
export function signingAlgorithmToJs(algorithm: string): any;

export function localStoreClearAll(): void;
export function localStoreListKeys(prefix?: string | null): string[];
export function localStoreLoadDocument(key: string): string | undefined;
export function localStoreLoadEncryptedAgent(key: string): string | undefined;
export function localStoreRemove(key: string): void;
export function localStoreSaveDocument(key: string, signed_json: string): void;
export function localStoreSaveEncryptedAgent(
  key: string,
  material_json: string,
): void;

export function workerHandleMessage(message: any): any;

export type InitInput =
  | RequestInfo
  | URL
  | Response
  | BufferSource
  | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  // Wasm-bindgen also exports many `__wbg_*` low-level bindings; they are
  // intentionally omitted from this stub since the TS wrappers never
  // touch them.
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
export function initSync(
  module: { module: SyncInitInput } | SyncInitInput,
): InitOutput;

export default function __wbg_init(
  module_or_path?:
    | { module_or_path: InitInput | Promise<InitInput> }
    | InitInput
    | Promise<InitInput>,
): Promise<InitOutput>;

// ---------------------------------------------------------------------------
// Agreement v2 typed surface (additive; Task C7).
//
// The `CoreAgentHandle` agreement v2 methods carry a `Json` suffix and take/
// return JSON strings. The aliases and interfaces below give callers accurate
// names and shapes without changing the generated wasm-bindgen surface. The
// suffix-free method names (e.g. `signAgreementV2`) are exposed by the
// higher-level `index.ts` wrappers, not by this raw handle.
// ---------------------------------------------------------------------------

/** Named roles accepted by `CoreAgentHandle.signAgreementV2Json`. */
export type AgreementV2Role = 'signer' | 'witness' | 'notary';

/** Parsed shape of `CoreAgentHandle.verifyAgreementV2Json` (camelCase wire format). */
export interface AgreementV2VerificationReport {
  valid: boolean;
  status: string;
  expectedStatus: string;
  recomputedAgreementHash: string;
  recomputedTranscriptHash: string;
  signerCount: number;
  witnessCount: number;
  notaryCount: number;
  verifiedChainDepth?: number;
  chainFullyVerified?: boolean;
  errors?: string[];
  notes?: string[];
}

/** Parsed shape of `CoreAgentHandle.detectAgreementV2BranchConflictJson`. */
export interface AgreementV2MergeAnalysis {
  sameDocument: boolean;
  sameParent: boolean;
  autoMergeable: boolean;
  conflictFields?: string[];
  leftChangedFields?: string[];
  rightChangedFields?: string[];
  leftTranscriptAdditions: number;
  rightTranscriptAdditions: number;
  errors?: string[];
}
