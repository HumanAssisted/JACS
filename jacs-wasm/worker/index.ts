// Main-thread API for `@jacs/wasm/worker`. Spawns a Web Worker, posts
// messages, and resolves promises against the worker's structured
// `{ id, ok, result | error }` replies.
//
// Usage:
//
// ```ts
// import { createEphemeralInWorker } from "@jacs/wasm/worker";
// const agent = await createEphemeralInWorker("pq2025");
// const signed = await agent.signMessage('{"hello":"world"}');
// const outcome = JSON.parse(await agent.verify(signed));
// ```
//
// The returned `WorkerAgentHandle` keeps a single shared worker open
// for the lifetime of the page and dispatches by `handleId` (the
// numeric handle returned by the worker on `createEphemeral` /
// `importEncryptedAgent`).

/* eslint-disable @typescript-eslint/no-explicit-any */

export type Algorithm = "ed25519" | "pq2025" | "es256";

export interface JacsWorkerError {
  code: string;
  message: string;
  details?: unknown;
}

interface PendingCall {
  resolve: (value: any) => void;
  reject: (err: JacsWorkerError) => void;
}

interface WorkerReply {
  id: number;
  ok: boolean;
  result?: any;
  error?: JacsWorkerError;
}

let nextRequestId = 1;
const pending: Map<number, PendingCall> = new Map();
let worker: Worker | null = null;

/** Fan a fatal error out to every pending call and clear the table. */
function failAllPending(error: JacsWorkerError): void {
  for (const [, slot] of pending) {
    slot.reject(error);
  }
  pending.clear();
}

/** Open (or reuse) the shared worker. */
function ensureWorker(workerUrl?: URL | string): Worker {
  if (worker) return worker;
  // Keep the literal URL adjacent to the Worker constructor so Vite/Rollup
  // can build the worker's imports and WASM asset as a separate entry point.
  const w = workerUrl
    ? new Worker(workerUrl, { type: "module" })
    : new Worker(new URL("./jacs-worker.js", import.meta.url), { type: "module" });
  w.addEventListener("message", (event: MessageEvent<WorkerReply>) => {
    const reply = event.data;
    if (!reply || typeof reply.id !== "number") return;
    const slot = pending.get(reply.id);
    if (!slot) {
      // Unmatched reply. If the worker reported ok:false with no
      // matching pending id, treat it as a fatal protocol error and
      // fan it out to every in-flight call — otherwise callers whose
      // request triggered the bootstrap/dispatch failure would hang
      // forever (Issue 011).
      if (reply.ok === false) {
        failAllPending(
          reply.error ?? {
            code: "WorkerProtocolError",
            message: `worker replied ok:false for unknown id ${reply.id}`,
          },
        );
      }
      return;
    }
    pending.delete(reply.id);
    if (reply.ok) {
      slot.resolve(reply.result);
    } else {
      slot.reject(
        reply.error ?? {
          code: "WorkerProtocolError",
          message: "worker replied with ok: false and no error payload",
        },
      );
    }
  });
  w.addEventListener("error", (event: ErrorEvent) => {
    // Fan a worker-level error out to *every* pending call. A worker
    // that died can't reply to any of them; better to fail loudly than
    // to hang forever.
    failAllPending({
      code: "WorkerCrashed",
      message: event.message ?? "worker crashed",
    });
  });
  worker = w;
  return w;
}

/** Send a `{ id, op, args }` request and return a promise that resolves
 * with the `result` (or rejects with the `error`). */
function dispatch<T = any>(
  op: string,
  args: Record<string, unknown>,
  workerUrl?: URL | string,
): Promise<T> {
  const w = ensureWorker(workerUrl);
  const id = nextRequestId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve, reject });
    w.postMessage({ id, op, args });
  });
}

/** Stop the shared worker and reject every in-flight call. */
export function terminateWorker(): void {
  if (worker) {
    worker.terminate();
    worker = null;
  }
  failAllPending({
    code: "WorkerTerminated",
    message: "worker was terminated by the caller",
  });
}

// ---------------------------------------------------------------------------
// Public handle — wraps the numeric `handleId` returned by the worker.
// ---------------------------------------------------------------------------

export class WorkerAgentHandle {
  readonly handleId: number;
  publicKeyBase64: string;
  algorithm: Algorithm;

  /** @internal */
  constructor(handleId: number, publicKeyBase64: string, algorithm: Algorithm) {
    this.handleId = handleId;
    this.publicKeyBase64 = publicKeyBase64;
    this.algorithm = algorithm;
  }

  /** Persist this encrypted stage beside the active material before registration. */
  async prepareKeyRotation(password: string): Promise<string> {
    return (await dispatch<{value: string}>("prepareKeyRotation", {handleId: this.handleId, password})).value;
  }

  /** Candidate possession proof; content is the exact enrollment challenge. */
  async signRotationDocument(materialJson: string, password: string, dataJson: string): Promise<string> {
    return (await dispatch<{value: string}>("signRotationDocument", {handleId: this.handleId, materialJson, password, dataJson})).value;
  }

  async exportRotationRecovery(materialJson: string, password: string): Promise<{code: string; materialJson: string}> {
    return JSON.parse((await dispatch<{value: string}>("exportRotationRecovery", {handleId: this.handleId, materialJson, password})).value);
  }

  /** Authenticate server status and exact candidate pins before calling. Preserve
   * encrypted active/staged records until successful durable local promotion. */
  async commitKeyRotation(materialJson: string, password: string, acceptedIdentityJson: string,
    acceptedPublicKeyBase64: string): Promise<string> {
    const value = (await dispatch<{value: string}>("commitKeyRotation", {handleId: this.handleId, materialJson,
      password, acceptedIdentityJson, acceptedPublicKeyBase64})).value;
    this.publicKeyBase64 = acceptedPublicKeyBase64;
    this.algorithm = JSON.parse(materialJson).algorithm;
    return value;
  }

  /** Exact content in a complete document with locally generated signed root IDs. */
  async signDocument(dataJson: string): Promise<string> {
    const result = await dispatch<{ value: string }>("signDocument", {handleId: this.handleId, dataJson});
    return result.value;
  }

  /** Sign serialized PreparedDocumentV2 without changing its frozen envelope/context. */
  async signPreparedDocument(preparedJson: string): Promise<string> {
    const result = await dispatch<{ value: string }>("signPreparedDocument", {handleId: this.handleId, preparedJson});
    return result.value;
  }

  async signMessage(dataJson: string): Promise<string> {
    const result = await dispatch<{ signedJson: string }>("signMessage", {
      handleId: this.handleId,
      dataJson,
    });
    return result.signedJson;
  }

  async signString(message: string): Promise<string> {
    const result = await dispatch<{ value: string }>("signString", {
      handleId: this.handleId, message,
    });
    return result.value;
  }

  async buildRequestAuthHeader(
    method: string, url: string, body: Uint8Array, audience: string,
  ): Promise<string> {
    const result = await dispatch<{ value: string }>("buildRequestAuthHeader", {
      handleId: this.handleId, method, url, body: Array.from(body), audience,
    });
    return result.value;
  }

  async getPublicKeyHash(): Promise<string> {
    const result = await dispatch<{ value: string }>("getPublicKeyHash", {
      handleId: this.handleId,
    });
    return result.value;
  }

  async getPublicKeyPem(): Promise<string> {
    const result = await dispatch<{ value: string }>("getPublicKeyPem", {
      handleId: this.handleId,
    });
    return result.value;
  }

  async getPublicKeyPemBase64(): Promise<string> {
    const result = await dispatch<{ value: string }>("getPublicKeyPemBase64", {
      handleId: this.handleId,
    });
    return result.value;
  }

  async exportAgent(): Promise<string> {
    const result = await dispatch<{ value: string }>("exportAgent", {
      handleId: this.handleId,
    });
    return result.value;
  }

  async updateAgentJson(agentJson: string): Promise<string> {
    const result = await dispatch<{ value: string }>("updateAgent", {
      handleId: this.handleId, agentJson,
    });
    return result.value;
  }

  /** Sign an update while retaining the current version for request auth. */
  async prepareAgentUpdateJson(updatesJson: string): Promise<string> {
    const result = await dispatch<{ value: string }>("prepareAgentUpdate", {
      handleId: this.handleId, updatesJson,
    });
    return result.value;
  }

  /** Adopt the prepared successor after registration succeeds. */
  async commitAgentUpdateJson(preparedJson: string): Promise<string> {
    const result = await dispatch<{ value: string }>("commitAgentUpdate", {
      handleId: this.handleId, preparedJson,
    });
    return result.value;
  }

  /** Generated 128-bit code and ciphertext; display code only on explicit request.
   * The host must clear visible copies and lock/drop on completion or background. */
  async exportRecovery(): Promise<{ code: string; materialJson: string }> {
    const result = await dispatch<{ value: string }>("exportRecovery", { handleId: this.handleId });
    return JSON.parse(result.value);
  }

  async exportEncryptedAgent(password: string): Promise<string> {
    const result = await dispatch<{ value: string }>("exportEncryptedAgent", {
      handleId: this.handleId, password,
    });
    return result.value;
  }

  async verify(signedJson: string): Promise<string> {
    const result = await dispatch<{ outcomeJson: string }>("verify", {
      handleId: this.handleId,
      signedJson,
    });
    return result.outcomeJson;
  }

  async clearSecrets(): Promise<void> {
    await dispatch("clearSecrets", { handleId: this.handleId });
  }

  /** Free the worker-side handle. After this call any further method
   * on this handle rejects with `InvalidHandle`. */
  async drop(): Promise<void> {
    await dispatch("dropHandle", { handleId: this.handleId });
  }
}

// ---------------------------------------------------------------------------
// Constructors.
// ---------------------------------------------------------------------------

/** First-version human metadata; ML-DSA-87 only. */
export async function createHumanInWorker(
  options?: { workerUrl?: URL | string },
): Promise<WorkerAgentHandle> {
  const result = await dispatch<{
    handleId: number; publicKeyBase64: string; algorithm: Algorithm;
  }>("createHuman", {}, options?.workerUrl);
  return new WorkerAgentHandle(result.handleId, result.publicKeyBase64, result.algorithm);
}

/** Pins come from authenticated registration, never from the backup itself. */
export async function importRecoveryInWorker(
  materialJson: string, code: string, expectedAgentId: string,
  expectedPublicKeyBase64: string, expectedAlgorithm: Algorithm,
  options?: { workerUrl?: URL | string },
): Promise<WorkerAgentHandle> {
  const result = await dispatch<{
    handleId: number; publicKeyBase64: string; algorithm: Algorithm;
  }>("importRecovery", {
    materialJson, code, expectedAgentId, expectedPublicKeyBase64, expectedAlgorithm,
  }, options?.workerUrl);
  return new WorkerAgentHandle(result.handleId, result.publicKeyBase64, result.algorithm);
}

/** No handle/persistence: signed identity JSON only; caller checks current version. */
export async function verifyRecoveryInWorker(materialJson: string, code: string, expectedAgentId: string,
  expectedPublicKeyBase64: string, expectedAlgorithm: Algorithm,
  options?: {workerUrl?: URL | string}): Promise<string> {
  const result = await dispatch<{identityJson: string}>("verifyRecovery", {
    materialJson, code, expectedAgentId, expectedPublicKeyBase64, expectedAlgorithm,
  }, options?.workerUrl);
  return result.identityJson;
}

export async function normalizeRecoveryCodeInWorker(code: string,
  options?: {workerUrl?: URL | string}): Promise<string> {
  const result = await dispatch<{code: string}>("normalizeRecoveryCode", {code}, options?.workerUrl);
  return result.code;
}

export async function generateRecoveryCodeInWorker(
  options?: { workerUrl?: URL | string },
): Promise<string> {
  const result = await dispatch<{ code: string }>("generateRecoveryCode", {}, options?.workerUrl);
  return result.code;
}

export async function createEphemeralInWorker(
  algorithm: Algorithm = "pq2025",
  options?: { workerUrl?: URL | string },
): Promise<WorkerAgentHandle> {
  const result = await dispatch<{
    handleId: number;
    publicKeyBase64: string;
    algorithm: Algorithm;
  }>("createEphemeral", { algorithm }, options?.workerUrl);
  return new WorkerAgentHandle(result.handleId, result.publicKeyBase64, result.algorithm);
}

export async function importEncryptedAgentInWorker(
  materialJson: string,
  password: string,
  options?: { workerUrl?: URL | string },
): Promise<WorkerAgentHandle> {
  const result = await dispatch<{
    handleId: number;
    publicKeyBase64: string;
    algorithm: Algorithm;
  }>("importEncryptedAgent", { materialJson, password }, options?.workerUrl);
  return new WorkerAgentHandle(result.handleId, result.publicKeyBase64, result.algorithm);
}

/** Import only after comparing pins obtained from a trusted key registry. */
export async function importEncryptedAgentPinnedInWorker(
  materialJson: string,
  password: string,
  expectedAgentId: string,
  expectedPublicKeyBase64: string,
  expectedAlgorithm: Algorithm,
  options?: { workerUrl?: URL | string },
): Promise<WorkerAgentHandle> {
  const result = await dispatch<{
    handleId: number; publicKeyBase64: string; algorithm: Algorithm;
  }>("importEncryptedAgentPinned", {
    materialJson, password, expectedAgentId, expectedPublicKeyBase64, expectedAlgorithm,
  }, options?.workerUrl);
  return new WorkerAgentHandle(result.handleId, result.publicKeyBase64, result.algorithm);
}

export async function generateTransferCodeInWorker(
  options?: { workerUrl?: URL | string },
): Promise<string> {
  const result = await dispatch<{ code: string }>("generateTransferCode", {}, options?.workerUrl);
  return result.code;
}

/** Rewrap transferred material without retaining an unlocked worker handle. */
export async function reencryptTransferredAgentInWorker(
  materialJson: string,
  code: string,
  expectedAgentId: string,
  expectedPublicKeyBase64: string,
  expectedAlgorithm: Algorithm,
  storagePassword: string,
  options?: { workerUrl?: URL | string },
): Promise<string> {
  const result = await dispatch<{ materialJson: string }>("reencryptTransferredAgent", {
    materialJson, code, expectedAgentId, expectedPublicKeyBase64,
    expectedAlgorithm, storagePassword,
  }, options?.workerUrl);
  return result.materialJson;
}
