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

export type Algorithm = "ed25519" | "pq2025";

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

const DEFAULT_WORKER_URL = new URL("./jacs-worker.js", import.meta.url);

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
  const url = workerUrl ?? DEFAULT_WORKER_URL;
  const w = new Worker(url, { type: "module" });
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
  readonly publicKeyBase64: string;
  readonly algorithm: Algorithm;

  /** @internal */
  constructor(handleId: number, publicKeyBase64: string, algorithm: Algorithm) {
    this.handleId = handleId;
    this.publicKeyBase64 = publicKeyBase64;
    this.algorithm = algorithm;
  }

  async signMessage(dataJson: string): Promise<string> {
    const result = await dispatch<{ signedJson: string }>("signMessage", {
      handleId: this.handleId,
      dataJson,
    });
    return result.signedJson;
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

export async function createEphemeralInWorker(
  algorithm: Algorithm,
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
