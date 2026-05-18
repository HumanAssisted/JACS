// Worker-side bootstrap for `@jacs/wasm/worker`. This file is loaded as
// the entry point of a `new Worker(... { type: "module" })`; it imports
// the wasm-bindgen output, calls the default `init()` to instantiate
// the module, and then routes every inbound `postMessage` through
// `workerHandleMessage`.
//
// See `worker/index.ts` for the main-thread side of the bridge.
//
// Failure contract (Issue 011): every inbound message **must** receive a
// structured `{ id, ok: false, error }` reply on this same channel —
// callers in the main thread match against `id`, so an `id: 0` reply
// would silently leak. We therefore:
//
// 1. Move `await ready` inside the per-message try block so a wasm init
//    rejection surfaces as `{ id: <message id>, ok: false, error }`
//    rather than an uncaught promise rejection.
// 2. Use `event.data?.id` (falling back to `0` only when the inbound
//    payload is malformed enough that it lacks an id altogether) so a
//    legitimate caller waiting on a known id can always be unblocked.
// 3. For payloads with no usable id, post a sentinel `ok: false` reply
//    so the main-thread bridge can treat unmatched failures as fatal
//    instead of dropping them.

/// <reference lib="webworker" />

import init, { workerHandleMessage } from "../jacs_wasm.js";

// `ready` is shared by every dispatch — start it eagerly so callers
// don't pay the init latency twice, but await it *inside* the per-
// message try so init failures get a structured reply.
const ready: Promise<void> = init().then(() => {
  // Nothing else to do — the wasm module is instantiated lazily and
  // every dispatched message awaits `ready` before invoking the Rust
  // handler.
});

const scope = self as unknown as DedicatedWorkerGlobalScope;

scope.addEventListener("message", async (event: MessageEvent) => {
  // Extract the inbound id once so both the success path and every
  // failure path can quote it. `event.data?.id` may be `undefined` for
  // pathological inputs; we fall back to `0` which the main-thread
  // bridge treats as a fatal protocol error and uses to fail every
  // pending call.
  const inboundId =
    typeof event.data?.id === "number" ? event.data.id : 0;
  try {
    await ready;
    const reply = workerHandleMessage(event.data);
    scope.postMessage(reply);
  } catch (err) {
    // Two failure classes reach here:
    //   - wasm init rejected (e.g. instantiation failed) → surfaces
    //     with `WorkerBootstrapError`.
    //   - `workerHandleMessage` threw (the wasm-bindgen serialization
    //     layer can throw before reaching the Rust handler) →
    //     `WorkerDispatchError`.
    // We can't distinguish them reliably from JS, so we tag based on
    // whether `ready` has resolved.
    let code = "WorkerDispatchError";
    try {
      // `Promise.race` against an immediately-resolved sentinel tells us
      // whether `ready` has settled without throwing.
      await Promise.race([ready, Promise.resolve("pending")]).then((v) => {
        if (v === "pending") code = "WorkerBootstrapError";
      });
    } catch {
      // `ready` rejected → bootstrap failure.
      code = "WorkerBootstrapError";
    }
    scope.postMessage({
      id: inboundId,
      ok: false,
      error: {
        code,
        message: err instanceof Error ? err.message : String(err),
      },
    });
  }
});
