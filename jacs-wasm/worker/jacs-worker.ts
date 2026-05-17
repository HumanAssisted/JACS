// Worker-side bootstrap for `@jacs/wasm/worker`. This file is loaded as
// the entry point of a `new Worker(... { type: "module" })`; it imports
// the wasm-bindgen output, calls the default `init()` to instantiate
// the module, and then routes every inbound `postMessage` through
// `workerHandleMessage`.
//
// See `worker/index.ts` for the main-thread side of the bridge.

/// <reference lib="webworker" />

import init, { workerHandleMessage } from "../jacs_wasm.js";

const ready: Promise<void> = init().then(() => {
  // Nothing else to do — the wasm module is instantiated lazily and
  // every dispatched message awaits `ready` before invoking the Rust
  // handler.
});

const scope = self as unknown as DedicatedWorkerGlobalScope;

scope.addEventListener("message", async (event: MessageEvent) => {
  await ready;
  try {
    const reply = workerHandleMessage(event.data);
    scope.postMessage(reply);
  } catch (err) {
    // `workerHandleMessage` is designed to *never* throw — it always
    // produces a structured `{ id, ok: false, error }` reply. If we
    // land here it means the wasm-bindgen layer itself threw (e.g.
    // serialization). Surface it with `id: 0` so the main thread can
    // still see what went wrong.
    scope.postMessage({
      id: 0,
      ok: false,
      error: {
        code: "WorkerBootstrapError",
        message: err instanceof Error ? err.message : String(err),
      },
    });
  }
});
