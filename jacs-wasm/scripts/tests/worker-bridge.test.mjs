#!/usr/bin/env node
// Node-runnable bridge test for `jacs-wasm/worker/index.ts` (Issue 011).
//
// The bridge is pure TypeScript/JavaScript logic — it does not touch the
// wasm-bindgen layer directly. We can exercise it with a stub `Worker`
// that we control end-to-end:
//
// 1. Send a known request; trigger an unmatched `ok: false` reply from
//    the worker (simulating a bootstrap / dispatch failure where the
//    `id` was lost). The bridge must fail every pending call so callers
//    can't hang.
// 2. Send a known request; reply normally with matching id. The bridge
//    must resolve.
//
// We import the **finalized** `pkg/worker/index.js` (produced by
// finalize-pkg.sh + tsc) so this test exercises the published surface,
// not the in-tree TypeScript source.

import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JACS_WASM_DIR = path.resolve(__dirname, "..", "..");
const BRIDGE_URL = pathToFileURL(
  path.join(JACS_WASM_DIR, "pkg", "worker", "index.js"),
).href;

// Provide a minimal global `Worker` class plus `URL`/`MessageEvent`
// substitutes so the bridge's `new Worker(url, { type: "module" })`
// call succeeds. The stub captures the most recently constructed worker
// so each test can drive it directly.
let lastWorker = null;

class StubWorker {
  constructor(url, _opts) {
    this.url = url;
    this.listeners = { message: [], error: [] };
    this.posted = [];
    lastWorker = this;
  }
  addEventListener(type, fn) {
    (this.listeners[type] ??= []).push(fn);
  }
  postMessage(data) {
    this.posted.push(data);
  }
  terminate() {
    /* no-op for the bridge test */
  }
  // Test helper — simulate the worker side posting a message back to
  // the main thread.
  emitMessage(data) {
    for (const fn of this.listeners.message) fn({ data });
  }
}

if (!globalThis.Worker) {
  globalThis.Worker = StubWorker;
} else {
  // We need to override it deterministically — replace whatever the
  // host provided so tests are reproducible.
  globalThis.Worker = StubWorker;
}

// Import after monkey-patching so the bridge module captures *our*
// `Worker`. The bridge uses a module-level `import.meta.url` to build
// `DEFAULT_WORKER_URL` — that is fine because we never read it.
const bridge = await import(BRIDGE_URL);

// ---------------------------------------------------------------------------
// Test 1: matched reply resolves the pending call.
// ---------------------------------------------------------------------------

await (async function matched_reply_resolves() {
  // `createEphemeralInWorker` is async — start it, capture the request
  // the bridge posted, and reply with a matching id.
  const promise = bridge.createEphemeralInWorker("ed25519");
  // Yield one microtask so the bridge can post the message.
  await Promise.resolve();
  assert.ok(lastWorker, "bridge must construct a Worker");
  const request = lastWorker.posted.at(-1);
  assert.equal(request.op, "createEphemeral");
  assert.equal(request.args.algorithm, "ed25519");
  const id = request.id;
  // Reply with success.
  lastWorker.emitMessage({
    id,
    ok: true,
    result: {
      handleId: 7,
      publicKeyBase64: "AAA=",
      algorithm: "ed25519",
    },
  });
  const handle = await promise;
  assert.equal(handle.handleId, 7);
  assert.equal(handle.algorithm, "ed25519");
  // Clean up shared bridge state — terminateWorker drops the pending
  // table + nulls the singleton worker.
  bridge.terminateWorker();
  console.log("worker-bridge.test: matched_reply_resolves OK");
})();

// ---------------------------------------------------------------------------
// Test 2: unmatched ok:false reply fails *every* pending call (Issue 011).
// ---------------------------------------------------------------------------

await (async function unmatched_failure_fails_all_pending() {
  // Start two requests and let the bridge post both.
  const a = bridge.createEphemeralInWorker("ed25519");
  const b = bridge.createEphemeralInWorker("pq2025");
  await Promise.resolve();
  assert.ok(lastWorker, "bridge must construct a Worker");
  assert.equal(lastWorker.posted.length, 2);
  // Simulate the worker emitting an unmatched ok:false (id=0, which is
  // what a pre-Issue-011 bootstrap failure would emit).
  lastWorker.emitMessage({
    id: 0,
    ok: false,
    error: {
      code: "WorkerBootstrapError",
      message: "wasm init failed",
    },
  });
  // Both pending calls must reject (NOT hang).
  await assert.rejects(a, (err) => {
    assert.equal(err.code, "WorkerBootstrapError");
    return true;
  });
  await assert.rejects(b, (err) => {
    assert.equal(err.code, "WorkerBootstrapError");
    return true;
  });
  bridge.terminateWorker();
  console.log("worker-bridge.test: unmatched_failure_fails_all_pending OK");
})();

// ---------------------------------------------------------------------------
// Test 3: worker `error` event also rejects every pending call.
// ---------------------------------------------------------------------------

await (async function worker_error_event_fails_all_pending() {
  const a = bridge.createEphemeralInWorker("ed25519");
  await Promise.resolve();
  assert.ok(lastWorker, "bridge must construct a Worker");
  // Fire the `error` listener directly.
  for (const fn of lastWorker.listeners.error) {
    fn({ message: "worker crashed for reasons" });
  }
  await assert.rejects(a, (err) => {
    assert.equal(err.code, "WorkerCrashed");
    return true;
  });
  bridge.terminateWorker();
  console.log("worker-bridge.test: worker_error_event_fails_all_pending OK");
})();

console.log("worker-bridge.test: PASS");
