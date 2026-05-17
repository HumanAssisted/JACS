// Worker-smoke check for `@jacs/wasm/worker` (Task 019 acceptance
// criterion). Creates an ephemeral pq2025 agent inside a Web Worker,
// signs a message, and verifies the result on the main thread. Output
// is appended to `#output`; a successful run shows `valid: true`.

import {
  createEphemeralInWorker,
  terminateWorker,
  type WorkerAgentHandle,
} from "@jacs/wasm/worker";

async function runSmoke(): Promise<void> {
  const out = document.getElementById("output") as HTMLPreElement;
  const write = (line: string) => {
    out.textContent = (out.textContent ?? "") + "\n" + line;
  };
  try {
    write("creating ephemeral pq2025 agent in worker...");
    const agent: WorkerAgentHandle = await createEphemeralInWorker("pq2025");
    write(`got handle ${agent.handleId} (${agent.algorithm}, pk=${agent.publicKeyBase64.length} chars)`);

    const message = JSON.stringify({ hello: "world", ts: Date.now() });
    write(`signing: ${message}`);
    const signed = await agent.signMessage(message);
    write(`signed length: ${signed.length}`);

    write("verifying...");
    const outcomeJson = await agent.verify(signed);
    const outcome = JSON.parse(outcomeJson);
    write(`outcome: valid=${outcome.valid}`);

    await agent.drop();
    write("dropped handle");
    if (!outcome.valid) {
      throw new Error("verification did not return valid=true");
    }
    write("SMOKE OK");
  } catch (err) {
    write(`SMOKE FAILED: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    terminateWorker();
  }
}

void runSmoke();
