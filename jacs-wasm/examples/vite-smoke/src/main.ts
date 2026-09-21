// Vite bundler smoke for `@hai.ai/jacs-wasm`. Validates that the npm package
// shape works end-to-end inside a real bundler: initialize the wasm,
// create an ephemeral agent, sign + verify a message, assert success.
//
// The Playwright check (tests/smoke.spec.ts) loads this page and reads
// the `#output` element.

import { createEphemeral, initJacsWasm } from "@hai.ai/jacs-wasm";
import { deviceTransferSmoke } from "./device-transfer-smoke";

async function main(): Promise<void> {
  const out = document.getElementById("output") as HTMLPreElement;
  const write = (line: string) => {
    out.textContent = (out.textContent ?? "") + "\n" + line;
  };
  try {
    write("initJacsWasm...");
    await initJacsWasm();
    write("createEphemeral pq2025 (default)...");
    // PRD §4.3: constructors return Promise<CoreAgentHandle>.
    const agent = await createEphemeral();
    if (agent.algorithm() !== "pq2025") throw new Error("New identities must default to pq2025");
    write(`pk len: ${agent.getPublicKeyBase64().length}`);

    const message = JSON.stringify({ hello: "world" });
    write(`signing: ${message}`);
    const signed = agent.signMessageJson(message);
    write(`signed length: ${signed.length}`);

    const outcomeStr = agent.verifyJson(signed);
    const outcome = JSON.parse(outcomeStr);
    write(`verify.valid = ${outcome.valid}`);

    if (outcome.valid !== true) {
      throw new Error(`expected valid=true, got ${outcome.valid}`);
    }
    agent.clearSecrets();
    agent.free();
    await deviceTransferSmoke(write);
    write("DEVICE TRANSFER OK (ed25519, es256, pq2025, worker)");
    write("SMOKE OK");
  } catch (err) {
    write(`SMOKE FAILED: ${err instanceof Error ? err.message : String(err)}`);
  }
}

void main();
