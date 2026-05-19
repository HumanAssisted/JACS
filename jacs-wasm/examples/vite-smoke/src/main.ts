// Vite bundler smoke for `@jacs/wasm`. Validates that the npm package
// shape works end-to-end inside a real bundler: initialize the wasm,
// create an ephemeral agent, sign + verify a message, assert success.
//
// The Playwright check (tests/smoke.spec.ts) loads this page and reads
// the `#output` element.

import { createEphemeral, initJacsWasm } from "@jacs/wasm";

async function main(): Promise<void> {
  const out = document.getElementById("output") as HTMLPreElement;
  const write = (line: string) => {
    out.textContent = (out.textContent ?? "") + "\n" + line;
  };
  try {
    write("initJacsWasm...");
    await initJacsWasm();
    write("createEphemeral ed25519...");
    // PRD §4.3: constructors return Promise<CoreAgentHandle>.
    const agent = await createEphemeral("ed25519");
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
    write("SMOKE OK");
  } catch (err) {
    write(`SMOKE FAILED: ${err instanceof Error ? err.message : String(err)}`);
  }
}

void main();
