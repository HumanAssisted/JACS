import {
  createEphemeral, generateTransferCode, importEncryptedAgent,
  importEncryptedAgentPinned, localStore, reencryptTransferredAgent,
} from "@jacs/wasm";
import {
  createEphemeralInWorker, generateTransferCodeInWorker,
  importEncryptedAgentPinnedInWorker, terminateWorker,
} from "@jacs/wasm/worker";

function check(condition: boolean, description: string): void {
  if (!condition) throw new Error(description);
}

async function rejects(operation: () => unknown | Promise<unknown>): Promise<void> {
  try { await operation(); } catch { return; }
  throw new Error("Expected transfer validation to reject");
}

type Awaitable<T> = T | Promise<T>;
interface StagedIdentityHandle {
  exportAgent(): Awaitable<string>;
  prepareAgentUpdateJson(updatesJson: string): Awaitable<string>;
  commitAgentUpdateJson(preparedJson: string): Awaitable<string>;
  buildRequestAuthHeader(method: string, url: string, body: Uint8Array, audience: string): Awaitable<string>;
}

function authKeyId(header: string): string {
  check(header.startsWith("JACS v2."), "Expected request-auth-v2");
  const encoded = header.slice("JACS v2.".length).split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "="))).keyId;
}

async function stagedIdentityUpdate(handle: StagedIdentityHandle): Promise<void> {
  const original = JSON.parse(await handle.exportAgent());
  const candidate = await handle.prepareAgentUpdateJson(JSON.stringify({ name: "Staged phone identity" }));
  const prepared = JSON.parse(candidate);
  check(prepared.jacsId === original.jacsId && prepared.jacsVersion !== original.jacsVersion,
    "Preparation must preserve identity and create a new version");
  check(JSON.parse(await handle.exportAgent()).jacsVersion === original.jacsVersion,
    "Preparation must leave the registered version active");
  const admissionAuth = await handle.buildRequestAuthHeader(
    "POST", "https://hai.ai/api/v1/agents/register", new TextEncoder().encode(candidate), "hai.ai",
  );
  check(authKeyId(admissionAuth) === `${original.jacsId}:${original.jacsVersion}`,
    "Registration must authenticate using the existing registered version");
  await handle.commitAgentUpdateJson(candidate);
  check(JSON.parse(await handle.exportAgent()).jacsVersion === prepared.jacsVersion,
    "Successful commit must adopt the prepared version");
  const committedAuth = await handle.buildRequestAuthHeader(
    "GET", "https://hai.ai/api/v1/agents/me", new Uint8Array(), "hai.ai",
  );
  check(authKeyId(committedAuth) === `${prepared.jacsId}:${prepared.jacsVersion}`,
    "Committed requests must authenticate with the new version");
  await rejects(() => handle.commitAgentUpdateJson(candidate));
}

/** Runs against the built npm/WASM artifact in a real browser. */
export async function deviceTransferSmoke(report: (message: string) => void): Promise<void> {
  for (const algorithm of ["ed25519", "es256", "pq2025"] as const) {
    report(`Transfer ${algorithm}: create, update, export`);
    const phone = await createEphemeral(algorithm);
    await stagedIdentityUpdate(phone);
    const updated = JSON.parse(phone.exportAgent());
    report(`Staged identity ${algorithm}: old-version auth, commit, new-version auth OK`);
    const id = updated.jacsId;
    const key = phone.getPublicKeyBase64();
    const code = await generateTransferCode();
    check(code.split(" ").length === 6, "Generated code must have six words");
    check(atob(phone.getPublicKeyPemBase64()) === phone.getPublicKeyPem(), "PEM encoding mismatch");
    check(phone.signString("café 🗝").length > 0, "Raw UTF-8 signing failed");
    check(phone.buildRequestAuthHeader(
      "POST", "https://hai.ai/api/v1/link/session", new TextEncoder().encode('{"a":1}'), "hai.ai",
    ).length > 0, "Request authentication failed");
    const material = phone.exportEncryptedAgent(code);
    report(`Transfer ${algorithm}: pin and identity validation`);
    await rejects(() => importEncryptedAgentPinned(material, code, "wrong-id", key, algorithm));
    await rejects(() => reencryptTransferredAgent(material, code, id, key, algorithm, code));
    const tampered = JSON.parse(material);
    tampered.agent.name = "Unsigned attacker edit";
    await rejects(() => importEncryptedAgentPinned(JSON.stringify(tampered), code, id, key, algorithm));
    const browserSecret = "test-only distinct browser password";
    const stored = await reencryptTransferredAgent(material, code, id, key, algorithm, browserSecret);
    report(`Transfer ${algorithm}: store and restore`);
    localStore.saveEncryptedAgent(`transfer-smoke-${algorithm}`, stored);
    const loaded = localStore.loadEncryptedAgent(`transfer-smoke-${algorithm}`);
    check(loaded === stored, "Encrypted local storage round trip failed");
    const browser = await importEncryptedAgent(loaded!, browserSecret);
    try {
      check(browser.getPublicKeyHash() === phone.getPublicKeyHash(), "Transferred key changed");
      const signed = browser.signMessageJson(JSON.stringify({ linked: true }));
      check(JSON.parse(phone.verifyJson(signed)).valid, "Transferred signature did not verify");
    } finally {
      browser.clearSecrets(); browser.free(); phone.clearSecrets(); phone.free();
      localStore.remove(`transfer-smoke-${algorithm}`);
    }
  }

  try {
    report("Transfer worker: create default pq2025 and unlock");
    const phone = await createEphemeralInWorker();
    check(phone.algorithm === "pq2025", "Worker identities must default to pq2025 without fallback");
    await stagedIdentityUpdate(phone);
    report("Staged worker identity pq2025: old-version auth, commit, new-version auth OK");
    const code = await generateTransferCodeInWorker();
    const material = await phone.exportEncryptedAgent(code);
    const id = JSON.parse(await phone.exportAgent()).jacsId;
    const received = await importEncryptedAgentPinnedInWorker(material, code, id, phone.publicKeyBase64, "pq2025");
    check(await received.getPublicKeyHash() === await phone.getPublicKeyHash(), "Worker key mismatch");
    check((await received.signString("auth")).length > 0, "Worker raw signing failed");
    check((await received.buildRequestAuthHeader(
      "GET", "https://hai.ai/api/v1/agents/me", new Uint8Array(), "hai.ai",
    )).length > 0, "Worker request authentication failed");
    await received.clearSecrets();
    await rejects(() => received.signString("locked"));
    await rejects(() => importEncryptedAgentPinnedInWorker(material, code, "wrong-id", phone.publicKeyBase64, "pq2025"));
    await received.drop(); await phone.drop();
  } finally {
    terminateWorker();
  }
}
