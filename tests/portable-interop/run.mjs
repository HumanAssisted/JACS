#!/usr/bin/env node
/** Real native-UniFFI -> Chromium/WASM -> native-UniFFI PQ roundtrip. */
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const env = process.env;
const wasmPkg = path.resolve(env.JACS_INTEROP_WASM_PKG ?? path.join(repo, 'jacs-wasm/pkg'));
const pythonModule = path.resolve(env.JACS_INTEROP_MOBILE_PYTHON ?? path.join(repo, 'jacs-mobile/generated/python/jacs_mobile.py'));
const defaultLibrary = process.platform === 'darwin' ? 'libjacs_mobile.dylib' : process.platform === 'win32' ? 'jacs_mobile.dll' : 'libjacs_mobile.so';
const mobileLibrary = path.resolve(env.JACS_INTEROP_MOBILE_LIB ?? path.join(repo, 'target/debug', defaultLibrary));
const python = env.JACS_INTEROP_PYTHON ?? env.CODEX_PRIMARY_RUNTIME_PYTHON ?? 'python3';
const playwrightModule = env.JACS_INTEROP_PLAYWRIGHT_MODULE ?? (env.CODEX_PRIMARY_RUNTIME_NODE_MODULES ? path.join(env.CODEX_PRIMARY_RUNTIME_NODE_MODULES, 'playwright/index.mjs') : 'playwright');
const importConfigured = value => import(path.isAbsolute(value) ? pathToFileURL(value).href : value);
const timeoutMs = Number(env.JACS_INTEROP_TIMEOUT_MS ?? 120000);
if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300000) throw new Error('Invalid interop timeout');

function mobile(operation, binding, fixture, returned) {
  const args = [path.join(here, 'mobile_fixture.py'), operation, '--binding', binding, '--fixture', fixture];
  if (returned) args.push('--returned', returned);
  const result = spawnSync(python, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 * 1024 });
  // Only emit fixed status lines, never subprocess tracebacks or serialized fixtures.
  for (const line of result.stdout?.split('\n') ?? []) if (/^PASS: mobile /.test(line)) console.log(line);
  if (result.status !== 0) throw new Error(`mobile-${operation}-failed`);
}

let phase = 'setup';
let temporary;
let server;
let browser;
let deadline;
try {
  temporary = await mkdtemp(path.join(tmpdir(), 'jacs-pq-interop-'));
  const bindingDir = path.join(temporary, 'binding');
  await mkdir(bindingDir, { mode: 0o700 });
  const binding = path.join(bindingDir, 'jacs_mobile.py');
  await copyFile(pythonModule, binding);
  await symlink(mobileLibrary, path.join(bindingDir, defaultLibrary));
  const fixturePath = path.join(temporary, 'mobile-fixture.json');
  const returnPath = path.join(temporary, 'browser-return.json');
  phase = 'mobile-create';
  mobile('create', binding, fixturePath);
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  // Serve only public WASM files. Neither test passwords nor fixtures are HTTP routes.
  const publicFiles = new Set(['index.js', 'jacs_wasm.js', 'jacs_wasm_bg.wasm', 'worker/index.js', 'worker/jacs-worker.js']);
  server = createServer(async (request, response) => {
    try {
      const name = new URL(request.url, 'http://localhost').pathname.slice(1);
      if (name === '') {
        response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
        response.end('<!doctype html><title>JACS PQ interoperability</title>');
      } else if (publicFiles.has(name)) {
        response.writeHead(200, { 'Content-Type': name.endsWith('.wasm') ? 'application/wasm' : 'text/javascript', 'Cache-Control': 'no-store' });
        response.end(await readFile(path.join(wasmPkg, name)));
      } else {
        response.writeHead(404); response.end();
      }
    } catch {
      response.writeHead(404); response.end();
    }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const playwright = await importConfigured(playwrightModule);
  const options = { headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'], timeout: timeoutMs };
  if (env.JACS_INTEROP_CHROMIUM_MODULE) {
    const { default: chromium } = await importConfigured(env.JACS_INTEROP_CHROMIUM_MODULE);
    options.args = chromium.args.filter(arg => !['--single-process', '--disable-web-security', '--disable-site-isolation-trials'].includes(arg));
    options.executablePath = env.JACS_INTEROP_CHROMIUM_EXECUTABLE ?? await chromium.executablePath();
  } else if (env.JACS_INTEROP_CHROMIUM_EXECUTABLE) {
    options.executablePath = env.JACS_INTEROP_CHROMIUM_EXECUTABLE;
  }
  phase = 'browser-launch';
  browser = await playwright.chromium.launch(options);
  const page = await browser.newPage();
  page.setDefaultTimeout(timeoutMs);
  await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
  phase = 'browser-pq-roundtrip';
  const result = await Promise.race([
    page.evaluate(async fixture => {
      let phase = 'init';
      let agent;
      const require = (condition, label) => { if (!condition) throw new Error(label); };
      try {
        const jacs = await import('/index.js');
        await jacs.initJacsWasm();
        phase = 'pinned-import';
        const importAgent = fixture.recovery ? jacs.importRecovery : jacs.importEncryptedAgentPinned;
        agent = await importAgent(fixture.material_json, fixture.transfer_password, fixture.agent_id, fixture.public_key_base64, 'pq2025');
        require(agent.algorithm() === 'pq2025' && agent.isUnlocked(), 'PQ unlock');
        require(agent.getPublicKeyBase64() === fixture.public_key_base64, 'public key pin');
        require(agent.getPublicKeyHash() === fixture.public_key_hash, 'public key hash');
        require(JSON.parse(agent.exportAgent()).jacsVersion === fixture.agent_version, 'version pin');
        phase = 'verify-mobile';
        const verified = JSON.parse(agent.verifyWithKeyJson(fixture.signed_challenge, fixture.public_key_base64, 'pq2025'));
        require(verified.valid && verified.signer_id === fixture.agent_id, 'mobile signature');
        const content = verified.data.content;
        require(content.test === fixture.challenge.test && content.direction === 'mobile-to-browser' && content.nonce === fixture.challenge.nonce, 'mobile challenge');
        phase = 'sign-browser';
        const contentToSign = JSON.stringify({ test: 'jacs-portable-pq-interop', direction: 'browser-to-mobile', reply_to: fixture.challenge.nonce });
        const signedResponse = fixture.recovery ? agent.signDocumentJson(contentToSign) : agent.signMessageJson(contentToSign);
        if (fixture.recovery) {
          const complete = JSON.parse(signedResponse);
          require(complete.jacsId && complete.jacsVersion && complete.jacsSha256, 'full root headers');
          require(Object.keys(complete.content).length === 3 && Object.entries(JSON.parse(contentToSign)).every(([key, value]) => complete.content[key] === value), 'exact content');
          require(await jacs.verifyRecovery(fixture.material_json, fixture.transfer_password, fixture.agent_id,
            fixture.public_key_base64, 'pq2025') === agent.exportAgent(), 'web readback');
        }
        phase = 'reencrypt';
        const recovery = fixture.recovery ? JSON.parse(agent.exportRecovery()) : null;
        const materialJson = recovery?.materialJson ?? agent.exportEncryptedAgent(fixture.return_password);
        const material = JSON.parse(materialJson);
        require(material.algorithm === 'pq2025' && material.public_key === fixture.public_key_base64, 'rewrap identity');
        require(material.encrypted_private_key !== JSON.parse(fixture.material_json).encrypted_private_key, 'fresh envelope');
        let createdHumans = [];
        let rotatedMaterial, rotationProof;
        if (fixture.recovery) {
          phase = 'human-worker-recovery';
          const human = await jacs.createHuman();
          try {
            const identity = JSON.parse(human.exportAgent());
            require(identity.jacsAgentType === 'human' && identity.jacsVersion === identity.jacsOriginalVersion, 'human constructor');
            createdHumans.push({ signed_identity: human.exportAgent(), public_key_base64: human.getPublicKeyBase64() });
          } finally { human.clearSecrets(); human.free(); }
          const worker = await import('/worker/index.js');
          const workerHuman = await worker.createHumanInWorker();
          let workerRestored;
          try {
            const identityJson = await workerHuman.exportAgent();
            const identity = JSON.parse(identityJson);
            require(identity.jacsAgentType === 'human', 'worker human constructor');
            createdHumans.push({ signed_identity: identityJson, public_key_base64: workerHuman.publicKeyBase64 });
            const backup = await workerHuman.exportRecovery();
            require(await worker.normalizeRecoveryCodeInWorker(backup.code.toLowerCase().replaceAll('-', ' ')) === backup.code, 'worker paste normalization');
            require(await worker.verifyRecoveryInWorker(backup.materialJson, backup.code,
              identity.jacsId, workerHuman.publicKeyBase64, 'pq2025') === identityJson, 'worker readback');
            workerRestored = await worker.importRecoveryInWorker(backup.materialJson, backup.code.toLowerCase().replaceAll('-', ' '),
              identity.jacsId, workerHuman.publicKeyBase64, 'pq2025');
            require(await workerRestored.exportAgent() === identityJson, 'worker recovery identity');
            for (const [blob, code, id, expectedError] of [
              [backup.materialJson, await worker.generateRecoveryCodeInWorker(), identity.jacsId, 'InvalidPassword'],
              [backup.materialJson, backup.code, 'wrong-identity', 'MalformedKey'],
              ['{}', backup.code, identity.jacsId, 'MalformedDocument'],
              [backup.materialJson, 'one two three four five six', identity.jacsId, 'InvalidPasswordFormat'],
            ]) {
              let rejected = false;
              try { await worker.importRecoveryInWorker(blob, code, id, workerHuman.publicKeyBase64, 'pq2025'); }
              catch (error) { rejected = error.code === expectedError; }
              require(rejected, 'worker recovery rejects invalid input');
              let readbackRejected = false;
              try { await worker.verifyRecoveryInWorker(blob, code, id, workerHuman.publicKeyBase64, 'pq2025'); }
              catch (error) { readbackRejected = error.code === expectedError; }
              require(readbackRejected, 'worker readback rejects invalid input');
            }
            // A failed import never clears/replaces an existing worker key.
            const signed = await workerHuman.signDocument('{"exact":"worker approval"}');
            const complete = JSON.parse(signed);
            require(complete.jacsId && complete.jacsVersion && complete.jacsSha256 && complete.content.exact === 'worker approval', 'worker full document');
            require(JSON.parse(await workerRestored.verify(signed)).valid, 'working handle preserved');
            await workerRestored.clearSecrets();
            let locked = false;
            try { await workerRestored.exportRecovery(); } catch (error) { locked = error.code === 'Locked'; }
            require(locked, 'locked worker cannot export');
            let lockedSigning = false;
            try { await workerRestored.signDocument('{}'); } catch (error) { lockedSigning = error.code === 'Locked'; }
            require(lockedSigning, 'locked worker cannot sign full document');
          } finally {
            await workerHuman.drop();
            await workerRestored?.drop();
            worker.terminateWorker();
          }
        }
        if (fixture.rotation_material) {
          phase = 'cross-runtime-staged-rotation';
          const worker = await import('/worker/index.js');
          let current = await worker.importRecoveryInWorker(fixture.material_json, fixture.transfer_password,
            fixture.agent_id, fixture.public_key_base64, 'pq2025');
          try {
            const nativeStage = JSON.parse(fixture.rotation_material);
            const possession = await current.signRotationDocument(fixture.rotation_material, fixture.return_password, '{"challenge":"native-stage"}');
            require(JSON.parse(agent.verifyWithKeyJson(possession, nativeStage.public_key, 'pq2025')).valid, 'worker resumes native stage');
            rotatedMaterial = await current.prepareKeyRotation(fixture.return_password);
            const staged = JSON.parse(rotatedMaterial);
            const oldJson = await current.exportAgent();
            const oldStorage = await current.exportEncryptedAgent(fixture.return_password);
            await current.drop(); worker.terminateWorker(); // process death before acceptance
            current = await worker.importEncryptedAgentPinnedInWorker(oldStorage, fixture.return_password,
              fixture.agent_id, fixture.public_key_base64, 'pq2025');
            require(await current.exportAgent() === oldJson, 'old key survives interruption');
            rotationProof = await current.signRotationDocument(rotatedMaterial, fixture.return_password, '{"challenge":"worker-stage"}');
            require(JSON.parse(agent.verifyWithKeyJson(rotationProof, staged.public_key, 'pq2025')).valid, 'candidate possession before commit');
            const backup = await current.exportRotationRecovery(rotatedMaterial, fixture.return_password);
            require(JSON.parse(await worker.verifyRecoveryInWorker(backup.materialJson, backup.code,
              staged.agent.jacsId, staged.public_key, 'pq2025')).jacsVersion === staged.agent.jacsVersion, 'candidate backup before activation');
            let refused = false;
            try { await current.commitKeyRotation(rotatedMaterial, fixture.return_password, oldJson, fixture.public_key_base64); }
            catch { refused = true; }
            require(refused && await current.exportAgent() === oldJson, 'wrong acceptance preserves active key');
            for (let i = 0; i < 2; i++) {
              require(JSON.parse(await current.commitKeyRotation(rotatedMaterial, fixture.return_password,
                JSON.stringify(staged.agent), staged.public_key)).jacsVersion === staged.agent.jacsVersion, 'exact commit/replay');
              const committedProof = await current.signDocument(JSON.stringify({challenge: 'promoted-worker', replay: i === 1}));
              require(JSON.parse(agent.verifyWithKeyJson(committedProof, staged.public_key, 'pq2025')).valid, 'promoted worker signs with new key after commit/replay');
              require(!JSON.parse(agent.verifyWithKeyJson(committedProof, fixture.public_key_base64, 'pq2025')).valid, 'promoted worker no longer signs with old key');
            }
            require(current.publicKeyBase64 === staged.public_key, 'worker metadata follows commit');
          } finally { await current?.drop(); worker.terminateWorker(); }
        }
        phase = 'clear';
        agent.clearSecrets();
        require(!agent.isUnlocked(), 'browser key cleared');
        return { ok: true, rotation_material: rotatedMaterial, rotation_proof: rotationProof, recovery_code: recovery?.code, created_humans: createdHumans, algorithm: 'pq2025', agent_id: fixture.agent_id, public_key_base64: fixture.public_key_base64, material_json: materialJson, signed_response: signedResponse, verified_mobile: true };
      } catch {
        return { ok: false, phase };
      } finally {
        agent?.clearSecrets();
        agent?.free();
      }
    }, fixture),
    new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('browser-timeout')), timeoutMs); }),
  ]);
  clearTimeout(deadline);
  if (!result.ok) { phase = `browser-${result.phase}`; throw new Error('browser-roundtrip-failed'); }
  console.log('PASS: real Chromium imported PQ material, verified, signed, re-encrypted, and cleared its key');
  await writeFile(returnPath, JSON.stringify(result), { mode: 0o600, flag: 'wx' });
  phase = 'mobile-import-and-verify';
  mobile('verify', binding, fixturePath, returnPath);
  if (fixture.rotation_material) console.log('PASS: native/worker staged rotation, interrupted reopen, candidate proof/backup, exact acceptance and new-key signing after commit/replay');
  console.log(fixture.recovery ? 'PASS: human creation and 128-bit recovery through native UniFFI, Chromium WASM and Web Worker; wrong-code/pin/material rejection' : 'PASS: native UniFFI -> browser WASM -> native UniFFI PQ interoperability');
} catch {
  console.error(`FAIL: PQ interoperability at ${phase}`);
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
  await browser?.close();
  if (server) await new Promise(resolve => server.close(resolve));
  if (temporary) await rm(temporary, { recursive: true, force: true });
}
