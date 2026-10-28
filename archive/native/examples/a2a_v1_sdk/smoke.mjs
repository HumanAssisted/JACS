/** Actual official SDK 1.3.0 ML-DSA-87 verification and finite JSON-RPC exchange. */
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm, readFile, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import express from 'express';
import { importJWK } from 'jose';
import { AgentCard, Message, Task, TaskState, canonicalizeAgentCard, verifyAgentCardSignature } from '@a2a-js/sdk';
import { ClientFactory, DefaultAgentCardResolver } from '@a2a-js/sdk/client';
import { AgentEvent, DefaultRequestHandler, InMemoryTaskStore } from '@a2a-js/sdk/server';
import { jsonRpcHandler, UserBuilder } from '@a2a-js/sdk/server/express';

const EXTENSION = 'urn:jacs:provenance-v1';
const CARD = '/.well-known/agent-card.json';
const JWKS = '/.well-known/jwks.json';
const LIMIT = 1_048_576;
const require = createRequire(import.meta.url);
const [major, minor] = process.versions.node.split('.').map(Number);
assert(major > 24 || (major === 24 && minor >= 7), 'ML-DSA WebCrypto needs Node >=24.7');

function jacsRequire(entry) {
  // Optional staging directory is useful when testing freshly built native libs.
  return require(process.env.JACS_NODE_PACKAGE
    ? join(process.env.JACS_NODE_PACKAGE, entry === 'client' ? 'client.js' : 'src/a2a-server.js')
    : `@hai.ai/jacs/${entry}`);
}

async function fixture(messagingUrl) {
  const { JacsClient } = jacsRequire('client');
  const { buildWellKnownDocuments } = jacsRequire('a2a-server');
  // macOS /var is a symlink. Resolve the existing parent before creating any
  // private workspace; custody deliberately rejects symlink path components.
  const tempParent = await realpath(tmpdir());
  const work = await mkdtemp(join(tempParent, 'jacs-official-a2a-pq-'));
  const sender = new JacsClient();
  try {
    await sender.create({
      name: 'SDK café 雪 🦀', description: 'Finite independently verified report',
      domain: 'example.test', algorithm: 'pq2025', defaultStorage: 'fs',
      password: `Synthetic!9aA${randomBytes(32).toString('hex')}`,
      configPath: join(work, 'jacs.config.json'),
      keyDirectory: join(work, 'keys'), dataDirectory: join(work, 'data'),
    });
    // Capture trust independently of discovery; the recipient must not derive it
    // from the card or its fetched JWKS. Only public evidence leaves this process.
    const trustedRoot = Buffer.from(sender.getPublicKey()
      .replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64');
    assert.equal(trustedRoot.length, 2592);
    const expectedId = sender.agentId;
    const expectedVersion = JSON.parse(sender.exportAgent()).jacsVersion;
    const profile = {
      protocolVersion: '1.0', messagingUrl,
      skills: [{ id: 'sdk-report', name: 'Public JavaScript SDK report',
        description: 'Return exactly one pre-signed report', tags: ['provenance'] }],
      defaultInputModes: ['text/plain'], defaultOutputModes: ['application/json'],
    };
    assert.throws(() => buildWellKnownDocuments(sender, {
      protocolVersion: '1.0', messagingUrl,
    }), 'v1 must require caller skills and modes');
    assert.throws(() => buildWellKnownDocuments(sender, {
      ...profile, a2aAlgorithm: 'unsupported',
    }), 'Unsupported algorithms must not fall back');
    const documents = buildWellKnownDocuments(sender, profile);
    const repeated = buildWellKnownDocuments(sender, profile);
    assert.deepEqual(repeated[JWKS], documents[JWKS], 'Root key changes on repeated export');
    assert(!documents['/.well-known/jacs-compat-binding.json']);
    assert.equal(documents[CARD].supportedInterfaces[0].protocolVersion, '1.0');
    const report = (await sender.signMessage({ report: 'Synthetic café 雪', score: 7 })).raw;
    return { documents, trustedRoot: trustedRoot.toString('base64url'),
      expectedId, expectedVersion, report };
  } finally {
    sender.dispose();
    await rm(work, { recursive: true, force: true });
  }
}

async function trustedVerifier(jwk, trust) {
  assert.equal(jwk.kty, 'AKP');
  assert.equal(jwk.alg, 'ML-DSA-87');
  assert.equal(jwk.pub, trust.trustedRoot, 'JWKS is not the independently trusted root');
  const key = await importJWK(jwk, 'ML-DSA-87');
  const official = verifyAgentCardSignature(async (kid, jku) => {
    assert.equal(kid, jwk.kid, 'Unexpected kid');
    assert.equal(jku, undefined, 'Remote key retrieval is not authorized');
    return key;
  });
  return async (card) => {
    assert.equal(card.signatures.length, 1);
    const signature = card.signatures[0];
    assert(!signature.header || Object.keys(signature.header).length === 0);
    const header = JSON.parse(Buffer.from(signature.protected, 'base64url'));
    assert.deepEqual(header, { alg: 'ML-DSA-87', kid: jwk.kid, typ: 'JOSE' });
    const extensions = card.capabilities.extensions.filter(e => e.uri === EXTENSION);
    assert.equal(extensions.length, 1);
    assert.deepEqual(extensions[0].params, { jacsId: trust.expectedId,
      jacsVersion: trust.expectedVersion, jacsRootKid: jwk.kid });
    assert.equal(card.version, trust.expectedVersion);
    await official(card); // Stock SDK + jose + Node WebCrypto; no custom crypto verifier.
  };
}

async function expectRefusal(operation) {
  // The stock SDK logs entire signatures for expected negative vectors. Keep
  // diagnostics on unexpected failures while avoiding megabytes of test noise.
  const debug = console.debug;
  console.debug = (message, ...args) => {
    if (message !== 'Signature verification on entry was not successful:') debug(message, ...args);
  };
  try { await assert.rejects(operation); } finally { console.debug = debug; }
}

async function run() {
  const sdkPackage = JSON.parse(await readFile(join(dirname(require.resolve('@a2a-js/sdk')), '../package.json'), 'utf8'));
  assert.equal(sdkPackage.version, '1.3.0', 'Install the exact SDK lock');
  const app = express();
  app.disable('x-powered-by');
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  let requests = 0;
  const refused = [];
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const messagingUrl = `${origin}/a2a`;
    const generated = spawnSync(process.execPath,
      [fileURLToPath(import.meta.url), '--fixture', messagingUrl], {
        env: { ...process.env, JACS_USE_KEYCHAIN: 'false', JACS_ALLOW_NETWORK: 'false',
          JACS_ALLOW_REMOTE_KEY_LOOKUP: 'false', RUST_LOG: 'off' },
        encoding: 'utf8', timeout: 120_000, maxBuffer: LIMIT,
      });
    assert.equal(generated.status, 0, `Public JACS fixture failed: ${generated.stderr}`);
    const packet = JSON.parse(generated.stdout);
    const wire = packet.documents[CARD];
    const jwk = packet.documents[JWKS].keys[0];
    assert.equal(packet.documents[JWKS].keys.length, 1);
    const card = AgentCard.fromJSON(wire);
    const verify = await trustedVerifier(jwk, packet);
    await verify(card);
    assert.equal(card.supportedInterfaces[0].url, messagingUrl);
    assert.equal(card.supportedInterfaces[0].protocolVersion, '1.0');
    assert.equal(card.skills[0].id, 'sdk-report');
    const report = Buffer.from(packet.report);
    const executor = {
      async execute(context, eventBus) {
        assert.equal(++requests, 1, 'Finite host accepts one request');
        eventBus.publish(AgentEvent.task(Task.fromJSON({
          id: context.taskId, contextId: context.contextId,
          status: { state: 'TASK_STATE_COMPLETED' },
          artifacts: [{ artifactId: 'synthetic-report', extensions: [EXTENSION],
            parts: [{ raw: report.toString('base64'), mediaType: 'application/json', filename: 'report.jacs.json' }] }],
        })));
        eventBus.finished();
      },
      async cancelTask() { throw new Error('No live task to cancel'); },
    };
    const handler = new DefaultRequestHandler(card, new InMemoryTaskStore(), executor);
    for (const path of [CARD, JWKS]) {
      app.get(path, (_request, response) => response.set('Cache-Control', 'no-store').json(packet.documents[path]));
    }
    app.use('/a2a', jsonRpcHandler({ requestHandler: handler, userBuilder: UserBuilder.noAuthentication }));

    let untrustedRequests = 0;
    const untrustedCard = structuredClone(wire);
    untrustedCard.capabilities.extendedAgentCard = true;
    untrustedCard.supportedInterfaces[0].url = `${origin}/must-not-call`;
    app.get('/tampered-card.json', (_request, response) => response.json(untrustedCard));
    app.use('/must-not-call', (_request, response) => {
      ++untrustedRequests;
      response.sendStatus(500);
    });

    // Verify immediately after stock HTTP resolution, BEFORE transport selection
    // or getAgentCard (which can fetch an advertised extended card first).
    const resolver = new DefaultAgentCardResolver();
    const connect = async (path) => {
      const resolved = await resolver.resolve(origin, path);
      await verify(resolved);
      return { resolved, peer: await new ClientFactory().createFromAgentCard(resolved) };
    };
    await expectRefusal(() => connect('/tampered-card.json'));
    assert.equal(untrustedRequests, 0, 'Unverified endpoint or extended card was fetched');
    refused.push('unverified_interface_and_extended_card');
    const { resolved, peer } = await connect();
    assert.equal(canonicalizeAgentCard(resolved), canonicalizeAgentCard(card));
    const result = await peer.sendMessage({ message: Message.fromJSON({
      messageId: randomUUID(), role: 'ROLE_USER', parts: [{ text: 'Return the synthetic report' }],
    }) }, { signal: AbortSignal.timeout(10_000) });
    assert.equal(result.status.state, TaskState.TASK_STATE_COMPLETED);
    assert.equal(requests, 1);
    assert.equal(result.artifacts.length, 1);
    const part = result.artifacts[0].parts[0];
    assert.equal(part.content.$case, 'raw');
    assert.equal(part.mediaType, 'application/json');
    assert.deepEqual(Buffer.from(part.content.value), report, 'Artifact bytes changed');

    for (const name of ['content', 'signature', 'algorithm', 'key_reference']) {
      const altered = structuredClone(wire);
      if (name === 'content') altered.description += ' tampered';
      else if (name === 'signature') {
        const bytes = Buffer.from(altered.signatures[0].signature, 'base64url');
        bytes[0] ^= 1;
        altered.signatures[0].signature = bytes.toString('base64url');
      } else {
        const header = { alg: 'ML-DSA-87', kid: jwk.kid, typ: 'JOSE' };
        if (name === 'algorithm') header.alg = 'ES256';
        else header.jku = `${origin}/untrusted-key`;
        altered.signatures[0].protected = Buffer.from(JSON.stringify(header)).toString('base64url');
      }
      await expectRefusal(() => verify(AgentCard.fromJSON(altered)));
      refused.push(name);
    }
    const wrong = Buffer.from(packet.trustedRoot, 'base64url');
    wrong[0] ^= 1;
    await assert.rejects(() => trustedVerifier(jwk, { ...packet, trustedRoot: wrong.toString('base64url') }));
    refused.push('independent_root_mismatch');
    console.log(JSON.stringify({ sdk: '@a2a-js/sdk', sdkVersion: '1.3.0',
      node: process.versions.node, protocol: '1.0', algorithm: 'ML-DSA-87',
      publicBindingUsed: true, stockSdkSignatureVerified: true, returnedInterfaceCalled: true,
      artifactBytesPreserved: true, artifactSha256: createHash('sha256').update(report).digest('hex'),
      refused, privateIdentityRemovedBeforePeer: true }));
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

if (process.argv[2] === '--fixture') console.log(JSON.stringify(await fixture(process.argv[3])));
else await run();
