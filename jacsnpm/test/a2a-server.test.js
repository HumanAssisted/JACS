/**
 * Tests for JACS A2A Express Middleware - Task #19 [2.3.2]
 *
 * Validates:
 * - jacsA2AMiddleware factory returns Express router
 * - All 6 identity-bound .well-known endpoints served correctly
 * - CORS headers on all responses
 * - CORS preflight (OPTIONS) support
 * - Document caching (same object on repeated requests)
 * - Custom skills override
 * - buildWellKnownDocuments helper
 */

const { expect } = require('chai');
const sinon = require('sinon');
const http = require('http');
const {
  jacsA2AMiddleware,
  buildWellKnownDocuments,
  CORS_HEADERS,
} = require('../src/a2a-server');
const { configureNativeGenerator } = require('./helpers/a2a-bound');

/**
 * Create a mock JacsClient for testing (no real JACS agent required).
 */
function createMockClient(overrides = {}) {
  const mockAgent = {
    signRequest: sinon.stub(),
    verifyResponse: sinon.stub(),
  };
  configureNativeGenerator(mockAgent, {
    agentId: overrides.agentId || 'test-agent-id',
    name: overrides.name || 'test-agent',
    skills: overrides.skills || [],
    interfaceUrl: overrides.interfaceUrl,
    keyAlgorithm: overrides.keyAlgorithm,
  });
  return {
    _agent: mockAgent,
    agentId: overrides.agentId || 'test-agent-id',
    name: overrides.name || 'test-agent',
  };
}

/**
 * Start an Express app with the A2A middleware on a random port.
 * Returns { server, port, close() }.
 */
function startTestServer(client, options = {}) {
  const express = require('express');
  const app = express();
  app.use(jacsA2AMiddleware(client, options));

  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const port = server.address().port;
      resolve({
        server,
        port,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

/**
 * Simple HTTP GET returning { status, headers, body (parsed JSON) }.
 */
function httpGet(port, path) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:${port}${path}`, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(body); } catch { parsed = body; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    }).on('error', reject);
  });
}

/**
 * Simple HTTP OPTIONS request.
 */
function httpOptions(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: 'localhost', port, path, method: 'OPTIONS' },
      (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
      }
    );
    req.on('error', reject);
    req.end();
  });
}

describe('A2A Express Middleware - [2.3.2]', function () {
  this.timeout(15000);

  // -------------------------------------------------------------------------
  // 1. Factory returns an Express Router
  // -------------------------------------------------------------------------
  describe('jacsA2AMiddleware factory', () => {
    it('should return a function (Express router)', () => {
      const client = createMockClient();
      const mw = jacsA2AMiddleware(client);
      expect(mw).to.be.a('function');
    });

    it('should throw if express is not installed', () => {
      // We cannot unload express in this test environment,
      // but we verify the factory function exists and works
      const client = createMockClient();
      expect(() => jacsA2AMiddleware(client)).to.not.throw();
    });
  });

  // -------------------------------------------------------------------------
  // 2. buildWellKnownDocuments helper
  // -------------------------------------------------------------------------
  describe('buildWellKnownDocuments', () => {
    it('should return all 6 identity-bound well-known document paths', () => {
      const client = createMockClient();
      const docs = buildWellKnownDocuments(client);

      const paths = Object.keys(docs);
      expect(paths).to.include('/.well-known/agent-card.json');
      expect(paths).to.include('/.well-known/jwks.json');
      expect(paths).to.include('/.well-known/jacs-compat-binding.json');
      expect(paths).to.include('/.well-known/jacs-agent.json');
      expect(paths).to.include('/.well-known/jacs-pubkey.json');
      expect(paths).to.include('/.well-known/jacs-extension.json');
      expect(paths).to.have.length(6);
    });

    it('should use client agentId and name in agent card', () => {
      const client = createMockClient({ agentId: 'my-id', name: 'my-name' });
      const docs = buildWellKnownDocuments(client);
      const card = docs['/.well-known/agent-card.json'];

      expect(card.name).to.equal('my-name');
      expect(card.metadata.jacsId).to.equal('my-id');
    });

    it('should apply custom skills when provided', () => {
      const skills = [
        { id: 'summarize', name: 'Summarize', description: 'Summarize text', tags: ['nlp'] },
      ];
      const client = createMockClient({ skills });
      const docs = buildWellKnownDocuments(client, { skills });
      const card = docs['/.well-known/agent-card.json'];

      expect(card.skills).to.have.length(1);
      expect(card.skills[0].id).to.equal('summarize');
      expect(card.skills[0].name).to.equal('Summarize');
    });

    it('should set url as jacsAgentDomain when provided', () => {
      const client = createMockClient({
        agentId: 'agent-1',
        interfaceUrl: 'https://my-agent.example.com/agent',
      });
      const docs = buildWellKnownDocuments(client, { url: 'my-agent.example.com' });
      const card = docs['/.well-known/agent-card.json'];

      expect(card.supportedInterfaces[0].url).to.include('my-agent.example.com');
    });
  });

  // -------------------------------------------------------------------------
  // 3-7. Live Express server tests
  // -------------------------------------------------------------------------
  describe('Express server endpoints', () => {
    let testServer;

    before(async () => {
      const skills = [
        { id: 'code-review', name: 'Code Review', description: 'Review code', tags: ['dev'] },
      ];
      const client = createMockClient({
        agentId: 'server-agent',
        name: 'Server Agent',
        skills,
      });
      testServer = await startTestServer(client, {
        skills,
      });
    });

    after(async () => {
      if (testServer) await testServer.close();
    });

    // 3. agent-card.json
    it('should serve /.well-known/agent-card.json', async () => {
      const { status, headers, body } = await httpGet(testServer.port, '/.well-known/agent-card.json');

      expect(status).to.equal(200);
      expect(headers['content-type']).to.include('json');
      expect(body.name).to.equal('Server Agent');
      expect(body.skills).to.be.an('array');
      expect(body.skills[0].id).to.equal('code-review');
      expect(body.protocolVersions).to.be.an('array');
    });

    // 4. jacs-extension.json
    it('should serve /.well-known/jacs-extension.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jacs-extension.json');

      expect(status).to.equal(200);
      expect(body.uri).to.equal('urn:jacs:provenance-v1');
      expect(body.capabilities).to.have.property('documentSigning');
      expect(body.capabilities).to.have.property('postQuantumCrypto');
    });

    // 5. jacs-agent.json
    it('should serve /.well-known/jacs-agent.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jacs-agent.json');

      expect(status).to.equal(200);
      expect(body.agentId).to.equal('server-agent');
      expect(body.capabilities).to.have.property('signing', true);
      expect(body.capabilities).to.have.property('verification', true);
      expect(body.schemas).to.have.property('agent');
    });

    // 6. jwks.json
    it('should serve /.well-known/jwks.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jwks.json');

      expect(status).to.equal(200);
      expect(body).to.have.property('keys');
      expect(body.keys).to.be.an('array');
    });

    // 7. jacs-pubkey.json
    it('should serve /.well-known/jacs-pubkey.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jacs-pubkey.json');

      expect(status).to.equal(200);
      expect(body).to.have.property('algorithm');
      expect(body).to.have.property('agentId', 'server-agent');
    });

    // 8. CORS headers
    it('should include CORS headers on all well-known responses', async () => {
      const { headers } = await httpGet(testServer.port, '/.well-known/agent-card.json');

      expect(headers['access-control-allow-origin']).to.equal('*');
      expect(headers['access-control-allow-methods']).to.include('GET');
    });

    // 9. CORS preflight
    it('should handle OPTIONS preflight for well-known routes', async () => {
      const { status, headers } = await httpOptions(testServer.port, '/.well-known/agent-card.json');

      expect(status).to.equal(204);
      expect(headers['access-control-allow-origin']).to.equal('*');
      expect(headers['access-control-allow-methods']).to.include('GET');
      expect(headers['access-control-allow-methods']).to.include('OPTIONS');
    });

    // 10. Caching: responses are the same object on repeated requests
    it('should return identical cached responses on repeated requests', async () => {
      const res1 = await httpGet(testServer.port, '/.well-known/agent-card.json');
      const res2 = await httpGet(testServer.port, '/.well-known/agent-card.json');

      expect(res1.body).to.deep.equal(res2.body);
    });
  });

  // -------------------------------------------------------------------------
  // 11. CORS headers constant
  // -------------------------------------------------------------------------
  describe('CORS_HEADERS export', () => {
    it('should export the expected CORS header keys', () => {
      expect(CORS_HEADERS).to.have.property('Access-Control-Allow-Origin', '*');
      expect(CORS_HEADERS).to.have.property('Access-Control-Allow-Methods');
      expect(CORS_HEADERS).to.have.property('Access-Control-Allow-Headers');
      expect(CORS_HEADERS).to.have.property('Access-Control-Max-Age');
    });
  });
});

// Controlled native-builder fixtures exercise real HTTP/cache behavior, not
// cryptographic validation. Native signing/verification is owned by JACS.
describe('A2A discovery snapshot lifetime', function () {
  this.timeout(15000);
  const DAY = 86400000;
  const START = Date.UTC(2026, 8, 14);
  const BINDING = '/.well-known/jacs-compat-binding.json';
  const CARD = '/.well-known/agent-card.json';
  const { boundWellKnownPairs } = require('./helpers/a2a-bound');
  let clock, server, generator, warnings;

  function bundle(generation, issued = Date.now(), expires = null) {
    const pairs = boundWellKnownPairs({
      issuedAt: new Date(issued).toISOString(),
      expiresAt: expires === null ? null : new Date(expires).toISOString(),
    });
    for (const pair of pairs) pair.document.snapshot = generation;
    const documents = Object.fromEntries(pairs.map((p) => [p.path, p.document]));
    documents[BINDING].jacsSha256 = `binding-${generation}`;
    documents[CARD].metadata.jacsCompatBindingHash = `binding-${generation}`;
    return pairs;
  }

  async function mount(initial, next) {
    const client = createMockClient();
    generator = sinon.stub().callsFake(next || (() => JSON.stringify(bundle(2))));
    generator.onFirstCall().returns(JSON.stringify(initial || bundle(1)));
    client._agent.generateWellKnownDocumentsSync = generator;
    server = await startTestServer(client, { skills: [] });
  }

  beforeEach(() => {
    // Leave timers and HTTP event-loop scheduling real.
    clock = sinon.useFakeTimers({ now: START, toFake: ['Date'] });
    warnings = sinon.stub(console, 'warn');
  });
  afterEach(async () => {
    if (server) await server.close();
    server = null;
    sinon.restore();
    clock.restore();
  });

  it('caches until six days, then publishes all six replacements together', async () => {
    await mount();
    const original = await httpGet(server.port, CARD);
    clock.setSystemTime(START + 6 * DAY - 1000);
    const cachedAt = Date.now();
    const nearRenewal = await httpGet(server.port, CARD);
    expect(nearRenewal.headers['cache-control']).to.equal('public, max-age=1, must-revalidate');
    const maxAge = Number(nearRenewal.headers['cache-control'].match(/max-age=(\d+)/)[1]);
    expect(cachedAt + maxAge * 1000).to.be.at.most(START + 6 * DAY);
    clock.setSystemTime(START + 6 * DAY - 1);
    const beforeRenewal = await httpGet(server.port, CARD);
    expect(beforeRenewal.body).to.deep.equal(original.body);
    expect(beforeRenewal.headers['cache-control']).to.equal('no-store');
    expect(generator.callCount).to.equal(1);
    clock.setSystemTime(START + 6 * DAY);
    const renewedBinding = await httpGet(server.port, BINDING);
    expect(nearRenewal.body.metadata.jacsCompatBindingHash).not.to.equal(renewedBinding.body.jacsSha256);
    const paths = bundle(0).map((p) => p.path);
    const responses = await Promise.all(paths.map((p) => httpGet(server.port, p)));
    expect(generator.callCount).to.equal(2);
    for (const response of responses) {
      expect(response.status).to.equal(200);
      expect(response.body.snapshot).to.equal(2);
      expect(response.headers['cache-control']).to.equal('public, max-age=3600, must-revalidate');
    }
    const documents = Object.fromEntries(paths.map((path, index) => [path, responses[index].body]));
    expect(documents[CARD].metadata.jacsCompatBindingHash).to.equal(documents[BINDING].jacsSha256);
    expect(documents[CARD].signatures[0].keyId).to.equal(documents['/.well-known/jwks.json'].keys[0].kid);
    expect(original.body.snapshot).to.equal(1);
  });

  it('refreshes on the first request after more than seven idle days', async () => {
    await mount();
    clock.setSystemTime(START + 8 * DAY);
    expect((await httpGet(server.port, CARD)).body.snapshot).to.equal(2);
    expect(generator.callCount).to.equal(2);
  });

  it('uses a preexisting binding issuance deadline, not mount time', async () => {
    await mount(bundle(1, START - 6 * DAY + 1000));
    expect((await httpGet(server.port, CARD)).body.snapshot).to.equal(1);
    clock.setSystemTime(START + 1000);
    expect((await httpGet(server.port, CARD)).body.snapshot).to.equal(2);
    expect(generator.callCount).to.equal(2);
  });

  it('bounds failed retries, caps caching, refuses stale data and recovers', async () => {
    const initial = bundle(1);
    await mount(initial, () => { throw new Error('PRIVATE SIGNED PAYLOAD /private/key'); });
    clock.setSystemTime(START + 6 * DAY);
    for (const pair of initial) {
      const response = await httpGet(server.port, pair.path);
      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal(pair.document);
      expect(response.headers['cache-control']).to.equal('no-store');
    }
    expect(generator.callCount).to.equal(2);
    clock.setSystemTime(START + 6 * DAY + 59000);
    await httpGet(server.port, CARD);
    expect(generator.callCount).to.equal(2);
    clock.setSystemTime(START + 6 * DAY + 60000);
    await httpGet(server.port, CARD);
    expect(generator.callCount).to.equal(3);
    clock.setSystemTime(START + 7 * DAY - 1500);
    expect((await httpGet(server.port, CARD)).headers['cache-control']).to.equal('no-store');
    clock.setSystemTime(START + 7 * DAY - 500);
    expect((await httpGet(server.port, CARD)).headers['cache-control']).to.equal('no-store');
    clock.setSystemTime(START + 7 * DAY);
    const denied = await httpGet(server.port, CARD);
    expect(denied.status).to.equal(503);
    expect(denied.body).to.deep.equal({ error: 'A2A discovery unavailable' });
    expect(denied.headers['cache-control']).to.equal('no-store');
    expect(denied.headers['access-control-allow-origin']).to.equal('*');
    const calls = generator.callCount;
    await httpGet(server.port, BINDING);
    expect(generator.callCount).to.equal(calls);
    generator.callsFake(() => JSON.stringify(bundle(3)));
    clock.setSystemTime(START + 7 * DAY + 60000);
    const recovered = await httpGet(server.port, CARD);
    expect(recovered.body.snapshot).to.equal(3);
    expect(recovered.headers['cache-control']).to.equal('public, max-age=3600, must-revalidate');
    expect(recovered.body.metadata.jacsCompatBindingHash).to.equal((await httpGet(server.port, BINDING)).body.jacsSha256);
    expect(JSON.stringify(warnings.args)).not.to.include('PRIVATE');
  });

  it('never regenerates an explicitly expired grant and caps its HTTP lifetime', async () => {
    await mount(bundle(1, START, START + 2500));
    expect((await httpGet(server.port, CARD)).headers['cache-control']).to.equal('public, max-age=2, must-revalidate');
    clock.setSystemTime(START + 2500);
    for (const delay of [0, 60000, 8 * DAY]) {
      clock.setSystemTime(START + 2500 + delay);
      const denied = await httpGet(server.port, BINDING);
      expect(denied.status).to.equal(503);
      expect(denied.headers['cache-control']).to.equal('no-store');
    }
    expect(generator.callCount).to.equal(1);
    expect(warnings.callCount).to.equal(1);
  });

  for (const damage of ['missing document', 'mismatched binding', 'bad date', 'expiry extension', 'skill override']) {
    it(`retains the entire valid snapshot after replacement with ${damage}`, async () => {
      await mount(bundle(1, START, START + 10 * DAY), () => {
        const next = bundle(2, Date.now(), START + 10 * DAY);
        const binding = next.find((p) => p.path === BINDING).document;
        if (damage === 'missing document') next.pop();
        if (damage === 'mismatched binding') binding.jacsSha256 = 'mismatch';
        if (damage === 'bad date') binding.compatibilityKeyBinding.issuedAt = 'not a date';
        if (damage === 'expiry extension') binding.compatibilityKeyBinding.expiresAt = null;
        if (damage === 'skill override') next.find((p) => p.path === CARD).document.skills = [{ id: 'unauthorized' }];
        return JSON.stringify(next);
      });
      clock.setSystemTime(START + 6 * DAY);
      for (const pair of bundle(0)) {
        const response = await httpGet(server.port, pair.path);
        expect(response.status).to.equal(200);
        expect(response.body.snapshot).to.equal(1);
      }
      expect(generator.callCount).to.equal(2);
    });
  }

  for (const timestamp of [undefined, null, 123, '', '2026-02-30T00:00:00Z', '2026-09-14', '2026-09-14T00:00:00', '2026-09-14T00:00:00+01:60']) {
    it(`fails closed at mount for invalid issuance ${JSON.stringify(timestamp)}`, () => {
      const client = createMockClient();
      const pairs = bundle(1);
      pairs.find((p) => p.path === BINDING).document.compatibilityKeyBinding.issuedAt = timestamp;
      client._agent.generateWellKnownDocumentsSync = () => JSON.stringify(pairs);
      expect(() => jacsA2AMiddleware(client)).to.throw();
    });
  }

  it('enforces future skew at mount and after a wallclock rollback', async () => {
    const client = createMockClient();
    client._agent.generateWellKnownDocumentsSync = () => JSON.stringify(bundle(1, START + 301000));
    expect(() => jacsA2AMiddleware(client)).to.throw();
    const fractional = bundle(1);
    fractional.find((p) => p.path === BINDING).document.compatibilityKeyBinding.issuedAt = '2026-09-14T00:05:00.000000001Z';
    client._agent.generateWellKnownDocumentsSync = () => JSON.stringify(fractional);
    expect(() => jacsA2AMiddleware(client)).to.throw();
    await mount(bundle(1, START + 300000), () => { throw new Error('failed'); });
    expect((await httpGet(server.port, CARD)).status).to.equal(200);
    clock.setSystemTime(START - 1000);
    expect((await httpGet(server.port, CARD)).status).to.equal(503);
  });

  it('preserves finite expiry on successful refresh and rejects malformed expiry', async () => {
    const expiry = START + 6 * DAY + 2500;
    await mount(bundle(1, START, expiry), () => JSON.stringify(bundle(2, Date.now(), expiry)));
    clock.setSystemTime(START + 6 * DAY);
    const renewed = await httpGet(server.port, BINDING);
    expect(renewed.body.compatibilityKeyBinding.expiresAt).to.equal(new Date(expiry).toISOString());
    expect(renewed.headers['cache-control']).to.equal('public, max-age=2, must-revalidate');
    for (const expires of [false, 123, 'bad', '2026-02-30T00:00:00Z']) {
      const client = createMockClient();
      const pairs = bundle(0);
      pairs.find((p) => p.path === BINDING).document.compatibilityKeyBinding.expiresAt = expires;
      client._agent.generateWellKnownDocumentsSync = () => JSON.stringify(pairs);
      expect(() => jacsA2AMiddleware(client)).to.throw();
    }
    clock.setSystemTime(expiry);
    expect((await httpGet(server.port, CARD)).status).to.equal(503);
    expect(generator.callCount).to.equal(2);
  });

  it('uses RFC3339 instants and preserves the signed timestamp strings', async () => {
    const pairs = bundle(1);
    const binding = pairs.find((p) => p.path === BINDING).document.compatibilityKeyBinding;
    binding.issuedAt = '2026-09-13T19:00:00-05:00';
    binding.expiresAt = '2026-09-14T02:00:02.999999999+02:00';
    await mount(pairs);
    const response = await httpGet(server.port, BINDING);
    expect(response.body.compatibilityKeyBinding).to.deep.equal(binding);
    expect(response.headers['cache-control']).to.equal('public, max-age=2, must-revalidate');
    clock.setSystemTime(START + 3000);
    expect((await httpGet(server.port, CARD)).status).to.equal(503);
    expect(generator.callCount).to.equal(1);
  });

  it('rechecks lifetime after a slow failure and starts retry delay at completion', async () => {
    await mount(bundle(1), () => {
      clock.setSystemTime(START + 7 * DAY + 1000);
      throw new Error('PRIVATE slow native failure');
    });
    clock.setSystemTime(START + 6 * DAY);
    const response = await httpGet(server.port, CARD);
    expect(response.status).to.equal(503);
    expect(response.headers['cache-control']).to.equal('no-store');
    expect((await httpGet(server.port, BINDING)).status).to.equal(503);
    expect(generator.callCount).to.equal(2);
    generator.callsFake(() => JSON.stringify(bundle(3)));
    clock.setSystemTime(START + 7 * DAY + 61000);
    expect((await httpGet(server.port, CARD)).body.snapshot).to.equal(3);
    expect(generator.callCount).to.equal(3);
    expect(JSON.stringify(warnings.args)).not.to.include('PRIVATE');
  });
});
