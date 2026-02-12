/**
 * Tests for Express middleware A2A well-known route injection - Task #39 [2.9.1]
 *
 * Validates:
 * - a2a: true enables well-known endpoints
 * - All 5 well-known documents are served
 * - CORS headers on responses
 * - OPTIONS preflight handling
 * - a2aSkills and a2aUrl options
 * - a2a: false (default) does not serve well-known routes
 * - Caching (same content on repeated requests)
 */

const { expect } = require('chai');
const sinon = require('sinon');
const http = require('http');
const express = require('express');

// The compiled middleware
let expressModule;
try {
  expressModule = require('../express.js');
} catch (e) {
  expressModule = null;
}

/**
 * Create a stubbed JacsClient.
 */
function createMockClient(overrides = {}) {
  return {
    signMessage: sinon.stub().resolves({ raw: '{}', documentId: 'x', agentId: 'a', timestamp: '' }),
    verify: sinon.stub().resolves({ valid: true, data: {}, signerId: '', timestamp: '', attachments: [], errors: [] }),
    agentId: overrides.agentId || 'express-a2a-agent',
    name: overrides.name || 'Express A2A Agent',
    _agent: { signRequest: sinon.stub(), verifyResponse: sinon.stub() },
  };
}

/**
 * Start an Express app on a random port with the given middleware.
 */
function startServer(middleware) {
  const app = express();
  app.use(middleware);
  // Add a fallback route to verify non-well-known requests still work
  app.get('/api/health', (_req, res) => res.json({ ok: true }));
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const port = server.address().port;
      resolve({ server, port, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

/**
 * HTTP GET helper.
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
 * HTTP OPTIONS helper.
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

describe('Express Middleware A2A Route Injection - [2.9.1]', function () {
  this.timeout(15000);

  const available = expressModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping - express.js not compiled');
      this.skip();
    }
  });

  // -------------------------------------------------------------------------
  // 1. a2a: true serves well-known endpoints
  // -------------------------------------------------------------------------
  describe('a2a: true', () => {
    let testServer;

    before(async function () {
      if (!available) this.skip();
      const client = createMockClient({ agentId: 'a2a-agent-1', name: 'A2A Test Agent' });
      const mw = expressModule.jacsMiddleware({
        client,
        verify: false,
        a2a: true,
        a2aSkills: [{ id: 'code-gen', name: 'Code Generation', description: 'Generate code', tags: ['dev'] }],
        a2aUrl: 'my-agent.example.com',
      });
      testServer = await startServer(mw);
    });

    after(async () => {
      if (testServer) await testServer.close();
    });

    it('should serve /.well-known/agent-card.json', async () => {
      const { status, headers, body } = await httpGet(testServer.port, '/.well-known/agent-card.json');

      expect(status).to.equal(200);
      expect(headers['content-type']).to.include('json');
      expect(body.name).to.equal('A2A Test Agent');
      expect(body.skills).to.be.an('array');
      expect(body.skills[0].id).to.equal('code-gen');
    });

    it('should serve /.well-known/jacs-extension.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jacs-extension.json');

      expect(status).to.equal(200);
      expect(body.uri).to.equal('urn:hai.ai:jacs-provenance-v1');
    });

    it('should serve /.well-known/jacs-agent.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jacs-agent.json');

      expect(status).to.equal(200);
      expect(body.agentId).to.equal('a2a-agent-1');
    });

    it('should serve /.well-known/jwks.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jwks.json');

      expect(status).to.equal(200);
      expect(body).to.have.property('keys');
    });

    it('should serve /.well-known/jacs-pubkey.json', async () => {
      const { status, body } = await httpGet(testServer.port, '/.well-known/jacs-pubkey.json');

      expect(status).to.equal(200);
      expect(body.agentId).to.equal('a2a-agent-1');
    });

    it('should include CORS headers on well-known responses', async () => {
      const { headers } = await httpGet(testServer.port, '/.well-known/agent-card.json');

      expect(headers['access-control-allow-origin']).to.equal('*');
      expect(headers['access-control-allow-methods']).to.include('GET');
    });

    it('should handle OPTIONS preflight', async () => {
      const { status, headers } = await httpOptions(testServer.port, '/.well-known/agent-card.json');

      expect(status).to.equal(204);
      expect(headers['access-control-allow-origin']).to.equal('*');
    });

    it('should still pass non-well-known requests through', async () => {
      const { status, body } = await httpGet(testServer.port, '/api/health');

      expect(status).to.equal(200);
      expect(body).to.deep.equal({ ok: true });
    });

    it('should return cached content on repeated requests', async () => {
      const res1 = await httpGet(testServer.port, '/.well-known/agent-card.json');
      const res2 = await httpGet(testServer.port, '/.well-known/agent-card.json');

      expect(res1.body).to.deep.equal(res2.body);
    });
  });

  // -------------------------------------------------------------------------
  // 2. a2a: false (default) does NOT serve well-known
  // -------------------------------------------------------------------------
  describe('a2a: false (default)', () => {
    let testServer;

    before(async function () {
      if (!available) this.skip();
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client, verify: false });
      testServer = await startServer(mw);
    });

    after(async () => {
      if (testServer) await testServer.close();
    });

    it('should NOT serve well-known endpoints when a2a is not enabled', async () => {
      const { status } = await httpGet(testServer.port, '/.well-known/agent-card.json');

      // Without a2a, the middleware calls next() and Express returns 404
      expect(status).to.equal(404);
    });
  });
});
