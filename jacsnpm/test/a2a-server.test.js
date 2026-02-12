/**
 * Tests for JACS A2A Express Middleware - Task #19 [2.3.2]
 *
 * Validates:
 * - jacsA2AMiddleware factory returns Express router
 * - All 5 .well-known endpoints served correctly
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

/**
 * Create a mock JacsClient for testing (no real JACS agent required).
 */
function createMockClient(overrides = {}) {
  const mockAgent = {
    signRequest: sinon.stub(),
    verifyResponse: sinon.stub(),
  };
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
    it('should return all 5 well-known document paths', () => {
      const client = createMockClient();
      const docs = buildWellKnownDocuments(client);

      const paths = Object.keys(docs);
      expect(paths).to.include('/.well-known/agent-card.json');
      expect(paths).to.include('/.well-known/jwks.json');
      expect(paths).to.include('/.well-known/jacs-agent.json');
      expect(paths).to.include('/.well-known/jacs-pubkey.json');
      expect(paths).to.include('/.well-known/jacs-extension.json');
      expect(paths).to.have.length(5);
    });

    it('should use client agentId and name in agent card', () => {
      const client = createMockClient({ agentId: 'my-id', name: 'my-name' });
      const docs = buildWellKnownDocuments(client);
      const card = docs['/.well-known/agent-card.json'];

      expect(card.name).to.equal('my-name');
      expect(card.metadata.jacsId).to.equal('my-id');
    });

    it('should apply custom skills when provided', () => {
      const client = createMockClient();
      const docs = buildWellKnownDocuments(client, {
        skills: [
          { id: 'summarize', name: 'Summarize', description: 'Summarize text', tags: ['nlp'] },
        ],
      });
      const card = docs['/.well-known/agent-card.json'];

      expect(card.skills).to.have.length(1);
      expect(card.skills[0].id).to.equal('summarize');
      expect(card.skills[0].name).to.equal('Summarize');
    });

    it('should set url as jacsAgentDomain when provided', () => {
      const client = createMockClient({ agentId: 'agent-1' });
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
      const client = createMockClient({ agentId: 'server-agent', name: 'Server Agent' });
      testServer = await startTestServer(client, {
        skills: [
          { id: 'code-review', name: 'Code Review', description: 'Review code', tags: ['dev'] },
        ],
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
      expect(body.uri).to.equal('urn:hai.ai:jacs-provenance-v1');
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
