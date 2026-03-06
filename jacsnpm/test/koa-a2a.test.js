/**
 * Tests for Koa middleware A2A well-known route injection - Task #40 [2.9.2]
 *
 * Validates:
 * - a2a: true enables well-known endpoints via mock Koa context
 * - All 5 well-known documents are served
 * - CORS headers on responses
 * - OPTIONS preflight handling
 * - a2a: false (default) does not intercept well-known routes
 * - Caching (same content on repeated requests)
 */

const { expect } = require('chai');
const sinon = require('sinon');

// The compiled middleware — skip entire suite if not compiled yet.
let koaModule;
try {
  koaModule = require('../koa.js');
} catch (e) {
  koaModule = null;
}

/**
 * Create a stubbed JacsClient.
 */
function createMockClient(overrides = {}) {
  return {
    signMessage: sinon.stub().resolves({ raw: '{}', documentId: 'x', agentId: 'a', timestamp: '' }),
    verify: sinon.stub().resolves({ valid: true, data: {}, signerId: '', timestamp: '', attachments: [], errors: [] }),
    agentId: overrides.agentId || 'koa-a2a-agent',
    name: overrides.name || 'Koa A2A Agent',
    _agent: { signRequest: sinon.stub(), verifyResponse: sinon.stub() },
  };
}

/**
 * Create a mock Koa context for a given method and path.
 */
function mockCtx(method, path) {
  const headers = {};
  return {
    method,
    path,
    status: 200,
    body: undefined,
    type: '',
    state: {},
    request: { method, body: undefined },
    set(field, value) { headers[field.toLowerCase()] = value; },
    _headers: headers,
  };
}

function mockNext() {
  return sinon.stub().resolves();
}

const WELL_KNOWN_PATHS = [
  '/.well-known/agent-card.json',
  '/.well-known/jacs-extension.json',
  '/.well-known/jacs-agent.json',
  '/.well-known/jwks.json',
  '/.well-known/jacs-pubkey.json',
];

describe('Koa Middleware A2A Route Injection - [2.9.2]', function () {
  this.timeout(15000);

  const available = koaModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping - koa.js not compiled');
      this.skip();
    }
  });

  // -------------------------------------------------------------------------
  // 1. a2a: true serves well-known endpoints
  // -------------------------------------------------------------------------
  describe('a2a: true', () => {
    let mw;

    before(function () {
      if (!available) this.skip();
      const client = createMockClient({ agentId: 'koa-agent-1', name: 'Koa A2A Test' });
      mw = koaModule.jacsKoaMiddleware({
        client,
        verify: false,
        a2a: true,
        a2aSkills: [{ id: 'summarize', name: 'Summarize', description: 'Summarize text', tags: ['nlp'] }],
        a2aUrl: 'koa-agent.example.com',
      });
    });

    it('should serve /.well-known/agent-card.json', async () => {
      const ctx = mockCtx('GET', '/.well-known/agent-card.json');
      const next = mockNext();

      await mw(ctx, next);

      expect(next.called).to.be.false;
      expect(ctx.body).to.be.an('object');
      expect(ctx.body.name).to.equal('Koa A2A Test');
      expect(ctx.body.skills).to.be.an('array');
      expect(ctx.body.skills[0].id).to.equal('summarize');
      expect(ctx.type).to.equal('application/json');
    });

    it('should serve all 5 well-known documents', async () => {
      for (const path of WELL_KNOWN_PATHS) {
        const ctx = mockCtx('GET', path);
        const next = mockNext();

        await mw(ctx, next);

        expect(next.called).to.be.false;
        expect(ctx.body).to.not.be.undefined;
        expect(ctx.type).to.equal('application/json');
      }
    });

    it('should include CORS headers on well-known responses', async () => {
      const ctx = mockCtx('GET', '/.well-known/agent-card.json');
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx._headers['access-control-allow-origin']).to.equal('*');
      expect(ctx._headers['access-control-allow-methods']).to.include('GET');
      expect(ctx._headers['access-control-allow-headers']).to.include('Content-Type');
      expect(ctx._headers['access-control-max-age']).to.equal('86400');
    });

    it('should handle OPTIONS preflight', async () => {
      const ctx = mockCtx('OPTIONS', '/.well-known/agent-card.json');
      const next = mockNext();

      await mw(ctx, next);

      expect(next.called).to.be.false;
      expect(ctx.status).to.equal(204);
      expect(ctx._headers['access-control-allow-origin']).to.equal('*');
    });

    it('should pass non-well-known requests through to next()', async () => {
      const ctx = mockCtx('GET', '/api/health');
      const next = mockNext();

      await mw(ctx, next);

      expect(next.calledOnce).to.be.true;
    });

    it('should return cached content on repeated requests', async () => {
      const ctx1 = mockCtx('GET', '/.well-known/jacs-extension.json');
      const ctx2 = mockCtx('GET', '/.well-known/jacs-extension.json');
      const next1 = mockNext();
      const next2 = mockNext();

      await mw(ctx1, next1);
      await mw(ctx2, next2);

      expect(ctx1.body).to.deep.equal(ctx2.body);
    });
  });

  // -------------------------------------------------------------------------
  // 2. a2a: false (default) does NOT intercept well-known
  // -------------------------------------------------------------------------
  describe('a2a: false (default)', () => {
    it('should NOT intercept well-known endpoints when a2a is not enabled', async function () {
      if (!available) this.skip();

      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false });

      const ctx = mockCtx('GET', '/.well-known/agent-card.json');
      const next = mockNext();

      await mw(ctx, next);

      // Without a2a, middleware calls next() — body stays undefined
      expect(next.calledOnce).to.be.true;
      expect(ctx.body).to.be.undefined;
    });
  });
});
