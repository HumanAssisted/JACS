/**
 * Tests for JACS Koa Middleware
 *
 * Uses mock Koa context objects and a stubbed JacsClient.
 * No real Koa server is started.
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

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function mockCtx(overrides = {}) {
  const ctx = {
    method: 'GET',
    status: 200,
    body: undefined,
    type: '',
    state: {},
    request: {
      method: 'GET',
      body: undefined,
      ...overrides.request,
    },
    ...overrides,
  };
  // Sync request.method with ctx.method
  ctx.request.method = ctx.method;
  return ctx;
}

function mockNext(fn) {
  if (fn) return sinon.spy(fn);
  return sinon.stub().resolves();
}

/** Create a stubbed JacsClient with configurable behavior. */
function createMockClient(options = {}) {
  const signedRaw = JSON.stringify({
    jacsId: 'mock-doc-id:1',
    jacsSignature: { agentID: 'mock-agent', date: '2025-01-01T00:00:00Z' },
    content: options.signContent || { signed: true },
  });

  const verifyResult = options.verifyResult || {
    valid: true,
    data: { message: 'hello' },
    signerId: 'agent-123',
    timestamp: '2025-01-01T00:00:00Z',
    attachments: [],
    errors: [],
  };

  return {
    signMessage: sinon.stub().resolves({
      raw: signedRaw,
      documentId: 'mock-doc-id:1',
      agentId: 'mock-agent',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    verify: sinon.stub().resolves(verifyResult),
    agentId: 'mock-agent',
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('JACS Koa Middleware', function () {
  this.timeout(10000);

  const available = koaModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping Koa middleware tests - koa.js not compiled');
      this.skip();
    }
  });

  // ---- 1. Factory returns a function ----

  describe('factory', () => {
    (available ? it : it.skip)('jacsKoaMiddleware() returns a function', () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client });
      expect(mw).to.be.a('function');
    });

    (available ? it : it.skip)('returned middleware has arity 2 (ctx, next)', () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client });
      expect(mw.length).to.equal(2);
    });
  });

  // ---- 2. ctx.state.jacsClient is set ----

  describe('ctx.state.jacsClient', () => {
    (available ? it : it.skip)('should attach jacsClient to ctx.state on GET', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client });

      const ctx = mockCtx({ method: 'GET' });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.state.jacsClient).to.equal(client);
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should attach jacsClient to ctx.state on POST', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false });

      const ctx = mockCtx({ method: 'POST', request: { body: 'some body' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.state.jacsClient).to.equal(client);
      expect(next.calledOnce).to.be.true;
    });
  });

  // ---- 3. verify: true verifies incoming signed POST body ----

  describe('verify: true (default)', () => {
    (available ? it : it.skip)('should verify incoming POST body and set ctx.state.jacsPayload', async () => {
      const client = createMockClient({
        verifyResult: {
          valid: true,
          data: { action: 'approve', amount: 100 },
          signerId: 'agent-abc',
          timestamp: '2025-06-01T00:00:00Z',
          attachments: [],
          errors: [],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({ client, verify: true });

      const signedBody = JSON.stringify({ jacsId: 'x', jacsSignature: {}, content: {} });
      const ctx = mockCtx({ method: 'POST', request: { body: signedBody } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.calledOnce).to.be.true;
      expect(client.verify.firstCall.args[0]).to.equal(signedBody);
      expect(ctx.state.jacsPayload).to.deep.equal({ action: 'approve', amount: 100 });
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should verify PUT requests', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client });

      const signedBody = '{"jacsId":"x"}';
      const ctx = mockCtx({ method: 'PUT', request: { body: signedBody } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.calledOnce).to.be.true;
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should verify PATCH requests', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client });

      const ctx = mockCtx({ method: 'PATCH', request: { body: '{"data":1}' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should NOT verify GET requests', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client });

      const ctx = mockCtx({ method: 'GET' });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.called).to.be.false;
      expect(next.calledOnce).to.be.true;
    });
  });

  // ---- 4. 401 on invalid signature when optional: false ----

  describe('invalid signature handling', () => {
    (available ? it : it.skip)('should return 401 for invalid signature when optional is false', async () => {
      const client = createMockClient({
        verifyResult: {
          valid: false,
          signerId: '',
          timestamp: '',
          attachments: [],
          errors: ['Signature mismatch'],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({ client, optional: false });

      const ctx = mockCtx({ method: 'POST', request: { body: '{"bad":"data"}' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.status).to.equal(401);
      expect(ctx.body).to.have.property('error', 'JACS verification failed');
      expect(ctx.body.details).to.include('Signature mismatch');
      expect(next.called).to.be.false;
    });

    (available ? it : it.skip)('should return 401 when verify() throws', async () => {
      const client = createMockClient();
      client.verify = sinon.stub().rejects(new Error('Crypto failure'));
      const mw = koaModule.jacsKoaMiddleware({ client, optional: false });

      const ctx = mockCtx({ method: 'POST', request: { body: '{"data":1}' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.status).to.equal(401);
      expect(next.called).to.be.false;
    });
  });

  // ---- 5. optional: true passes through unsigned requests ----

  describe('optional: true', () => {
    (available ? it : it.skip)('should pass through when verification fails and optional is true', async () => {
      const client = createMockClient({
        verifyResult: {
          valid: false,
          signerId: '',
          timestamp: '',
          attachments: [],
          errors: ['Invalid signature'],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({ client, optional: true });

      const ctx = mockCtx({ method: 'POST', request: { body: '{"unsigned":"data"}' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.state.jacsPayload).to.be.undefined;
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should pass through when verify() throws and optional is true', async () => {
      const client = createMockClient();
      client.verify = sinon.stub().rejects(new Error('Boom'));
      const mw = koaModule.jacsKoaMiddleware({ client, optional: true });

      const ctx = mockCtx({ method: 'POST', request: { body: '{"data":1}' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.state.jacsPayload).to.be.undefined;
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should still set jacsPayload when verification succeeds and optional is true', async () => {
      const client = createMockClient({
        verifyResult: {
          valid: true,
          data: { ok: true },
          signerId: 'agent-x',
          timestamp: '',
          attachments: [],
          errors: [],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({ client, optional: true });

      const ctx = mockCtx({ method: 'POST', request: { body: '{"signed":"data"}' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.state.jacsPayload).to.deep.equal({ ok: true });
      expect(next.calledOnce).to.be.true;
    });
  });

  // ---- 6. verify: false skips verification ----

  describe('verify: false', () => {
    (available ? it : it.skip)('should skip verification entirely', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false });

      const ctx = mockCtx({ method: 'POST', request: { body: '{"anything":"here"}' } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.called).to.be.false;
      expect(ctx.state.jacsPayload).to.be.undefined;
      expect(next.calledOnce).to.be.true;
    });
  });

  // ---- 7. sign: true auto-signs response body ----

  describe('sign: true (auto-sign)', () => {
    (available ? it : it.skip)('should auto-sign ctx.body after next() when body is an object', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false, sign: true });

      const ctx = mockCtx({ method: 'GET' });
      // Simulate downstream middleware setting ctx.body
      const next = mockNext(async () => {
        ctx.body = { status: 'ok', data: 42 };
      });

      await mw(ctx, next);

      expect(client.signMessage.calledOnce).to.be.true;
      expect(client.signMessage.firstCall.args[0]).to.deep.equal({ status: 'ok', data: 42 });
      // ctx.body should now be the signed raw string
      expect(typeof ctx.body).to.equal('string');
      const parsed = JSON.parse(ctx.body);
      expect(parsed).to.have.property('jacsSignature');
    });

    (available ? it : it.skip)('should set content type to application/json after signing', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false, sign: true });

      const ctx = mockCtx({ method: 'GET' });
      const next = mockNext(async () => {
        ctx.body = { result: true };
      });

      await mw(ctx, next);

      expect(ctx.type).to.equal('application/json');
    });

    (available ? it : it.skip)('should NOT sign when body is a string', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false, sign: true });

      const ctx = mockCtx({ method: 'GET' });
      const next = mockNext(async () => {
        ctx.body = 'plain text response';
      });

      await mw(ctx, next);

      expect(client.signMessage.called).to.be.false;
      expect(ctx.body).to.equal('plain text response');
    });

    (available ? it : it.skip)('should NOT sign when body is null/undefined', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false, sign: true });

      const ctx = mockCtx({ method: 'GET' });
      const next = mockNext(async () => {
        ctx.body = null;
      });

      await mw(ctx, next);

      expect(client.signMessage.called).to.be.false;
    });

    (available ? it : it.skip)('should NOT sign when body is a Buffer', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false, sign: true });

      const ctx = mockCtx({ method: 'GET' });
      const next = mockNext(async () => {
        ctx.body = Buffer.from('binary data');
      });

      await mw(ctx, next);

      expect(client.signMessage.called).to.be.false;
    });

    (available ? it : it.skip)('should NOT override body when sign is false (default)', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false }); // sign defaults to false

      const ctx = mockCtx({ method: 'GET' });
      const responseObj = { untouched: true };
      const next = mockNext(async () => {
        ctx.body = responseObj;
      });

      await mw(ctx, next);

      expect(client.signMessage.called).to.be.false;
      expect(ctx.body).to.equal(responseObj);
    });

    (available ? it : it.skip)('should leave body intact if signing fails', async () => {
      const client = createMockClient();
      client.signMessage = sinon.stub().rejects(new Error('Sign failed'));
      const mw = koaModule.jacsKoaMiddleware({ client, verify: false, sign: true });

      const ctx = mockCtx({ method: 'GET' });
      const originalBody = { keep: 'me' };
      const next = mockNext(async () => {
        ctx.body = originalBody;
      });

      await mw(ctx, next);

      // Body should remain untouched on sign failure
      expect(ctx.body).to.equal(originalBody);
    });
  });

  // ---- 8. Works with pre-initialized JacsClient ----

  describe('pre-initialized client', () => {
    (available ? it : it.skip)('should use the provided client instance directly', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client });

      const signedBody = '{"jacsId":"x","content":"hello"}';
      const ctx = mockCtx({ method: 'POST', request: { body: signedBody } });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.state.jacsClient).to.equal(client);
      expect(client.verify.calledOnce).to.be.true;
    });
  });

  // ---- 9. JACS initialization failure ----

  describe('initialization failure', () => {
    (available ? it : it.skip)('should return 500 if client resolution fails', async () => {
      const mw = koaModule.jacsKoaMiddleware({ client: undefined, configPath: '/nonexistent/config.json' });

      const ctx = mockCtx({ method: 'GET' });
      const next = mockNext();

      await mw(ctx, next);

      expect(ctx.status).to.equal(500);
      expect(ctx.body).to.have.property('error', 'JACS initialization failed');
      expect(next.called).to.be.false;
    });
  });

  // ---- 10. Non-string body on POST ----

  describe('non-string body', () => {
    (available ? it : it.skip)('should call next when POST body is an object (not string)', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, optional: false });

      const ctx = mockCtx({ method: 'POST', request: { body: { parsed: true } } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.called).to.be.false;
      expect(next.calledOnce).to.be.true;
    });
  });
});
