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

    (available ? it : it.skip)('should verify parsed JSON object bodies', async () => {
      const client = createMockClient({
        verifyResult: {
          valid: true,
          data: { from: 'parsed-body' },
          signerId: 'agent-abc',
          timestamp: '2025-06-01T00:00:00Z',
          attachments: [],
          errors: [],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({ client, verify: true });

      const parsedBody = { jacsId: 'x', jacsSignature: {}, content: { ok: true } };
      const ctx = mockCtx({ method: 'POST', request: { body: parsedBody } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.calledOnce).to.be.true;
      expect(client.verify.firstCall.args[0]).to.equal(JSON.stringify(parsedBody));
      expect(ctx.state.jacsPayload).to.deep.equal({ from: 'parsed-body' });
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

    (available ? it : it.skip)('should return 401 for invalid parsed object body when optional is false', async () => {
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

      const parsedBody = { bad: 'data' };
      const ctx = mockCtx({ method: 'POST', request: { body: parsedBody } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.calledOnce).to.be.true;
      expect(client.verify.firstCall.args[0]).to.equal(JSON.stringify(parsedBody));
      expect(ctx.status).to.equal(401);
      expect(ctx.body).to.have.property('error', 'JACS verification failed');
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

  // ---- Auth replay protection (opt-in) ----

  describe('authReplay', () => {
    (available ? it : it.skip)('should reject replayed signed requests when enabled', async () => {
      const nowIso = new Date().toISOString();
      const client = createMockClient({
        verifyResult: {
          valid: true,
          data: { action: 'pay', amount: 100 },
          signerId: 'agent-replay',
          timestamp: nowIso,
          attachments: [],
          errors: [],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({
        client,
        authReplay: { enabled: true, maxAgeSeconds: 360000, clockSkewSeconds: 5 },
      });

      const replayBody = JSON.stringify({
        jacsId: 'doc-replay:1',
        jacsSignature: {
          agentID: 'agent-replay',
          date: nowIso,
          signature: 'same-signature',
        },
        content: { action: 'pay', amount: 100 },
      });

      const ctx1 = mockCtx({ method: 'POST', request: { body: replayBody } });
      const next1 = mockNext();
      await mw(ctx1, next1);
      expect(ctx1.status).to.equal(200);
      expect(next1.calledOnce).to.be.true;

      const ctx2 = mockCtx({ method: 'POST', request: { body: replayBody } });
      const next2 = mockNext();
      await mw(ctx2, next2);
      expect(ctx2.status).to.equal(401);
      expect(ctx2.body).to.have.property('error', 'JACS verification failed');
      expect(String(ctx2.body.details?.[0] || '')).to.include('replay');
      expect(next2.called).to.be.false;
    });

    (available ? it : it.skip)('should reject expired timestamps when enabled', async () => {
      const client = createMockClient({
        verifyResult: {
          valid: true,
          data: { action: 'expired' },
          signerId: 'agent-expired',
          timestamp: '2020-01-01T00:00:00Z',
          attachments: [],
          errors: [],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({
        client,
        authReplay: { enabled: true, maxAgeSeconds: 30, clockSkewSeconds: 0 },
      });

      const expiredBody = JSON.stringify({
        jacsId: 'doc-expired:1',
        jacsSignature: {
          agentID: 'agent-expired',
          date: '2020-01-01T00:00:00Z',
          signature: 'expired-signature',
        },
        content: { action: 'expired' },
      });

      const ctx = mockCtx({ method: 'POST', request: { body: expiredBody } });
      const next = mockNext();
      await mw(ctx, next);
      expect(ctx.status).to.equal(401);
      expect(String(ctx.body?.details?.[0] || '')).to.include('expired');
      expect(next.called).to.be.false;
    });

    (available ? it : it.skip)('should reject future timestamps beyond skew when enabled', async () => {
      const futureIso = new Date(Date.now() + 60_000).toISOString();
      const client = createMockClient({
        verifyResult: {
          valid: true,
          data: { action: 'future' },
          signerId: 'agent-future',
          timestamp: futureIso,
          attachments: [],
          errors: [],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({
        client,
        authReplay: { enabled: true, maxAgeSeconds: 60, clockSkewSeconds: 0 },
      });

      const body = JSON.stringify({
        jacsId: 'doc-future:1',
        jacsSignature: {
          agentID: 'agent-future',
          date: futureIso,
          signature: 'future-signature',
        },
        content: { action: 'future' },
      });

      const ctx = mockCtx({ method: 'POST', request: { body } });
      const next = mockNext();
      await mw(ctx, next);

      expect(ctx.status).to.equal(401);
      expect(String(ctx.body?.details?.[0] || '')).to.include('future');
      expect(next.called).to.be.false;
    });

    (available ? it : it.skip)('should allow duplicate signed requests when disabled', async () => {
      const client = createMockClient({
        verifyResult: {
          valid: true,
          data: { action: 'duplicate-ok' },
          signerId: 'agent-dup',
          timestamp: '2025-06-01T00:00:00Z',
          attachments: [],
          errors: [],
        },
      });
      const mw = koaModule.jacsKoaMiddleware({ client, authReplay: false });

      const body = JSON.stringify({
        jacsId: 'doc-dup:1',
        jacsSignature: {
          agentID: 'agent-dup',
          date: '2025-06-01T00:00:00Z',
          signature: 'dup-signature',
        },
        content: { action: 'duplicate-ok' },
      });

      const ctx1 = mockCtx({ method: 'POST', request: { body } });
      const next1 = mockNext();
      await mw(ctx1, next1);

      const ctx2 = mockCtx({ method: 'POST', request: { body } });
      const next2 = mockNext();
      await mw(ctx2, next2);

      expect(ctx1.status).to.equal(200);
      expect(ctx2.status).to.equal(200);
      expect(next1.calledOnce).to.be.true;
      expect(next2.calledOnce).to.be.true;
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
    (available ? it : it.skip)('should verify parsed object bodies on POST', async () => {
      const client = createMockClient();
      const mw = koaModule.jacsKoaMiddleware({ client, optional: false });

      const parsedBody = { parsed: true };
      const ctx = mockCtx({ method: 'POST', request: { body: parsedBody } });
      const next = mockNext();

      await mw(ctx, next);

      expect(client.verify.calledOnce).to.be.true;
      expect(client.verify.firstCall.args[0]).to.equal(JSON.stringify(parsedBody));
      expect(next.calledOnce).to.be.true;
    });
  });
});
