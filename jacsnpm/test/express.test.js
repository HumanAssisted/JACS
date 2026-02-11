/**
 * Tests for JACS Express Middleware
 *
 * Uses mock req/res/next objects and a stubbed JacsClient.
 * No real Express server is started.
 */

const { expect } = require('chai');
const sinon = require('sinon');

// The compiled middleware — skip entire suite if not compiled yet.
let expressModule;
try {
  expressModule = require('../express.js');
} catch (e) {
  expressModule = null;
}

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function mockReq(overrides = {}) {
  return {
    method: 'GET',
    body: undefined,
    headers: {},
    ...overrides,
  };
}

function mockRes() {
  const res = {
    statusCode: 200,
    _headers: {},
    _body: undefined,
    _jsonBody: undefined,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(body) {
      res._jsonBody = body;
      return res;
    },
    send(body) {
      res._body = body;
      return res;
    },
    set(key, val) {
      res._headers[key.toLowerCase()] = val;
      return res;
    },
    type(val) {
      res._headers['content-type'] = val;
      return res;
    },
    headersSent: false,
  };
  return res;
}

function mockNext() {
  const fn = sinon.stub();
  return fn;
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

describe('JACS Express Middleware', function () {
  this.timeout(10000);

  const available = expressModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping Express middleware tests - express.js not compiled');
      this.skip();
    }
  });

  // ---- 1. Factory returns a function ----

  describe('factory', () => {
    (available ? it : it.skip)('jacsMiddleware() returns a function', () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });
      expect(mw).to.be.a('function');
    });

    (available ? it : it.skip)('returned middleware has arity 3 (req, res, next)', () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });
      // Async functions still have a .length reflecting declared params
      expect(mw.length).to.equal(3);
    });
  });

  // ---- 2. req.jacsClient is set ----

  describe('req.jacsClient', () => {
    (available ? it : it.skip)('should attach jacsClient to req on GET', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });

      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(req.jacsClient).to.equal(client);
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should attach jacsClient to req on POST', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client, verify: false });

      const req = mockReq({ method: 'POST', body: 'some body' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(req.jacsClient).to.equal(client);
      expect(next.calledOnce).to.be.true;
    });
  });

  // ---- 3. verify: true verifies incoming signed POST body ----

  describe('verify: true (default)', () => {
    (available ? it : it.skip)('should verify incoming POST body and set req.jacsPayload', async () => {
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
      const mw = expressModule.jacsMiddleware({ client, verify: true });

      const signedBody = JSON.stringify({ jacsId: 'x', jacsSignature: {}, content: {} });
      const req = mockReq({ method: 'POST', body: signedBody });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(client.verify.calledOnce).to.be.true;
      expect(client.verify.firstCall.args[0]).to.equal(signedBody);
      expect(req.jacsPayload).to.deep.equal({ action: 'approve', amount: 100 });
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should verify PUT requests too', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });

      const signedBody = '{"jacsId":"x"}';
      const req = mockReq({ method: 'PUT', body: signedBody });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(client.verify.calledOnce).to.be.true;
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should verify PATCH requests too', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });

      const req = mockReq({ method: 'PATCH', body: '{"data":1}' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(client.verify.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should NOT verify GET requests', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });

      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

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
      const mw = expressModule.jacsMiddleware({ client, optional: false });

      const req = mockReq({ method: 'POST', body: '{"bad":"data"}' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(res.statusCode).to.equal(401);
      expect(res._jsonBody).to.have.property('error', 'JACS verification failed');
      expect(res._jsonBody.details).to.include('Signature mismatch');
      expect(next.called).to.be.false;
    });

    (available ? it : it.skip)('should return 401 when verify() throws', async () => {
      const client = createMockClient();
      client.verify = sinon.stub().rejects(new Error('Crypto failure'));
      const mw = expressModule.jacsMiddleware({ client, optional: false });

      const req = mockReq({ method: 'POST', body: '{"data":1}' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(res.statusCode).to.equal(401);
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
      const mw = expressModule.jacsMiddleware({ client, optional: true });

      const req = mockReq({ method: 'POST', body: '{"unsigned":"data"}' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(req.jacsPayload).to.be.undefined;
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should pass through when verify() throws and optional is true', async () => {
      const client = createMockClient();
      client.verify = sinon.stub().rejects(new Error('Boom'));
      const mw = expressModule.jacsMiddleware({ client, optional: true });

      const req = mockReq({ method: 'POST', body: '{"data":1}' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(req.jacsPayload).to.be.undefined;
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
      const mw = expressModule.jacsMiddleware({ client, optional: true });

      const req = mockReq({ method: 'POST', body: '{"signed":"data"}' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(req.jacsPayload).to.deep.equal({ ok: true });
      expect(next.calledOnce).to.be.true;
    });
  });

  // ---- 6. verify: false skips verification ----

  describe('verify: false', () => {
    (available ? it : it.skip)('should skip verification entirely', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client, verify: false });

      const req = mockReq({ method: 'POST', body: '{"anything":"here"}' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(client.verify.called).to.be.false;
      expect(req.jacsPayload).to.be.undefined;
      expect(next.calledOnce).to.be.true;
    });
  });

  // ---- 7. sign: true auto-signs JSON responses ----

  describe('sign: true (auto-sign)', () => {
    (available ? it : it.skip)('should override res.json to auto-sign', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client, verify: false, sign: true });

      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      const originalJson = res.json;
      const next = mockNext();

      await mw(req, res, next);

      // res.json should be replaced
      expect(res.json).to.not.equal(originalJson);
      expect(res.json).to.be.a('function');
    });

    (available ? it : it.skip)('auto-signed res.json should call client.signMessage', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client, verify: false, sign: true });

      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      // Capture what gets passed to the original json
      const sentBodies = [];
      const origJson = res.json.bind(res);
      res.json = function (b) { return origJson(b); };
      const next = mockNext();

      await mw(req, res, next);

      // Now call the overridden res.json
      const result = res.json({ status: 'ok' });

      // Should return res for chaining
      expect(result).to.equal(res);

      // Wait for async signing to complete
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(client.signMessage.calledOnce).to.be.true;
      expect(client.signMessage.firstCall.args[0]).to.deep.equal({ status: 'ok' });
    });

    (available ? it : it.skip)('should NOT override res.json when sign is false (default)', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client, verify: false }); // sign defaults to false

      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      const originalJson = res.json;
      const next = mockNext();

      await mw(req, res, next);

      expect(res.json).to.equal(originalJson);
    });
  });

  // ---- 8. Works with pre-initialized JacsClient ----

  describe('pre-initialized client', () => {
    (available ? it : it.skip)('should use the provided client instance directly', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });

      const signedBody = '{"jacsId":"x","content":"hello"}';
      const req = mockReq({ method: 'POST', body: signedBody });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      // Should use the exact same client instance
      expect(req.jacsClient).to.equal(client);
      expect(client.verify.calledOnce).to.be.true;
    });
  });

  // ---- 9. JACS initialization failure ----

  describe('initialization failure', () => {
    (available ? it : it.skip)('should return 500 if client resolution fails', async () => {
      // Provide no client and a bad configPath that will fail
      // We simulate this by providing a broken configPath option and mocking the import
      // Instead, we create a middleware with a configPath but the client module will fail
      // For this test, we directly test the error branch by patching the promise

      const mw = expressModule.jacsMiddleware({ client: undefined, configPath: '/nonexistent/config.json' });

      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(res.statusCode).to.equal(500);
      expect(res._jsonBody).to.have.property('error', 'JACS initialization failed');
      expect(next.called).to.be.false;
    });
  });

  // ---- 10. Non-string body on POST ----

  describe('non-string body', () => {
    (available ? it : it.skip)('should call next when POST body is an object (not string)', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client, optional: false });

      const req = mockReq({ method: 'POST', body: { parsed: true } });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      // Body is not a string, so verify is not called but next is still called
      expect(client.verify.called).to.be.false;
      expect(next.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should call next when POST has no body', async () => {
      const client = createMockClient();
      const mw = expressModule.jacsMiddleware({ client });

      const req = mockReq({ method: 'POST' });
      const res = mockRes();
      const next = mockNext();

      await mw(req, res, next);

      expect(client.verify.called).to.be.false;
      expect(next.calledOnce).to.be.true;
    });
  });
});
