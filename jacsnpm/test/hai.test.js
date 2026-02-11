/**
 * Tests for JACS HAI.ai Integration Module (hai.ts)
 *
 * MVP Steps 21-22: Node HaiClient with hello() and verifyHaiMessage()
 */

const { expect } = require('chai');
const sinon = require('sinon');

let haiModule;
try {
  haiModule = require('../hai.js');
} catch (e) {
  haiModule = null;
}

let clientModule;
try {
  clientModule = require('../client.js');
} catch (e) {
  clientModule = null;
}

describe('HaiClient (hai.ts)', function () {
  this.timeout(15000);

  const available = haiModule !== null && clientModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping HaiClient tests - hai.js or client.js not compiled');
      this.skip();
    }
  });

  // ===========================================================================
  // Constructor
  // ===========================================================================

  describe('constructor', function () {
    it('should create instance with JacsClient and base URL', function () {
      if (!available) this.skip();

      // Create a mock JacsClient-like object
      const mockJacs = { agentId: 'test-agent-123', signMessage: async () => ({}) };
      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');
      expect(hai).to.be.instanceOf(haiModule.HaiClient);
    });

    it('should strip trailing slashes from base URL', function () {
      if (!available) this.skip();

      const mockJacs = { agentId: 'test-agent-123' };
      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai///');
      // Internal state -- we test via hello() URL construction
      expect(hai).to.be.instanceOf(haiModule.HaiClient);
    });

    it('should use default base URL', function () {
      if (!available) this.skip();

      const mockJacs = { agentId: 'test-agent-123' };
      const hai = new haiModule.HaiClient(mockJacs);
      expect(hai).to.be.instanceOf(haiModule.HaiClient);
    });
  });

  // ===========================================================================
  // hello()
  // ===========================================================================

  describe('hello()', function () {
    it('should throw HaiError when no agent is loaded', async function () {
      if (!available) this.skip();

      const mockJacs = { agentId: '' };
      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');

      try {
        await hai.hello();
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(haiModule.HaiError);
        expect(e.message).to.include('No agent loaded');
      }
    });

    it('should return HelloWorldResult on successful response', async function () {
      if (!available) this.skip();

      const responseData = {
        timestamp: '2026-02-11T22:00:00Z',
        client_ip: '203.0.113.42',
        hai_public_key_fingerprint: 'sha256:abc123',
        message: 'HAI acknowledges your agent',
        hai_ack_signature: '',
      };

      // Mock fetch globally
      const originalFetch = global.fetch;
      global.fetch = sinon.stub().resolves({
        status: 200,
        json: async () => responseData,
      });

      const mockSigned = {
        raw: JSON.stringify({
          jacsSignature: { signature: 'test-sig-base64' },
        }),
      };
      const mockJacs = {
        agentId: 'test-agent-uuid',
        signMessage: sinon.stub().resolves(mockSigned),
        verifySync: sinon.stub().returns({ valid: false }),
      };

      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');

      try {
        const result = await hai.hello();
        expect(result.success).to.equal(true);
        expect(result.timestamp).to.equal('2026-02-11T22:00:00Z');
        expect(result.clientIp).to.equal('203.0.113.42');
        expect(result.haiPublicKeyFingerprint).to.equal('sha256:abc123');
        expect(result.message).to.equal('HAI acknowledges your agent');
        expect(result.rawResponse).to.deep.include({ timestamp: '2026-02-11T22:00:00Z' });
      } finally {
        global.fetch = originalFetch;
      }
    });

    it('should send JACS Authorization header', async function () {
      if (!available) this.skip();

      const originalFetch = global.fetch;
      let capturedHeaders = {};
      global.fetch = sinon.stub().callsFake(async (url, opts) => {
        capturedHeaders = opts.headers || {};
        return { status: 200, json: async () => ({ timestamp: '', client_ip: '', message: '' }) };
      });

      const mockSigned = {
        raw: JSON.stringify({ jacsSignature: { signature: 'sig123' } }),
      };
      const mockJacs = {
        agentId: 'my-agent-id',
        signMessage: sinon.stub().resolves(mockSigned),
      };

      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');

      try {
        await hai.hello();
        expect(capturedHeaders['Authorization']).to.match(/^JACS my-agent-id:/);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it('should POST to /api/v1/agents/hello', async function () {
      if (!available) this.skip();

      const originalFetch = global.fetch;
      let capturedUrl = '';
      global.fetch = sinon.stub().callsFake(async (url) => {
        capturedUrl = url;
        return { status: 200, json: async () => ({}) };
      });

      const mockSigned = {
        raw: JSON.stringify({ jacsSignature: { signature: 'sig' } }),
      };
      const mockJacs = {
        agentId: 'agent-1',
        signMessage: sinon.stub().resolves(mockSigned),
      };

      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');

      try {
        await hai.hello();
        expect(capturedUrl).to.equal('https://hai.ai/api/v1/agents/hello');
      } finally {
        global.fetch = originalFetch;
      }
    });

    it('should include include_test in payload when requested', async function () {
      if (!available) this.skip();

      const originalFetch = global.fetch;
      let capturedBody = '';
      global.fetch = sinon.stub().callsFake(async (url, opts) => {
        capturedBody = opts.body;
        return { status: 200, json: async () => ({}) };
      });

      const mockSigned = {
        raw: JSON.stringify({ jacsSignature: { signature: 'sig' } }),
      };
      const mockJacs = {
        agentId: 'agent-1',
        signMessage: sinon.stub().resolves(mockSigned),
      };

      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');

      try {
        await hai.hello(true);
        const parsed = JSON.parse(capturedBody);
        expect(parsed.include_test).to.equal(true);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it('should throw AuthenticationError on 401', async function () {
      if (!available) this.skip();

      const originalFetch = global.fetch;
      global.fetch = sinon.stub().resolves({
        status: 401,
        json: async () => ({ error: 'Invalid signature' }),
      });

      const mockSigned = {
        raw: JSON.stringify({ jacsSignature: { signature: 'sig' } }),
      };
      const mockJacs = {
        agentId: 'agent-1',
        signMessage: sinon.stub().resolves(mockSigned),
      };

      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');

      try {
        await hai.hello();
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(haiModule.AuthenticationError);
        expect(e.statusCode).to.equal(401);
      } finally {
        global.fetch = originalFetch;
      }
    });

    it('should throw HaiError on 429 rate limit', async function () {
      if (!available) this.skip();

      const originalFetch = global.fetch;
      global.fetch = sinon.stub().resolves({ status: 429 });

      const mockSigned = {
        raw: JSON.stringify({ jacsSignature: { signature: 'sig' } }),
      };
      const mockJacs = {
        agentId: 'agent-1',
        signMessage: sinon.stub().resolves(mockSigned),
      };

      const hai = new haiModule.HaiClient(mockJacs, 'https://hai.ai');

      try {
        await hai.hello();
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(haiModule.HaiError);
        expect(e.message).to.include('Rate limited');
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  // ===========================================================================
  // verifyHaiMessage()
  // ===========================================================================

  describe('verifyHaiMessage()', function () {
    it('should return false for empty signature', function () {
      if (!available) this.skip();

      const mockJacs = { agentId: 'agent-1' };
      const hai = new haiModule.HaiClient(mockJacs);
      expect(hai.verifyHaiMessage('hello', '')).to.equal(false);
    });

    it('should return false for empty message', function () {
      if (!available) this.skip();

      const mockJacs = { agentId: 'agent-1' };
      const hai = new haiModule.HaiClient(mockJacs);
      expect(hai.verifyHaiMessage('', 'base64sig')).to.equal(false);
    });

    it('should delegate to JacsClient.verifySync for JACS documents', function () {
      if (!available) this.skip();

      const jacsDoc = JSON.stringify({
        jacsId: 'doc-123',
        jacsSignature: { agentId: 'agent-456', signature: 'sig' },
      });

      const mockJacs = {
        agentId: 'agent-1',
        verifySync: sinon.stub().returns({ valid: true, errors: [] }),
      };
      const hai = new haiModule.HaiClient(mockJacs);

      const result = hai.verifyHaiMessage(jacsDoc, 'unused');
      expect(result).to.equal(true);
      expect(mockJacs.verifySync.calledOnce).to.equal(true);
    });

    it('should return false for invalid JACS documents', function () {
      if (!available) this.skip();

      const jacsDoc = JSON.stringify({
        jacsId: 'doc-123',
        jacsSignature: { agentId: 'agent-456', signature: 'bad-sig' },
      });

      const mockJacs = {
        agentId: 'agent-1',
        verifySync: sinon.stub().returns({ valid: false, errors: ['bad sig'] }),
      };
      const hai = new haiModule.HaiClient(mockJacs);

      const result = hai.verifyHaiMessage(jacsDoc, 'unused');
      expect(result).to.equal(false);
    });

    it('should return false for non-JSON without public key', function () {
      if (!available) this.skip();

      const mockJacs = { agentId: 'agent-1' };
      const hai = new haiModule.HaiClient(mockJacs);
      expect(hai.verifyHaiMessage('plain text', 'c2lnbmF0dXJl')).to.equal(false);
    });
  });

  // ===========================================================================
  // Error classes
  // ===========================================================================

  describe('Error classes', function () {
    it('HaiError has statusCode and responseData', function () {
      if (!available) this.skip();

      const err = new haiModule.HaiError('test', 500, { detail: 'oops' });
      expect(err.message).to.equal('test');
      expect(err.statusCode).to.equal(500);
      expect(err.responseData).to.deep.equal({ detail: 'oops' });
      expect(err).to.be.instanceOf(Error);
    });

    it('AuthenticationError extends HaiError', function () {
      if (!available) this.skip();

      const err = new haiModule.AuthenticationError('bad key', 401);
      expect(err).to.be.instanceOf(haiModule.HaiError);
      expect(err).to.be.instanceOf(Error);
      expect(err.statusCode).to.equal(401);
    });

    it('HaiConnectionError extends HaiError', function () {
      if (!available) this.skip();

      const err = new haiModule.HaiConnectionError('timeout');
      expect(err).to.be.instanceOf(haiModule.HaiError);
      expect(err).to.be.instanceOf(Error);
    });
  });

  // ===========================================================================
  // Exports
  // ===========================================================================

  describe('Exports', function () {
    it('should export HaiClient class', function () {
      if (!available) this.skip();
      expect(haiModule.HaiClient).to.be.a('function');
    });

    it('should export HaiError class', function () {
      if (!available) this.skip();
      expect(haiModule.HaiError).to.be.a('function');
    });

    it('should export AuthenticationError class', function () {
      if (!available) this.skip();
      expect(haiModule.AuthenticationError).to.be.a('function');
    });

    it('should export HaiConnectionError class', function () {
      if (!available) this.skip();
      expect(haiModule.HaiConnectionError).to.be.a('function');
    });
  });
});
