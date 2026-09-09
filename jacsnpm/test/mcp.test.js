/**
 * Tests for JACS MCP Transport Proxy
 *
 * Tests the JACSTransportProxy which wraps MCP transports with
 * JACS signing (outgoing) and verification (incoming).
 */

const { expect } = require('chai');
const sinon = require('sinon');
const path = require('path');

const fs = require('fs');
const NATIVE_FIXTURES_DIR = path.resolve(__dirname, '../../jacs/tests/scratch');
const NATIVE_TEST_CONFIG = path.join(NATIVE_FIXTURES_DIR, 'jacs.config.json');
// The shared scratch fixtures are gitignored and absent on CI runners.
const nativeFixturesExist = fs.existsSync(NATIVE_TEST_CONFIG);

let mcpModule;
let NativeJacsAgent;
try {
  mcpModule = require('../mcp.js');
  ({ JacsAgent: NativeJacsAgent } = require('../index.js'));
} catch (e) {
  mcpModule = null;
  NativeJacsAgent = null;
}

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function createMockTransport() {
  return {
    start: sinon.stub().resolves(),
    close: sinon.stub().resolves(),
    send: sinon.stub().resolves(),
    onmessage: null,
    onclose: null,
    onerror: null,
    sessionId: 'test-session-123',
    url: 'http://localhost:9999/sse',
  };
}

function createSignedEnvelope(overrides = {}) {
  const { jacsSignature: signatureOverrides = {}, ...documentOverrides } = overrides;
  return JSON.stringify({
    jacsId: 'doc-1',
    jacsVersion: 'document-version-1',
    jacsSignature: {
      agentID: 'agent-a',
      agentVersion: 'agent-version-1',
      date: '2026-07-10T00:00:00Z',
      publicKeyHash: 'public-key-hash-1',
      signature: 'signed-envelope-bytes',
      signatureContentVersion: 'jacs-signature-v2',
      ...signatureOverrides,
    },
    ...documentOverrides,
  });
}

function createCarrier(envelope = createSignedEnvelope()) {
  return {
    jsonrpc: '2.0',
    method: 'notifications/jacs/signed',
    params: { version: 1, envelope },
  };
}

function createMockAgent() {
  return {
    signRequest: sinon.stub().returns(createSignedEnvelope()),
    verifyResponse: sinon.stub().returns({ jsonrpc: '2.0', id: 1, result: { status: 'ok' } }),
    verifyResponseWithAgentId: sinon.stub().returns({
      agent_id: 'agent-a',
      payload: { jsonrpc: '2.0', id: 1, result: { status: 'ok' } },
    }),
    load: sinon.stub().resolves('loaded'),
    // Make it look like a JacsAgent instance to extractNativeAgent
    constructor: { name: 'JacsAgent' },
  };
}

function createMockJacsClient(agent) {
  // JacsClient has a private `agent` field accessed at runtime
  const mockAgent = agent || createMockAgent();
  return {
    agent: mockAgent,
    agentId: 'client-agent-123',
    name: 'test-client',
    strict: false,
    signMessage: sinon.stub().resolves({
      raw: '{"jacsId":"doc-1:1","content":"signed"}',
      documentId: 'doc-1:1',
      agentId: 'client-agent-123',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    verify: sinon.stub().resolves({
      valid: true, signerId: 'agent-b',
      timestamp: '2025-01-01T00:00:00Z',
      data: { key: 'value' }, errors: [],
    }),
    verifyById: sinon.stub().resolves({ valid: true, errors: [] }),
    verifySelf: sinon.stub().resolves({ valid: true, signerId: 'client-agent-123', errors: [] }),
    createAgreement: sinon.stub().resolves({
      raw: '{"jacsId":"agr-1:1"}',
      documentId: 'agr-1:1', agentId: 'client-agent-123',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    signAgreement: sinon.stub().resolves({
      raw: '{"jacsId":"agr-1:2"}',
      documentId: 'agr-1:2', agentId: 'client-agent-123',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    checkAgreement: sinon.stub().resolves({ complete: true, signedCount: 2, totalRequired: 2 }),
    audit: sinon.stub().resolves({ status: 'ok', documents: 5 }),
    signFile: sinon.stub().resolves({
      raw: '{"jacsId":"file-1:1"}',
      documentId: 'file-1:1', agentId: 'client-agent-123',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    trustAgent: sinon.stub().returns('trusted'),
    trustAgentWithKey: sinon.stub().returns('trusted-with-key'),
    listTrustedAgents: sinon.stub().returns(['agent-a', 'agent-b']),
    getTrustedAgent: sinon.stub().returns('{"jacsId":"agent-a","jacsVersion":"v1"}'),
    untrustAgent: sinon.stub().returns(),
    isTrusted: sinon.stub().returns(true),
    exportAgentCard: sinon.stub().returns({ name: 'test-agent', capabilities: {} }),
    signArtifact: sinon.stub().resolves({ jacsId: 'artifact-1', a2aArtifact: { task: 'test' } }),
    verifyArtifact: sinon.stub().resolves({ valid: true, signerId: 'agent-b', artifactType: 'task' }),
    getA2A: sinon.stub().returns({
      assessRemoteAgent: sinon.stub().returns({
        allowed: true,
        trustLevel: 'Verified',
        jacsRegistered: true,
        inTrustStore: false,
        reason: 'ok',
      }),
    }),
    sharePublicKey: sinon.stub().returns('-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----'),
    shareAgent: sinon.stub().returns('{"jacsId":"client-agent-123","jacsVersion":"v1"}'),
    // Inline-text + media verbs (REVIEW_001 — MCP arms must call these on
    // the JacsClient, NOT on the native JacsAgent which does not have them).
    signText: sinon.stub().resolves({
      path: '/base/file.md',
      signersAdded: 1,
      backupPath: '/base/file.md.bak',
    }),
    verifyText: sinon.stub().resolves({
      status: 'signed',
      signatures: [{ signerId: 'agent-b', status: 'Valid' }],
    }),
    signImage: sinon.stub().resolves({
      outPath: '/base/out.png',
      signerId: 'client-agent-123',
      format: 'png',
      robust: false,
    }),
    verifyImage: sinon.stub().resolves({
      status: 'signed',
      signerId: 'agent-b',
      format: 'png',
    }),
    extractMediaSignature: sinon.stub().resolves('{"jacsId":"img-1:1"}'),
  };
}

function createRoundTripAgent(agentId = 'agent-a') {
  let sequence = 0;
  const seen = new Set();
  return {
    signRequest: sinon.spy((message) => createSignedEnvelope({
      jacsId: `roundtrip-${++sequence}`,
      content: message,
    })),
    verifyResponseWithAgentId: sinon.spy((envelope) => {
      const document = JSON.parse(envelope);
      if (document.jacsSignature.signature !== 'signed-envelope-bytes') {
        throw new Error('tampered signature');
      }
      if (seen.has(document.jacsId)) {
        throw new Error('replay detected');
      }
      seen.add(document.jacsId);
      return { agent_id: agentId, payload: document.content };
    }),
  };
}

function createInMemoryTransportPair() {
  const left = createMockTransport();
  const right = createMockTransport();
  left.send.callsFake(async (message) => {
    if (right.onmessage) right.onmessage(message);
  });
  right.send.callsFake(async (message) => {
    if (left.onmessage) left.onmessage(message);
  });
  return { left, right };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('JACSTransportProxy', function () {
  this.timeout(10000);

  const available = mcpModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping MCP tests - mcp.js not compiled');
      this.skip();
    }
  });

  // -------------------------------------------------------------------------
  // Constructor
  // -------------------------------------------------------------------------

  describe('constructor', () => {
    (available ? it : it.skip)('should accept a JacsAgent-like object and wrap transport', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      // Duck-type as JacsAgent by making instanceof check pass via prototype trick
      // Since we can't easily fake instanceof, use the extractNativeAgent path
      // by making the object instanceof JacsAgent. Instead, we pass it as if
      // it were a JacsClient with an .agent field, since that's the fallback.
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      expect(proxy).to.have.property('send');
      expect(proxy).to.have.property('start');
      expect(proxy).to.have.property('close');
    });

    (available ? it : it.skip)('should accept a JacsClient-like object', () => {
      const transport = createMockTransport();
      const client = createMockJacsClient();

      const proxy = new mcpModule.JACSTransportProxy(transport, client, 'client');
      expect(proxy).to.have.property('send');
    });

    (available ? it : it.skip)('should throw if JacsClient has no loaded agent', () => {
      const transport = createMockTransport();
      const client = { agent: null, agentId: '' };

      expect(() => {
        new mcpModule.JACSTransportProxy(transport, client, 'server');
      }).to.throw(/no loaded agent/i);
    });

    (available ? it : it.skip)('should set up onmessage on the wrapped transport', () => {
      const transport = createMockTransport();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });

      expect(transport.onmessage).to.be.a('function');
    });

    (available ? it : it.skip)('should forward onclose from wrapped transport', () => {
      const transport = createMockTransport();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });

      const closeSpy = sinon.spy();
      proxy.onclose = closeSpy;

      // Trigger onclose on the wrapped transport
      transport.onclose();

      expect(closeSpy.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should forward onerror from wrapped transport', () => {
      const transport = createMockTransport();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });

      const errorSpy = sinon.spy();
      proxy.onerror = errorSpy;

      transport.onerror(new Error('test error'));

      expect(errorSpy.calledOnce).to.be.true;
      expect(errorSpy.firstCall.args[0].message).to.equal('test error');
    });

    (available ? it : it.skip)('should forward sessionId from wrapped transport', () => {
      const transport = createMockTransport();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });

      expect(proxy.sessionId).to.equal('test-session-123');
    });

    (available ? it : it.skip)('should reject remote transports in local-only mode by default', () => {
      const transport = createMockTransport();
      transport.url = 'https://remote.example.com/sse';

      expect(() => {
        new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });
      }).to.throw(/local mode only/i);
    });

    (available ? it : it.skip)('should reject attempts to disable local-only mode', () => {
      const transport = createMockTransport();

      expect(() => {
        new mcpModule.JACSTransportProxy(
          transport,
          { agent: createMockAgent() },
          'server',
          { localOnly: false },
        );
      }).to.throw(/disabling local-only mode is not allowed/i);
    });

    (available ? it : it.skip)('should reject env-based attempts to disable local-only mode', () => {
      const transport = createMockTransport();
      const original = process.env.JACS_MCP_LOCAL_ONLY;
      process.env.JACS_MCP_LOCAL_ONLY = 'false';
      try {
        expect(() => {
          new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });
        }).to.throw(/disabling local-only mode is not allowed/i);
      } finally {
        if (typeof original === 'undefined') {
          delete process.env.JACS_MCP_LOCAL_ONLY;
        } else {
          process.env.JACS_MCP_LOCAL_ONLY = original;
        }
      }
    });

    (available ? it : it.skip)('should reject truthy non-boolean any-signer opt-ins', () => {
      for (const malformed of ['true', 1, {}, []]) {
        expect(() => new mcpModule.JACSTransportProxy(
          createMockTransport(),
          { agent: createMockAgent() },
          'server',
          { dangerouslyAllowAnyValidSigner: malformed },
        )).to.throw(/dangerouslyAllowAnyValidSigner.*boolean/i);
      }
    });

    (available ? it : it.skip)('should reject ambiguous or malformed peer identity policies', () => {
      const cases = [
        { expectedPeerAgentId: '' },
        { expectedPeerAgentId: ' agent-a' },
        { allowedPeerAgentIds: [] },
        { allowedPeerAgentIds: ['agent-a', 'agent-a'] },
        { expectedPeerAgentId: 'agent-a', allowedPeerAgentIds: ['agent-a'] },
        { expectedPeerAgentId: 'agent-a', dangerouslyAllowAnyValidSigner: true },
        { expectedPeerPublicKeyHash: 'hash-without-peer' },
      ];
      for (const options of cases) {
        expect(() => new mcpModule.JACSTransportProxy(
          createMockTransport(),
          { agent: createMockAgent() },
          'server',
          options,
        )).to.throw(/peer|signer|public key hash/i);
      }
    });
  });

  // -------------------------------------------------------------------------
  // send()
  // -------------------------------------------------------------------------

  describe('send()', () => {
    (available ? it : it.skip)('should sign outgoing messages via signRequest', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.signRequest.returns(createSignedEnvelope({ jacsId: 'doc-2' }));

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const message = { jsonrpc: '2.0', method: 'tools/list', id: 1 };
      await proxy.send(message);

      expect(agent.signRequest.calledOnce).to.be.true;
      expect(transport.send.calledOnce).to.be.true;
      expect(transport.send.firstCall.args[0]).to.deep.equal(
        createCarrier(createSignedEnvelope({ jacsId: 'doc-2' })),
      );
    });

    (available ? it : it.skip)('should sign JSON-RPC error responses', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const errorMessage = { jsonrpc: '2.0', id: 1, error: { code: -32600, message: 'Invalid Request' } };
      await proxy.send(errorMessage);

      expect(agent.signRequest.calledOnce).to.be.true;
      expect(agent.signRequest.firstCall.args[0]).to.deep.equal(errorMessage);
      expect(transport.send.calledOnce).to.be.true;
      expect(transport.send.firstCall.args[0]).to.deep.equal(createCarrier());
    });

    (available ? it : it.skip)('should remove null params before signing', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const message = { jsonrpc: '2.0', method: 'test', id: 1, params: null };
      await proxy.send(message);

      expect(agent.signRequest.calledOnce).to.be.true;
      const signedInput = agent.signRequest.firstCall.args[0];
      expect(signedInput).to.not.have.property('params');
    });

    (available ? it : it.skip)('should fail closed if signing fails and fallback is disabled', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.signRequest.throws(new Error('signing error'));

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const message = { jsonrpc: '2.0', method: 'test', id: 1 };
      let caught;
      try {
        await proxy.send(message);
      } catch (err) {
        caught = err;
      }

      expect(caught).to.be.an('error');
      expect(String(caught.message || caught)).to.match(/unsigned fallback is disabled/i);
      expect(transport.send.called).to.be.false;
    });

    (available ? it : it.skip)('should fail closed if signing returns an empty envelope', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.signRequest.returns('');
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      let error;
      try {
        await proxy.send({ jsonrpc: '2.0', id: 1, error: { code: -1, message: 'nope' } });
      } catch (err) {
        error = err;
      }

      expect(error).to.be.an('error');
      expect(error.message).to.match(/signed envelope|portable v2 signature metadata|unsigned fallback is disabled/i);
      expect(transport.send.called).to.be.false;
    });

    (available ? it : it.skip)('should fail closed if signing returns plain unsigned JSON', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.signRequest.returns('{"jsonrpc":"2.0","id":1,"result":"raw"}');
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      let error;
      try {
        await proxy.send({ jsonrpc: '2.0', id: 1, result: { value: 'raw' } });
      } catch (err) {
        error = err;
      }

      expect(error).to.be.an('error');
      expect(error.message).to.match(/signed envelope|portable v2 signature metadata|unsigned fallback is disabled/i);
      expect(transport.send.called).to.be.false;
    });

    (available ? it : it.skip)('should fall back to plain message if signing fails when explicitly enabled', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.signRequest.throws(new Error('signing error'));

      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { allowUnsignedFallback: true },
      );

      const message = { jsonrpc: '2.0', method: 'test', id: 1 };
      await proxy.send(message);

      expect(transport.send.calledOnce).to.be.true;
      expect(transport.send.firstCall.args[0]).to.deep.include({
        jsonrpc: '2.0',
        method: 'test',
      });
      expect(transport.send.firstCall.args[0].id).to.be.a('string').and.not.equal(1);
    });

    (available ? it : it.skip)('should bound outstanding request correlations', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'client',
        { expectedPeerAgentId: 'agent-a' },
      );

      for (let id = 0; id < 1024; id += 1) {
        await proxy.send({ jsonrpc: '2.0', id, method: 'tools/list' });
      }

      let error;
      try {
        await proxy.send({ jsonrpc: '2.0', id: 1024, method: 'tools/list' });
      } catch (caught) {
        error = caught;
      }
      expect(error).to.be.an('error');
      expect(error.message).to.match(/pending request limit/i);
      expect(agent.signRequest.callCount).to.equal(1024);
    });
  });

  // -------------------------------------------------------------------------
  // Incoming messages
  // -------------------------------------------------------------------------

  describe('incoming messages', () => {
    (available ? it : it.skip)('should require a peer identity policy before dispatch', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      transport.onmessage(createCarrier());

      expect(agent.verifyResponseWithAgentId.calledOnce).to.equal(true);
      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.calledOnce).to.equal(true);
      expect(errorSpy.firstCall.args[0].message).to.match(/peer identity policy/i);
    });

    (available ? it : it.skip)('should accept only the exact expected peer agent and key hash', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        {
          expectedPeerAgentId: 'agent-a',
          expectedPeerPublicKeyHash: 'public-key-hash-1',
        },
      );
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      const notification = { jsonrpc: '2.0', method: 'notifications/progress', params: {} };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-a', payload: notification });
      transport.onmessage(createCarrier(createSignedEnvelope({ content: notification })));

      expect(messageSpy.calledOnce).to.equal(true);
      expect(messageSpy.firstCall.args[0]).to.deep.equal(notification);
      expect(errorSpy.called).to.equal(false);
    });

    (available ? it : it.skip)('should reject a different valid signer before onmessage', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { expectedPeerAgentId: 'agent-a' },
      );
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      const notification = { jsonrpc: '2.0', method: 'notifications/progress', params: {} };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-b', payload: notification });
      transport.onmessage(createCarrier(createSignedEnvelope({
        content: notification,
        jacsSignature: { agentID: 'agent-b' },
      })));

      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.calledOnce).to.equal(true);
      expect(errorSpy.firstCall.args[0].message).to.match(/unexpected MCP peer agent/i);
    });

    (available ? it : it.skip)('should never treat a signed carrier peer mismatch as unsigned fallback', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { expectedPeerAgentId: 'agent-a', allowUnsignedFallback: true },
      );
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;
      const notification = { jsonrpc: '2.0', method: 'notifications/progress' };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-b', payload: notification });

      transport.onmessage(createCarrier(createSignedEnvelope({
        content: notification,
        jacsSignature: { agentID: 'agent-b' },
      })));

      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.calledOnce).to.equal(true);
      expect(errorSpy.firstCall.args[0].message).to.match(/unexpected MCP peer agent/i);
    });

    (available ? it : it.skip)('should reject an unexpected authenticated public key hash', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        {
          expectedPeerAgentId: 'agent-a',
          expectedPeerPublicKeyHash: 'different-public-key-hash',
        },
      );
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;
      const notification = { jsonrpc: '2.0', method: 'notifications/progress' };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-a', payload: notification });

      transport.onmessage(createCarrier(createSignedEnvelope({ content: notification })));

      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.calledOnce).to.equal(true);
      expect(errorSpy.firstCall.args[0].message).to.match(/unexpected MCP peer public key hash/i);
    });

    (available && nativeFixturesExist ? it : it.skip)('should bind a real native verification to the configured peer', () => {
      const originalCwd = process.cwd();
      const originalLegacy = process.env.JACS_ALLOW_LEGACY_SIGNATURE_CONTENT;
      process.chdir(NATIVE_FIXTURES_DIR);
      process.env.JACS_ALLOW_LEGACY_SIGNATURE_CONTENT = 'true';
      const agent = new NativeJacsAgent();
      try {
        agent.setPrivateKeyPassword('TestP@ss123!#');
        agent.loadSync(NATIVE_TEST_CONFIG);
        const agentId = JSON.parse(agent.exportAgent()).jacsId;
        const notification = { jsonrpc: '2.0', method: 'notifications/progress', params: {} };

        const acceptedTransport = createMockTransport();
        const acceptedProxy = new mcpModule.JACSTransportProxy(
          acceptedTransport,
          agent,
          'server',
          { expectedPeerAgentId: agentId },
        );
        const acceptedSpy = sinon.spy();
        acceptedProxy.onmessage = acceptedSpy;
        acceptedTransport.onmessage(createCarrier(agent.signRequest(notification)));
        expect(acceptedSpy.calledOnce).to.equal(true);

        const rejectedTransport = createMockTransport();
        const rejectedProxy = new mcpModule.JACSTransportProxy(
          rejectedTransport,
          agent,
          'server',
          { expectedPeerAgentId: '00000000-0000-0000-0000-000000000000' },
        );
        const rejectedSpy = sinon.spy();
        const errorSpy = sinon.spy();
        rejectedProxy.onmessage = rejectedSpy;
        rejectedProxy.onerror = errorSpy;
        rejectedTransport.onmessage(createCarrier(agent.signRequest(notification)));
        expect(rejectedSpy.called).to.equal(false);
        expect(errorSpy.calledOnce).to.equal(true);
        expect(errorSpy.firstCall.args[0].message).to.match(/unexpected MCP peer agent/i);
      } finally {
        process.chdir(originalCwd);
        if (originalLegacy === undefined) {
          delete process.env.JACS_ALLOW_LEGACY_SIGNATURE_CONTENT;
        } else {
          process.env.JACS_ALLOW_LEGACY_SIGNATURE_CONTENT = originalLegacy;
        }
      }
    });

    (available ? it : it.skip)('should accept an exact allowlisted signer', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { allowedPeerAgentIds: ['agent-a', 'agent-b'] },
      );
      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      const notification = { jsonrpc: '2.0', method: 'notifications/progress' };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-b', payload: notification });

      transport.onmessage(createCarrier(createSignedEnvelope({
        content: notification,
        jacsSignature: { agentID: 'agent-b' },
      })));

      expect(messageSpy.calledOnce).to.equal(true);
    });

    (available ? it : it.skip)('should require a literal dangerous opt-in for any valid signer', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { dangerouslyAllowAnyValidSigner: true },
      );
      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      const notification = { jsonrpc: '2.0', method: 'notifications/progress' };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-b', payload: notification });

      transport.onmessage(createCarrier(createSignedEnvelope({
        content: notification,
        jacsSignature: { agentID: 'agent-b' },
      })));

      expect(messageSpy.calledOnce).to.equal(true);
    });

    (available ? it : it.skip)('should randomize request IDs and reject cross-session response transplantation', async () => {
      const transportA = createMockTransport();
      const transportB = createMockTransport();
      const agentA = createMockAgent();
      const agentB = createMockAgent();
      const options = { expectedPeerAgentId: 'agent-a' };
      const proxyA = new mcpModule.JACSTransportProxy(transportA, { agent: agentA }, 'client', options);
      const proxyB = new mcpModule.JACSTransportProxy(transportB, { agent: agentB }, 'client', options);
      const request = { jsonrpc: '2.0', id: 1, method: 'tools/list' };

      await proxyA.send(request);
      await proxyB.send(request);
      const wireIdA = agentA.signRequest.firstCall.args[0].id;
      const wireIdB = agentB.signRequest.firstCall.args[0].id;
      expect(wireIdA).to.be.a('string').and.not.equal(wireIdB);
      expect(wireIdA).to.not.equal(1);
      expect(wireIdB).to.not.equal(1);

      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxyB.onmessage = messageSpy;
      proxyB.onerror = errorSpy;

      agentB.verifyResponseWithAgentId.returns({
        agent_id: 'agent-a',
        payload: { jsonrpc: '2.0', id: wireIdA, result: { tools: [] } },
      });
      transportB.onmessage(createCarrier());
      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.calledOnce).to.equal(true);
      expect(errorSpy.firstCall.args[0].message).to.match(/unknown or expired MCP response id/i);

      agentB.verifyResponseWithAgentId.returns({
        agent_id: 'agent-a',
        payload: { jsonrpc: '2.0', id: wireIdB, result: { tools: [] } },
      });
      transportB.onmessage(createCarrier(createSignedEnvelope({ jacsId: 'response-b' })));
      expect(messageSpy.calledOnce).to.equal(true);
      expect(messageSpy.firstCall.args[0].id).to.equal(1);

      transportB.onmessage(createCarrier(createSignedEnvelope({ jacsId: 'response-b-replay' })));
      expect(messageSpy.calledOnce).to.equal(true);
      expect(errorSpy.callCount).to.equal(2);
      expect(errorSpy.secondCall.args[0].message).to.match(/unknown or expired MCP response id/i);
    });

    (available ? it : it.skip)('should clear pending response correlations when closed', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'client',
        { expectedPeerAgentId: 'agent-a' },
      );
      await proxy.send({ jsonrpc: '2.0', id: 7, method: 'tools/list' });
      const wireId = agent.signRequest.firstCall.args[0].id;
      await proxy.close();

      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;
      agent.verifyResponseWithAgentId.returns({
        agent_id: 'agent-a',
        payload: { jsonrpc: '2.0', id: wireId, result: { tools: [] } },
      });
      transport.onmessage(createCarrier());

      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.calledOnce).to.equal(true);
      expect(errorSpy.firstCall.args[0].message).to.match(/unknown or expired MCP response id/i);
    });

    (available ? it : it.skip)('should round-trip schema-valid request, result, and error carriers', async () => {
      const { left, right } = createInMemoryTransportPair();
      const senderAgent = createRoundTripAgent();
      const receiverAgent = createRoundTripAgent();
      const peerOptions = { expectedPeerAgentId: 'agent-a' };
      const sender = new mcpModule.JACSTransportProxy(
        left,
        { agent: senderAgent },
        'client',
        peerOptions,
      );
      const receiver = new mcpModule.JACSTransportProxy(
        right,
        { agent: receiverAgent },
        'server',
        peerOptions,
      );
      const serverReceived = [];
      const clientReceived = [];
      receiver.onmessage = (message) => serverReceived.push(message);
      sender.onmessage = (message) => clientReceived.push(message);

      await sender.send({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
      expect(serverReceived).to.have.length(1);
      expect(serverReceived[0]).to.deep.include({ jsonrpc: '2.0', method: 'tools/list' });
      expect(serverReceived[0].id).to.be.a('string').and.not.equal(1);
      await receiver.send({ jsonrpc: '2.0', id: serverReceived[0].id, result: { tools: [] } });

      await sender.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: {} });
      expect(serverReceived).to.have.length(2);
      await receiver.send({
        jsonrpc: '2.0',
        id: serverReceived[1].id,
        error: { code: -32600, message: 'Invalid Request' },
      });

      expect(clientReceived).to.deep.equal([
        { jsonrpc: '2.0', id: 1, result: { tools: [] } },
        { jsonrpc: '2.0', id: 2, error: { code: -32600, message: 'Invalid Request' } },
      ]);
      expect(left.send.callCount).to.equal(2);
      expect(right.send.callCount).to.equal(2);
      for (const call of [...left.send.getCalls(), ...right.send.getCalls()]) {
        expect(call.args[0]).to.deep.include({
          jsonrpc: '2.0',
          method: mcpModule.JACS_MCP_SIGNED_CARRIER_METHOD,
        });
        expect(call.args[0].params.version).to.equal(
          mcpModule.JACS_MCP_SIGNED_CARRIER_VERSION,
        );
      }
    });

    (available ? it : it.skip)('should reject tampered and replayed signed carriers', () => {
      const transport = createMockTransport();
      const agent = createRoundTripAgent();
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { expectedPeerAgentId: 'agent-a' },
      );
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      const request = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} };
      const envelope = createSignedEnvelope({ jacsId: 'replay-1', content: request });
      transport.onmessage(createCarrier(envelope));
      transport.onmessage(createCarrier(envelope));

      const tampered = JSON.parse(envelope);
      tampered.jacsId = 'tampered-1';
      tampered.jacsSignature.signature = 'attacker-bytes';
      transport.onmessage(createCarrier(JSON.stringify(tampered)));

      expect(messageSpy.calledOnce).to.equal(true);
      expect(errorSpy.callCount).to.equal(2);
      expect(errorSpy.firstCall.args[0].message).to.match(/replay detected/i);
      expect(errorSpy.secondCall.args[0].message).to.match(/tampered signature/i);
    });

    (available ? it : it.skip)('should reject malformed signed carriers before verification', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      const malformed = [
        { ...createCarrier(), params: { ...createCarrier().params, version: 2 } },
        { ...createCarrier(), params: { ...createCarrier().params, envelope: '' } },
        { ...createCarrier(), params: { ...createCarrier().params, extra: true } },
        { ...createCarrier(), unexpected: true },
        { jsonrpc: '2.0', method: 'notifications/jacs/signed' },
      ];
      for (const carrier of malformed) transport.onmessage(carrier);

      expect(agent.verifyResponseWithAgentId.called).to.equal(false);
      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.callCount).to.equal(malformed.length);
      for (const call of errorSpy.getCalls()) {
        expect(call.args[0].message).to.match(/malformed JACS MCP signed-envelope carrier/i);
      }
    });

    (available ? it : it.skip)('should reject a verified envelope whose payload is not JSON-RPC', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.verifyResponseWithAgentId.returns({
        agent_id: 'agent-a',
        payload: { arbitrary: 'object' },
      });
      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { expectedPeerAgentId: 'agent-a' },
      );
      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      transport.onmessage(createCarrier());

      expect(messageSpy.called).to.equal(false);
      expect(errorSpy.calledOnce).to.equal(true);
      expect(errorSpy.firstCall.args[0].message).to.match(/valid JSON-RPC message/i);
    });

    (available ? it : it.skip)('should verify incoming string messages and pass to onmessage', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const verifiedPayload = { jsonrpc: '2.0', method: 'notifications/progress', params: {} };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-a', payload: verifiedPayload });

      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { expectedPeerAgentId: 'agent-a' },
      );

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      // Simulate incoming string from transport
      transport.onmessage(createSignedEnvelope({ content: verifiedPayload }));

      expect(agent.verifyResponseWithAgentId.calledOnce).to.be.true;
      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(verifiedPayload);
    });

    (available ? it : it.skip)('should extract payload field if present in verification result', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const innerPayload = { jsonrpc: '2.0', method: 'notifications/progress', params: { value: 'inner' } };
      agent.verifyResponseWithAgentId.returns({ agent_id: 'agent-a', payload: innerPayload });

      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { expectedPeerAgentId: 'agent-a' },
      );

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      transport.onmessage(createSignedEnvelope({ content: innerPayload }));

      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(innerPayload);
    });

    (available ? it : it.skip)('should fail closed on verification failure by default', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.verifyResponse.throws(new Error('not a JACS artifact'));

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      const plainMessage = { jsonrpc: '2.0', method: 'ping', id: 42 };
      transport.onmessage(JSON.stringify(plainMessage));

      expect(messageSpy.called).to.be.false;
      expect(errorSpy.calledOnce).to.be.true;
      expect(errorSpy.firstCall.args[0].message).to.match(/unsigned fallback is disabled/i);
    });

    (available ? it : it.skip)('should fall through as plain JSON when verification fails and fallback is enabled', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.verifyResponse.throws(new Error('not a JACS artifact'));

      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { allowUnsignedFallback: true },
      );

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      const plainMessage = { jsonrpc: '2.0', method: 'ping', id: 42 };
      transport.onmessage(JSON.stringify(plainMessage));

      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(plainMessage);
    });

    (available ? it : it.skip)('should fail closed on unsigned object messages by default', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const messageSpy = sinon.spy();
      const errorSpy = sinon.spy();
      proxy.onmessage = messageSpy;
      proxy.onerror = errorSpy;

      const objMessage = { jsonrpc: '2.0', method: 'test', id: 1 };
      transport.onmessage(objMessage);

      expect(agent.verifyResponse.called).to.be.false;
      expect(messageSpy.called).to.be.false;
      expect(errorSpy.calledOnce).to.be.true;
      expect(errorSpy.firstCall.args[0].message).to.match(/unsigned fallback is disabled/i);
    });

    (available ? it : it.skip)('should pass through object messages only with explicit unsigned fallback', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = new mcpModule.JACSTransportProxy(
        transport,
        { agent },
        'server',
        { allowUnsignedFallback: true },
      );

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      const objMessage = { jsonrpc: '2.0', method: 'test', id: 1 };
      transport.onmessage(objMessage);

      expect(agent.verifyResponse.called).to.be.false;
      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(objMessage);
    });

    for (const malformedOptIn of ['true', 1, {}, []]) {
      (available ? it : it.skip)(
        `should not enable object fallback for non-boolean ${JSON.stringify(malformedOptIn)}`,
        () => {
          const transport = createMockTransport();
          const agent = createMockAgent();
          const proxy = new mcpModule.JACSTransportProxy(
            transport,
            { agent },
            'server',
            { allowUnsignedFallback: malformedOptIn },
          );
          const messageSpy = sinon.spy();
          const errorSpy = sinon.spy();
          proxy.onmessage = messageSpy;
          proxy.onerror = errorSpy;

          transport.onmessage({ jsonrpc: '2.0', method: 'test', id: 1 });

          expect(messageSpy.called).to.equal(false);
          expect(errorSpy.calledOnce).to.equal(true);
          expect(errorSpy.firstCall.args[0].message).to.match(/unsigned fallback is disabled/i);
        },
      );
    }

    (available ? it : it.skip)('should call onerror for unexpected data types', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const errorSpy = sinon.spy();
      proxy.onerror = errorSpy;

      // Pass a non-jsonrpc object (no 'jsonrpc' key)
      transport.onmessage({ foo: 'bar' });

      expect(errorSpy.calledOnce).to.be.true;
      expect(errorSpy.firstCall.args[0].message).to.match(/unexpected/i);
    });
  });

  // -------------------------------------------------------------------------
  // start() and close()
  // -------------------------------------------------------------------------

  describe('start() and close()', () => {
    (available ? it : it.skip)('should delegate start() to wrapped transport', async () => {
      const transport = createMockTransport();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });

      await proxy.start();

      expect(transport.start.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('should delegate close() to wrapped transport', async () => {
      const transport = createMockTransport();
      const proxy = new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });

      await proxy.close();

      expect(transport.close.calledOnce).to.be.true;
    });
  });

  // -------------------------------------------------------------------------
  // createJACSTransportProxyAsync
  // -------------------------------------------------------------------------

  describe('createJACSTransportProxyAsync', () => {
    // This test requires the native JacsAgent to be available, so we skip
    // if it can't be loaded. The factory loads from a config file.
    (available ? it : it.skip)('should be an async function that returns a proxy', () => {
      expect(mcpModule.createJACSTransportProxyAsync).to.be.a('function');
    });
  });

  // -------------------------------------------------------------------------
  // createJACSTransportProxy
  // -------------------------------------------------------------------------

  describe('createJACSTransportProxy', () => {
    (available ? it : it.skip)('should create a proxy from a pre-loaded agent', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = mcpModule.createJACSTransportProxy(transport, { agent }, 'server');

      expect(proxy).to.be.instanceOf(mcpModule.JACSTransportProxy);
    });

    (available ? it : it.skip)('should default role to server', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      // No role arg
      const proxy = mcpModule.createJACSTransportProxy(transport, { agent });
      expect(proxy).to.be.instanceOf(mcpModule.JACSTransportProxy);
    });
  });

  // -------------------------------------------------------------------------
  // removeNullValues
  // -------------------------------------------------------------------------

  describe('removeNullValues', () => {
    let proxy;

    before(function () {
      if (!available) this.skip();
      const transport = createMockTransport();
      proxy = new mcpModule.JACSTransportProxy(transport, { agent: createMockAgent() });
    });

    (available ? it : it.skip)('should return undefined for null input', () => {
      expect(proxy.removeNullValues(null)).to.be.undefined;
    });

    (available ? it : it.skip)('should return undefined for undefined input', () => {
      expect(proxy.removeNullValues(undefined)).to.be.undefined;
    });

    (available ? it : it.skip)('should return primitives as-is', () => {
      expect(proxy.removeNullValues(42)).to.equal(42);
      expect(proxy.removeNullValues('hello')).to.equal('hello');
      expect(proxy.removeNullValues(true)).to.equal(true);
    });

    (available ? it : it.skip)('should strip null values from objects', () => {
      const input = { a: 1, b: null, c: 'test', d: undefined };
      const result = proxy.removeNullValues(input);
      expect(result).to.deep.equal({ a: 1, c: 'test' });
    });

    (available ? it : it.skip)('should recursively strip nulls from nested objects', () => {
      const input = {
        level1: {
          a: 1,
          b: null,
          level2: {
            c: 'ok',
            d: null,
          },
        },
        e: 'keep',
      };
      const result = proxy.removeNullValues(input);
      expect(result).to.deep.equal({
        level1: { a: 1, level2: { c: 'ok' } },
        e: 'keep',
      });
    });

    (available ? it : it.skip)('should handle arrays', () => {
      const input = [1, null, 'test', { a: null, b: 2 }];
      const result = proxy.removeNullValues(input);
      // null in arrays becomes undefined (map preserves indices)
      expect(result[0]).to.equal(1);
      expect(result[1]).to.be.undefined;
      expect(result[2]).to.equal('test');
      expect(result[3]).to.deep.equal({ b: 2 });
    });

    (available ? it : it.skip)('should return empty object when all values are null', () => {
      const input = { a: null, b: null };
      const result = proxy.removeNullValues(input);
      expect(result).to.deep.equal({});
    });
  });

  // -------------------------------------------------------------------------
  // MCP Tool Definitions
  // -------------------------------------------------------------------------

  describe('getJacsMcpToolDefinitions()', () => {
    (available ? it : it.skip)('should return an array of 32 tool definitions', () => {
      // 27 v0.10 tools + 5 inline-text/media verbs added in v0.11
      // (jacs_sign_text, jacs_verify_text, jacs_sign_image, jacs_verify_image,
      //  jacs_extract_media_signature).
      const tools = mcpModule.getJacsMcpToolDefinitions();
      expect(tools).to.be.an('array');
      expect(tools).to.have.length(32);
    });

    (available ? it : it.skip)('should include core JACS tools', () => {
      const tools = mcpModule.getJacsMcpToolDefinitions();
      const names = tools.map(t => t.name);
      expect(names).to.include('jacs_sign_document');
      expect(names).to.include('jacs_verify_document');
      expect(names).to.include('jacs_create_agreement');
      expect(names).to.include('jacs_sign_agreement');
      expect(names).to.include('jacs_check_agreement');
      expect(names).to.not.include('jacs_audit');
      expect(names).to.include('jacs_verify_self');
      expect(names).to.include('jacs_export_agent');
      expect(names).to.include('jacs_export_agent_card');
      expect(names).to.include('jacs_wrap_a2a_artifact');
      expect(names).to.include('jacs_verify_a2a_artifact');
      expect(names).to.include('jacs_assess_a2a_agent');
      expect(names).to.include('fetch_agent_key');
      expect(names).to.include('jacs_trust_agent');
      expect(names).to.include('jacs_trust_agent_with_key');
      expect(names).to.include('jacs_list_trusted');
      expect(names).to.include('jacs_list_trusted_agents');
      expect(names).to.include('jacs_get_trusted_agent');
      expect(names).to.include('jacs_untrust_agent');
      expect(names).to.include('jacs_share_public_key');
      expect(names).to.include('jacs_share_agent');
    });

    (available ? it : it.skip)('each tool should have name, description, and inputSchema', () => {
      const tools = mcpModule.getJacsMcpToolDefinitions();
      for (const tool of tools) {
        expect(tool).to.have.property('name').that.is.a('string');
        expect(tool).to.have.property('description').that.is.a('string');
        expect(tool).to.have.property('inputSchema');
        expect(tool.inputSchema).to.have.property('type', 'object');
      }
    });
  });

  // -------------------------------------------------------------------------
  // handleJacsMcpToolCall
  // -------------------------------------------------------------------------

  describe('handleJacsMcpToolCall()', () => {
    const previousAllowRemoteKeyFetch = process.env.JACS_ALLOW_REMOTE_KEY_FETCH;

    before(() => {
      process.env.JACS_ALLOW_REMOTE_KEY_FETCH = 'true';
    });

    after(() => {
      if (previousAllowRemoteKeyFetch === undefined) {
        delete process.env.JACS_ALLOW_REMOTE_KEY_FETCH;
      } else {
        process.env.JACS_ALLOW_REMOTE_KEY_FETCH = previousAllowRemoteKeyFetch;
      }
    });

    (available ? it : it.skip)('jacs_sign_document should sign data', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_sign_document', { data: '{"action":"test"}' },
      );
      expect(result.content).to.have.length(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(parsed).to.have.property('documentId', 'doc-1:1');
      expect(client.signMessage.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('jacs_verify_document verifies exact bytes with the caller-selected raw key', async function () {
      this.timeout(30000);
      const { JacsSimpleAgent } = require('../index.js');
      const client = createMockJacsClient();
      for (const algorithm of ['ed25519', 'pq2025']) {
        const signer = JacsSimpleAgent.ephemeral(algorithm);
        const signed = signer.signMessage(JSON.stringify({ hello: algorithm }));
        const signerId = JSON.parse(signed).jacsSignature.agentID;
        const publicKey = Array.from(Buffer.from(signer.getPublicKeyBase64(), 'base64'));

        const ok = JSON.parse((await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_verify_document', { document: signed, public_key: publicKey, algorithm },
        )).content[0].text);
        expect(ok).to.include({ success: true, valid: true, signer_id: signerId, error: null });

        const other = JacsSimpleAgent.ephemeral(algorithm);
        const wrongKey = Array.from(Buffer.from(other.getPublicKeyBase64(), 'base64'));
        const rejected = JSON.parse((await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_verify_document', { document: signed, public_key: wrongKey, algorithm },
        )).content[0].text);
        expect(rejected.valid).to.equal(false);
        expect(rejected.success).to.equal(true);
        expect(rejected.error).to.be.a('string').and.not.empty;

        const tampered = signed.replace(`"hello":"${algorithm}"`, '"hello":"tampered"');
        expect(tampered).to.not.equal(signed);
        const tamperedResult = JSON.parse((await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_verify_document', { document: tampered, public_key: publicKey, algorithm },
        )).content[0].text);
        expect(tamperedResult.valid).to.equal(false);
      }
      // The loaded MCP identity never participates in canonical verification.
      expect(client.verify.called).to.equal(false);
    });

    (available ? it : it.skip)('jacs_verify_document fails closed on malformed key selection', async () => {
      const client = createMockJacsClient();
      const cases = [
        [{ document: '{"signed":"doc"}', public_key: new Array(32).fill(0), algorithm: 'rsa' }, 'INVALID_ALGORITHM'],
        [{ document: '{"signed":"doc"}', public_key: new Array(31).fill(0), algorithm: 'ed25519' }, 'INVALID_PUBLIC_KEY'],
        [{ document: '{"signed":"doc"}', public_key: [1, 2, 300], algorithm: 'ed25519' }, 'INVALID_PUBLIC_KEY'],
        [{ document: '{"signed":"doc"}', public_key: 'AAAA', algorithm: 'ed25519' }, 'INVALID_PUBLIC_KEY'],
        [{ document: '', public_key: new Array(32).fill(0), algorithm: 'ed25519' }, 'EMPTY_DOCUMENT'],
      ];
      for (const [args, error] of cases) {
        const parsed = JSON.parse((await mcpModule.handleJacsMcpToolCall(client, 'jacs_verify_document', args)).content[0].text);
        expect(parsed).to.include({ success: false, valid: false, error });
      }
      expect(client.verify.called).to.equal(false);
    });

    (available ? it : it.skip)('jacs_verify_by_id should verify by storage ID', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_verify_by_id', { document_id: 'abc:1' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('valid', true);
    });

    (available ? it : it.skip)('jacs_create_agreement should create agreement', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_create_agreement',
        {
          document: '{"action":"deploy"}',
          agent_ids: ['a', 'b'],
          question: 'OK?',
          context: 'review requested',
          quorum: 2,
          required_algorithms: ['pq2025'],
          minimum_strength: 'post-quantum',
        },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(parsed).to.have.property('documentId', 'agr-1:1');
      expect(client.createAgreement.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('jacs_check_agreement should check status', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_check_agreement', { signed_agreement: '{"agr":"doc"}' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('complete', true);
    });

    (available ? it : it.skip)('fetch_agent_key should delegate remote key lookup to the native Rust binding', async () => {
      const client = createMockJacsClient();
      const nativeBindings = require('../index.js');
      const lookupStub = sinon.stub(nativeBindings, 'fetchRemoteKeyLookup').returns(
        JSON.stringify({
          jacs_id: 'agent-123',
          version: 'latest',
          public_key: '-----BEGIN PUBLIC KEY-----...',
        }),
      );

      try {
        const result = await mcpModule.handleJacsMcpToolCall(
          client,
          'fetch_agent_key',
          { jacs_id: 'agent-123' },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(lookupStub.calledOnceWithExactly(null, 'agent-123', null, null, null)).to.be.true;
        expect(parsed).to.have.property('success', true);
        expect(parsed).to.have.property('jacs_id', 'agent-123');
      } finally {
        lookupStub.restore();
      }
    });

    (available ? it : it.skip)('fetch_agent_key should pass by-hash lookups through to the native Rust binding', async () => {
      const client = createMockJacsClient();
      const nativeBindings = require('../index.js');
      const lookupStub = sinon.stub(nativeBindings, 'fetchRemoteKeyLookup').returns(
        JSON.stringify({
          jacs_id: 'agent-xyz',
          public_key_hash: 'sha256:abcd',
        }),
      );

      try {
        const result = await mcpModule.handleJacsMcpToolCall(
          client,
          'fetch_agent_key',
          { public_key_hash: 'abcd', base_url: 'https://hai.ai/' },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(
          lookupStub.calledOnceWithExactly('https://hai.ai/', null, null, 'abcd', null),
        ).to.be.true;
        expect(parsed).to.have.property('success', true);
        expect(parsed).to.have.property('public_key_hash', 'sha256:abcd');
      } finally {
        lookupStub.restore();
      }
    });

    (available ? it : it.skip)('jacs_trust_agent should add to trust store', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_trust_agent', { agent_json: '{"id":"x"}' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
    });

    (available ? it : it.skip)('jacs_agent_info should not expose local filesystem paths', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client,
        'jacs_agent_info',
        {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('agentId', 'client-agent-123');
      expect(parsed).to.not.have.property('configPath');
      expect(parsed).to.not.have.property('publicKeyPath');
    });

    (available ? it : it.skip)('jacs_trust_agent_with_key should trust using explicit PEM key', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client,
        'jacs_trust_agent_with_key',
        { agent_json: '{"id":"x"}', public_key_pem: '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(client.trustAgentWithKey.calledOnce).to.be.true;
    });

    (available ? it : it.skip)('jacs_share_public_key should return PEM', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client,
        'jacs_share_public_key',
        {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(parsed.publicKeyPem).to.include('BEGIN PUBLIC KEY');
    });

    (available ? it : it.skip)('jacs_share_agent should return agent document', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client,
        'jacs_share_agent',
        {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(parsed.agentJson).to.include('jacsId');
    });

    (available ? it : it.skip)('jacs_export_agent should return agent document', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client,
        'jacs_export_agent',
        {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(parsed.agentJson).to.include('jacsId');
    });

    (available ? it : it.skip)('jacs_list_trusted should list agents', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_list_trusted', {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.trustedAgents).to.deep.equal(['agent-a', 'agent-b']);
    });

    (available ? it : it.skip)('jacs_list_trusted_agents should list agents', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_list_trusted_agents', {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.trustedAgents).to.deep.equal(['agent-a', 'agent-b']);
    });

    (available ? it : it.skip)('jacs_untrust_agent should require explicit opt-in', async () => {
      const client = createMockJacsClient();
      const original = process.env.JACS_MCP_ALLOW_UNTRUST;
      delete process.env.JACS_MCP_ALLOW_UNTRUST;
      try {
        const result = await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_untrust_agent', { agent_id: 'agent-a' },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed).to.have.property('success', false);
        expect(parsed).to.have.property('error', 'UNTRUST_DISABLED');
        expect(client.untrustAgent.called).to.be.false;
      } finally {
        if (typeof original === 'undefined') {
          delete process.env.JACS_MCP_ALLOW_UNTRUST;
        } else {
          process.env.JACS_MCP_ALLOW_UNTRUST = original;
        }
      }
    });

    (available ? it : it.skip)('jacs_untrust_agent should untrust when enabled', async () => {
      const client = createMockJacsClient();
      const original = process.env.JACS_MCP_ALLOW_UNTRUST;
      process.env.JACS_MCP_ALLOW_UNTRUST = 'true';
      try {
        const result = await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_untrust_agent', { agent_id: 'agent-a' },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed).to.have.property('success', true);
        expect(client.untrustAgent.calledOnceWith('agent-a')).to.be.true;
      } finally {
        if (typeof original === 'undefined') {
          delete process.env.JACS_MCP_ALLOW_UNTRUST;
        } else {
          process.env.JACS_MCP_ALLOW_UNTRUST = original;
        }
      }
    });

    (available ? it : it.skip)('unknown tool should return error', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'unknown_tool', {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('error');
    });

    (available ? it : it.skip)('should handle errors gracefully', async () => {
      const client = createMockJacsClient();
      client.signMessage = sinon.stub().rejects(new Error('boom'));
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_sign_document', { data: '{}' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', false);
      expect(parsed.error).to.include('boom');
    });

    // -------------------------------------------------------------------------
    // REVIEW_001 regression — inline-text + media MCP arms must call the
    // JacsClient (not the native JacsAgent which lacks these methods).
    // -------------------------------------------------------------------------

    describe('inline-text + media tool routing (REVIEW_001)', () => {
      let baseDir;
      let prevBaseDir;

      beforeEach(function () {
        const fs = require('fs');
        const os = require('os');
        const path = require('path');
        baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-mcp-arm-'));
        // Seed a real file so resolveMcpPath('input') accepts it.
        fs.writeFileSync(path.join(baseDir, 'in.md'), '# hello\n');
        fs.writeFileSync(path.join(baseDir, 'in.png'), Buffer.alloc(8));
        prevBaseDir = process.env.JACS_MCP_BASE_DIR;
        process.env.JACS_MCP_BASE_DIR = baseDir;
      });

      afterEach(function () {
        const fs = require('fs');
        if (prevBaseDir === undefined) {
          delete process.env.JACS_MCP_BASE_DIR;
        } else {
          process.env.JACS_MCP_BASE_DIR = prevBaseDir;
        }
        try { fs.rmSync(baseDir, { recursive: true, force: true }); } catch (_) {}
      });

      (available ? it : it.skip)('jacs_sign_text routes through client.signText', async () => {
        const client = createMockJacsClient();
        const result = await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_sign_text', { file_path: 'in.md', no_backup: false },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed).to.have.property('success', true);
        expect(client.signText.calledOnce).to.be.true;
        // Verify we're NOT reaching for the native JacsAgent.
        expect(client.agent.signText).to.be.undefined;
      });

      (available ? it : it.skip)('jacs_verify_text routes through client.verifyText', async () => {
        const client = createMockJacsClient();
        const result = await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_verify_text', { file_path: 'in.md', strict: false },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed).to.have.property('success', true);
        expect(client.verifyText.calledOnce).to.be.true;
      });

      (available ? it : it.skip)('jacs_sign_image routes through client.signImage', async () => {
        const client = createMockJacsClient();
        const result = await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_sign_image',
          { input_path: 'in.png', output_path: 'out.png', robust: false },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed).to.have.property('success', true);
        expect(client.signImage.calledOnce).to.be.true;
      });

      (available ? it : it.skip)('jacs_verify_image routes through client.verifyImage', async () => {
        const client = createMockJacsClient();
        const result = await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_verify_image', { file_path: 'in.png', strict: false },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed).to.have.property('success', true);
        expect(client.verifyImage.calledOnce).to.be.true;
      });

      (available ? it : it.skip)('jacs_extract_media_signature routes through client.extractMediaSignature', async () => {
        const client = createMockJacsClient();
        const result = await mcpModule.handleJacsMcpToolCall(
          client, 'jacs_extract_media_signature',
          { file_path: 'in.png', raw_payload: false },
        );
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed).to.have.property('success', true);
        expect(client.extractMediaSignature.calledOnce).to.be.true;
      });
    });
  });
});
