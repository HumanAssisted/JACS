/**
 * Tests for JACS MCP Transport Proxy
 *
 * Tests the JACSTransportProxy which wraps MCP transports with
 * JACS signing (outgoing) and verification (incoming).
 */

const { expect } = require('chai');
const sinon = require('sinon');

let mcpModule;
try {
  mcpModule = require('../mcp.js');
} catch (e) {
  mcpModule = null;
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
  };
}

function createMockAgent() {
  return {
    signRequest: sinon.stub().returns('{"signed":"artifact"}'),
    verifyResponse: sinon.stub().returns({ jsonrpc: '2.0', id: 1, result: 'ok' }),
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
    listTrustedAgents: sinon.stub().returns(['agent-a', 'agent-b']),
    isTrusted: sinon.stub().returns(true),
  };
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
  });

  // -------------------------------------------------------------------------
  // send()
  // -------------------------------------------------------------------------

  describe('send()', () => {
    (available ? it : it.skip)('should sign outgoing messages via signRequest', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.signRequest.returns('{"signed":"data"}');

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const message = { jsonrpc: '2.0', method: 'tools/list', id: 1 };
      await proxy.send(message);

      expect(agent.signRequest.calledOnce).to.be.true;
      expect(transport.send.calledOnce).to.be.true;
      expect(transport.send.firstCall.args[0]).to.equal('{"signed":"data"}');
    });

    (available ? it : it.skip)('should skip signing for error responses', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const errorMessage = { jsonrpc: '2.0', id: 1, error: { code: -32600, message: 'Invalid Request' } };
      await proxy.send(errorMessage);

      expect(agent.signRequest.called).to.be.false;
      expect(transport.send.calledOnce).to.be.true;
      expect(transport.send.firstCall.args[0]).to.deep.equal(errorMessage);
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

    (available ? it : it.skip)('should fall back to plain message if signing fails', async () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.signRequest.throws(new Error('signing error'));

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const message = { jsonrpc: '2.0', method: 'test', id: 1 };
      await proxy.send(message);

      expect(transport.send.calledOnce).to.be.true;
      expect(transport.send.firstCall.args[0]).to.deep.equal(message);
    });
  });

  // -------------------------------------------------------------------------
  // Incoming messages
  // -------------------------------------------------------------------------

  describe('incoming messages', () => {
    (available ? it : it.skip)('should verify incoming string messages and pass to onmessage', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const verifiedPayload = { jsonrpc: '2.0', id: 1, result: { tools: [] } };
      agent.verifyResponse.returns(verifiedPayload);

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      // Simulate incoming string from transport
      transport.onmessage('{"some":"signed-data"}');

      expect(agent.verifyResponse.calledOnce).to.be.true;
      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(verifiedPayload);
    });

    (available ? it : it.skip)('should extract payload field if present in verification result', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      const innerPayload = { jsonrpc: '2.0', id: 1, result: 'inner' };
      agent.verifyResponse.returns({ payload: innerPayload, signature: 'abc' });

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      transport.onmessage('{"signed":"envelope"}');

      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(innerPayload);
    });

    (available ? it : it.skip)('should fall through as plain JSON when verification fails', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();
      agent.verifyResponse.throws(new Error('not a JACS artifact'));

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      const plainMessage = { jsonrpc: '2.0', method: 'ping', id: 42 };
      transport.onmessage(JSON.stringify(plainMessage));

      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(plainMessage);
    });

    (available ? it : it.skip)('should pass through object messages as-is', () => {
      const transport = createMockTransport();
      const agent = createMockAgent();

      const proxy = new mcpModule.JACSTransportProxy(transport, { agent }, 'server');

      const messageSpy = sinon.spy();
      proxy.onmessage = messageSpy;

      const objMessage = { jsonrpc: '2.0', method: 'test', id: 1 };
      transport.onmessage(objMessage);

      expect(agent.verifyResponse.called).to.be.false;
      expect(messageSpy.calledOnce).to.be.true;
      expect(messageSpy.firstCall.args[0]).to.deep.equal(objMessage);
    });

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
    (available ? it : it.skip)('should return an array of 17 tool definitions', () => {
      const tools = mcpModule.getJacsMcpToolDefinitions();
      expect(tools).to.be.an('array');
      expect(tools).to.have.length(17);
    });

    (available ? it : it.skip)('should include core JACS tools', () => {
      const tools = mcpModule.getJacsMcpToolDefinitions();
      const names = tools.map(t => t.name);
      expect(names).to.include('jacs_sign_document');
      expect(names).to.include('jacs_verify_document');
      expect(names).to.include('jacs_create_agreement');
      expect(names).to.include('jacs_sign_agreement');
      expect(names).to.include('jacs_check_agreement');
      expect(names).to.include('jacs_audit');
      expect(names).to.include('jacs_verify_self');
      expect(names).to.include('fetch_agent_key');
      expect(names).to.include('jacs_trust_agent');
      expect(names).to.include('jacs_list_trusted');
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

    (available ? it : it.skip)('jacs_verify_document should verify', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_verify_document', { document: '{"signed":"doc"}' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('valid', true);
      expect(parsed).to.have.property('signerId', 'agent-b');
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
        { document: '{"action":"deploy"}', agent_ids: ['a', 'b'], question: 'OK?', quorum: 2 },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(parsed).to.have.property('documentId', 'agr-1:1');
    });

    (available ? it : it.skip)('jacs_check_agreement should check status', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_check_agreement', { document: '{"agr":"doc"}' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('complete', true);
    });

    (available ? it : it.skip)('jacs_audit should run audit', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_audit', { recent_n: 10 },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
      expect(parsed).to.have.property('status', 'ok');
    });

    (available ? it : it.skip)('jacs_trust_agent should add to trust store', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_trust_agent', { agent_json: '{"id":"x"}' },
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).to.have.property('success', true);
    });

    (available ? it : it.skip)('jacs_list_trusted should list agents', async () => {
      const client = createMockJacsClient();
      const result = await mcpModule.handleJacsMcpToolCall(
        client, 'jacs_list_trusted', {},
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.trustedAgents).to.deep.equal(['agent-a', 'agent-b']);
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
  });
});
