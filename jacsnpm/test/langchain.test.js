/**
 * Tests for JACS LangChain.js Adapter
 *
 * Uses mock JacsClient and mock LangChain classes to verify
 * adapter behavior without requiring real JACS agents or
 * LangChain dependencies.
 */

const { expect } = require('chai');
const sinon = require('sinon');
const Module = require('module');

// ---------------------------------------------------------------------------
// Mock LangChain classes
// ---------------------------------------------------------------------------

class MockDynamicStructuredTool {
  constructor(opts) {
    this.name = opts.name;
    this.description = opts.description;
    this.schema = opts.schema;
    this._func = opts.func;
  }
  async invoke(input) {
    return this._func(input);
  }
}

class MockToolMessage {
  constructor(opts) {
    this.content = opts.content;
    this.tool_call_id = opts.tool_call_id || '';
    this.name = opts.name;
  }
}

class MockToolNode {
  constructor(opts) {
    if (Array.isArray(opts)) {
      this.tools = opts;
      this.handleToolErrors = true;
    } else {
      this.tools = opts.tools || [];
      this.handleToolErrors = opts.handleToolErrors !== false;
    }
  }
}

// ---------------------------------------------------------------------------
// Module-level require interception for lazy imports
// ---------------------------------------------------------------------------

// We intercept require() calls for @langchain/* so the adapter can resolve
// them without having the real packages installed.
const originalRequire = Module.prototype.require;
let requireInterceptEnabled = true;

// Minimal Zod mock that supports the schema shapes used by createJacsTools
const mockZod = {
  object: (shape) => ({ ...shape, _type: 'ZodObject' }),
  string: () => ({
    describe: (d) => ({ _type: 'ZodString', _description: d }),
    optional: () => ({ _type: 'ZodOptional', describe: (d) => ({ _type: 'ZodOptional', _description: d }) }),
  }),
  number: () => ({
    describe: (d) => ({ _type: 'ZodNumber', _description: d }),
    optional: () => ({ _type: 'ZodOptional', describe: (d) => ({ _type: 'ZodOptional', _description: d }) }),
  }),
  array: (item) => ({
    describe: (d) => ({ _type: 'ZodArray', _description: d }),
  }),
};

function installRequireIntercept() {
  Module.prototype.require = function (id) {
    if (requireInterceptEnabled) {
      if (id === '@langchain/core/tools') {
        return { DynamicStructuredTool: MockDynamicStructuredTool };
      }
      if (id === '@langchain/core/messages') {
        return { ToolMessage: MockToolMessage };
      }
      if (id === '@langchain/langgraph/prebuilt') {
        return { ToolNode: MockToolNode };
      }
      if (id === 'zod') {
        return mockZod;
      }
    }
    return originalRequire.apply(this, arguments);
  };
}

function removeRequireIntercept() {
  Module.prototype.require = originalRequire;
}

// ---------------------------------------------------------------------------
// Load the adapter (compiled JS)
// ---------------------------------------------------------------------------

let adapterModule;
try {
  installRequireIntercept();
  adapterModule = require('../langchain.js');
} catch (e) {
  adapterModule = null;
} finally {
  // Keep intercept active for test execution -- adapter calls require lazily.
}

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function createMockClient(overrides) {
  return {
    signMessage: sinon.stub().resolves({
      raw: '{"jacsId":"doc-1:1","jacsSignature":{"agentID":"agent-a","date":"2025-01-01T00:00:00Z"},"content":"signed-content"}',
      documentId: 'doc-1:1',
      agentId: 'agent-a',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    verify: sinon.stub().resolves({
      valid: true,
      signerId: 'agent-b',
      timestamp: '2025-01-01T00:00:00Z',
      data: { key: 'value' },
      errors: [],
    }),
    verifySelf: sinon.stub().resolves({
      valid: true,
      signerId: 'agent-a',
      errors: [],
    }),
    createAgreement: sinon.stub().resolves({
      raw: '{"jacsId":"agr-1:1","jacsAgreement":{}}',
      documentId: 'agr-1:1',
      agentId: 'agent-a',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    signAgreement: sinon.stub().resolves({
      raw: '{"jacsId":"agr-1:2","jacsAgreement":{}}',
      documentId: 'agr-1:2',
      agentId: 'agent-a',
      timestamp: '2025-01-01T00:00:00Z',
    }),
    checkAgreement: sinon.stub().resolves({
      complete: false,
      signedCount: 1,
      totalRequired: 2,
    }),
    trustAgent: sinon.stub().returns('trusted'),
    listTrustedAgents: sinon.stub().returns(['agent-b', 'agent-c']),
    isTrusted: sinon.stub().returns(true),
    audit: sinon.stub().resolves({ status: 'ok', documents: 5 }),
    agentId: 'agent-a',
    name: 'test-agent',
    strict: false,
    ...overrides,
  };
}

function createMockTool(overrides) {
  return {
    name: 'search',
    description: 'Search the web',
    schema: { type: 'object' },
    invoke: sinon.stub().resolves('search result'),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('LangChain.js Adapter', function () {
  this.timeout(15000);

  const available = adapterModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping LangChain adapter tests - langchain.js not compiled');
      this.skip();
    }
  });

  after(function () {
    removeRequireIntercept();
  });

  // =========================================================================
  // signedTool
  // =========================================================================

  describe('signedTool()', () => {
    (available ? it : it.skip)('should return a DynamicStructuredTool with the same name and description', () => {
      const client = createMockClient();
      const tool = createMockTool();

      const wrapped = adapterModule.signedTool(tool, { client });

      expect(wrapped).to.be.an.instanceOf(MockDynamicStructuredTool);
      expect(wrapped.name).to.equal('search');
      expect(wrapped.description).to.equal('Search the web');
      expect(wrapped.schema).to.equal(tool.schema);
    });

    (available ? it : it.skip)('should stash reference to original tool as _innerTool', () => {
      const client = createMockClient();
      const tool = createMockTool();

      const wrapped = adapterModule.signedTool(tool, { client });

      expect(wrapped._innerTool).to.equal(tool);
    });

    (available ? it : it.skip)('should invoke the original tool and sign its output', async () => {
      const client = createMockClient();
      const tool = createMockTool();

      const wrapped = adapterModule.signedTool(tool, { client });
      const result = await wrapped.invoke({ query: 'test' });

      expect(tool.invoke.calledOnce).to.be.true;
      expect(tool.invoke.firstCall.args[0]).to.deep.equal({ query: 'test' });
      expect(client.signMessage.calledOnce).to.be.true;

      const signArg = client.signMessage.firstCall.args[0];
      expect(signArg).to.have.property('tool', 'search');
      expect(signArg).to.have.property('result', 'search result');

      // Result should be the signed raw string
      expect(result).to.include('jacsId');
    });

    (available ? it : it.skip)('should JSON.stringify non-string tool results before signing', async () => {
      const client = createMockClient();
      const tool = createMockTool({
        invoke: sinon.stub().resolves({ data: [1, 2, 3] }),
      });

      const wrapped = adapterModule.signedTool(tool, { client });
      await wrapped.invoke({});

      const signArg = client.signMessage.firstCall.args[0];
      expect(signArg.result).to.equal('{"data":[1,2,3]}');
    });

    (available ? it : it.skip)('should pass through unsigned result on signing failure (permissive mode)', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Key expired')),
      });
      const tool = createMockTool();

      const consoleStub = sinon.stub(console, 'error');
      try {
        const wrapped = adapterModule.signedTool(tool, { client, strict: false });
        const result = await wrapped.invoke({ query: 'test' });

        expect(result).to.equal('search result');
        expect(consoleStub.calledWithMatch('[jacs/langchain] signing failed:')).to.be.true;
      } finally {
        consoleStub.restore();
      }
    });

    (available ? it : it.skip)('should throw on signing failure in strict mode', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Key expired')),
      });
      const tool = createMockTool();

      const wrapped = adapterModule.signedTool(tool, { client, strict: true });

      try {
        await wrapped.invoke({ query: 'test' });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Key expired');
      }
    });

    (available ? it : it.skip)('should use default name when tool has no name', () => {
      const client = createMockClient();
      const tool = createMockTool({ name: undefined });

      const wrapped = adapterModule.signedTool(tool, { client });
      expect(wrapped.name).to.equal('jacs_tool');
    });
  });

  // =========================================================================
  // jacsWrapToolCall
  // =========================================================================

  describe('jacsWrapToolCall()', () => {
    (available ? it : it.skip)('should return a function', () => {
      const client = createMockClient();
      const wrapFn = adapterModule.jacsWrapToolCall({ client });

      expect(wrapFn).to.be.a('function');
    });

    (available ? it : it.skip)('should execute runnable and sign the ToolMessage content', async () => {
      const client = createMockClient();
      const wrapFn = adapterModule.jacsWrapToolCall({ client });

      const toolMessage = new MockToolMessage({
        content: 'tool output',
        tool_call_id: 'call-1',
        name: 'search',
      });
      const runnable = { invoke: sinon.stub().resolves(toolMessage) };
      const toolCall = { name: 'search', args: { query: 'test' } };

      const result = await wrapFn(toolCall, runnable);

      expect(runnable.invoke.calledOnce).to.be.true;
      expect(runnable.invoke.firstCall.args[0]).to.equal(toolCall);
      expect(client.signMessage.calledOnce).to.be.true;

      const signArg = client.signMessage.firstCall.args[0];
      expect(signArg).to.have.property('tool', 'search');
      expect(signArg).to.have.property('content', 'tool output');

      // Result should be a new ToolMessage with signed content
      expect(result).to.be.an.instanceOf(MockToolMessage);
      expect(result.content).to.include('jacsId');
      expect(result.tool_call_id).to.equal('call-1');
      expect(result.name).to.equal('search');
    });

    (available ? it : it.skip)('should JSON.stringify non-string content', async () => {
      const client = createMockClient();
      const wrapFn = adapterModule.jacsWrapToolCall({ client });

      const toolMessage = new MockToolMessage({
        content: { key: 'value' },
        tool_call_id: 'call-2',
        name: 'fetch',
      });
      const runnable = { invoke: sinon.stub().resolves(toolMessage) };
      const toolCall = { name: 'fetch' };

      await wrapFn(toolCall, runnable);

      const signArg = client.signMessage.firstCall.args[0];
      expect(signArg.content).to.equal('{"key":"value"}');
    });

    (available ? it : it.skip)('should pass through result unchanged when content is undefined', async () => {
      const client = createMockClient();
      const wrapFn = adapterModule.jacsWrapToolCall({ client });

      const rawResult = { someOtherField: 'data' };
      const runnable = { invoke: sinon.stub().resolves(rawResult) };

      const result = await wrapFn({}, runnable);

      expect(result).to.equal(rawResult);
      expect(client.signMessage.called).to.be.false;
    });

    (available ? it : it.skip)('should pass through on signing failure in permissive mode', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Transient error')),
      });
      const wrapFn = adapterModule.jacsWrapToolCall({ client, strict: false });

      const toolMessage = new MockToolMessage({
        content: 'output',
        tool_call_id: 'call-3',
        name: 'tool_a',
      });
      const runnable = { invoke: sinon.stub().resolves(toolMessage) };

      const consoleStub = sinon.stub(console, 'error');
      try {
        const result = await wrapFn({ name: 'tool_a' }, runnable);

        expect(result).to.equal(toolMessage);
        expect(consoleStub.calledWithMatch('[jacs/langchain] signing failed:')).to.be.true;
      } finally {
        consoleStub.restore();
      }
    });

    (available ? it : it.skip)('should throw on signing failure in strict mode', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Strict failure')),
      });
      const wrapFn = adapterModule.jacsWrapToolCall({ client, strict: true });

      const toolMessage = new MockToolMessage({
        content: 'output',
        tool_call_id: 'call-4',
        name: 'tool_b',
      });
      const runnable = { invoke: sinon.stub().resolves(toolMessage) };

      try {
        await wrapFn({ name: 'tool_b' }, runnable);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Strict failure');
      }
    });

    (available ? it : it.skip)('should use toolCall.name for signing metadata', async () => {
      const client = createMockClient();
      const wrapFn = adapterModule.jacsWrapToolCall({ client });

      const toolMessage = new MockToolMessage({
        content: 'output',
        tool_call_id: 'call-5',
        name: 'result_name',
      });
      const runnable = { invoke: sinon.stub().resolves(toolMessage) };

      await wrapFn({ name: 'call_name' }, runnable);

      const signArg = client.signMessage.firstCall.args[0];
      expect(signArg.tool).to.equal('call_name');
    });
  });

  // =========================================================================
  // jacsToolNode
  // =========================================================================

  describe('jacsToolNode()', () => {
    (available ? it : it.skip)('should return a ToolNode with wrapped tools', () => {
      const client = createMockClient();
      const tool1 = createMockTool({ name: 'tool1' });
      const tool2 = createMockTool({ name: 'tool2' });

      const node = adapterModule.jacsToolNode([tool1, tool2], { client });

      expect(node).to.be.an.instanceOf(MockToolNode);
      expect(node.tools).to.have.length(2);
      expect(node.handleToolErrors).to.be.true;
    });

    (available ? it : it.skip)('should wrap each tool with signedTool', () => {
      const client = createMockClient();
      const tool1 = createMockTool({ name: 'alpha' });
      const tool2 = createMockTool({ name: 'beta' });

      const node = adapterModule.jacsToolNode([tool1, tool2], { client });

      // Each tool in the node should be a DynamicStructuredTool wrapping the original
      expect(node.tools[0]).to.be.an.instanceOf(MockDynamicStructuredTool);
      expect(node.tools[0].name).to.equal('alpha');
      expect(node.tools[0]._innerTool).to.equal(tool1);
      expect(node.tools[1].name).to.equal('beta');
      expect(node.tools[1]._innerTool).to.equal(tool2);
    });

    (available ? it : it.skip)('should work with an empty tools array', () => {
      const client = createMockClient();
      const node = adapterModule.jacsToolNode([], { client });

      expect(node).to.be.an.instanceOf(MockToolNode);
      expect(node.tools).to.have.length(0);
    });
  });

  // =========================================================================
  // createJacsTools
  // =========================================================================

  describe('createJacsTools()', () => {
    (available ? it : it.skip)('should return an array of 11 tools', () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });

      expect(tools).to.be.an('array');
      expect(tools).to.have.length(11);
    });

    (available ? it : it.skip)('should include all expected tool names', () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const names = tools.map(t => t.name);

      expect(names).to.include('jacs_sign');
      expect(names).to.include('jacs_verify');
      expect(names).to.include('jacs_create_agreement');
      expect(names).to.include('jacs_sign_agreement');
      expect(names).to.include('jacs_check_agreement');
      expect(names).to.include('jacs_verify_self');
      expect(names).to.include('jacs_trust_agent');
      expect(names).to.include('jacs_list_trusted');
      expect(names).to.include('jacs_is_trusted');
      expect(names).to.include('jacs_audit');
      expect(names).to.include('jacs_agent_info');
    });

    (available ? it : it.skip)('jacs_sign tool should call client.signMessage', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const signTool = tools.find(t => t.name === 'jacs_sign');

      const result = await signTool.invoke({ data: '{"action":"approve"}' });
      const parsed = JSON.parse(result);

      expect(client.signMessage.calledOnce).to.be.true;
      expect(client.signMessage.firstCall.args[0]).to.deep.equal({ action: 'approve' });
      expect(parsed).to.have.property('documentId', 'doc-1:1');
      expect(parsed).to.have.property('agentId', 'agent-a');
    });

    (available ? it : it.skip)('jacs_verify tool should call client.verify', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const verifyTool = tools.find(t => t.name === 'jacs_verify');

      const result = await verifyTool.invoke({ document: '{"jacsId":"doc-1:1"}' });
      const parsed = JSON.parse(result);

      expect(client.verify.calledOnce).to.be.true;
      expect(parsed).to.have.property('valid', true);
      expect(parsed).to.have.property('signerId', 'agent-b');
    });

    (available ? it : it.skip)('jacs_create_agreement tool should call client.createAgreement', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const agrTool = tools.find(t => t.name === 'jacs_create_agreement');

      const result = await agrTool.invoke({
        document: '{"action":"deploy"}',
        agentIds: ['agent-b', 'agent-c'],
        question: 'Approve?',
        quorum: 2,
      });
      const parsed = JSON.parse(result);

      expect(client.createAgreement.calledOnce).to.be.true;
      const [doc, ids, opts] = client.createAgreement.firstCall.args;
      expect(doc).to.deep.equal({ action: 'deploy' });
      expect(ids).to.deep.equal(['agent-b', 'agent-c']);
      expect(opts).to.have.property('question', 'Approve?');
      expect(opts).to.have.property('quorum', 2);
      expect(parsed).to.have.property('documentId', 'agr-1:1');
    });

    (available ? it : it.skip)('jacs_sign_agreement tool should call client.signAgreement', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const signAgrTool = tools.find(t => t.name === 'jacs_sign_agreement');

      const result = await signAgrTool.invoke({ document: '{"jacsAgreement":{}}' });
      const parsed = JSON.parse(result);

      expect(client.signAgreement.calledOnce).to.be.true;
      expect(parsed).to.have.property('documentId', 'agr-1:2');
    });

    (available ? it : it.skip)('jacs_check_agreement tool should call client.checkAgreement', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const checkTool = tools.find(t => t.name === 'jacs_check_agreement');

      const result = await checkTool.invoke({ document: '{"jacsAgreement":{}}' });
      const parsed = JSON.parse(result);

      expect(client.checkAgreement.calledOnce).to.be.true;
      expect(parsed).to.have.property('complete', false);
      expect(parsed).to.have.property('signedCount', 1);
      expect(parsed).to.have.property('totalRequired', 2);
    });

    (available ? it : it.skip)('jacs_verify_self tool should call client.verifySelf', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const selfTool = tools.find(t => t.name === 'jacs_verify_self');

      const result = await selfTool.invoke({});
      const parsed = JSON.parse(result);

      expect(client.verifySelf.calledOnce).to.be.true;
      expect(parsed).to.have.property('valid', true);
    });

    (available ? it : it.skip)('jacs_trust_agent tool should call client.trustAgent', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const trustTool = tools.find(t => t.name === 'jacs_trust_agent');

      const result = await trustTool.invoke({ agentJson: '{"id":"agent-b"}' });
      const parsed = JSON.parse(result);

      expect(client.trustAgent.calledOnce).to.be.true;
      expect(parsed).to.have.property('success', true);
    });

    (available ? it : it.skip)('jacs_list_trusted tool should call client.listTrustedAgents', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const listTool = tools.find(t => t.name === 'jacs_list_trusted');

      const result = await listTool.invoke({});
      const parsed = JSON.parse(result);

      expect(client.listTrustedAgents.calledOnce).to.be.true;
      expect(parsed.trustedAgents).to.deep.equal(['agent-b', 'agent-c']);
    });

    (available ? it : it.skip)('jacs_is_trusted tool should call client.isTrusted', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const isTrustedTool = tools.find(t => t.name === 'jacs_is_trusted');

      const result = await isTrustedTool.invoke({ agentId: 'agent-b' });
      const parsed = JSON.parse(result);

      expect(client.isTrusted.calledOnce).to.be.true;
      expect(parsed).to.have.property('agentId', 'agent-b');
      expect(parsed).to.have.property('trusted', true);
    });

    (available ? it : it.skip)('jacs_audit tool should call client.audit', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const auditTool = tools.find(t => t.name === 'jacs_audit');

      const result = await auditTool.invoke({ recentN: 10 });
      const parsed = JSON.parse(result);

      expect(client.audit.calledOnce).to.be.true;
      expect(parsed).to.have.property('status', 'ok');
    });

    (available ? it : it.skip)('jacs_agent_info tool should return agent metadata', async () => {
      const client = createMockClient();
      const tools = adapterModule.createJacsTools({ client });
      const infoTool = tools.find(t => t.name === 'jacs_agent_info');

      const result = await infoTool.invoke({});
      const parsed = JSON.parse(result);

      expect(parsed).to.have.property('agentId', 'agent-a');
      expect(parsed).to.have.property('name', 'test-agent');
    });

    (available ? it : it.skip)('tools should return error JSON in permissive mode', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Boom')),
      });
      const tools = adapterModule.createJacsTools({ client, strict: false });
      const signTool = tools.find(t => t.name === 'jacs_sign');

      const result = await signTool.invoke({ data: '{"x":1}' });
      const parsed = JSON.parse(result);

      expect(parsed).to.have.property('error');
      expect(parsed.error).to.include('Boom');
    });

    (available ? it : it.skip)('tools should throw in strict mode', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Strict boom')),
      });
      const tools = adapterModule.createJacsTools({ client, strict: true });
      const signTool = tools.find(t => t.name === 'jacs_sign');

      try {
        await signTool.invoke({ data: '{"x":1}' });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Strict boom');
      }
    });
  });

  // =========================================================================
  // Lazy import error messages
  // =========================================================================

  describe('lazy import errors', () => {
    (available ? it : it.skip)('signedTool should throw clear error when @langchain/core is missing', () => {
      requireInterceptEnabled = false;
      try {
        adapterModule.signedTool(createMockTool(), { client: createMockClient() });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.include('@langchain/core is required');
        expect(err.message).to.include('npm install');
      } finally {
        requireInterceptEnabled = true;
      }
    });

    (available ? it : it.skip)('createJacsTools should throw clear error when @langchain/core is missing', () => {
      requireInterceptEnabled = false;
      try {
        adapterModule.createJacsTools({ client: createMockClient() });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.include('@langchain/core is required');
        expect(err.message).to.include('npm install');
      } finally {
        requireInterceptEnabled = true;
      }
    });

    (available ? it : it.skip)('jacsToolNode should throw clear error when @langchain/langgraph is missing', () => {
      requireInterceptEnabled = false;
      try {
        adapterModule.jacsToolNode([], { client: createMockClient() });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.include('@langchain/langgraph is required');
        expect(err.message).to.include('npm install');
      } finally {
        requireInterceptEnabled = true;
      }
    });
  });
});
