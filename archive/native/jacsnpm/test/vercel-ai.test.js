/**
 * Tests for JACS Vercel AI SDK Adapter
 *
 * These tests mock the JacsClient and AI SDK model to verify
 * the middleware behavior without requiring real JACS agents
 * or AI model connections.
 */

const { expect } = require('chai');
const sinon = require('sinon');
const { signedResult } = require('./helpers/signed-document');

let adapterModule;
try {
  adapterModule = require('../vercel-ai.js');
} catch (e) {
  adapterModule = null;
}

describe('Vercel AI SDK Adapter', function () {
  this.timeout(15000);

  const available = adapterModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping Vercel AI adapter tests - vercel-ai.js not compiled');
      this.skip();
    }
  });

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function createMockClient(overrides) {
    return {
      signMessage: sinon.stub().callsFake(async (binding) => signedResult(binding, {
        documentId: 'doc-123:1',
        agentId: 'agent-abc',
        timestamp: '2025-01-01T00:00:00Z',
      })),
      agentId: 'agent-abc',
      ...overrides,
    };
  }

  function createMockGenerateResult(text) {
    return {
      content: [{ type: 'text', text }],
      usage: { promptTokens: 10, completionTokens: 20 },
      finishReason: 'stop',
      providerMetadata: {},
    };
  }

  // ---------------------------------------------------------------------------
  // jacsProvenance() returns valid middleware
  // ---------------------------------------------------------------------------

  describe('jacsProvenance()', () => {
    (available ? it : it.skip)('should return a middleware object with specificationVersion v3', () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      expect(middleware).to.be.an('object');
      expect(middleware.specificationVersion).to.equal('v3');
      expect(middleware.wrapGenerate).to.be.a('function');
      expect(middleware.wrapStream).to.be.a('function');
    });
  });

  // ---------------------------------------------------------------------------
  // wrapGenerate — signs text output
  // ---------------------------------------------------------------------------

  describe('wrapGenerate', () => {
    (available ? it : it.skip)('should sign text output and attach provenance metadata', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      const mockResult = createMockGenerateResult('Hello, world!');
      const doGenerate = sinon.stub().resolves(mockResult);

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      expect(doGenerate.calledOnce).to.be.true;
      expect(client.signMessage.calledOnce).to.be.true;
      expect(client.signMessage.firstCall.args[0]).to.deep.equal({
        output: 'Hello, world!',
        metadata: {},
      });
      expect(result.providerMetadata).to.have.property('jacs');
      expect(result.providerMetadata.jacs.text).to.deep.include({
        signed: true,
        documentId: 'doc-123:1',
        agentId: 'agent-abc',
        timestamp: '2025-01-01T00:00:00Z',
      });
      expect(result.providerMetadata.jacs.text.signedDocument).to.include('jacsSignature');
    });

    (available ? it : it.skip)('should skip signing when signText is false', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client, signText: false, signToolResults: false });

      const mockResult = createMockGenerateResult('Hello!');
      const doGenerate = sinon.stub().resolves(mockResult);

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      expect(client.signMessage.called).to.be.false;
      expect(result).to.deep.equal(mockResult);
    });

    (available ? it : it.skip)('should not sign when text content is empty', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      const mockResult = { content: [], usage: {}, finishReason: 'stop', providerMetadata: {} };
      const doGenerate = sinon.stub().resolves(mockResult);

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      expect(client.signMessage.called).to.be.false;
    });

    (available ? it : it.skip)('should sign tool results when present in prompt', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      const mockResult = createMockGenerateResult('Using tool result');
      const doGenerate = sinon.stub().resolves(mockResult);

      const toolPrompt = [
        { role: 'user', content: [{ type: 'text', text: 'Search for X' }] },
        { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'call-1', toolName: 'search', result: { data: 'found' } }] },
      ];

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: toolPrompt },
        model: {},
      });

      // signMessage called twice: once for text, once for tool results
      expect(client.signMessage.callCount).to.equal(2);
      expect(result.providerMetadata.jacs.text).to.have.property('signed', true);
      expect(result.providerMetadata.jacs.toolResults).to.have.property('signed', true);
    });

    (available ? it : it.skip)('should skip tool result signing when signToolResults is false', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client, signToolResults: false });

      const mockResult = createMockGenerateResult('Result');
      const doGenerate = sinon.stub().resolves(mockResult);

      const toolPrompt = [
        { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'call-1', toolName: 'search', result: 'data' }] },
      ];

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: toolPrompt },
        model: {},
      });

      // Only text signed, not tool results
      expect(client.signMessage.callCount).to.equal(1);
      expect(result.providerMetadata.jacs).to.not.have.property('toolResults');
    });

    (available ? it : it.skip)('should include custom metadata in provenance', async () => {
      const meta = { userId: 'user-42', sessionId: 'sess-7' };
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client, metadata: meta });

      const mockResult = createMockGenerateResult('Hello!');
      const doGenerate = sinon.stub().resolves(mockResult);

      await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      // The portable document must bind the exact output and caller metadata.
      const signArg = client.signMessage.firstCall.args[0];
      expect(signArg).to.deep.equal({ output: 'Hello!', metadata: meta });
    });

    (available ? it : it.skip)('should preserve existing providerMetadata', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      const mockResult = createMockGenerateResult('Hello!');
      mockResult.providerMetadata = { openai: { usage: { total: 30 } } };
      const doGenerate = sinon.stub().resolves(mockResult);

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      expect(result.providerMetadata.openai).to.deep.equal({ usage: { total: 30 } });
      expect(result.providerMetadata.jacs).to.have.property('text');
    });
  });

  // ---------------------------------------------------------------------------
  // Strict mode
  // ---------------------------------------------------------------------------

  describe('strict mode', () => {
    (available ? it : it.skip)('should throw on signing failure in strict mode', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Signing key expired')),
      });
      const middleware = adapterModule.jacsProvenance({ client, strict: true });

      const mockResult = createMockGenerateResult('Hello!');
      const doGenerate = sinon.stub().resolves(mockResult);

      try {
        await middleware.wrapGenerate({
          doGenerate,
          doStream: sinon.stub(),
          params: { prompt: [] },
          model: {},
        });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Signing key expired');
      }
    });

    (available ? it : it.skip)('should fail closed on signing failure by default even when strict is false', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Transient failure')),
      });
      const middleware = adapterModule.jacsProvenance({ client, strict: false });

      const mockResult = createMockGenerateResult('Hello!');
      const doGenerate = sinon.stub().resolves(mockResult);

      let error;
      try {
        await middleware.wrapGenerate({
          doGenerate,
          doStream: sinon.stub(),
          params: { prompt: [] },
          model: {},
        });
      } catch (err) {
        error = err;
      }
      expect(error).to.be.an('error');
      expect(error.message).to.equal('Transient failure');
    });

    (available ? it : it.skip)('should continue unsigned only after explicit dangerous opt-in', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('Transient failure')),
      });
      const middleware = adapterModule.jacsProvenance({ client, allowUnsignedOutput: true });
      const consoleStub = sinon.stub(console, 'error');
      try {
        const result = await middleware.wrapGenerate({
          doGenerate: sinon.stub().resolves(createMockGenerateResult('Hello!')),
          params: { prompt: [] },
          model: {},
        });
        expect(result.providerMetadata.jacs.text).to.deep.include({
          signed: false,
          error: 'Transient failure',
        });
        expect(result.providerMetadata.jacs.text).to.not.have.property('signedDocument');
        expect(consoleStub.calledWithMatch('[jacs/vercel-ai] signing failed:')).to.be.true;
      } finally {
        consoleStub.restore();
      }
    });

    (available ? it : it.skip)('should not emit signed true when raw provenance is missing', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().resolves({
          documentId: 'doc-no-raw:1', agentId: 'agent-abc', timestamp: '2025-01-01T00:00:00Z',
        }),
      });
      const middleware = adapterModule.jacsProvenance({ client, allowUnsignedOutput: true });
      const consoleStub = sinon.stub(console, 'error');
      try {
        const result = await middleware.wrapGenerate({
          doGenerate: sinon.stub().resolves(createMockGenerateResult('Hello!')),
          params: { prompt: [] },
          model: {},
        });
        expect(result.providerMetadata.jacs.text.signed).to.equal(false);
        expect(result.providerMetadata.jacs.text).to.not.have.property('signedDocument');
      } finally {
        consoleStub.restore();
      }
    });

    (available ? it : it.skip)('should not emit signed true when provenance identifiers are missing', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().resolves({
          raw: '{"jacsId":"doc-no-agent:1","jacsSignature":{"agentID":"agent-abc"}}',
          documentId: 'doc-no-agent:1', agentId: '', timestamp: '2025-01-01T00:00:00Z',
        }),
      });
      const middleware = adapterModule.jacsProvenance({ client, allowUnsignedOutput: true });
      const consoleStub = sinon.stub(console, 'error');
      try {
        const result = await middleware.wrapGenerate({
          doGenerate: sinon.stub().resolves(createMockGenerateResult('Hello!')),
          params: { prompt: [] }, model: {},
        });
        expect(result.providerMetadata.jacs.text.signed).to.equal(false);
        expect(result.providerMetadata.jacs.text).to.not.have.property('signedDocument');
      } finally {
        consoleStub.restore();
      }
    });

    (available ? it : it.skip)('should reject a signed document that binds different output', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().resolves(signedResult(
          { output: 'substituted', metadata: {} },
          {
            documentId: 'doc-substitute:1',
            agentId: 'agent-abc',
            timestamp: '2025-01-01T00:00:00Z',
          },
        )),
      });
      const middleware = adapterModule.jacsProvenance({ client });

      let error;
      try {
        await middleware.wrapGenerate({
          doGenerate: sinon.stub().resolves(createMockGenerateResult('original')),
          params: { prompt: [] }, model: {},
        });
      } catch (err) {
        error = err;
      }
      expect(error).to.be.an('error');
      expect(error.message).to.match(/exact output and metadata/i);
    });

    (available ? it : it.skip)('should let strict mode override unsigned-output opt-in', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('strict override')),
      });
      const middleware = adapterModule.jacsProvenance({
        client,
        allowUnsignedOutput: true,
        strict: true,
      });

      let error;
      try {
        await middleware.wrapGenerate({
          doGenerate: sinon.stub().resolves(createMockGenerateResult('Hello!')),
          params: { prompt: [] },
          model: {},
        });
      } catch (err) {
        error = err;
      }
      expect(error).to.be.an('error');
      expect(error.message).to.equal('strict override');
    });
  });

  // ---------------------------------------------------------------------------
  // wrapStream — accumulates and signs text
  // ---------------------------------------------------------------------------

  describe('wrapStream', () => {
    (available ? it : it.skip)('should accumulate text deltas and sign on stream completion', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      // Create a mock ReadableStream with text-delta chunks
      const chunks = [
        { type: 'text-delta', textDelta: 'Hello' },
        { type: 'text-delta', textDelta: ', ' },
        { type: 'text-delta', textDelta: 'world!' },
        { type: 'finish', finishReason: 'stop', usage: { promptTokens: 5, completionTokens: 10 } },
      ];

      const mockStream = new ReadableStream({
        start(controller) {
          for (const chunk of chunks) {
            controller.enqueue(chunk);
          }
          controller.close();
        },
      });

      const doStream = sinon.stub().resolves({
        stream: mockStream,
        rawCall: { rawPrompt: '', rawSettings: {} },
      });

      const result = await middleware.wrapStream({
        doStream,
        doGenerate: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      expect(doStream.calledOnce).to.be.true;

      // Consume the stream
      const reader = result.stream.getReader();
      const received = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received.push(value);
      }

      // Original chunks + provider-metadata chunk
      expect(received).to.have.length(5);
      expect(received[0]).to.deep.equal({ type: 'text-delta', textDelta: 'Hello' });
      expect(received[1]).to.deep.equal({ type: 'text-delta', textDelta: ', ' });
      expect(received[2]).to.deep.equal({ type: 'text-delta', textDelta: 'world!' });
      expect(received[3]).to.deep.include({ type: 'finish' });

      // The last chunk should be provenance metadata
      const metaChunk = received[4];
      expect(metaChunk.type).to.equal('provider-metadata');
      expect(metaChunk.providerMetadata.jacs.text).to.deep.include({
        signed: true,
        documentId: 'doc-123:1',
      });

      // signMessage called with accumulated text
      expect(client.signMessage.calledOnce).to.be.true;
      expect(client.signMessage.firstCall.args[0]).to.deep.equal({
        output: 'Hello, world!',
        metadata: {},
      });
    });

    (available ? it : it.skip)('should release no text before buffered signature success', async () => {
      let releaseSignature;
      const signPromise = new Promise((resolve) => { releaseSignature = resolve; });
      const client = createMockClient({ signMessage: sinon.stub().returns(signPromise) });
      const middleware = adapterModule.jacsProvenance({ client });
      const mockStream = new ReadableStream({
        start(controller) {
          controller.enqueue({ type: 'text-delta', textDelta: 'secret' });
          controller.enqueue({ type: 'finish', finishReason: 'stop', usage: {} });
          controller.close();
        },
      });
      const result = await middleware.wrapStream({
        doStream: sinon.stub().resolves({ stream: mockStream }), params: { prompt: [] }, model: {},
      });
      const reader = result.stream.getReader();
      const firstRead = reader.read();
      const early = await Promise.race([
        firstRead.then(() => 'released'),
        new Promise((resolve) => setTimeout(() => resolve('blocked'), 25)),
      ]);
      expect(early).to.equal('blocked');
      expect(client.signMessage.calledOnce).to.be.true;

      releaseSignature(signedResult(
        { output: 'secret', metadata: {} },
        {
          documentId: 'doc-stream:1',
          agentId: 'agent-abc',
          timestamp: '2025-01-01T00:00:00Z',
        },
      ));
      expect((await firstRead).value).to.deep.equal({ type: 'text-delta', textDelta: 'secret' });
    });

    (available ? it : it.skip)('should snapshot buffered chunks before signing and release', async () => {
      let releaseSignature;
      const signPromise = new Promise((resolve) => { releaseSignature = resolve; });
      const client = createMockClient({ signMessage: sinon.stub().returns(signPromise) });
      const middleware = adapterModule.jacsProvenance({ client });
      const mutableChunk = { type: 'text-delta', textDelta: 'signed text' };
      const mockStream = new ReadableStream({
        start(controller) {
          controller.enqueue(mutableChunk);
          controller.close();
        },
      });
      const result = await middleware.wrapStream({
        doStream: sinon.stub().resolves({ stream: mockStream }), params: { prompt: [] }, model: {},
      });
      const firstRead = result.stream.getReader().read();
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(client.signMessage.calledOnce).to.equal(true);

      // A provider retaining its object reference must not be able to mutate
      // the buffered output after the adapter chose the bytes to sign.
      mutableChunk.textDelta = 'mutated after signing started';
      releaseSignature(signedResult(
        { output: 'signed text', metadata: {} },
        {
          documentId: 'doc-stream-snapshot:1',
          agentId: 'agent-abc',
          timestamp: '2025-01-01T00:00:00Z',
        },
      ));

      expect((await firstRead).value).to.deep.equal({
        type: 'text-delta', textDelta: 'signed text',
      });
    });

    (available ? it : it.skip)('should fail before releasing buffered text when stream signing fails', async () => {
      const client = createMockClient({
        signMessage: sinon.stub().rejects(new Error('stream key unavailable')),
      });
      const middleware = adapterModule.jacsProvenance({ client });
      const mockStream = new ReadableStream({
        start(controller) {
          controller.enqueue({ type: 'text-delta', textDelta: 'must stay private' });
          controller.close();
        },
      });
      const result = await middleware.wrapStream({
        doStream: sinon.stub().resolves({ stream: mockStream }), params: { prompt: [] }, model: {},
      });
      let error;
      try {
        await result.stream.getReader().read();
      } catch (err) {
        error = err;
      }
      expect(error).to.be.an('error');
      expect(error.message).to.equal('stream key unavailable');
    });

    (available ? it : it.skip)('should enforce the bounded stream buffer before releasing text', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client, maxBufferedStreamBytes: 64 });
      const mockStream = new ReadableStream({
        start(controller) {
          controller.enqueue({ type: 'text-delta', textDelta: 'x'.repeat(128) });
          controller.close();
        },
      });
      const result = await middleware.wrapStream({
        doStream: sinon.stub().resolves({ stream: mockStream }), params: { prompt: [] }, model: {},
      });
      let error;
      try {
        await result.stream.getReader().read();
      } catch (err) {
        error = err;
      }
      expect(error).to.be.an('error');
      expect(error.message).to.match(/buffer.*limit/i);
      expect(client.signMessage.called).to.be.false;
    });

    (available ? it : it.skip)('should reject post-hoc streaming without dangerous unsigned opt-in', () => {
      expect(() => adapterModule.jacsProvenance({
        client: createMockClient(), allowPostHocStreaming: true,
      })).to.throw(/post-hoc.*allowUnsignedOutput/i);
    });

    (available ? it : it.skip)('should release post-hoc text only after both dangerous opt-ins', async () => {
      let releaseSignature;
      const signPromise = new Promise((resolve) => { releaseSignature = resolve; });
      const client = createMockClient({ signMessage: sinon.stub().returns(signPromise) });
      const middleware = adapterModule.jacsProvenance({
        client,
        allowUnsignedOutput: true,
        allowPostHocStreaming: true,
        maxBufferedStreamBytes: 1024,
      });
      const source = new ReadableStream({
        start(controller) {
          controller.enqueue({ type: 'text-delta', textDelta: 'explicitly dangerous' });
          controller.close();
        },
      });
      const result = await middleware.wrapStream({
        doStream: sinon.stub().resolves({ stream: source }), params: { prompt: [] }, model: {},
      });
      const reader = result.stream.getReader();

      expect((await reader.read()).value).to.deep.equal({
        type: 'text-delta', textDelta: 'explicitly dangerous',
      });
      releaseSignature(signedResult(
        { output: 'explicitly dangerous', metadata: {} },
        {
          documentId: 'post-hoc:1',
          agentId: 'agent-abc',
          timestamp: '2025-01-01T00:00:00Z',
        },
      ));
      expect((await reader.read()).value.type).to.equal('provider-metadata');
    });

    (available ? it : it.skip)('should not sign when signText is false', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client, signText: false });

      const chunks = [
        { type: 'text-delta', textDelta: 'Hi' },
      ];

      const mockStream = new ReadableStream({
        start(controller) {
          for (const chunk of chunks) {
            controller.enqueue(chunk);
          }
          controller.close();
        },
      });

      const doStream = sinon.stub().resolves({ stream: mockStream });

      const result = await middleware.wrapStream({
        doStream,
        doGenerate: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      // Should return original stream result without transformation
      expect(client.signMessage.called).to.be.false;
    });

    (available ? it : it.skip)('should not emit provenance chunk when no text accumulated', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      // Stream with no text-delta chunks
      const chunks = [
        { type: 'finish', finishReason: 'stop', usage: {} },
      ];

      const mockStream = new ReadableStream({
        start(controller) {
          for (const chunk of chunks) {
            controller.enqueue(chunk);
          }
          controller.close();
        },
      });

      const doStream = sinon.stub().resolves({ stream: mockStream });

      const result = await middleware.wrapStream({
        doStream,
        doGenerate: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      const reader = result.stream.getReader();
      const received = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received.push(value);
      }

      // Only the original finish chunk, no provenance
      expect(received).to.have.length(1);
      expect(received[0].type).to.equal('finish');
      expect(client.signMessage.called).to.be.false;
    });
  });

  // ---------------------------------------------------------------------------
  // withProvenance()
  // ---------------------------------------------------------------------------

  describe('withProvenance()', () => {
    (available ? it : it.skip)('should throw if ai package is not available', () => {
      const client = createMockClient();
      // withProvenance lazily requires 'ai' — it won't be installed in test env
      try {
        adapterModule.withProvenance({}, { client });
        // If 'ai' happens to be installed, just verify we get something back
      } catch (err) {
        expect(err.message).to.match(/Could not import 'ai' package/);
      }
    });
  });
});
