/**
 * Tests for Vercel AI adapter A2A metadata - Task #42 [2.9.4]
 *
 * Validates:
 * - a2a: true includes agent card in wrapGenerate provenance metadata
 * - a2a: true includes agent card in wrapStream provenance metadata
 * - a2a: false (default) does not include agent card
 */

const { expect } = require('chai');
const sinon = require('sinon');

let adapterModule;
try {
  adapterModule = require('../vercel-ai.js');
} catch (e) {
  adapterModule = null;
}

describe('Vercel AI Adapter A2A Metadata - [2.9.4]', function () {
  this.timeout(15000);

  const available = adapterModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping - vercel-ai.js not compiled');
      this.skip();
    }
  });

  function createMockClient(overrides = {}) {
    return {
      signMessage: sinon.stub().resolves({
        raw: '{"jacsId":"doc-a2a:1","jacsSignature":{"agentID":"a2a-agent","date":"2026-01-01T00:00:00Z"}}',
        documentId: 'doc-a2a:1',
        agentId: 'a2a-agent',
        timestamp: '2026-01-01T00:00:00Z',
      }),
      agentId: overrides.agentId || 'a2a-agent-id',
      name: overrides.name || 'A2A Test Agent',
      _agent: { signRequest: sinon.stub(), verifyResponse: sinon.stub() },
      isTrusted: sinon.stub().returns(false),
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

  // -------------------------------------------------------------------------
  // wrapGenerate with a2a: true
  // -------------------------------------------------------------------------
  describe('wrapGenerate with a2a: true', () => {
    (available ? it : it.skip)('should include agentCard in provenance metadata', async () => {
      const client = createMockClient({ agentId: 'vercel-a2a-1', name: 'Vercel A2A Agent' });
      const middleware = adapterModule.jacsProvenance({ client, a2a: true });

      const mockResult = createMockGenerateResult('Hello from A2A!');
      const doGenerate = sinon.stub().resolves(mockResult);

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      expect(result.providerMetadata.jacs).to.have.property('agentCard');
      const card = result.providerMetadata.jacs.agentCard;
      expect(card.name).to.equal('Vercel A2A Agent');
      expect(card.protocolVersions).to.include('0.4.0');
      expect(card.capabilities).to.have.property('extensions');
      // Signing should still work alongside A2A
      expect(result.providerMetadata.jacs.text).to.deep.include({ signed: true });
    });
  });

  // -------------------------------------------------------------------------
  // wrapStream with a2a: true
  // -------------------------------------------------------------------------
  describe('wrapStream with a2a: true', () => {
    (available ? it : it.skip)('should include agentCard in stream provenance metadata', async () => {
      const client = createMockClient({ agentId: 'stream-a2a-1', name: 'Stream A2A Agent' });
      const middleware = adapterModule.jacsProvenance({ client, a2a: true });

      const chunks = [
        { type: 'text-delta', textDelta: 'Streamed' },
        { type: 'text-delta', textDelta: ' response' },
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

      // Consume the stream
      const reader = result.stream.getReader();
      const received = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received.push(value);
      }

      // Last chunk should be provider-metadata with agentCard
      const metaChunk = received[received.length - 1];
      expect(metaChunk.type).to.equal('provider-metadata');
      expect(metaChunk.providerMetadata.jacs).to.have.property('agentCard');
      expect(metaChunk.providerMetadata.jacs.agentCard.name).to.equal('Stream A2A Agent');
      // Text signing should also be present
      expect(metaChunk.providerMetadata.jacs.text).to.deep.include({ signed: true });
    });
  });

  // -------------------------------------------------------------------------
  // a2a: false (default) does not include agent card
  // -------------------------------------------------------------------------
  describe('a2a: false (default)', () => {
    (available ? it : it.skip)('should not include agentCard when a2a is not enabled', async () => {
      const client = createMockClient();
      const middleware = adapterModule.jacsProvenance({ client });

      const mockResult = createMockGenerateResult('No A2A');
      const doGenerate = sinon.stub().resolves(mockResult);

      const result = await middleware.wrapGenerate({
        doGenerate,
        doStream: sinon.stub(),
        params: { prompt: [] },
        model: {},
      });

      expect(result.providerMetadata.jacs).to.not.have.property('agentCard');
    });
  });
});
