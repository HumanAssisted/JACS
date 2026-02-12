/**
 * Tests for JACS A2A Phase 2 - JacsClient integration (B-3/B-4/B-6 fixes)
 *
 * Validates:
 * - Constructor accepts JacsClient (not config path)
 * - signRequest used via client._agent (B-3)
 * - verifyResponse used via client._agent with JSON.stringify (B-4)
 * - crypto.createHash('sha256') replaces jacs.hashString (B-5 related)
 * - wrapArtifactWithProvenance is async
 * - verifyWrappedArtifact is async
 * - JACS_ALGORITHMS has correct values (B-6)
 * - sha256 utility works correctly
 */

const { expect } = require('chai');
const sinon = require('sinon');
const crypto = require('crypto');
const {
  JACSA2AIntegration,
  A2AAgentCard,
  A2AAgentInterface,
  A2AAgentCapabilities,
  A2A_PROTOCOL_VERSION,
  JACS_EXTENSION_URI,
  JACS_ALGORITHMS,
  TRUST_POLICIES,
  DEFAULT_TRUST_POLICY,
  sha256
} = require('../src/a2a');

/**
 * Create a mock JacsClient with a mock _agent for testing.
 */
function createMockClient() {
  const mockAgent = {
    signRequest: sinon.stub(),
    verifyResponse: sinon.stub(),
  };
  return {
    _agent: mockAgent,
    agentId: 'test-agent-id',
    name: 'test-agent',
  };
}

describe('A2A Phase 2 - JacsClient Integration', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  // -------------------------------------------------------------------------
  // Test 1: Constructor accepts JacsClient
  // -------------------------------------------------------------------------
  describe('constructor', () => {
    it('should accept a JacsClient instance', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient);
      expect(integration.client).to.equal(mockClient);
    });

    it('should not require a config path', () => {
      const mockClient = createMockClient();
      // No config path, no jacs.load call - just a client reference
      const integration = new JACSA2AIntegration(mockClient);
      expect(integration.client._agent).to.exist;
    });
  });

  // -------------------------------------------------------------------------
  // Test 2: wrapArtifactWithProvenance is async and uses client._agent.signRequest (B-3)
  // -------------------------------------------------------------------------
  describe('wrapArtifactWithProvenance (B-3 fix)', () => {
    it('should return a Promise (async method)', async () => {
      const mockClient = createMockClient();
      const signedResult = {
        jacsId: 'wrapped-123',
        jacsType: 'a2a-task',
        a2aArtifact: { data: 'test' },
        jacsSignature: { agentID: 'test-agent', signature: 'sig' }
      };
      mockClient._agent.signRequest.returns(signedResult);

      const integration = new JACSA2AIntegration(mockClient);
      const result = integration.wrapArtifactWithProvenance({ data: 'test' }, 'task');

      // Must be a Promise
      expect(result).to.be.an.instanceOf(Promise);

      const resolved = await result;
      expect(resolved.jacsType).to.equal('a2a-task');
    });

    it('should call client._agent.signRequest (not jacs.legacySignRequest)', async () => {
      const mockClient = createMockClient();
      const artifact = { taskId: 'task-1', action: 'process' };
      const signedResult = {
        jacsId: 'wrapped-456',
        jacsType: 'a2a-task',
        a2aArtifact: artifact,
        jacsSignature: { agentID: 'agent-1' }
      };
      mockClient._agent.signRequest.returns(signedResult);

      const integration = new JACSA2AIntegration(mockClient);
      await integration.wrapArtifactWithProvenance(artifact, 'task');

      expect(mockClient._agent.signRequest.calledOnce).to.be.true;

      // Verify the wrapped document structure passed to signRequest
      const arg = mockClient._agent.signRequest.firstCall.args[0];
      expect(arg.jacsType).to.equal('a2a-task');
      expect(arg.jacsLevel).to.equal('artifact');
      expect(arg.a2aArtifact).to.deep.equal(artifact);
      expect(arg.$schema).to.equal('https://hai.ai/schemas/header/v1/header.schema.json');
    });

    it('should include parent signatures when provided', async () => {
      const mockClient = createMockClient();
      const parentSig = { jacsId: 'parent-1', jacsSignature: { agentID: 'parent-agent' } };
      mockClient._agent.signRequest.callsFake((wrapped) => ({
        ...wrapped,
        jacsSignature: { agentID: 'agent-1' }
      }));

      const integration = new JACSA2AIntegration(mockClient);
      await integration.wrapArtifactWithProvenance({ data: 'test' }, 'step', [parentSig]);

      const arg = mockClient._agent.signRequest.firstCall.args[0];
      expect(arg.jacsParentSignatures).to.deep.equal([parentSig]);
    });
  });

  // -------------------------------------------------------------------------
  // Test 3: verifyWrappedArtifact is async and uses client._agent.verifyResponse (B-4)
  // -------------------------------------------------------------------------
  describe('verifyWrappedArtifact (B-4 fix)', () => {
    it('should return a Promise (async method)', async () => {
      const mockClient = createMockClient();
      mockClient._agent.verifyResponse.returns(true);

      const wrappedArtifact = {
        jacsId: 'artifact-1',
        jacsType: 'a2a-task',
        jacsVersionDate: '2025-01-15T10:00:00Z',
        a2aArtifact: { data: 'test' },
        jacsSignature: { agentID: 'signer', agentVersion: 'v1', publicKeyHash: 'hash' }
      };

      const integration = new JACSA2AIntegration(mockClient);
      const result = integration.verifyWrappedArtifact(wrappedArtifact);

      expect(result).to.be.an.instanceOf(Promise);

      const resolved = await result;
      expect(resolved.valid).to.be.true;
      expect(resolved.signerId).to.equal('signer');
    });

    it('should call client._agent.verifyResponse with JSON.stringify', async () => {
      const mockClient = createMockClient();
      mockClient._agent.verifyResponse.returns(true);

      const wrappedArtifact = {
        jacsId: 'artifact-2',
        jacsType: 'a2a-message',
        a2aArtifact: { content: 'hello' },
        jacsSignature: { agentID: 'agent-2' }
      };

      const integration = new JACSA2AIntegration(mockClient);
      await integration.verifyWrappedArtifact(wrappedArtifact);

      expect(mockClient._agent.verifyResponse.calledOnce).to.be.true;

      // Verify it was called with a JSON string, not the raw object
      const arg = mockClient._agent.verifyResponse.firstCall.args[0];
      expect(typeof arg).to.equal('string');
      const parsed = JSON.parse(arg);
      expect(parsed.jacsId).to.equal('artifact-2');
    });

    it('should handle parent signature chain verification', async () => {
      const mockClient = createMockClient();
      // All verifications return true
      mockClient._agent.verifyResponse.returns(true);

      const parent = {
        jacsId: 'parent-1',
        jacsType: 'a2a-task',
        a2aArtifact: { step: 1 },
        jacsSignature: { agentID: 'parent-agent', agentVersion: 'v1' }
      };

      const child = {
        jacsId: 'child-1',
        jacsType: 'a2a-task',
        a2aArtifact: { step: 2 },
        jacsSignature: { agentID: 'child-agent', agentVersion: 'v1' },
        jacsParentSignatures: [parent]
      };

      const integration = new JACSA2AIntegration(mockClient);
      const result = await integration.verifyWrappedArtifact(child);

      expect(result.valid).to.be.true;
      expect(result.parentSignaturesCount).to.equal(1);
      expect(result.parentSignaturesValid).to.be.true;
      // verifyResponse called twice: once for child, once for parent
      expect(mockClient._agent.verifyResponse.callCount).to.equal(2);
    });
  });

  // -------------------------------------------------------------------------
  // Test 4: sha256 utility replaces jacs.hashString
  // -------------------------------------------------------------------------
  describe('sha256 utility', () => {
    it('should produce correct SHA-256 hex digest', () => {
      const input = 'test-public-key-data';
      const expected = crypto.createHash('sha256').update(input).digest('hex');
      expect(sha256(input)).to.equal(expected);
    });

    it('should be used in generateWellKnownDocuments instead of jacs.hashString', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient);

      const agentCard = new A2AAgentCard({
        name: 'Test', description: 'Test', version: '1.0.0',
        protocolVersions: ['0.4.0'],
        supportedInterfaces: [new A2AAgentInterface('https://example.com', 'jsonrpc')],
        defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
        capabilities: new A2AAgentCapabilities(), skills: []
      });

      const publicKeyB64 = 'dGVzdC1wdWJsaWMta2V5';
      const agentData = {
        jacsId: 'agent-1', jacsVersion: 'v1', jacsAgentType: 'ai', keyAlgorithm: 'RSA-PSS'
      };

      const documents = integration.generateWellKnownDocuments(
        agentCard, 'mock-jws', publicKeyB64, agentData
      );

      const expectedHash = crypto.createHash('sha256').update(publicKeyB64).digest('hex');
      expect(documents['/.well-known/jacs-agent.json'].publicKeyHash).to.equal(expectedHash);
      expect(documents['/.well-known/jacs-pubkey.json'].publicKeyHash).to.equal(expectedHash);
    });
  });

  // -------------------------------------------------------------------------
  // Test 5: JACS_ALGORITHMS has correct values (B-6 fix)
  // -------------------------------------------------------------------------
  describe('JACS_ALGORITHMS (B-6 fix)', () => {
    it('should export the correct algorithm list', () => {
      expect(JACS_ALGORITHMS).to.deep.equal([
        'ring-Ed25519', 'RSA-PSS', 'pq-dilithium', 'pq2025'
      ]);
    });

    it('should use JACS_ALGORITHMS in extension descriptor', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient);
      const descriptor = integration.createExtensionDescriptor();

      expect(descriptor.capabilities.documentSigning.algorithms).to.deep.equal(JACS_ALGORITHMS);
    });

    it('should list only post-quantum algorithms in postQuantumCrypto', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient);
      const descriptor = integration.createExtensionDescriptor();

      expect(descriptor.capabilities.postQuantumCrypto.algorithms).to.deep.equal([
        'pq-dilithium', 'pq2025'
      ]);
    });
  });

  // -------------------------------------------------------------------------
  // Test 6: No jacs module import (removed dependency)
  // -------------------------------------------------------------------------
  describe('module independence', () => {
    it('should not import the jacs index module', () => {
      // Read the source and strip comments, then check for legacy calls
      const fs = require('fs');
      const path = require('path');
      const source = fs.readFileSync(
        path.join(__dirname, '..', 'src', 'a2a.js'), 'utf8'
      );
      // Strip block comments and single-line comments for code-only check
      const codeOnly = source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '');
      expect(codeOnly).to.not.include("require('../index')");
      expect(codeOnly).to.not.include("require('./index')");
      expect(codeOnly).to.not.include('legacySignRequest');
      expect(codeOnly).to.not.include('legacyVerifyResponse');
      expect(codeOnly).to.not.include('jacs.hashString');
    });
  });

  // -------------------------------------------------------------------------
  // Test 7: signArtifact alias
  // -------------------------------------------------------------------------
  describe('signArtifact alias', () => {
    it('should be the primary method and call signRequest', async () => {
      const mockClient = createMockClient();
      const artifact = { action: 'process', data: { x: 1 } };
      const signedResult = {
        jacsId: 'signed-1',
        jacsType: 'a2a-task',
        a2aArtifact: artifact,
        jacsSignature: { agentID: 'agent-1' }
      };
      mockClient._agent.signRequest.returns(signedResult);

      const integration = new JACSA2AIntegration(mockClient);
      const result = await integration.signArtifact(artifact, 'task');

      expect(result.jacsType).to.equal('a2a-task');
      expect(mockClient._agent.signRequest.calledOnce).to.be.true;
    });

    it('wrapArtifactWithProvenance should delegate to signArtifact', async () => {
      const mockClient = createMockClient();
      const artifact = { step: 'verify' };
      const signedResult = {
        jacsId: 'signed-2',
        jacsType: 'a2a-message',
        a2aArtifact: artifact,
        jacsSignature: { agentID: 'agent-2' }
      };
      mockClient._agent.signRequest.returns(signedResult);

      const integration = new JACSA2AIntegration(mockClient);
      const result = await integration.wrapArtifactWithProvenance(artifact, 'message');

      expect(result.jacsType).to.equal('a2a-message');
      expect(mockClient._agent.signRequest.calledOnce).to.be.true;
    });
  });

  // -------------------------------------------------------------------------
  // Test 8: Trust policy constants
  // -------------------------------------------------------------------------
  describe('trust policy constants', () => {
    it('should export correct trust policy names', () => {
      expect(TRUST_POLICIES.OPEN).to.equal('open');
      expect(TRUST_POLICIES.VERIFIED).to.equal('verified');
      expect(TRUST_POLICIES.STRICT).to.equal('strict');
    });

    it('should default to verified trust policy', () => {
      expect(DEFAULT_TRUST_POLICY).to.equal('verified');
    });
  });
});
