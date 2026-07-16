/**
 * Tests for JACS A2A Trust Policy API - [2.2.4] Node portion
 *
 * Validates:
 * - assessRemoteAgent() with open/verified/strict policies
 * - trustA2AAgent() convenience method
 * - verifyWrappedArtifact() includes trustAssessment in result
 * - TrustAssessment interface shape
 */

const { expect } = require('chai');
const sinon = require('sinon');
const {
  JACSA2AIntegration,
  A2AAgentCapabilities,
  A2AAgentExtension,
  JACS_EXTENSION_URI,
  TRUST_POLICIES,
  DEFAULT_TRUST_POLICY,
} = require('../src/a2a');

/**
 * Build a mock agent card with or without the JACS extension.
 */
function buildAgentCard({ jacsExtension = true, agentId = 'remote-agent-123' } = {}) {
  const extensions = jacsExtension
    ? [{ uri: JACS_EXTENSION_URI, description: 'JACS provenance', required: false }]
    : [];

  return {
    name: 'Test Remote Agent',
    description: 'A test agent for trust assessment',
    version: '1',
    protocolVersions: ['0.4.0'],
    supportedInterfaces: [{ url: 'https://agent.example.com', protocolBinding: 'jsonrpc' }],
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    capabilities: { extensions },
    skills: [{ id: 'test', name: 'test', description: 'test', tags: ['test'] }],
    metadata: { jacsId: agentId, jacsVersion: '1' },
  };
}

/**
 * Create a mock JacsClient with trust store stubs.
 */
function createMockClient({ trustedAgents = [] } = {}) {
  const mockAgent = {
    signRequest: sinon.stub(),
    verifyResponse: sinon.stub(),
  };
  return {
    _agent: mockAgent,
    agentId: 'local-agent-id',
    name: 'local-agent',
    isTrusted: sinon.stub().callsFake((id) => trustedAgents.includes(id)),
    trustAgent: sinon.stub().returns('ok'),
    trustAgentWithKey: sinon.stub().returns('ok'),
    listTrustedAgents: sinon.stub().returns(trustedAgents),
  };
}

describe('A2A Trust Policy API - [2.2.4]', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  // -------------------------------------------------------------------------
  // assessRemoteAgent - open policy
  // -------------------------------------------------------------------------
  describe('assessRemoteAgent (open policy)', () => {
    it('should allow any agent with open policy', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);

      const cardNoJacs = buildAgentCard({ jacsExtension: false });
      const result = integration.assessRemoteAgent(cardNoJacs);

      expect(result.allowed).to.be.true;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.jacsRegistered).to.be.false;
      expect(result.inTrustStore).to.be.false;
      expect(result.reason).to.include('Open policy');
    });

    it('should allow a JACS agent with open policy', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);

      const card = buildAgentCard({ jacsExtension: true });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.true;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.jacsRegistered).to.be.true;
    });
  });

  // -------------------------------------------------------------------------
  // assessRemoteAgent - verified policy
  // -------------------------------------------------------------------------
  describe('assessRemoteAgent (verified policy)', () => {
    it('surfaces native first-contact TOFU state', () => {
      const client = createMockClient();
      client._agent.assessA2aAgentSync = sinon.stub().returns(JSON.stringify({
        allowed: true,
        trustLevel: 'JacsVerified',
        jacsRegistered: true,
        reason: 'origin key pinned on first contact',
        policy: 'Verified',
        firstContact: true,
      }));
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const result = integration.assessRemoteAgent(buildAgentCard({ jacsExtension: true }));
      expect(result.allowed).to.be.true;
      expect(result.firstContact).to.be.true;
    });

    it('fails closed when native assessment omits allowed', () => {
      const client = createMockClient();
      client._agent.assessA2aAgentSync = sinon.stub().returns(JSON.stringify({
        trustLevel: 'JacsVerified',
        jacsRegistered: true,
        reason: 'malformed result',
      }));
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const result = integration.assessRemoteAgent(buildAgentCard({ jacsExtension: true }));
      expect(result.allowed).to.be.false;
    });

    it('fails closed when native cryptographic assessment is unavailable', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const card = buildAgentCard({ jacsExtension: true });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.jacsRegistered).to.be.true;
      expect(result.reason).to.include('native cryptographic assessment');
    });

    it('should reject agents without JACS extension', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const card = buildAgentCard({ jacsExtension: false });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.jacsRegistered).to.be.false;
      expect(result.reason).to.include('native cryptographic assessment');
    });

    it('should use verified as the default policy', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client);

      expect(integration.trustPolicy).to.equal(DEFAULT_TRUST_POLICY);
      expect(integration.trustPolicy).to.equal('verified');
    });
  });

  // -------------------------------------------------------------------------
  // assessRemoteAgent - strict policy
  // -------------------------------------------------------------------------
  describe('assessRemoteAgent (strict policy)', () => {
    it('does not accept a trust-store boolean without native binding verification', () => {
      const client = createMockClient({ trustedAgents: ['remote-agent-123'] });
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);

      const card = buildAgentCard({ jacsExtension: true, agentId: 'remote-agent-123' });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.inTrustStore).to.be.false;
      expect(result.reason).to.include('native cryptographic assessment');
    });

    it('should reject agents not in the trust store', () => {
      const client = createMockClient({ trustedAgents: [] });
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);

      const card = buildAgentCard({ jacsExtension: true, agentId: 'unknown-agent' });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.inTrustStore).to.be.false;
      expect(result.reason).to.include('Strict policy');
    });

    it('should reject non-JACS agents not in trust store', () => {
      const client = createMockClient({ trustedAgents: [] });
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);

      const card = buildAgentCard({ jacsExtension: false, agentId: 'rogue-agent' });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.jacsRegistered).to.be.false;
      expect(result.inTrustStore).to.be.false;
    });
  });

  // -------------------------------------------------------------------------
  // assessRemoteAgent - JSON string input
  // -------------------------------------------------------------------------
  describe('assessRemoteAgent (string input)', () => {
    it('should accept a JSON string as input', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);

      const card = buildAgentCard({ jacsExtension: true });
      const result = integration.assessRemoteAgent(JSON.stringify(card));

      expect(result.allowed).to.be.true;
      expect(result.jacsRegistered).to.be.true;
    });
  });

  // -------------------------------------------------------------------------
  // trustA2AAgent
  // -------------------------------------------------------------------------
  describe('trustA2AAgent', () => {
    it('requires a native agent document and explicit public key', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client);

      const agentDocument = {
        jacsId: 'remote-agent-123',
        jacsVersion: 'version-1',
        jacsSignature: { publicKeyHash: 'sha256-placeholder' },
      };
      integration.trustA2AAgent(agentDocument, '-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----');

      expect(client.trustAgent.called).to.be.false;
      expect(client.trustAgentWithKey.calledOnce).to.be.true;
      const [arg, key] = client.trustAgentWithKey.firstCall.args;
      expect(typeof arg).to.equal('string');
      const parsed = JSON.parse(arg);
      expect(parsed.jacsId).to.equal('remote-agent-123');
      expect(key).to.include('BEGIN PUBLIC KEY');
    });

    it('rejects an unauthenticated Agent Card even when a key is supplied', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client);

      const cardStr = JSON.stringify(buildAgentCard());
      expect(() => integration.trustA2AAgent(cardStr, 'public-key')).to.throw(
        /full native JACS agent document/,
      );
      expect(client.trustAgentWithKey.called).to.be.false;
    });

    it('rejects a missing explicit public key', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client);
      const document = JSON.stringify({
        jacsId: 'remote-agent-123',
        jacsVersion: 'version-1',
        jacsSignature: {},
      });

      expect(() => integration.trustA2AAgent(document, '')).to.throw(/explicit public key/);
      expect(client.trustAgentWithKey.called).to.be.false;
    });
  });

  // -------------------------------------------------------------------------
  // verifyWrappedArtifact includes trustAssessment
  // -------------------------------------------------------------------------
  describe('verifyWrappedArtifact with trustAssessment', () => {
    it('should include trustAssessment for verified signer (verified policy)', async () => {
      const client = createMockClient({ trustedAgents: [] });
      client._agent.verifyResponse.returns(true);
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const artifact = {
        jacsId: 'doc-1',
        jacsVersion: 'v1',
        jacsType: 'a2a-task',
        jacsVersionDate: '2026-01-01T00:00:00Z',
        a2aArtifact: { action: 'test' },
        jacsSignature: {
          agentID: 'signer-agent-abc',
          agentVersion: '1',
          publicKeyHash: 'abc123',
        },
      };

      const result = await integration.verifyWrappedArtifact(
        artifact,
        buildAgentCard({ agentId: 'signer-agent-abc' }),
      );

      expect(result.valid).to.be.false;
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.allowed).to.be.false;
      expect(result.trustAssessment.jacsRegistered).to.be.false;
      expect(result.trustAssessment.trustLevel).to.equal('Untrusted');
      expect(result.trustAssessment.reason).to.include('cannot elevate trust');
      expect(client._agent.verifyResponse.called).to.be.false;
    });

    it('should reject untrusted signer under strict policy', async () => {
      const client = createMockClient({ trustedAgents: [] });
      client._agent.verifyResponse.returns(true);
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);

      const artifact = {
        jacsId: 'doc-2',
        jacsVersion: 'v1',
        jacsType: 'a2a-task',
        jacsVersionDate: '2026-01-01T00:00:00Z',
        a2aArtifact: { action: 'test' },
        jacsSignature: {
          agentID: 'untrusted-signer',
          agentVersion: '1',
        },
      };

      const result = await integration.verifyWrappedArtifact(
        artifact,
        buildAgentCard({ agentId: 'untrusted-signer' }),
      );

      expect(result.valid).to.be.false;
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.allowed).to.be.false;
      expect(result.trustAssessment.inTrustStore).to.be.false;
      expect(result.trustAssessment.reason).to.include('canonical native A2A verification');
      expect(client._agent.verifyResponse.called).to.be.false;
    });

    it('does not allow a trust-store boolean without native binding verification', async () => {
      const client = createMockClient({ trustedAgents: ['trusted-signer'] });
      client._agent.verifyResponse.returns(true);
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);

      const artifact = {
        jacsId: 'doc-3',
        jacsVersion: 'v1',
        jacsType: 'a2a-task',
        jacsVersionDate: '2026-01-01T00:00:00Z',
        a2aArtifact: { action: 'test' },
        jacsSignature: {
          agentID: 'trusted-signer',
          agentVersion: '1',
        },
      };

      const result = await integration.verifyWrappedArtifact(
        artifact,
        buildAgentCard({ agentId: 'trusted-signer' }),
      );

      expect(result.valid).to.be.false;
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.allowed).to.be.false;
      expect(result.trustAssessment.inTrustStore).to.be.false;
      expect(result.trustAssessment.trustLevel).to.equal('Untrusted');
    });
  });

  // -------------------------------------------------------------------------
  // TrustAssessment shape
  // -------------------------------------------------------------------------
  describe('TrustAssessment shape', () => {
    it('should return all required fields', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const card = buildAgentCard({ jacsExtension: true });
      const result = integration.assessRemoteAgent(card);

      expect(result).to.have.all.keys(
        'allowed',
        'trustLevel',
        'jacsRegistered',
        'inTrustStore',
        'reason',
        'firstContact',
      );
      expect(typeof result.allowed).to.equal('boolean');
      expect(typeof result.trustLevel).to.equal('string');
      expect(typeof result.jacsRegistered).to.equal('boolean');
      expect(typeof result.inTrustStore).to.equal('boolean');
      expect(typeof result.reason).to.equal('string');
      expect(typeof result.firstContact).to.equal('boolean');
    });
  });
});
