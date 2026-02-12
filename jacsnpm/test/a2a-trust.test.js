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
      expect(result.trustLevel).to.equal('jacs_registered');
      expect(result.jacsRegistered).to.be.true;
    });
  });

  // -------------------------------------------------------------------------
  // assessRemoteAgent - verified policy
  // -------------------------------------------------------------------------
  describe('assessRemoteAgent (verified policy)', () => {
    it('should allow agents with JACS extension', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const card = buildAgentCard({ jacsExtension: true });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.true;
      expect(result.trustLevel).to.equal('jacs_registered');
      expect(result.jacsRegistered).to.be.true;
      expect(result.reason).to.include('JACS extension');
    });

    it('should reject agents without JACS extension', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

      const card = buildAgentCard({ jacsExtension: false });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.jacsRegistered).to.be.false;
      expect(result.reason).to.include('does not declare JACS extension');
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
    it('should allow agents in the trust store', () => {
      const client = createMockClient({ trustedAgents: ['remote-agent-123'] });
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);

      const card = buildAgentCard({ jacsExtension: true, agentId: 'remote-agent-123' });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.true;
      expect(result.trustLevel).to.equal('trusted');
      expect(result.inTrustStore).to.be.true;
      expect(result.reason).to.include('trust store');
      expect(client.isTrusted.calledWith('remote-agent-123')).to.be.true;
    });

    it('should reject agents not in the trust store', () => {
      const client = createMockClient({ trustedAgents: [] });
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);

      const card = buildAgentCard({ jacsExtension: true, agentId: 'unknown-agent' });
      const result = integration.assessRemoteAgent(card);

      expect(result.allowed).to.be.false;
      expect(result.trustLevel).to.equal('jacs_registered');
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
    it('should call client.trustAgent with the card JSON string', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client);

      const card = buildAgentCard();
      integration.trustA2AAgent(card);

      expect(client.trustAgent.calledOnce).to.be.true;
      const arg = client.trustAgent.firstCall.args[0];
      expect(typeof arg).to.equal('string');
      const parsed = JSON.parse(arg);
      expect(parsed.name).to.equal('Test Remote Agent');
    });

    it('should accept a JSON string directly', () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client);

      const cardStr = JSON.stringify(buildAgentCard());
      integration.trustA2AAgent(cardStr);

      expect(client.trustAgent.calledOnce).to.be.true;
      expect(client.trustAgent.firstCall.args[0]).to.equal(cardStr);
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

      const result = await integration.verifyWrappedArtifact(artifact);

      expect(result.valid).to.be.true;
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.allowed).to.be.true;
      expect(result.trustAssessment.jacsRegistered).to.be.true;
      expect(result.trustAssessment.trustLevel).to.equal('jacs_registered');
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

      const result = await integration.verifyWrappedArtifact(artifact);

      expect(result.valid).to.be.true; // signature is valid
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.allowed).to.be.false;
      expect(result.trustAssessment.inTrustStore).to.be.false;
      expect(result.trustAssessment.reason).to.include('Strict policy');
    });

    it('should allow trusted signer under strict policy', async () => {
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

      const result = await integration.verifyWrappedArtifact(artifact);

      expect(result.valid).to.be.true;
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.allowed).to.be.true;
      expect(result.trustAssessment.inTrustStore).to.be.true;
      expect(result.trustAssessment.trustLevel).to.equal('trusted');
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

      expect(result).to.have.all.keys('allowed', 'trustLevel', 'jacsRegistered', 'inTrustStore', 'reason');
      expect(typeof result.allowed).to.equal('boolean');
      expect(typeof result.trustLevel).to.equal('string');
      expect(typeof result.jacsRegistered).to.equal('boolean');
      expect(typeof result.inTrustStore).to.equal('boolean');
      expect(typeof result.reason).to.equal('string');
    });
  });
});
