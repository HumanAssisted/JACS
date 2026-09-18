/**
 * Integration tests for A2A Trust Demo - Task #28 [2.5.3]
 *
 * Validates the hero demo scenario end-to-end:
 * - Agent A (JACS) signs artifact, Agent B (JACS) verifies & countersigns
 * - Agent C (plain A2A, no JACS) is blocked by trust policy
 * - Full chain of custody verified across agents
 */

const { expect } = require('chai');
const sinon = require('sinon');
const {
  JACSA2AIntegration,
  JACS_EXTENSION_URI,
  TRUST_POLICIES,
} = require('../src/a2a');
const {
  configureNativeAssessor,
  configureCanonicalArtifactVerifier,
  configureNativeArtifactSigner,
} = require('./helpers/a2a-bound');

/**
 * Create a mock JacsClient for the demo scenario.
 */
function createMockClient(overrides = {}) {
  const trustedAgents = overrides.trustedAgents || [];
  const agentId = overrides.agentId || 'mock-agent';
  const agent = {
    signRequest: sinon.stub(),
    signArtifactSync: sinon.stub(),
    verifyResponse: sinon.stub().returns(true),
  };
  configureNativeAssessor(agent, { trustedAgentIds: trustedAgents });
  configureCanonicalArtifactVerifier(agent, { trustedAgentIds: trustedAgents });
  configureNativeArtifactSigner(agent, { agentId });
  return {
    _agent: agent,
    agentId,
    name: overrides.name || 'Mock Agent',
    isTrusted: sinon.stub().callsFake((id) => trustedAgents.includes(id)),
    trustAgent: sinon.stub().returns('ok'),
    listTrustedAgents: sinon.stub().returns(trustedAgents),
  };
}

/**
 * Build a plain A2A agent card without the JACS extension.
 */
function buildPlainCard(name = 'Plain Agent C') {
  return {
    name,
    description: 'A standard A2A agent without JACS provenance',
    version: '1.0',
    protocolVersions: ['0.4.0'],
    skills: [{ id: 'chat', name: 'Chat', description: 'General chat', tags: ['chat'] }],
    capabilities: { streaming: true },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
  };
}

describe('A2A Trust Demo Integration - [2.5.3]', function () {
  this.timeout(15000);

  // ---------------------------------------------------------------------------
  // 1. Full 3-agent scenario: A signs, B verifies & countersigns, C is blocked
  // ---------------------------------------------------------------------------
  describe('3-agent trust scenario', () => {
    let clientA, clientB;
    let a2aA, a2aB;

    beforeEach(() => {
      clientA = createMockClient({ agentId: 'agent-alpha', name: 'Agent A (JACS)' });
      clientB = createMockClient({ agentId: 'agent-beta', name: 'Agent B (JACS)' });
      a2aA = new JACSA2AIntegration(clientA, TRUST_POLICIES.VERIFIED);
      a2aB = new JACSA2AIntegration(clientB, TRUST_POLICIES.VERIFIED);
    });

    it('should complete the full sign -> verify -> countersign -> chain workflow', async () => {
      // Agent A signs a task
      const task = { action: 'classify', input: 'Quarterly revenue data' };
      const signedByA = await a2aA.signArtifact(task, 'task');

      expect(signedByA.jacsType).to.equal('a2a-task');
      expect(signedByA.jacsSignature.agentID).to.equal('agent-alpha');
      expect(signedByA.a2aArtifact).to.deep.equal(task);

      // Agent B verifies Agent A's artifact
      const cardA = JSON.parse(JSON.stringify(a2aA.exportAgentCard({
        jacsId: 'agent-alpha',
        jacsName: 'Agent A',
        jacsDescription: 'JACS Agent A',
      })));
      const verifyAtB = await a2aB.verifyWrappedArtifact(signedByA, cardA);
      expect(verifyAtB.valid).to.be.true;
      expect(verifyAtB.signerId).to.equal('agent-alpha');
      expect(verifyAtB.trustAssessment).to.exist;
      expect(verifyAtB.trustAssessment.trustLevel).to.equal('JacsVerified');
      expect(verifyAtB.trustAssessment.allowed).to.be.true;

      // Agent B countersigns with chain of custody
      const result = { output: 'financial', confidence: 0.97 };
      const signedByB = await a2aB.signArtifact(result, 'result', [signedByA]);

      expect(signedByB.jacsSignature.agentID).to.equal('agent-beta');
      expect(signedByB.jacsParentSignatures).to.be.an('array').with.lengthOf(1);

      // Agent A verifies the full chain
      const chainResult = await a2aA.verifyWrappedArtifact(signedByB);
      expect(chainResult.valid).to.be.true;
      expect(chainResult.parentSignaturesValid).to.be.true;
      expect(chainResult.parentSignaturesCount).to.equal(1);
      expect(chainResult.parentVerificationResults[0].valid).to.be.true;
    });

    it('should block Agent C (plain A2A) under verified policy', () => {
      const cardC = buildPlainCard('Agent C');

      // Agent B assesses Agent C under "verified" policy
      const assessment = a2aB.assessRemoteAgent(cardC);

      expect(assessment.allowed).to.be.false;
      expect(assessment.jacsRegistered).to.be.false;
      expect(assessment.trustLevel).to.equal('untrusted');
      expect(assessment.reason).to.include('does not declare JACS extension');
    });

    it('should accept Agent C (plain A2A) under open policy', () => {
      const openB = new JACSA2AIntegration(clientB, TRUST_POLICIES.OPEN);
      const cardC = buildPlainCard('Agent C');

      const assessment = openB.assessRemoteAgent(cardC);

      expect(assessment.allowed).to.be.true;
      expect(assessment.jacsRegistered).to.be.false;
      expect(assessment.trustLevel).to.equal('untrusted');
      expect(assessment.reason).to.include('Open policy');
    });

    it('should block even JACS agents not in trust store under strict policy', () => {
      const strictB = new JACSA2AIntegration(clientB, TRUST_POLICIES.STRICT);

      // Agent A's card has the JACS extension but is not in B's trust store
      const cardA = a2aA.exportAgentCard({
        jacsId: 'agent-alpha',
        jacsName: 'Agent A',
        jacsDescription: 'JACS Agent A',
      });
      const cardJson = JSON.parse(JSON.stringify(cardA));
      // Ensure metadata.jacsId for trust store lookup
      if (!cardJson.metadata) cardJson.metadata = {};
      cardJson.metadata.jacsId = 'agent-alpha';

      const assessment = strictB.assessRemoteAgent(cardJson);

      expect(assessment.jacsRegistered).to.be.true;
      expect(assessment.inTrustStore).to.be.false;
      expect(assessment.allowed).to.be.false;
      expect(assessment.reason).to.include('Strict policy');
    });
  });
});
