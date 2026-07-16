/**
 * Tests for JacsClient A2A methods (Task #8 - [2.1.2])
 *
 * Validates that the A2A convenience methods on JacsClient correctly
 * delegate to JACSA2AIntegration and that the round-trip works.
 */

const { expect } = require('chai');
const sinon = require('sinon');

let clientModule;
try {
  clientModule = require('../client.js');
} catch (e) {
  clientModule = null;
}

const {
  JACSA2AIntegration,
  A2AAgentCard,
  A2AAgentSkill,
  TRUST_POLICIES,
  DEFAULT_TRUST_POLICY,
} = require('../src/a2a');

describe('JacsClient A2A methods', function () {
  this.timeout(30000);

  const available = clientModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping JacsClient A2A tests - client.js not compiled');
      this.skip();
    }
  });

  // ---------------------------------------------------------------------------
  // 1. getA2A returns a configured JACSA2AIntegration
  // ---------------------------------------------------------------------------
  describe('getA2A()', () => {
    (available ? it : it.skip)('should return a JACSA2AIntegration bound to this client', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const a2a = client.getA2A();
      expect(a2a).to.be.an.instanceOf(JACSA2AIntegration);
      expect(a2a.client).to.equal(client);
    });

    (available ? it : it.skip)('should return a new instance on each call', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const a = client.getA2A();
      const b = client.getA2A();
      expect(a).to.not.equal(b);
      expect(a.client).to.equal(b.client);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. exportAgentCard from ephemeral client
  // ---------------------------------------------------------------------------
  describe('exportAgentCard()', () => {
    (available ? it : it.skip)('should export an A2A Agent Card with provided data', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const card = client.exportAgentCard({
        jacsId: 'test-agent-42',
        jacsName: 'CardBot',
        jacsDescription: 'A test agent for card export',
        jacsAgentType: 'ai',
        jacsVersion: '2.0',
      });

      expect(card).to.be.an.instanceOf(A2AAgentCard);
      expect(card.name).to.equal('CardBot');
      expect(card.description).to.equal('A test agent for card export');
      expect(card.version).to.equal('2.0');
      expect(card.protocolVersions).to.deep.equal(['0.4.0']);
      expect(card.skills).to.be.an('array');
      expect(card.metadata.jacsId).to.equal('test-agent-42');
    });

    (available ? it : it.skip)('should fall back to client info when no agentData given', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const card = client.exportAgentCard();

      expect(card).to.be.an.instanceOf(A2AAgentCard);
      // Ephemeral clients have an agentId
      expect(card.metadata.jacsId).to.equal(client.agentId);
    });

    (available ? it : it.skip)('should include explicit skills when provided', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const card = client.exportAgentCard({
        jacsId: client.agentId,
        jacsName: 'SkillBot',
        skills: [{
          id: 'summarize',
          name: 'summarize',
          description: 'Summarize a document',
          tags: ['jacs', 'summarization'],
        }],
      });

      expect(card.skills).to.have.lengthOf(1);
      expect(card.skills[0].name).to.equal('summarize');
      expect(card.skills[0].id).to.equal('summarize');
      expect(card.skills[0].tags).to.include('jacs');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. signArtifact round-trip
  // ---------------------------------------------------------------------------
  describe('signArtifact()', () => {
    (available ? it : it.skip)('should sign an artifact via the native canonical A2A signer', async () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const artifact = { action: 'approve', data: { amount: 100 } };
      const signed = await client.signArtifact(artifact, 'task');

      expect(signed).to.be.an('object');
      expect(signed.jacsType).to.equal('a2a-task');
      expect(signed.a2aArtifact).to.deep.equal(artifact);
      expect(signed.jacsSignature).to.exist;
      expect(signed).to.not.have.property('jacs_payload');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. verifyArtifact
  // ---------------------------------------------------------------------------
  describe('verifyArtifact()', () => {
    (available ? it : it.skip)('should verify a native canonical signed artifact', async () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const artifact = { action: 'verify-me', data: { x: 1 } };
      const signed = await client.signArtifact(artifact, 'message');

      const result = await client.verifyArtifact(signed);

      expect(result).to.exist;
      expect(result.valid).to.equal(true);
      expect(result.artifactType).to.equal('a2a-message');
      expect(result.signerId).to.be.a('string');
      expect(result.originalArtifact).to.deep.equal(artifact);
      expect(result).to.not.have.property('trustAssessment');
    });

    (available ? it : it.skip)('rejects arbitrary legacy verifyResponse objects without exposing payload', async () => {
      const client = new clientModule.JacsClient();
      const fakeAgent = {
        verifyResponse: sinon.stub().returns({ payload: { accepted: true } }),
      };

      // Accesses private state intentionally for focused unit behavior.
      client.agent = fakeAgent;

      const wrapped = {
        jacsType: 'header',
        jacsVersionDate: '2025-01-01T00:00:00Z',
        jacsSignature: { agentID: 'agent-x', agentVersion: 'v1' },
        jacs_payload: {
          a2aArtifact: { ping: 'pong' },
          jacsType: 'a2a-message',
        },
      };

      const result = await client.verifyArtifact(JSON.stringify(wrapped));

      expect(result.valid).to.equal(false);
      expect(typeof result.valid).to.equal('boolean');
      expect(result).to.not.have.property('verifiedPayload');
      expect(fakeAgent.verifyResponse.called).to.equal(false);
    });

    (available ? it : it.skip)('rejects canonical success with incomplete parent evidence', async () => {
      const client = new clientModule.JacsClient();
      const fakeAgent = {
        verifyA2aArtifactWithPolicySync: sinon.stub().returns(JSON.stringify({
          valid: true,
          status: 'Verified',
          signerId: 'agent-x',
          signerVersion: 'version-x',
          artifactType: 'header',
          timestamp: '2026-07-10T00:00:00Z',
          originalArtifact: { accepted: true },
          parentSignaturesValid: false,
          parentVerificationResults: [],
          trustAssessment: {
            allowed: true,
            trustLevel: 'JacsVerified',
            jacsRegistered: true,
            inTrustStore: false,
            reason: 'verified',
            policy: 'verified',
            firstContact: false,
          },
        })),
      };
      client.agent = fakeAgent;
      const wrapped = {
        jacsType: 'header',
        jacsVersionDate: '2099-01-01T00:00:00Z',
        jacsSignature: { agentID: 'attacker-agent', agentVersion: 'attacker-version' },
        a2aArtifact: { attacker: true },
        jacsParentSignatures: [{ jacsId: 'missing-parent-evidence' }],
      };

      const result = await client.verifyArtifact(wrapped);

      expect(result.valid).to.equal(false);
      expect(result.signerId).to.equal('');
      expect(result.timestamp).to.equal('');
    });

    (available ? it : it.skip)('rejects canonical success missing authenticated provenance', async () => {
      const client = new clientModule.JacsClient();
      client.agent = {
        verifyA2aArtifactWithPolicySync: sinon.stub().returns(JSON.stringify({
          valid: true,
          status: 'Verified',
          parentSignaturesValid: true,
          parentVerificationResults: [],
          trustAssessment: {
            allowed: true,
            trustLevel: 'JacsVerified',
            jacsRegistered: true,
            inTrustStore: false,
            reason: 'verified',
            policy: 'verified',
            firstContact: false,
          },
        })),
      };
      const wrapped = {
        jacsType: 'header',
        jacsVersionDate: '2099-01-01T00:00:00Z',
        jacsSignature: { agentID: 'attacker-agent', agentVersion: 'attacker-version' },
        a2aArtifact: { attacker: true },
      };

      const result = await client.verifyArtifact(wrapped);

      expect(result.valid).to.equal(false);
      expect(result.signerId).to.equal('');
      expect(result.signerVersion).to.equal('');
      expect(result.timestamp).to.equal('');
      expect(result.originalArtifact).to.deep.equal({});
    });
  });

  // ---------------------------------------------------------------------------
  // 5. generateWellKnownDocuments via client
  // ---------------------------------------------------------------------------
  describe('generateWellKnownDocuments()', () => {
    (available ? it : it.skip)('fails closed when the loaded native binding lacks the bound generator', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const card = client.exportAgentCard({
        jacsId: client.agentId,
        jacsName: 'WellKnownBot',
        jacsVersion: '1',
        jacsAgentType: 'ai',
      });

      expect(() => client.generateWellKnownDocuments(
        card,
        'mock-jws-sig',
        'bW9jay1wdWJsaWMta2V5',
        {
          jacsId: client.agentId,
          jacsVersion: '1',
          jacsAgentType: 'ai',
          keyAlgorithm: 'ring-Ed25519',
        },
      )).to.throw(/requires the native JACS generator|identity-bound A2A discovery/i);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Async ephemeral factory with A2A
  // ---------------------------------------------------------------------------
  describe('async ephemeral + A2A', () => {
    (available ? it : it.skip)('should work with async ephemeral factory', async () => {
      const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
      expect(client.agentId).to.be.a('string').and.not.empty;

      const a2a = client.getA2A();
      expect(a2a).to.be.an.instanceOf(JACSA2AIntegration);

      const card = client.exportAgentCard({
        jacsId: client.agentId,
        jacsName: 'AsyncBot',
        jacsAgentType: 'ai',
      });
      expect(card.name).to.equal('AsyncBot');
    });
  });
});
