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
  JACS_ALGORITHMS,
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

    (available ? it : it.skip)('should include services as skills when provided', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const card = client.exportAgentCard({
        jacsId: client.agentId,
        jacsName: 'SkillBot',
        jacsServices: [{
          name: 'Summarization',
          serviceDescription: 'Summarize text documents',
          tools: [{
            function: {
              name: 'summarize',
              description: 'Summarize a document',
            },
          }],
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
    (available ? it : it.skip)('should sign an artifact via client._agent.signRequest', async () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const artifact = { action: 'approve', data: { amount: 100 } };
      const signed = await client.signArtifact(artifact, 'task');

      // signRequest returns a signed JACS document (string parsed to object by signRequest)
      expect(signed).to.exist;
      // The result comes from native signRequest which returns a string;
      // it may be a string or object depending on the native binding behavior
      if (typeof signed === 'string') {
        const parsed = JSON.parse(signed);
        expect(parsed.jacsSignature).to.exist;
      } else {
        expect(signed.jacsSignature || signed.jacsType).to.exist;
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 4. verifyArtifact
  // ---------------------------------------------------------------------------
  describe('verifyArtifact()', () => {
    (available ? it : it.skip)('should verify a signed artifact (string input)', async () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const artifact = { action: 'verify-me', data: { x: 1 } };
      const signed = await client.signArtifact(artifact, 'message');

      // Pass the raw string to preserve serialization and hash
      const result = await client.verifyArtifact(signed);

      expect(result).to.exist;
      expect(typeof result.valid).to.equal('boolean');
      // signRequest wraps in a JACS header; the artifact data
      // lives in jacs_payload, so top-level jacsType is 'header'
      expect(result.artifactType).to.equal('header');
      expect(result.signerId).to.be.a('string');

      // The original artifact is inside jacs_payload of the signed doc
      const doc = JSON.parse(signed);
      expect(doc.jacs_payload.a2aArtifact).to.deep.equal(artifact);
      expect(doc.jacs_payload.jacsType).to.equal('a2a-message');
    });

    (available ? it : it.skip)('should coerce object verifyResponse results to boolean and expose payload', async () => {
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

      expect(result.valid).to.equal(true);
      expect(typeof result.valid).to.equal('boolean');
      expect(result.verifiedPayload).to.deep.equal({ accepted: true });
      expect(result.verificationResult).to.deep.equal({ payload: { accepted: true } });
      expect(fakeAgent.verifyResponse.calledOnce).to.equal(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. generateWellKnownDocuments via client
  // ---------------------------------------------------------------------------
  describe('generateWellKnownDocuments()', () => {
    (available ? it : it.skip)('should generate well-known documents from a card', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const card = client.exportAgentCard({
        jacsId: client.agentId,
        jacsName: 'WellKnownBot',
        jacsVersion: '1',
        jacsAgentType: 'ai',
      });

      const documents = client.generateWellKnownDocuments(
        card,
        'mock-jws-sig',
        'bW9jay1wdWJsaWMta2V5', // base64 of "mock-public-key"
        {
          jacsId: client.agentId,
          jacsVersion: '1',
          jacsAgentType: 'ai',
          keyAlgorithm: 'ring-Ed25519',
        },
      );

      expect(documents).to.have.all.keys(
        '/.well-known/agent-card.json',
        '/.well-known/jwks.json',
        '/.well-known/jacs-agent.json',
        '/.well-known/jacs-pubkey.json',
        '/.well-known/jacs-extension.json',
      );

      // Agent card should have embedded signature
      expect(documents['/.well-known/agent-card.json'].signatures[0].jws).to.equal('mock-jws-sig');

      // Extension descriptor should have correct algorithms
      const ext = documents['/.well-known/jacs-extension.json'];
      expect(ext.capabilities.documentSigning.algorithms).to.deep.equal(JACS_ALGORITHMS);
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
