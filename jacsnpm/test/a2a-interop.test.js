/**
 * Tests for JACS A2A Ecosystem Interop - Task #27 [2.5.2]
 *
 * Tests the interaction between JACS A2A agents and plain (non-JACS) A2A agents:
 * - JACS agent discovering a plain A2A agent -> untrusted assessment
 * - Trust policy enforcement: open / verified / strict
 * - Plain HTTP client discovering JACS server well-known endpoints
 * - JACS agent discovering another JACS agent -> jacs_registered / trusted
 */

const { expect } = require('chai');
const express = require('express');
const sinon = require('sinon');
const { JACSA2AIntegration, JACS_EXTENSION_URI, TRUST_POLICIES } = require('../src/a2a');
const { jacsA2AMiddleware, buildWellKnownDocuments } = require('../src/a2a-server');
const { discoverAgent, discoverAndAssess, hasJacsExtension } = require('../src/a2a-discovery');

/**
 * Create a mock JacsClient with optional trust store entries.
 */
function createMockClient(overrides = {}) {
  const trustedAgents = overrides.trustedAgents || [];
  return {
    _agent: {
      signRequest: sinon.stub().callsFake((doc) => ({ ...doc, jacsSignature: { agentID: overrides.agentId || 'jacs-agent-1', agentVersion: '1' } })),
      verifyResponse: sinon.stub().returns(true),
    },
    agentId: overrides.agentId || 'jacs-agent-1',
    name: overrides.name || 'JACS Test Agent',
    isTrusted: sinon.stub().callsFake((id) => trustedAgents.includes(id)),
    trustAgent: sinon.stub().returns('ok'),
    listTrustedAgents: sinon.stub().returns(trustedAgents),
  };
}

/**
 * Start an Express server on a random port. Returns { port, close() }.
 */
function startServer(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const port = server.address().port;
      resolve({ port, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

/**
 * Build a plain A2A agent card (no JACS extension).
 */
function buildPlainA2ACard(overrides = {}) {
  return {
    name: overrides.name || 'Plain A2A Agent',
    description: overrides.description || 'A standard A2A agent without JACS',
    version: overrides.version || '1.0',
    protocolVersions: ['0.4.0'],
    skills: overrides.skills || [
      { id: 'summarize', name: 'Summarize', description: 'Summarize text', tags: ['nlp'] },
    ],
    capabilities: {
      streaming: true,
      pushNotifications: false,
      // No extensions array -> no JACS extension
    },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
  };
}

describe('A2A Ecosystem Interop - [2.5.2]', function () {
  this.timeout(15000);

  // -----------------------------------------------------------------------
  // Shared servers
  // -----------------------------------------------------------------------
  let plainA2AServer;   // A standard A2A server without JACS
  let jacsA2AServer;    // A JACS-powered A2A server

  before(async () => {
    // 1. Plain A2A server: serves a valid agent card without JACS extension
    const plainApp = express();
    plainApp.get('/.well-known/agent-card.json', (_req, res) => {
      res.json(buildPlainA2ACard({ name: 'Remote Plain Agent' }));
    });
    plainA2AServer = await startServer(plainApp);

    // 2. JACS A2A server: serves agent card WITH JACS extension + all 5 well-known docs
    const jacsClient = createMockClient({ agentId: 'jacs-remote-agent', name: 'JACS Remote Agent' });
    const jacsApp = express();
    jacsApp.use(jacsA2AMiddleware(jacsClient, {
      skills: [{ id: 'sign', name: 'Sign', description: 'Sign documents', tags: ['crypto'] }],
    }));
    jacsA2AServer = await startServer(jacsApp);
  });

  after(async () => {
    if (plainA2AServer) await plainA2AServer.close();
    if (jacsA2AServer) await jacsA2AServer.close();
  });

  // -----------------------------------------------------------------------
  // 1. JACS discovers a plain A2A agent -> untrusted
  // -----------------------------------------------------------------------
  describe('JACS agent discovers plain A2A agent', () => {
    it('should assess a plain A2A agent as untrusted', async () => {
      const result = await discoverAndAssess(`http://localhost:${plainA2AServer.port}`);

      expect(result.card.name).to.equal('Remote Plain Agent');
      expect(result.jacsRegistered).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
    });

    it('should verify agent card has no JACS extension', async () => {
      const card = await discoverAgent(`http://localhost:${plainA2AServer.port}`);

      expect(hasJacsExtension(card)).to.be.false;
      expect(card.capabilities).to.exist;
      expect(card.capabilities.extensions).to.be.undefined;
    });
  });

  // -----------------------------------------------------------------------
  // 2. Trust policy enforcement on plain A2A agents
  // -----------------------------------------------------------------------
  describe('Trust policy: open allows plain A2A agents', () => {
    it('should allow a plain A2A card under open policy', async () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);
      const card = await discoverAgent(`http://localhost:${plainA2AServer.port}`);
      const assessment = integration.assessRemoteAgent(card);

      expect(assessment.allowed).to.be.true;
      expect(assessment.trustLevel).to.equal('untrusted');
      expect(assessment.jacsRegistered).to.be.false;
      expect(assessment.reason).to.include('Open policy');
    });
  });

  describe('Trust policy: verified rejects plain A2A agents', () => {
    it('should reject a plain A2A card under verified policy', async () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);
      const card = await discoverAgent(`http://localhost:${plainA2AServer.port}`);
      const assessment = integration.assessRemoteAgent(card);

      expect(assessment.allowed).to.be.false;
      expect(assessment.trustLevel).to.equal('untrusted');
      expect(assessment.jacsRegistered).to.be.false;
      expect(assessment.reason).to.include('does not declare JACS extension');
    });
  });

  describe('Trust policy: strict rejects even JACS agents not in trust store', () => {
    it('should reject a JACS agent card not in trust store under strict policy', async () => {
      const client = createMockClient({ trustedAgents: [] });
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.STRICT);
      const card = await discoverAgent(`http://localhost:${jacsA2AServer.port}`);
      const assessment = integration.assessRemoteAgent(card);

      expect(assessment.allowed).to.be.false;
      expect(assessment.jacsRegistered).to.be.true;
      expect(assessment.inTrustStore).to.be.false;
      expect(assessment.reason).to.include('Strict policy');
    });
  });

  // -----------------------------------------------------------------------
  // 3. Plain HTTP client discovers JACS server well-known endpoints
  // -----------------------------------------------------------------------
  describe('Plain HTTP client discovers JACS server', () => {
    it('should fetch all 5 well-known documents from JACS server', async () => {
      const wellKnownPaths = [
        '/.well-known/agent-card.json',
        '/.well-known/jacs-extension.json',
        '/.well-known/jacs-agent.json',
        '/.well-known/jwks.json',
        '/.well-known/jacs-pubkey.json',
      ];

      for (const path of wellKnownPaths) {
        const url = `http://localhost:${jacsA2AServer.port}${path}`;
        const response = await fetch(url);
        expect(response.ok, `Expected 200 for ${path}`).to.be.true;

        const contentType = response.headers.get('content-type') || '';
        expect(contentType).to.include('json');

        const body = await response.json();
        expect(body).to.be.an('object');
      }
    });

    it('should include CORS headers for cross-origin discovery', async () => {
      const url = `http://localhost:${jacsA2AServer.port}/.well-known/agent-card.json`;
      const response = await fetch(url);

      expect(response.headers.get('access-control-allow-origin')).to.equal('*');
    });

    it('should serve an OPTIONS preflight with CORS for agent-card', async () => {
      const url = `http://localhost:${jacsA2AServer.port}/.well-known/agent-card.json`;
      const response = await fetch(url, { method: 'OPTIONS' });

      expect(response.status).to.equal(204);
      expect(response.headers.get('access-control-allow-origin')).to.equal('*');
      expect(response.headers.get('access-control-allow-methods')).to.include('GET');
    });
  });

  // -----------------------------------------------------------------------
  // 4. JACS discovers another JACS agent -> jacs_registered
  // -----------------------------------------------------------------------
  describe('JACS agent discovers another JACS agent', () => {
    it('should assess a JACS agent as jacs_registered', async () => {
      const result = await discoverAndAssess(`http://localhost:${jacsA2AServer.port}`);

      expect(result.card.name).to.include('JACS');
      expect(result.jacsRegistered).to.be.true;
      expect(result.trustLevel).to.equal('jacs_registered');
    });

    it('should allow a JACS agent under verified policy', async () => {
      const client = createMockClient();
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);
      const card = await discoverAgent(`http://localhost:${jacsA2AServer.port}`);
      const assessment = integration.assessRemoteAgent(card);

      expect(assessment.allowed).to.be.true;
      expect(assessment.jacsRegistered).to.be.true;
      expect(assessment.trustLevel).to.equal('jacs_registered');
    });
  });

  // -----------------------------------------------------------------------
  // 5. JACS <-> JACS artifact signing and cross-verification
  // -----------------------------------------------------------------------
  describe('JACS-to-JACS artifact exchange', () => {
    it('should sign an artifact with agent A and verify with agent B', async () => {
      const clientA = createMockClient({ agentId: 'agent-alpha', name: 'Agent Alpha' });
      const clientB = createMockClient({ agentId: 'agent-beta', name: 'Agent Beta' });

      const integrationA = new JACSA2AIntegration(clientA, TRUST_POLICIES.VERIFIED);
      const integrationB = new JACSA2AIntegration(clientB, TRUST_POLICIES.VERIFIED);

      // Agent A signs a task artifact
      const signed = await integrationA.signArtifact(
        { action: 'classify', input: 'hello world' },
        'task',
      );

      expect(signed.jacsType).to.equal('a2a-task');
      expect(signed.a2aArtifact).to.deep.equal({ action: 'classify', input: 'hello world' });
      expect(signed.jacsSignature).to.exist;
      expect(signed.jacsSignature.agentID).to.equal('agent-alpha');

      // Agent B verifies the artifact from Agent A
      const result = await integrationB.verifyWrappedArtifact(signed);

      expect(result.valid).to.be.true;
      expect(result.signerId).to.equal('agent-alpha');
      expect(result.artifactType).to.equal('a2a-task');
      // Trust assessment: agent-alpha has a JACS signature -> jacs_registered
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.trustLevel).to.equal('jacs_registered');
      expect(result.trustAssessment.allowed).to.be.true;
    });

    it('should build a chain of custody across two JACS agents', async () => {
      const clientA = createMockClient({ agentId: 'chain-agent-1', name: 'Chain Agent 1' });
      const clientB = createMockClient({ agentId: 'chain-agent-2', name: 'Chain Agent 2' });

      const integrationA = new JACSA2AIntegration(clientA);
      const integrationB = new JACSA2AIntegration(clientB);

      // Agent A signs step 1
      const step1 = await integrationA.signArtifact(
        { step: 1, data: 'raw input' },
        'message',
      );

      // Agent B signs step 2 with step 1 as parent
      const step2 = await integrationB.signArtifact(
        { step: 2, data: 'processed output' },
        'message',
        [step1],
      );

      expect(step2.jacsParentSignatures).to.be.an('array').with.lengthOf(1);
      expect(step2.jacsSignature.agentID).to.equal('chain-agent-2');

      // Verify the full chain from agent A's perspective
      const result = await integrationA.verifyWrappedArtifact(step2);

      expect(result.valid).to.be.true;
      expect(result.parentSignaturesCount).to.equal(1);
      expect(result.parentSignaturesValid).to.be.true;
      expect(result.parentVerificationResults[0].valid).to.be.true;
    });
  });
});
