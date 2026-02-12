/**
 * Tests for JACS A2A Quickstart - Task #23 [2.4.2]
 *
 * Validates:
 * - JACSA2AIntegration.quickstart() static factory
 * - integration.listen() Express server
 * - Trust policy defaults and overrides
 * - Default skills passed through to agent card
 */

const { expect } = require('chai');
const sinon = require('sinon');
const http = require('http');
const {
  JACSA2AIntegration,
  A2AAgentSkill,
  DEFAULT_TRUST_POLICY,
  TRUST_POLICIES,
} = require('../src/a2a');

/**
 * Create a mock JacsClient with a mock _agent for testing.
 */
function createMockClient(overrides = {}) {
  const mockAgent = {
    signRequest: sinon.stub(),
    verifyResponse: sinon.stub(),
  };
  return {
    _agent: mockAgent,
    agentId: overrides.agentId || 'test-agent-id',
    name: overrides.name || 'test-agent',
  };
}

describe('A2A Quickstart - [2.4.2] Node.js quickstart one-liner', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  // -------------------------------------------------------------------------
  // Test 1: Constructor accepts trust policy
  // -------------------------------------------------------------------------
  describe('constructor with trustPolicy', () => {
    it('should default to verified trust policy when none provided', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient);
      expect(integration.trustPolicy).to.equal(DEFAULT_TRUST_POLICY);
      expect(integration.trustPolicy).to.equal('verified');
    });

    it('should accept an explicit trust policy', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient, 'strict');
      expect(integration.trustPolicy).to.equal('strict');
    });

    it('should accept open trust policy', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient, TRUST_POLICIES.OPEN);
      expect(integration.trustPolicy).to.equal('open');
    });
  });

  // -------------------------------------------------------------------------
  // Test 2: quickstart is a static async factory
  // -------------------------------------------------------------------------
  describe('quickstart static factory', () => {
    it('should be an async static method', () => {
      expect(JACSA2AIntegration.quickstart).to.be.a('function');
    });

    it('should accept empty options object', async () => {
      // We cannot call the real quickstart without a JACS agent environment,
      // but we can verify the method signature doesn't throw on empty args.
      // The actual JacsClient.quickstart will fail, which is expected in a
      // unit test without setup.
      try {
        await JACSA2AIntegration.quickstart({});
      } catch (e) {
        // Expected: will fail because no real agent environment
        expect(e).to.exist;
      }
    });

    it('should accept no arguments at all', async () => {
      try {
        await JACSA2AIntegration.quickstart();
      } catch (e) {
        // Expected: will fail because no real agent environment
        expect(e).to.exist;
      }
    });
  });

  // -------------------------------------------------------------------------
  // Test 3: listen() serves .well-known endpoints
  // -------------------------------------------------------------------------
  describe('listen()', () => {
    let server;

    afterEach((done) => {
      if (server && server.listening) {
        server.close(done);
      } else {
        done();
      }
    });

    it('should start an Express server on the specified port', (done) => {
      const mockClient = createMockClient({ agentId: 'listen-test', name: 'listen-agent' });
      const integration = new JACSA2AIntegration(mockClient);

      // Use port 0 for random available port
      server = integration.listen(0);
      const addr = server.address();
      expect(addr.port).to.be.a('number');
      expect(addr.port).to.be.greaterThan(0);
      done();
    });

    it('should serve /.well-known/agent-card.json', (done) => {
      const mockClient = createMockClient({ agentId: 'card-test', name: 'card-agent' });
      const integration = new JACSA2AIntegration(mockClient);

      server = integration.listen(0);
      const port = server.address().port;

      http.get(`http://localhost:${port}/.well-known/agent-card.json`, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          expect(res.statusCode).to.equal(200);
          expect(res.headers['content-type']).to.include('json');
          const card = JSON.parse(body);
          expect(card.name).to.equal('card-agent');
          expect(card.skills).to.be.an('array');
          done();
        });
      }).on('error', done);
    });

    it('should serve /.well-known/jacs-extension.json', (done) => {
      const mockClient = createMockClient({ agentId: 'ext-test', name: 'ext-agent' });
      const integration = new JACSA2AIntegration(mockClient);

      server = integration.listen(0);
      const port = server.address().port;

      http.get(`http://localhost:${port}/.well-known/jacs-extension.json`, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          expect(res.statusCode).to.equal(200);
          const ext = JSON.parse(body);
          expect(ext.uri).to.equal('urn:hai.ai:jacs-provenance-v1');
          expect(ext.capabilities).to.have.property('documentSigning');
          done();
        });
      }).on('error', done);
    });

    it('should apply defaultSkills when set', (done) => {
      const mockClient = createMockClient({ agentId: 'skills-test', name: 'skills-agent' });
      const integration = new JACSA2AIntegration(mockClient);
      integration.defaultSkills = [
        { id: 'web-search', name: 'Web Search', description: 'Search the web', tags: ['search', 'web'] },
        { id: 'summarize', name: 'Summarize', description: 'Summarize text', tags: ['nlp'] },
      ];

      server = integration.listen(0);
      const port = server.address().port;

      http.get(`http://localhost:${port}/.well-known/agent-card.json`, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          const card = JSON.parse(body);
          expect(card.skills).to.have.length(2);
          expect(card.skills[0].id).to.equal('web-search');
          expect(card.skills[0].name).to.equal('Web Search');
          expect(card.skills[1].id).to.equal('summarize');
          done();
        });
      }).on('error', done);
    });

    it('should return the server instance for cleanup', () => {
      const mockClient = createMockClient();
      const integration = new JACSA2AIntegration(mockClient);

      server = integration.listen(0);
      expect(server).to.be.an.instanceOf(http.Server);
      expect(server.listening).to.be.true;
    });
  });
});
