/**
 * Tests for JACS A2A Discovery Client - Task #20 [2.3.3]
 *
 * Validates:
 * - discoverAgent() fetches and parses agent cards
 * - discoverAndAssess() checks JACS extension presence
 * - hasJacsExtension() helper
 * - Error handling: 404, non-JSON, unreachable, invalid JSON
 */

const { expect } = require('chai');
const http = require('http');
const express = require('express');
const sinon = require('sinon');
const { discoverAgent, discoverAndAssess, hasJacsExtension } = require('../src/a2a-discovery');
const { jacsA2AMiddleware } = require('../src/a2a-server');
const { JACS_EXTENSION_URI } = require('../src/a2a');

/**
 * Create a mock JacsClient for the a2a-server middleware.
 */
function createMockClient(overrides = {}) {
  return {
    _agent: { signRequest: sinon.stub(), verifyResponse: sinon.stub() },
    agentId: overrides.agentId || 'discovery-test-agent',
    name: overrides.name || 'Discovery Test Agent',
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

describe('A2A Discovery Client - [2.3.3]', function () {
  this.timeout(15000);

  // -------------------------------------------------------------------------
  // Shared JACS agent server (serves agent card with JACS extension)
  // -------------------------------------------------------------------------
  let jacsServer;

  before(async () => {
    const client = createMockClient({ agentId: 'jacs-agent-1', name: 'JACS Agent' });
    const app = express();
    app.use(jacsA2AMiddleware(client, {
      skills: [{ id: 'verify', name: 'Verify', description: 'Verify documents', tags: ['crypto'] }],
    }));
    jacsServer = await startServer(app);
  });

  after(async () => {
    if (jacsServer) await jacsServer.close();
  });

  // -------------------------------------------------------------------------
  // 1. discoverAgent - happy path
  // -------------------------------------------------------------------------
  describe('discoverAgent()', () => {
    it('should fetch and parse an agent card from a JACS server', async () => {
      const card = await discoverAgent(`http://localhost:${jacsServer.port}`);

      expect(card).to.be.an('object');
      expect(card.name).to.equal('JACS Agent');
      expect(card.skills).to.be.an('array');
      expect(card.skills[0].id).to.equal('verify');
      expect(card.protocolVersions).to.be.an('array');
    });

    it('should strip trailing slashes from the URL', async () => {
      const card = await discoverAgent(`http://localhost:${jacsServer.port}///`);
      expect(card.name).to.equal('JACS Agent');
    });
  });

  // -------------------------------------------------------------------------
  // 2. discoverAgent - 404
  // -------------------------------------------------------------------------
  describe('discoverAgent() - 404 handling', () => {
    let emptyServer;

    before(async () => {
      const app = express();
      // No routes at all - everything 404s
      emptyServer = await startServer(app);
    });

    after(async () => {
      if (emptyServer) await emptyServer.close();
    });

    it('should throw on 404 with descriptive message', async () => {
      try {
        await discoverAgent(`http://localhost:${emptyServer.port}`);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.include('404');
        expect(err.message).to.include('agent-card.json');
      }
    });
  });

  // -------------------------------------------------------------------------
  // 3. discoverAgent - non-JSON response
  // -------------------------------------------------------------------------
  describe('discoverAgent() - non-JSON response', () => {
    let htmlServer;

    before(async () => {
      const app = express();
      app.get('/.well-known/agent-card.json', (_req, res) => {
        res.type('text/html').send('<html>Not JSON</html>');
      });
      htmlServer = await startServer(app);
    });

    after(async () => {
      if (htmlServer) await htmlServer.close();
    });

    it('should throw when response content-type is not JSON', async () => {
      try {
        await discoverAgent(`http://localhost:${htmlServer.port}`);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.include('not JSON');
        expect(err.message).to.include('text/html');
      }
    });
  });

  // -------------------------------------------------------------------------
  // 4. discoverAgent - unreachable
  // -------------------------------------------------------------------------
  describe('discoverAgent() - unreachable host', () => {
    it('should throw when host is unreachable', async () => {
      try {
        // Port 1 is almost certainly not listening
        await discoverAgent('http://localhost:1', { timeoutMs: 2000 });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.match(/unreachable|timed out/i);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 5. discoverAgent - invalid JSON body
  // -------------------------------------------------------------------------
  describe('discoverAgent() - invalid JSON body', () => {
    let badJsonServer;

    before(async () => {
      const app = express();
      app.get('/.well-known/agent-card.json', (_req, res) => {
        res.type('application/json').send('{ broken json !!!');
      });
      badJsonServer = await startServer(app);
    });

    after(async () => {
      if (badJsonServer) await badJsonServer.close();
    });

    it('should throw when response body is not valid JSON', async () => {
      try {
        await discoverAgent(`http://localhost:${badJsonServer.port}`);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.include('not valid JSON');
      }
    });
  });

  // -------------------------------------------------------------------------
  // 6. hasJacsExtension helper
  // -------------------------------------------------------------------------
  describe('hasJacsExtension()', () => {
    it('should return true when JACS extension URI is present', () => {
      const card = {
        capabilities: {
          extensions: [{ uri: JACS_EXTENSION_URI, description: 'JACS' }],
        },
      };
      expect(hasJacsExtension(card)).to.be.true;
    });

    it('should return false when no extensions exist', () => {
      expect(hasJacsExtension({ capabilities: {} })).to.be.false;
      expect(hasJacsExtension({ capabilities: { extensions: [] } })).to.be.false;
    });

    it('should return false when extensions exist but none are JACS', () => {
      const card = {
        capabilities: {
          extensions: [{ uri: 'urn:other:extension', description: 'Other' }],
        },
      };
      expect(hasJacsExtension(card)).to.be.false;
    });

    it('should handle null/undefined card gracefully', () => {
      expect(hasJacsExtension(null)).to.be.false;
      expect(hasJacsExtension(undefined)).to.be.false;
      expect(hasJacsExtension({})).to.be.false;
    });
  });

  // -------------------------------------------------------------------------
  // 7. discoverAndAssess - JACS agent
  // -------------------------------------------------------------------------
  describe('discoverAndAssess()', () => {
    it('should return jacs_registered for a JACS agent', async () => {
      const result = await discoverAndAssess(`http://localhost:${jacsServer.port}`);

      expect(result.card).to.be.an('object');
      expect(result.card.name).to.equal('JACS Agent');
      expect(result.jacsRegistered).to.be.true;
      expect(result.trustLevel).to.equal('jacs_registered');
    });
  });

  // -------------------------------------------------------------------------
  // 8. discoverAndAssess - non-JACS agent
  // -------------------------------------------------------------------------
  describe('discoverAndAssess() - non-JACS agent', () => {
    let nonJacsServer;

    before(async () => {
      const app = express();
      app.get('/.well-known/agent-card.json', (_req, res) => {
        res.json({
          name: 'Plain A2A Agent',
          description: 'No JACS',
          version: '1.0',
          protocolVersions: ['0.4.0'],
          skills: [{ id: 'chat', name: 'Chat', description: 'Chat with me', tags: ['chat'] }],
          capabilities: {},
        });
      });
      nonJacsServer = await startServer(app);
    });

    after(async () => {
      if (nonJacsServer) await nonJacsServer.close();
    });

    it('should return untrusted for a non-JACS agent', async () => {
      const result = await discoverAndAssess(`http://localhost:${nonJacsServer.port}`);

      expect(result.card.name).to.equal('Plain A2A Agent');
      expect(result.jacsRegistered).to.be.false;
      expect(result.trustLevel).to.equal('untrusted');
    });
  });

  // -------------------------------------------------------------------------
  // 9. discoverAndAssess - propagates errors
  // -------------------------------------------------------------------------
  describe('discoverAndAssess() - error propagation', () => {
    it('should throw when agent is unreachable', async () => {
      try {
        await discoverAndAssess('http://localhost:1', { timeoutMs: 2000 });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.match(/unreachable|timed out/i);
      }
    });
  });
});
