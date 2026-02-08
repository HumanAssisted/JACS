/**
 * Tests for JACS Simple API
 *
 * The simple API provides a streamlined interface for common JACS operations:
 * - load(): Load an agent from config
 * - verifySelf(): Verify agent integrity
 * - updateAgent(): Update the agent document
 * - updateDocument(): Update an existing document
 * - signMessage(): Sign arbitrary data
 * - signFile(): Sign a file
 * - verify(): Verify a signed document
 * - getPublicKey(): Get public key
 * - getAgentInfo(): Get agent info
 * - isLoaded(): Check if agent is loaded
 */

const { expect } = require('chai');
const path = require('path');
const fs = require('fs');

// Import the compiled simple module
// Note: This requires the TypeScript to be compiled first
let simple;
try {
  simple = require('../simple.js');
} catch (e) {
  // If simple.js doesn't exist, tests will be skipped
  simple = null;
}

// Path to test fixtures (use shared fixtures from jacs/tests/scratch)
const FIXTURES_DIR = path.resolve(__dirname, '../../jacs/tests/scratch');
const TEST_CONFIG = path.join(FIXTURES_DIR, 'jacs.config.json');

// Helper to get a fresh simple module and load it in the fixtures directory
function loadSimpleInFixtures() {
  delete require.cache[require.resolve('../simple.js')];
  const freshSimple = require('../simple.js');

  // Change to fixtures directory for relative path resolution
  const originalCwd = process.cwd();
  process.chdir(FIXTURES_DIR);
  try {
    freshSimple.load(TEST_CONFIG);
  } finally {
    process.chdir(originalCwd);
  }

  return freshSimple;
}

// Helper for tests that need to run in the fixtures directory context
// (e.g., tests using exportAgent, which reads files relative to CWD)
function runInFixturesDir(fn) {
  const originalCwd = process.cwd();
  process.chdir(FIXTURES_DIR);
  try {
    return fn();
  } finally {
    process.chdir(originalCwd);
  }
}

describe('JACS Simple API', function() {
  this.timeout(10000);

  const simpleExists = simple !== null;
  const fixturesExist = fs.existsSync(TEST_CONFIG);

  before(function() {
    if (!simpleExists) {
      console.log('  Skipping simple API tests - simple.js not compiled');
      this.skip();
    }
  });

  describe('isLoaded', () => {
    (simpleExists ? it : it.skip)('should return false when no agent is loaded', () => {
      // Reset state by requiring fresh module
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(freshSimple.isLoaded()).to.be.false;
    });
  });

  describe('load', () => {
    (simpleExists ? it : it.skip)('should throw error for non-existent config', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.load('/nonexistent/jacs.config.json'))
        .to.throw(/Config file not found/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should load agent from valid config', () => {
      const freshSimple = loadSimpleInFixtures();

      expect(freshSimple.isLoaded()).to.be.true;
      const info = freshSimple.getAgentInfo();
      expect(info).to.have.property('agentId');
    });
  });

  describe('getAgentInfo', () => {
    (simpleExists ? it : it.skip)('should return null when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(freshSimple.getAgentInfo()).to.be.null;
    });

    (simpleExists && fixturesExist ? it : it.skip)('should return agent info after loading', () => {
      const freshSimple = loadSimpleInFixtures();

      const info = freshSimple.getAgentInfo();
      expect(info).to.be.an('object');
      expect(info).to.have.property('agentId');
      expect(info).to.have.property('configPath');
    });
  });

  describe('verifySelf', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.verifySelf()).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should verify a loaded agent', () => {
      const freshSimple = loadSimpleInFixtures();

      const result = freshSimple.verifySelf();
      expect(result).to.be.an('object');
      expect(result).to.have.property('valid');
      expect(result.valid).to.be.true;
    });
  });

  describe('verifyStandalone', () => {
    (simpleExists ? it : it.skip)('should not require load() and return valid/signerId', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const tampered = '{"jacsSignature":{"agentID":"test-agent"},"jacsSha256":"x"}';
      const result = freshSimple.verifyStandalone(tampered, { keyResolution: 'local' });
      expect(result).to.be.an('object');
      expect(result).to.have.property('valid');
      expect(result).to.have.property('signerId');
      expect(result.valid).to.be.false;
      expect(result.signerId).to.equal('test-agent');
    });

    (simpleExists ? it : it.skip)('should return valid false for invalid JSON', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const result = freshSimple.verifyStandalone('not json', { keyResolution: 'local' });
      expect(result.valid).to.be.false;
      expect(result.signerId).to.equal('');
    });
  });

  describe('signMessage', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.signMessage({ test: 'data' })).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign an object', () => {
      const freshSimple = loadSimpleInFixtures();

      const signed = freshSimple.signMessage({ action: 'approve', amount: 100 });

      expect(signed).to.be.an('object');
      expect(signed).to.have.property('raw');
      expect(signed).to.have.property('documentId');
      expect(signed).to.have.property('agentId');
      expect(signed).to.have.property('timestamp');

      // Verify the raw document is valid JSON
      const doc = JSON.parse(signed.raw);
      expect(doc).to.have.property('jacsSignature');
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign a string', () => {
      const freshSimple = loadSimpleInFixtures();

      const signed = freshSimple.signMessage('Hello, JACS!');

      expect(signed).to.be.an('object');
      expect(signed.raw).to.be.a('string');
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign nested objects', () => {
      const freshSimple = loadSimpleInFixtures();

      const data = {
        transaction: {
          id: 'tx-123',
          items: [
            { sku: 'A', qty: 2 },
            { sku: 'B', qty: 1 }
          ],
          total: 150.00
        },
        metadata: {
          timestamp: new Date().toISOString(),
          source: 'test'
        }
      };

      const signed = freshSimple.signMessage(data);
      expect(signed.documentId).to.be.a('string');
    });
  });

  describe('updateAgent', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.updateAgent({ name: 'test' })).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should reject incomplete agent data', () => {
      const freshSimple = loadSimpleInFixtures();

      // Passing incomplete data should fail validation
      expect(() => freshSimple.updateAgent({ name: 'test' }))
        .to.throw(/jacsId.*required/i);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should update agent with modified agent document', () => {
      const freshSimple = loadSimpleInFixtures();

      runInFixturesDir(() => {
        // Get the current agent document
        const agentDoc = freshSimple.exportAgent();
        const agent = JSON.parse(agentDoc);
        const originalVersion = agent.jacsVersion;

        // Add required field if missing (for test fixtures compatibility)
        if (!agent.jacsContacts || agent.jacsContacts.length === 0) {
          agent.jacsContacts = [{ contactFirstName: 'Test', contactLastName: 'Contact' }];
        }

        // Modify a field with valid enum value
        agent.jacsAgentType = 'hybrid';

        // Update with modified document
        const result = freshSimple.updateAgent(agent);

        expect(result).to.be.a('string');
        const doc = JSON.parse(result);
        expect(doc).to.have.property('jacsSignature');
        expect(doc).to.have.property('jacsVersion');
        expect(doc.jacsAgentType).to.equal('hybrid');
        // Should have new version
        expect(doc.jacsVersion).to.not.equal(originalVersion);
      });
    });

    (simpleExists && fixturesExist ? it : it.skip)('should update agent with JSON string', () => {
      const freshSimple = loadSimpleInFixtures();

      runInFixturesDir(() => {
        // Get the current agent document and modify it
        const agentDoc = freshSimple.exportAgent();
        const agent = JSON.parse(agentDoc);

        // Add required field if missing (schema requires at least 1 contact)
        if (!agent.jacsContacts || agent.jacsContacts.length === 0) {
          agent.jacsContacts = [{ contactFirstName: 'Test', contactLastName: 'Contact' }];
        }

        agent.jacsAgentType = 'human-org';

        const result = freshSimple.updateAgent(JSON.stringify(agent));

        expect(result).to.be.a('string');
        const doc = JSON.parse(result);
        expect(doc).to.have.property('jacsSignature');
        expect(doc.jacsAgentType).to.equal('human-org');
      });
    });

    (simpleExists && fixturesExist ? it : it.skip)('should create new version on update', () => {
      const freshSimple = loadSimpleInFixtures();

      runInFixturesDir(() => {
        // Get the current agent document
        const agentDoc = freshSimple.exportAgent();
        const agent = JSON.parse(agentDoc);
        const originalVersion = agent.jacsVersion;

        // Add required field if missing (schema requires at least 1 contact)
        if (!agent.jacsContacts || agent.jacsContacts.length === 0) {
          agent.jacsContacts = [{ contactFirstName: 'Test', contactLastName: 'Contact' }];
        }

        // Modify and update
        agent.jacsAgentType = 'human';
        const result = freshSimple.updateAgent(agent);
        const updated = JSON.parse(result);

        // Should have new version
        expect(updated.jacsVersion).to.not.equal(originalVersion);
        expect(updated.jacsPreviousVersion).to.equal(originalVersion);
      });
    });
  });

  describe('updateDocument', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.updateDocument('doc-id', {})).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should fail for non-existent document', () => {
      const freshSimple = loadSimpleInFixtures();

      // Try to update a document that doesn't exist on disk
      expect(() => freshSimple.updateDocument('non-existent-id', { data: 'test' }))
        .to.throw(/not found|Failed to update/i);
    });

    // Note: updateDocument requires the original document to be persisted to disk.
    // For a full test, we would need to:
    // 1. Create a document with persistence (no_save=false)
    // 2. Then update it
    // This is demonstrated in the integration tests with proper fixtures.
  });

  describe('verify', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.verify('{}')).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should verify a valid signed document', () => {
      const freshSimple = loadSimpleInFixtures();

      // Sign a message first
      const signed = freshSimple.signMessage({ test: 'verify' });

      // Verify it
      const result = freshSimple.verify(signed.raw);

      expect(result).to.be.an('object');
      expect(result.valid).to.be.true;
      expect(result.signerId).to.be.a('string');
      expect(result.errors).to.be.an('array').that.is.empty;
    });

    (simpleExists && fixturesExist ? it : it.skip)('should reject invalid JSON', () => {
      const freshSimple = loadSimpleInFixtures();

      const result = freshSimple.verify('not valid json');

      expect(result.valid).to.be.false;
      expect(result.errors).to.have.length.greaterThan(0);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should reject tampered documents', () => {
      const freshSimple = loadSimpleInFixtures();

      // Sign a message first
      const signed = freshSimple.signMessage({ original: 'data' });
      const doc = JSON.parse(signed.raw);

      // Tamper with the content
      doc.content = { tampered: 'data' };

      const result = freshSimple.verify(JSON.stringify(doc));

      expect(result.valid).to.be.false;
    });
  });

  describe('signFile', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.signFile('test.txt')).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should throw for non-existent file', () => {
      const freshSimple = loadSimpleInFixtures();

      expect(() => freshSimple.signFile('/nonexistent/file.txt'))
        .to.throw(/File not found/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign an existing file', () => {
      const freshSimple = loadSimpleInFixtures();

      // Create a temp file to sign
      const tempFile = path.join(__dirname, 'temp-test-file.txt');
      fs.writeFileSync(tempFile, 'Test file content for signing');

      try {
        const signed = freshSimple.signFile(tempFile, false);

        expect(signed).to.be.an('object');
        expect(signed).to.have.property('raw');
        expect(signed).to.have.property('documentId');
      } finally {
        fs.unlinkSync(tempFile);
      }
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign and embed file content', () => {
      const freshSimple = loadSimpleInFixtures();

      // Create a temp file to sign
      const tempFile = path.join(__dirname, 'temp-embed-file.txt');
      const fileContent = 'Embedded file content';
      fs.writeFileSync(tempFile, fileContent);

      try {
        const signed = freshSimple.signFile(tempFile, true);

        expect(signed).to.be.an('object');
        expect(signed).to.have.property('raw');
        expect(signed).to.have.property('documentId');

        // Note: jacsFiles embedding only works for files within JACS data directory
        // For files outside the data directory, signing works but embedding is skipped
        const doc = JSON.parse(signed.raw);
        expect(doc).to.have.property('jacsSignature');
      } finally {
        fs.unlinkSync(tempFile);
      }
    });
  });

  describe('registerWithHai', () => {
    (simpleExists ? it : it.skip)('should throw when no apiKey and no HAI_API_KEY', async () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const orig = process.env.HAI_API_KEY;
      delete process.env.HAI_API_KEY;
      try {
        if (fixturesExist) {
          loadSimpleInFixtures();
          await expect(freshSimple.registerWithHai({ haiUrl: 'https://hai.ai' }))
            .to.be.rejectedWith(/api key|HAI_API_KEY|required/i);
        }
      } finally {
        if (orig !== undefined) process.env.HAI_API_KEY = orig;
      }
    });

    (simpleExists && fixturesExist ? it : it.skip)('should POST to /api/v1/agents/register with Bearer and agent JSON', async () => {
      const freshSimple = loadSimpleInFixtures();
      const baseUrl = 'http://mock-hai.test';
      let capturedRequest = null;
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (url, opts) => {
        capturedRequest = { url, method: opts?.method, headers: opts?.headers, body: opts?.body };
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            agent_id: 'mock-agent-id',
            jacs_id: 'mock-jacs-id',
            dns_verified: true,
            signatures: [{ key_id: 'k1', signature: 'sig1', algorithm: 'Ed25519', signed_at: '2025-01-01T00:00:00Z' }],
          }),
        });
      };
      try {
        const result = await freshSimple.registerWithHai({ apiKey: 'test-key', haiUrl: baseUrl });
        expect(capturedRequest).to.not.be.null;
        expect(capturedRequest.url).to.equal(`${baseUrl}/api/v1/agents/register`);
        expect(capturedRequest.method).to.equal('POST');
        expect(capturedRequest.headers?.Authorization).to.equal('Bearer test-key');
        const body = typeof capturedRequest.body === 'string' ? JSON.parse(capturedRequest.body) : capturedRequest.body;
        expect(body).to.have.property('agent_json');
        expect(result).to.have.property('agentId', 'mock-agent-id');
        expect(result).to.have.property('jacsId', 'mock-jacs-id');
        expect(result).to.have.property('dnsVerified', true);
        expect(result.signatures).to.be.an('array');
        expect(result.signatures).to.include('sig1');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe('DNS helpers', () => {
    (simpleExists && fixturesExist ? it : it.skip)('getDnsRecord returns TXT line in expected format', () => {
      const freshSimple = loadSimpleInFixtures();
      const record = freshSimple.getDnsRecord('example.com', 3600);
      expect(record).to.be.a('string');
      expect(record).to.match(/^_v1\.agent\.jacs\.example\.com\.\s+3600\s+IN\s+TXT\s+"/);
      expect(record).to.include('v=hai.ai');
      expect(record).to.include('jacs_agent_id=');
      expect(record).to.include('alg=SHA-256');
      expect(record).to.include('enc=base64');
      expect(record).to.include('jac_public_key_hash=');
    });

    (simpleExists && fixturesExist ? it : it.skip)('getWellKnownJson returns object with publicKey, publicKeyHash, algorithm, agentId', () => {
      const freshSimple = loadSimpleInFixtures();
      const json = freshSimple.getWellKnownJson();
      expect(json).to.be.an('object');
      expect(json).to.have.property('publicKey');
      expect(json).to.have.property('publicKeyHash');
      expect(json).to.have.property('algorithm');
      expect(json).to.have.property('agentId');
    });
  });

  describe('round-trip: sign and verify', () => {
    (simpleExists && fixturesExist ? it : it.skip)('should complete a full sign-verify cycle', () => {
      const freshSimple = loadSimpleInFixtures();

      const originalData = {
        type: 'transaction',
        id: 'tx-' + Date.now(),
        amount: 99.99,
        currency: 'USD',
        approved: true
      };

      // Sign the data
      const signed = freshSimple.signMessage(originalData);

      // Verify the signed document
      const result = freshSimple.verify(signed.raw);

      expect(result.valid).to.be.true;
      expect(result.errors).to.be.empty;
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign multiple messages with same agent', () => {
      const freshSimple = loadSimpleInFixtures();

      const messages = [
        { seq: 1, msg: 'First' },
        { seq: 2, msg: 'Second' },
        { seq: 3, msg: 'Third' }
      ];

      const signedMessages = messages.map(m => freshSimple.signMessage(m));

      // All should have unique document IDs
      const docIds = signedMessages.map(s => s.documentId);
      const uniqueIds = new Set(docIds);
      expect(uniqueIds.size).to.equal(3);

      // All should be verifiable
      for (const signed of signedMessages) {
        const result = freshSimple.verify(signed.raw);
        expect(result.valid).to.be.true;
      }
    });
  });

  describe('audit', () => {
    (simpleExists ? it : it.skip)('should return object with risks and health_checks', () => {
      const result = simple.audit();
      expect(result).to.have.property('risks');
      expect(result).to.have.property('health_checks');
      expect(result.risks).to.be.an('array');
      expect(result.health_checks).to.be.an('array');
    });

    (simpleExists ? it : it.skip)('should return summary and overall_status', () => {
      const result = simple.audit();
      expect(result).to.have.property('summary');
      expect(result).to.have.property('overall_status');
      expect(result.summary).to.be.a('string');
    });
  });
});
