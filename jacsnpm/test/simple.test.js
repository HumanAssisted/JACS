/**
 * Tests for JACS Simple API
 *
 * Updated for v0.7.0 async-first API:
 * - Functions that hit NAPI use Sync suffix for blocking variants
 * - Pure sync helpers (getPublicKey, exportAgent, etc.) stay unchanged
 * - Async tests added for key operations
 */

const { expect } = require('chai');
const path = require('path');
const fs = require('fs');
const os = require('os');

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

// Helper to get a fresh simple module and load it in the fixtures directory (sync)
function loadSimpleInFixtures() {
  delete require.cache[require.resolve('../simple.js')];
  const freshSimple = require('../simple.js');

  // Change to fixtures directory for relative path resolution
  const originalCwd = process.cwd();
  process.chdir(FIXTURES_DIR);
  try {
    freshSimple.loadSync(TEST_CONFIG);
  } finally {
    process.chdir(originalCwd);
  }

  return freshSimple;
}

// Helper for tests that need to run in the fixtures directory context
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

  describe('loadSync', () => {
    (simpleExists ? it : it.skip)('should throw error for non-existent config', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.loadSync('/nonexistent/jacs.config.json'))
        .to.throw(/Config file not found/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should load agent from valid config', () => {
      const freshSimple = loadSimpleInFixtures();

      expect(freshSimple.isLoaded()).to.be.true;
      const info = freshSimple.getAgentInfo();
      expect(info).to.have.property('agentId');
    });
  });

  describe('load (async)', () => {
    (simpleExists ? it : it.skip)('should reject for non-existent config', async () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      let caught = null;
      try {
        await freshSimple.load('/nonexistent/jacs.config.json');
      } catch (e) {
        caught = e;
      }
      expect(caught).to.not.equal(null);
      expect(String(caught)).to.match(/Config file not found/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should load agent from valid config (async)', async () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const info = await freshSimple.load(TEST_CONFIG);
        expect(freshSimple.isLoaded()).to.be.true;
        expect(info).to.have.property('agentId');
      } finally {
        process.chdir(originalCwd);
      }
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

  describe('verifySelfSync', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.verifySelfSync()).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should verify a loaded agent', () => {
      const freshSimple = loadSimpleInFixtures();

      const result = freshSimple.verifySelfSync();
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

    (simpleExists && fixturesExist ? it : it.skip)('should verify a valid signed document without a loaded agent', () => {
      // Sign with a loaded agent, then verify standalone
      const freshSimple = loadSimpleInFixtures();
      const signed = freshSimple.signMessageSync({ standalone: 'test' });
      freshSimple.reset();

      delete require.cache[require.resolve('../simple.js')];
      const cleanSimple = require('../simple.js');
      expect(cleanSimple.isLoaded()).to.be.false;

      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const result = cleanSimple.verifyStandalone(signed.raw);
        expect(result.valid).to.be.true;
        expect(result.signerId).to.be.a('string').and.not.empty;
      } finally {
        process.chdir(originalCwd);
      }
    });

    (simpleExists && fixturesExist ? it : it.skip)('should reject a tampered signed document', () => {
      const freshSimple = loadSimpleInFixtures();
      const signed = freshSimple.signMessageSync({ original: true });
      const doc = JSON.parse(signed.raw);
      doc.content = { tampered: true };
      freshSimple.reset();

      delete require.cache[require.resolve('../simple.js')];
      const cleanSimple = require('../simple.js');

      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const result = cleanSimple.verifyStandalone(JSON.stringify(doc));
        expect(result.valid).to.be.false;
      } finally {
        process.chdir(originalCwd);
      }
    });

    (simpleExists && fixturesExist ? it : it.skip)('should work with custom keyDirectory option', () => {
      const freshSimple = loadSimpleInFixtures();
      const signed = freshSimple.signMessageSync({ customKey: true });
      const configJson = JSON.parse(fs.readFileSync(TEST_CONFIG, 'utf8'));
      const keyDir = path.resolve(FIXTURES_DIR, configJson.jacs_key_directory || './jacs_keys');
      freshSimple.reset();

      delete require.cache[require.resolve('../simple.js')];
      const cleanSimple = require('../simple.js');

      const result = cleanSimple.verifyStandalone(signed.raw, { keyDirectory: keyDir });
      expect(result.valid).to.be.true;
      expect(result.signerId).to.be.a('string').and.not.empty;
    });

    (simpleExists ? it : it.skip)('should return result shape with all expected fields', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const result = freshSimple.verifyStandalone('{}');
      expect(result).to.have.property('valid');
      expect(result).to.have.property('signerId');
      expect(result).to.have.property('timestamp');
      expect(result).to.have.property('attachments');
      expect(result).to.have.property('errors');
      expect(result.attachments).to.be.an('array');
      expect(result.errors).to.be.an('array');
    });
  });

  describe('generateVerifyLink', () => {
    (simpleExists ? it : it.skip)('should produce a valid hai.ai URL with base64url-encoded document', () => {
      const doc = '{"jacsId":"test","jacsSignature":{}}';
      const url = simple.generateVerifyLink(doc);
      expect(url).to.be.a('string');
      expect(url).to.match(/^https:\/\/hai\.ai\/jacs\/verify\?s=/);
      // Should not contain standard base64 chars that are URL-unsafe
      const param = url.split('?s=')[1];
      expect(param).to.not.include('+');
      expect(param).to.not.include('/');
      expect(param).to.not.include('=');
    });

    (simpleExists ? it : it.skip)('should allow a custom base URL', () => {
      const doc = '{"test": true}';
      const url = simple.generateVerifyLink(doc, 'https://custom.example.com');
      expect(url).to.match(/^https:\/\/custom\.example\.com\/jacs\/verify\?s=/);
    });

    (simpleExists ? it : it.skip)('should strip trailing slashes from base URL', () => {
      const doc = '{"test": true}';
      const url = simple.generateVerifyLink(doc, 'https://hai.ai///');
      expect(url).to.match(/^https:\/\/hai\.ai\/jacs\/verify\?s=/);
    });

    (simpleExists ? it : it.skip)('should round-trip: decode produces the original document', () => {
      const doc = '{"jacsId":"abc-123","content":"hello"}';
      const url = simple.generateVerifyLink(doc);
      const encoded = url.split('?s=')[1];
      // Restore standard base64 padding
      let b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) b64 += '=';
      const decoded = Buffer.from(b64, 'base64').toString('utf8');
      expect(decoded).to.equal(doc);
    });

    (simpleExists ? it : it.skip)('should throw for documents exceeding max URL length', () => {
      // Create a document larger than MAX_VERIFY_DOCUMENT_BYTES
      const bigDoc = JSON.stringify({ data: 'x'.repeat(2000) });
      expect(() => simple.generateVerifyLink(bigDoc)).to.throw(/max length/i);
    });

    (simpleExists ? it : it.skip)('should export MAX_VERIFY_URL_LEN and MAX_VERIFY_DOCUMENT_BYTES constants', () => {
      expect(simple.MAX_VERIFY_URL_LEN).to.equal(2048);
      expect(simple.MAX_VERIFY_DOCUMENT_BYTES).to.equal(1515);
    });
  });

  describe('signMessageSync', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.signMessageSync({ test: 'data' })).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign an object', () => {
      const freshSimple = loadSimpleInFixtures();

      const signed = freshSimple.signMessageSync({ action: 'approve', amount: 100 });

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

      const signed = freshSimple.signMessageSync('Hello, JACS!');

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

      const signed = freshSimple.signMessageSync(data);
      expect(signed.documentId).to.be.a('string');
    });
  });

  describe('agreements', () => {
    (simpleExists && fixturesExist ? it : it.skip)('should create, sign, and verify an agreement workflow', () => {
      const freshSimple = loadSimpleInFixtures();
      const info = freshSimple.getAgentInfo();
      expect(info).to.be.an('object');
      const agentId = info.agentId;

      const agreement = freshSimple.createAgreementSync(
        { proposal: 'Approve Q4 budget', amount: 10000 },
        [agentId],
        'Do you approve this budget?',
        'Node simple API agreement smoke test'
      );
      expect(agreement).to.have.property('raw');
      expect(agreement.documentId).to.be.a('string').and.not.empty;

      let pendingError = null;
      try {
        freshSimple.checkAgreementSync(agreement);
      } catch (e) {
        pendingError = e;
      }
      expect(pendingError).to.not.equal(null);
      expect(String(pendingError)).to.match(/not all agents have signed/i);

      const signed = freshSimple.signAgreementSync(agreement);
      expect(signed.documentId).to.be.a('string').and.not.empty;

      const complete = freshSimple.checkAgreementSync(signed);
      expect(complete.complete).to.equal(true);
      expect(complete.pending).to.be.an('array').that.is.empty;

      const verified = freshSimple.verifySync(signed.raw);
      expect(verified.valid).to.equal(true);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should create agreement from JSON string payload', () => {
      const freshSimple = loadSimpleInFixtures();
      const info = freshSimple.getAgentInfo();
      const payload = JSON.stringify({ proposal: 'String payload agreement' });
      const agreement = freshSimple.createAgreementSync(payload, [info.agentId]);
      expect(agreement.documentId).to.be.a('string').and.not.empty;
    });

    (simpleExists ? it : it.skip)('should require both agents for two-party agreement completion', () => {
      const modulePath = require.resolve('../simple.js');
      const password = 'TestP@ss123!#';
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-two-agent-'));
      const originalCwd = process.cwd();

      function freshSimpleModule() {
        delete require.cache[modulePath];
        return require('../simple.js');
      }

      try {
        // Use relative paths from an isolated working directory to match storage path handling.
        process.chdir(root);
        fs.mkdirSync('agent1', { recursive: true });
        fs.mkdirSync('agent2', { recursive: true });

        const simpleA = freshSimpleModule();
        const simpleB = freshSimpleModule();

        simpleA.createSync({
          name: 'mocha-agent-a',
          password,
          algorithm: 'ring-Ed25519',
          dataDirectory: 'shared-data',
          keyDirectory: 'agent1/keys',
          configPath: 'agent1/jacs.config.json',
        });
        simpleB.createSync({
          name: 'mocha-agent-b',
          password,
          algorithm: 'ring-Ed25519',
          dataDirectory: 'shared-data',
          keyDirectory: 'agent2/keys',
          configPath: 'agent2/jacs.config.json',
        });

        simpleA.loadSync('agent1/jacs.config.json');
        simpleB.loadSync('agent2/jacs.config.json');

        const infoA = simpleA.getAgentInfo();
        const infoB = simpleB.getAgentInfo();
        expect(infoA).to.be.an('object');
        expect(infoB).to.be.an('object');

        const agreement = simpleA.createAgreementSync(
          { proposal: 'two-party-approval', scope: 'integration-test' },
          [infoA.agentId, infoB.agentId],
          'Do both parties approve?',
          'Two-agent simple API test'
        );
        expect(agreement.documentId).to.be.a('string').and.not.empty;

        expect(() => simpleA.checkAgreementSync(agreement)).to.throw(/not all agents have signed/i);

        const signedByA = simpleA.signAgreementSync(agreement);
        expect(() => simpleA.checkAgreementSync(signedByA)).to.throw(/not all agents have signed/i);

        const signedByBoth = simpleB.signAgreementSync(signedByA);
        const status = simpleB.checkAgreementSync(signedByBoth);
        expect(status.complete).to.equal(true);
        expect(status.pending).to.be.an('array').that.is.empty;
      } finally {
        process.chdir(originalCwd);
        fs.rmSync(root, { recursive: true, force: true });
      }
    });
  });

  describe('updateAgentSync', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.updateAgentSync({ name: 'test' })).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should reject incomplete agent data', () => {
      const freshSimple = loadSimpleInFixtures();

      // Passing incomplete data should fail validation
      expect(() => freshSimple.updateAgentSync({ name: 'test' }))
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
        const result = freshSimple.updateAgentSync(agent);

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

        const result = freshSimple.updateAgentSync(JSON.stringify(agent));

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
        const result = freshSimple.updateAgentSync(agent);
        const updated = JSON.parse(result);

        // Should have new version
        expect(updated.jacsVersion).to.not.equal(originalVersion);
        expect(updated.jacsPreviousVersion).to.equal(originalVersion);
      });
    });
  });

  describe('updateDocumentSync', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.updateDocumentSync('doc-id', {})).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should fail for non-existent document', () => {
      const freshSimple = loadSimpleInFixtures();

      // Try to update a document that doesn't exist on disk
      expect(() => freshSimple.updateDocumentSync('non-existent-id', { data: 'test' }))
        .to.throw(/not found|Failed to update/i);
    });
  });

  describe('verifySync', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.verifySync('{}')).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should verify a valid signed document', () => {
      const freshSimple = loadSimpleInFixtures();

      // Sign a message first
      const signed = freshSimple.signMessageSync({ test: 'verify' });

      // Verify it
      const result = freshSimple.verifySync(signed.raw);

      expect(result).to.be.an('object');
      expect(result.valid).to.be.true;
      expect(result.signerId).to.be.a('string');
      expect(result.errors).to.be.an('array').that.is.empty;
    });

    (simpleExists && fixturesExist ? it : it.skip)('should reject invalid JSON', () => {
      const freshSimple = loadSimpleInFixtures();

      const result = freshSimple.verifySync('not valid json');

      expect(result.valid).to.be.false;
      expect(result.errors).to.have.length.greaterThan(0);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should reject tampered documents', () => {
      const freshSimple = loadSimpleInFixtures();

      // Sign a message first
      const signed = freshSimple.signMessageSync({ original: 'data' });
      const doc = JSON.parse(signed.raw);

      // Tamper with the content
      doc.content = { tampered: 'data' };

      const result = freshSimple.verifySync(JSON.stringify(doc));

      expect(result.valid).to.be.false;
    });
  });

  describe('signFileSync', () => {
    (simpleExists ? it : it.skip)('should throw when no agent is loaded', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      expect(() => freshSimple.signFileSync('test.txt')).to.throw(/No agent loaded/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should throw for non-existent file', () => {
      const freshSimple = loadSimpleInFixtures();

      expect(() => freshSimple.signFileSync('/nonexistent/file.txt'))
        .to.throw(/File not found/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should sign an existing file', () => {
      const freshSimple = loadSimpleInFixtures();

      // Create a temp file to sign
      const tempFile = path.join(__dirname, 'temp-test-file.txt');
      fs.writeFileSync(tempFile, 'Test file content for signing');

      try {
        const signed = freshSimple.signFileSync(tempFile, false);

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
        const signed = freshSimple.signFileSync(tempFile, true);

        expect(signed).to.be.an('object');
        expect(signed).to.have.property('raw');
        expect(signed).to.have.property('documentId');

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
          const loadedSimple = loadSimpleInFixtures();
          let caught = null;
          try {
            await loadedSimple.registerWithHai({ haiUrl: 'https://hai.ai' });
          } catch (e) {
            caught = e;
          }
          expect(caught).to.not.equal(null);
          expect(String(caught)).to.match(/api key|HAI_API_KEY|required/i);
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

  describe('round-trip: sign and verify (sync)', () => {
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
      const signed = freshSimple.signMessageSync(originalData);

      // Verify the signed document
      const result = freshSimple.verifySync(signed.raw);

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

      const signedMessages = messages.map(m => freshSimple.signMessageSync(m));

      // All should have unique document IDs
      const docIds = signedMessages.map(s => s.documentId);
      const uniqueIds = new Set(docIds);
      expect(uniqueIds.size).to.equal(3);

      // All should be verifiable
      for (const signed of signedMessages) {
        const result = freshSimple.verifySync(signed.raw);
        expect(result.valid).to.be.true;
      }
    });
  });

  describe('round-trip: sign and verify (async)', () => {
    (simpleExists && fixturesExist ? it : it.skip)('should complete a full async sign-verify cycle', async () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        await freshSimple.load(TEST_CONFIG);
      } finally {
        process.chdir(originalCwd);
      }

      const signed = await freshSimple.signMessage({ type: 'async-test', value: 42 });
      expect(signed).to.have.property('raw');
      expect(signed).to.have.property('documentId');

      const result = await freshSimple.verify(signed.raw);
      expect(result.valid).to.be.true;
      expect(result.errors).to.be.empty;
    });
  });

  describe('auditSync', () => {
    (simpleExists ? it : it.skip)('should return object with risks and health_checks', () => {
      const result = simple.auditSync();
      expect(result).to.have.property('risks');
      expect(result).to.have.property('health_checks');
      expect(result.risks).to.be.an('array');
      expect(result.health_checks).to.be.an('array');
    });

    (simpleExists ? it : it.skip)('should return summary and overall_status', () => {
      const result = simple.auditSync();
      expect(result).to.have.property('summary');
      expect(result).to.have.property('overall_status');
      expect(result.summary).to.be.a('string');
    });
  });

  describe('audit (async)', () => {
    (simpleExists ? it : it.skip)('should return object with risks and health_checks (async)', async () => {
      const result = await simple.audit();
      expect(result).to.have.property('risks');
      expect(result).to.have.property('health_checks');
      expect(result.risks).to.be.an('array');
      expect(result.health_checks).to.be.an('array');
    });
  });
});
