/**
 * Tests for JACS Agent class - Core functionality
 *
 * Updated for v0.7.0 async-first API:
 * - Instance methods use Sync suffix for blocking variants
 * - signRequest/verifyResponse remain sync (V8-thread-only)
 */

const { expect } = require('chai');
const { JacsAgent, hashString } = require('../index');
const path = require('path');
const fs = require('fs');
const { enableLegacyFixtureCompatibility } = require('./legacy-fixture');

// Path to test fixtures (use jacspy fixtures which have a working agent)
// Use shared fixtures from jacs/tests/scratch (single source of truth)
const FIXTURES_DIR = path.resolve(__dirname, '../../jacs/tests/scratch');
const TEST_CONFIG = path.join(FIXTURES_DIR, 'jacs.config.json');

// Helper to run tests in the fixtures directory context
function withFixturesDir(fn) {
  const originalCwd = process.cwd();
  process.chdir(FIXTURES_DIR);
  try {
    return fn();
  } finally {
    process.chdir(originalCwd);
  }
}

describe('JacsAgent Class', () => {
  let restoreLegacyFixtureCompatibility;

  before(() => {
    restoreLegacyFixtureCompatibility = enableLegacyFixtureCompatibility();
  });

  after(() => {
    restoreLegacyFixtureCompatibility();
  });

  describe('constructor', () => {
    it('should create a new JacsAgent instance', () => {
      const agent = new JacsAgent();
      expect(agent).to.be.instanceOf(JacsAgent);
    });

    it('should create multiple independent instances', () => {
      const agent1 = new JacsAgent();
      const agent2 = new JacsAgent();
      expect(agent1).to.not.equal(agent2);
    });
  });

  describe('strict raw JSON ingress', () => {
    it('rejects duplicate decoded keys before canonicalization', () => {
      const agent = new JacsAgent();
      expect(() => agent.canonicalizeJsonSync(
        '{"role":"reader","role":"admin","agentID":"one","agent\\u0049D":"two"}',
      )).to.throw(/duplicate JSON object key/);
    });
  });

  describe('request-bound authorization', () => {
    it('preserves the legacy builder and exposes request binding additively', async () => {
      const agent = new JacsAgent();
      agent.ephemeralSync('pq2025');
      const legacy = agent.buildAuthHeaderSync();
      expect(legacy).to.match(/^JACS /);

      const header = agent.buildRequestAuthHeaderSync(
        'POST',
        'https://api.example.test/v1/jobs?mode=fast',
        '{"task":"review"}',
        'hai-api',
      );
      expect(header).to.match(/^JACS v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      const asyncLegacy = await agent.buildAuthHeader();
      expect(asyncLegacy).to.match(/^JACS /);
      const asyncHeader = await agent.buildRequestAuthHeader(
        'POST',
        'https://api.example.test/v1/jobs?mode=fast',
        Buffer.from('{"task":"review"}'),
        'hai-api',
      );
      expect(asyncHeader).to.match(/^JACS v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      process.env.JACS_REJECT_UNBOUND_AUTH_HEADER = 'true';
      try {
        expect(() => agent.buildAuthHeaderSync()).to.throw(/legacy unbound|rejected/i);
      } finally {
        delete process.env.JACS_REJECT_UNBOUND_AUTH_HEADER;
      }
    });
  });

  describe('fully-bound response envelopes', () => {
    it('authenticates every envelope field and fails closed for unknown keys', () => {
      const agent = new JacsAgent();
      agent.ephemeralSync('pq2025');
      const signed = agent.signResponseSync('{"decision":"allow"}');
      const envelope = JSON.parse(signed);
      const signerId = envelope.jacsSignature.agentID;
      const keys = JSON.stringify({ [signerId]: agent.getPublicKeyPem() });

      expect(envelope.version).to.equal('2.0.0');
      expect(envelope.jacsSignature.signatureContentVersion)
        .to.equal('jacs-response-v2');
      const verified = JSON.parse(agent.unwrapSignedEventSync(signed, keys));
      expect(verified).to.include({ verified: true, status: 'verified' });
      expect(verified.data).to.deep.equal({ decision: 'allow' });
      expect(verified.signerId).to.equal(signerId);

      const attacks = [
        ['version', '9.9.9'],
        ['document_type', 'admin_command'],
      ];
      for (const [field, value] of attacks) {
        const mutated = structuredClone(envelope);
        mutated[field] = value;
        expect(() => agent.unwrapSignedEventSync(JSON.stringify(mutated), keys))
          .to.throw(/verification failed|response envelope/i);
      }
      for (const [section, field, value] of [
        ['metadata', 'issuer', 'attacker'],
        ['metadata', 'document_id', '00000000-0000-0000-0000-000000000000'],
        ['metadata', 'created_at', '2099-01-01T00:00:00Z'],
        ['metadata', 'hash', '0'.repeat(64)],
        ['jacsSignature', 'agentID', 'attacker'],
        ['jacsSignature', 'date', '2099-01-01T00:00:00Z'],
        ['jacsSignature', 'signingAlgorithm', 'ring-Ed25519'],
        ['jacsSignature', 'publicKeyHash', 'attacker-key'],
      ]) {
        const mutated = structuredClone(envelope);
        mutated[section][field] = value;
        const aliases = section === 'jacsSignature' && field === 'agentID'
          ? JSON.stringify({ [signerId]: agent.getPublicKeyPem(), attacker: agent.getPublicKeyPem() })
          : keys;
        expect(() => agent.unwrapSignedEventSync(JSON.stringify(mutated), aliases))
          .to.throw(/failed|mismatch|unsupported|unexpected|future|unknown/i);
      }

      expect(() => agent.unwrapSignedEventSync(signed, '{}'))
        .to.throw(/unknown|verification failed/i);
    });
  });

  describe('loadSync', function() {
    // Loading can take a moment
    this.timeout(10000);

    it('should throw error for non-existent config file', () => {
      const agent = new JacsAgent();
      expect(() => agent.loadSync('/nonexistent/path/jacs.config.json'))
        .to.throw();
    });

    it('should throw error for invalid config JSON', () => {
      const agent = new JacsAgent();
      // Create a temp file with invalid JSON
      const tempPath = path.join(__dirname, 'temp-invalid-config.json');
      fs.writeFileSync(tempPath, 'not valid json');

      try {
        expect(() => agent.loadSync(tempPath)).to.throw();
      } finally {
        fs.unlinkSync(tempPath);
      }
    });

    // Skip tests that require actual key files if fixtures don't exist
    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should load agent from valid config', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        const result = agent.loadSync(TEST_CONFIG);
        expect(result).to.be.a('string');
      });
    });
  });

  describe('load (async)', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    it('should reject for non-existent config file', async () => {
      const agent = new JacsAgent();
      let caught = null;
      try {
        await agent.load('/nonexistent/path/jacs.config.json');
      } catch (e) {
        caught = e;
      }
      expect(caught).to.not.equal(null);
    });

    (fixturesExist ? it : it.skip)('should load agent from valid config (async)', async () => {
      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const agent = new JacsAgent();
        const result = await agent.load(TEST_CONFIG);
        expect(result).to.be.a('string');
      } finally {
        process.chdir(originalCwd);
      }
    });
  });

  describe('signStringSync and verifyStringSync', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should sign and verify a string', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.loadSync(TEST_CONFIG);

        const data = 'Hello, JACS!';
        const signature = agent.signStringSync(data);

        expect(signature).to.be.a('string');
        expect(signature.length).to.be.greaterThan(0);
      });
    });
  });

  describe('createDocumentSync', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should create a signed document', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.loadSync(TEST_CONFIG);

        const docContent = JSON.stringify({
          jacsType: 'document',
          jacsLevel: 'raw',
          content: { message: 'test' }
        });

        const result = agent.createDocumentSync(
          docContent,
          null, // customSchema
          null, // outputfilename
          true, // noSave - don't save to disk
          null, // attachments
          null  // embed
        );

        expect(result).to.be.a('string');

        const doc = JSON.parse(result);
        expect(doc).to.have.property('jacsId');
        expect(doc).to.have.property('jacsSignature');
        expect(doc).to.have.property('jacsSha256');
        expect(doc.jacsSignature).to.have.property('signature');
        expect(doc.jacsSignature).to.have.property('agentID');
      });
    });

    (fixturesExist ? it : it.skip)('should create documents with different content', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.loadSync(TEST_CONFIG);

        const doc1Content = JSON.stringify({
          jacsType: 'document',
          jacsLevel: 'raw',
          content: { value: 1 }
        });

        const doc2Content = JSON.stringify({
          jacsType: 'document',
          jacsLevel: 'raw',
          content: { value: 2 }
        });

        const result1 = agent.createDocumentSync(doc1Content, null, null, true, null, null);
        const result2 = agent.createDocumentSync(doc2Content, null, null, true, null, null);

        const parsed1 = JSON.parse(result1);
        const parsed2 = JSON.parse(result2);

        // Different content should produce different document IDs
        expect(parsed1.jacsId).to.not.equal(parsed2.jacsId);
        // Different content should produce different hashes
        expect(parsed1.jacsSha256).to.not.equal(parsed2.jacsSha256);
      });
    });
  });

  describe('verifyDocumentSync', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should verify a valid signed document', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.loadSync(TEST_CONFIG);

        // Create a document first
        const docContent = JSON.stringify({
          jacsType: 'document',
          jacsLevel: 'raw',
          content: { action: 'approve' }
        });

        const signedDoc = agent.createDocumentSync(docContent, null, null, true, null, null);

        // Verify the document
        const isValid = agent.verifyDocumentSync(signedDoc);
        expect(isValid).to.be.true;
      });
    });

    (fixturesExist ? it : it.skip)('should reject a tampered document', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.loadSync(TEST_CONFIG);

        // Create a document first
        const docContent = JSON.stringify({
          jacsType: 'document',
          jacsLevel: 'raw',
          content: { action: 'approve' }
        });

        const signedDoc = agent.createDocumentSync(docContent, null, null, true, null, null);
        const doc = JSON.parse(signedDoc);

        // Tamper with the content
        doc.content = { action: 'TAMPERED' };
        const tamperedDoc = JSON.stringify(doc);

        // Verification should fail
        expect(() => agent.verifyDocumentSync(tamperedDoc)).to.throw();
      });
    });
  });

  describe('verifyAgentSync', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should verify agent integrity', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.loadSync(TEST_CONFIG);

        // verifyAgent should return true or throw if invalid
        const result = agent.verifyAgentSync();
        expect(result).to.be.true;
      });
    });
  });

  describe('signRequest and verifyResponse (V8-thread-only, no Sync suffix)', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should sign and verify a request/response', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.loadSync(TEST_CONFIG);

        const payload = {
          method: 'test',
          params: { foo: 'bar' }
        };

        const signedRequest = agent.signRequest(payload);
        expect(signedRequest).to.be.a('string');

        const parsed = JSON.parse(signedRequest);
        expect(parsed).to.have.property('jacsSignature');

        // Verify the response
        const result = agent.verifyResponse(signedRequest);
        expect(result).to.be.an('object');
      });
    });
  });

  // --- Async variants of key operations ---
  describe('async operations', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should create and verify document (async)', async () => {
      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const agent = new JacsAgent();
        await agent.load(TEST_CONFIG);

        const docContent = JSON.stringify({
          jacsType: 'document',
          jacsLevel: 'raw',
          content: { message: 'async test' }
        });

        const signedDoc = await agent.createDocument(docContent, null, null, true, null, null);
        expect(signedDoc).to.be.a('string');
        const doc = JSON.parse(signedDoc);
        expect(doc).to.have.property('jacsId');

        const isValid = await agent.verifyDocument(signedDoc);
        expect(isValid).to.be.true;
      } finally {
        process.chdir(originalCwd);
      }
    });

    (fixturesExist ? it : it.skip)('should verify agent integrity (async)', async () => {
      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const agent = new JacsAgent();
        await agent.load(TEST_CONFIG);
        const result = await agent.verifyAgent();
        expect(result).to.be.true;
      } finally {
        process.chdir(originalCwd);
      }
    });
  });
});
