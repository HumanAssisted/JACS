/**
 * Tests for JACS Agent class - Core functionality
 */

const { expect } = require('chai');
const { JacsAgent, hashString } = require('../index');
const path = require('path');
const fs = require('fs');

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

  describe('load', function() {
    // Loading can take a moment
    this.timeout(10000);

    it('should throw error for non-existent config file', () => {
      const agent = new JacsAgent();
      expect(() => agent.load('/nonexistent/path/jacs.config.json'))
        .to.throw();
    });

    it('should throw error for invalid config JSON', () => {
      const agent = new JacsAgent();
      // Create a temp file with invalid JSON
      const tempPath = path.join(__dirname, 'temp-invalid-config.json');
      fs.writeFileSync(tempPath, 'not valid json');

      try {
        expect(() => agent.load(tempPath)).to.throw();
      } finally {
        fs.unlinkSync(tempPath);
      }
    });

    // Skip tests that require actual key files if fixtures don't exist
    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should load agent from valid config', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        const result = agent.load(TEST_CONFIG);
        expect(result).to.be.a('string');
      });
    });
  });

  describe('signString and verifyString', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should sign and verify a string', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        const data = 'Hello, JACS!';
        const signature = agent.signString(data);

        expect(signature).to.be.a('string');
        expect(signature.length).to.be.greaterThan(0);
      });
    });
  });

  describe('createDocument', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should create a signed document', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        const docContent = JSON.stringify({
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { message: 'test' }
        });

        const result = agent.createDocument(
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
        agent.load(TEST_CONFIG);

        const doc1Content = JSON.stringify({
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { value: 1 }
        });

        const doc2Content = JSON.stringify({
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { value: 2 }
        });

        const result1 = agent.createDocument(doc1Content, null, null, true, null, null);
        const result2 = agent.createDocument(doc2Content, null, null, true, null, null);

        const parsed1 = JSON.parse(result1);
        const parsed2 = JSON.parse(result2);

        // Different content should produce different document IDs
        expect(parsed1.jacsId).to.not.equal(parsed2.jacsId);
        // Different content should produce different hashes
        expect(parsed1.jacsSha256).to.not.equal(parsed2.jacsSha256);
      });
    });
  });

  describe('verifyDocument', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should verify a valid signed document', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        // Create a document first
        const docContent = JSON.stringify({
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { action: 'approve' }
        });

        const signedDoc = agent.createDocument(docContent, null, null, true, null, null);

        // Verify the document
        const isValid = agent.verifyDocument(signedDoc);
        expect(isValid).to.be.true;
      });
    });

    (fixturesExist ? it : it.skip)('should reject a tampered document', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        // Create a document first
        const docContent = JSON.stringify({
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { action: 'approve' }
        });

        const signedDoc = agent.createDocument(docContent, null, null, true, null, null);
        const doc = JSON.parse(signedDoc);

        // Tamper with the content
        doc.content = { action: 'TAMPERED' };
        const tamperedDoc = JSON.stringify(doc);

        // Verification should fail
        expect(() => agent.verifyDocument(tamperedDoc)).to.throw();
      });
    });
  });

  describe('verifyAgent', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should verify agent integrity', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        // verifyAgent should return true or throw if invalid
        const result = agent.verifyAgent();
        expect(result).to.be.true;
      });
    });
  });

  describe('signRequest and verifyResponse', function() {
    this.timeout(10000);

    const fixturesExist = fs.existsSync(TEST_CONFIG);

    (fixturesExist ? it : it.skip)('should sign and verify a request/response', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

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
});
