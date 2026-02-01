/**
 * Integration tests for JACS Node.js bindings
 *
 * These tests verify end-to-end workflows and cross-module functionality.
 */

const { expect } = require('chai');
const { JacsAgent, hashString, createConfig } = require('../index');
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

describe('JACS Integration Tests', function() {
  this.timeout(15000);

  const fixturesExist = fs.existsSync(TEST_CONFIG);

  describe('Document Lifecycle', () => {
    (fixturesExist ? it : it.skip)('should create, sign, and verify a document', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        // Create document
        const content = {
          jacsType: 'message',
          jacsLevel: 'raw',
          content: {
            type: 'order',
            orderId: 'ORD-' + Date.now(),
            items: ['item1', 'item2'],
            total: 150.00
          }
        };

        const signedDoc = agent.createDocument(
          JSON.stringify(content),
          null, null, true, null, null
        );

        // Verify document
        const isValid = agent.verifyDocument(signedDoc);
        expect(isValid).to.be.true;

        // Parse and inspect
        const doc = JSON.parse(signedDoc);
        expect(doc.jacsId).to.be.a('string');
        expect(doc.jacsSha256).to.be.a('string');
        expect(doc.jacsSignature).to.be.an('object');
        expect(doc.jacsSignature.signature).to.be.a('string');
      });
    });

    (fixturesExist ? it : it.skip)('should handle multiple document operations sequentially', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        const documents = [];

        // Create multiple documents
        for (let i = 0; i < 5; i++) {
          const content = {
            jacsType: 'message',
            jacsLevel: 'raw',
            content: { index: i, timestamp: Date.now() }
          };

          const signedDoc = agent.createDocument(
            JSON.stringify(content),
            null, null, true, null, null
          );

          documents.push(signedDoc);
        }

        // Verify all documents
        for (const doc of documents) {
          const isValid = agent.verifyDocument(doc);
          expect(isValid).to.be.true;
        }

        // All documents should have unique IDs
        const ids = documents.map(d => JSON.parse(d).jacsId);
        const uniqueIds = new Set(ids);
        expect(uniqueIds.size).to.equal(5);
      });
    });
  });

  describe('Hash Consistency', () => {
    it('should produce consistent hashes across operations', () => {
      const testData = JSON.stringify({ key: 'value', num: 42 });

      // Hash multiple times
      const hashes = [];
      for (let i = 0; i < 10; i++) {
        hashes.push(hashString(testData));
      }

      // All hashes should be identical
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).to.equal(1);
    });

    (fixturesExist ? it : it.skip)('should produce different hashes for different document content', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        const contents = [
          { jacsType: 'message', jacsLevel: 'raw', content: { v: 1 } },
          { jacsType: 'message', jacsLevel: 'raw', content: { v: 2 } },
          { jacsType: 'message', jacsLevel: 'raw', content: { v: 3 } }
        ];

        const hashes = contents.map(c => {
          const signedDoc = agent.createDocument(
            JSON.stringify(c), null, null, true, null, null
          );
          return JSON.parse(signedDoc).jacsSha256;
        });

        // All hashes should be different
        const uniqueHashes = new Set(hashes);
        expect(uniqueHashes.size).to.equal(3);
      });
    });
  });

  describe('Request/Response Signing', () => {
    (fixturesExist ? it : it.skip)('should sign requests and verify responses', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        // Sign a request payload
        const request = {
          method: 'processPayment',
          params: {
            amount: 100.00,
            currency: 'USD',
            recipient: 'merchant-123'
          },
          id: 'req-' + Date.now()
        };

        const signedRequest = agent.signRequest(request);
        expect(signedRequest).to.be.a('string');

        // Parse and verify structure
        const parsed = JSON.parse(signedRequest);
        expect(parsed).to.have.property('jacsSignature');

        // Verify the response
        const verifyResult = agent.verifyResponse(signedRequest);
        expect(verifyResult).to.be.an('object');
      });
    });
  });

  describe('Multiple Agent Instances', () => {
    (fixturesExist ? it : it.skip)('should support multiple independent agent instances', () => {
      withFixturesDir(() => {
        // Create two independent agent instances
        const agent1 = new JacsAgent();
        const agent2 = new JacsAgent();

        agent1.load(TEST_CONFIG);
        agent2.load(TEST_CONFIG);

        // Both should be able to sign documents
        const content1 = {
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { from: 'agent1' }
        };

        const content2 = {
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { from: 'agent2' }
        };

        const doc1 = agent1.createDocument(JSON.stringify(content1), null, null, true, null, null);
        const doc2 = agent2.createDocument(JSON.stringify(content2), null, null, true, null, null);

        // Both should be verifiable
        expect(agent1.verifyDocument(doc1)).to.be.true;
        expect(agent2.verifyDocument(doc2)).to.be.true;

        // Cross-verification should also work (same key)
        expect(agent1.verifyDocument(doc2)).to.be.true;
        expect(agent2.verifyDocument(doc1)).to.be.true;
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid document JSON gracefully', () => {
      const agent = new JacsAgent();

      // Agent must be loaded first
      expect(() => agent.verifyDocument('not valid json')).to.throw();
    });

    (fixturesExist ? it : it.skip)('should reject tampered document signatures', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        // Create valid document
        const content = {
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { original: 'data' }
        };

        const signedDoc = agent.createDocument(
          JSON.stringify(content), null, null, true, null, null
        );

        // Tamper with the signature
        const doc = JSON.parse(signedDoc);
        doc.jacsSignature.signature = 'tampered-signature-value';

        expect(() => agent.verifyDocument(JSON.stringify(doc))).to.throw();
      });
    });

    (fixturesExist ? it : it.skip)('should reject documents with modified hash', () => {
      withFixturesDir(() => {
        const agent = new JacsAgent();
        agent.load(TEST_CONFIG);

        // Create valid document
        const content = {
          jacsType: 'message',
          jacsLevel: 'raw',
          content: { test: 'data' }
        };

        const signedDoc = agent.createDocument(
          JSON.stringify(content), null, null, true, null, null
        );

        // Tamper with the hash
        const doc = JSON.parse(signedDoc);
        doc.jacsSha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

        expect(() => agent.verifyDocument(JSON.stringify(doc))).to.throw();
      });
    });
  });

  describe('Config Creation', () => {
    it('should create valid config JSON', () => {
      const configJson = createConfig(
        'false',
        './test_data',
        './test_keys',
        'private.pem',
        'public.pem',
        'ring-Ed25519',
        '',
        '',
        'fs'
      );

      const config = JSON.parse(configJson);

      expect(config).to.have.property('$schema');
      expect(config.jacs_data_directory).to.equal('./test_data');
      expect(config.jacs_key_directory).to.equal('./test_keys');
      expect(config.jacs_agent_key_algorithm).to.equal('ring-Ed25519');
    });
  });
});
