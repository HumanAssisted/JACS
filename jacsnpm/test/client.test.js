/**
 * Tests for JACS JacsClient (instance-based API)
 *
 * Updated for v0.7.0 async-first API:
 * - Static factories: ephemeral() → async, ephemeralSync() → sync
 * - Instance methods: methodName() → async, methodNameSync() → sync
 * - Async tests added for key operations
 */

const { expect } = require('chai');
const path = require('path');
const fs = require('fs');
const os = require('os');

let clientModule;
try {
  clientModule = require('../client.js');
} catch (e) {
  clientModule = null;
}

let simpleModule;
try {
  simpleModule = require('../simple.js');
} catch (e) {
  simpleModule = null;
}

const FIXTURES_DIR = path.resolve(__dirname, '../../jacs/tests/scratch');
const TEST_CONFIG = path.join(FIXTURES_DIR, 'jacs.config.json');

// Check if fixtures are loadable (password may not match)
let fixturesLoadable = false;
if (clientModule && fs.existsSync(TEST_CONFIG)) {
  try {
    const probe = new clientModule.JacsClient();
    const originalCwd = process.cwd();
    process.chdir(FIXTURES_DIR);
    try {
      probe.loadSync(TEST_CONFIG);
      fixturesLoadable = true;
    } catch (_) {
      // password mismatch or other issue
    } finally {
      process.chdir(originalCwd);
    }
  } catch (_) {}
}

describe('JacsClient', function () {
  this.timeout(15000);

  const available = clientModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping JacsClient tests - client.js not compiled');
      this.skip();
    }
  });

  // ---------------------------------------------------------------------------
  // Ephemeral factory (sync)
  // ---------------------------------------------------------------------------

  describe('ephemeralSync factory', () => {
    (available ? it : it.skip)('should create an ephemeral client with an agent ID', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      expect(client.agentId).to.be.a('string').and.not.empty;
      expect(client.name).to.be.a('string');
    });

    (available ? it : it.skip)('two ephemeral clients should have different agent IDs', () => {
      const a = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const b = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      expect(a.agentId).to.not.equal(b.agentId);
    });
  });

  // ---------------------------------------------------------------------------
  // Ephemeral factory (async)
  // ---------------------------------------------------------------------------

  describe('ephemeral (async) factory', () => {
    (available ? it : it.skip)('should create an ephemeral client with an agent ID (async)', async () => {
      const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
      expect(client.agentId).to.be.a('string').and.not.empty;
      expect(client.name).to.be.a('string');
    });

    (available ? it : it.skip)('two async ephemeral clients should have different agent IDs', async () => {
      const a = await clientModule.JacsClient.ephemeral('ring-Ed25519');
      const b = await clientModule.JacsClient.ephemeral('ring-Ed25519');
      expect(a.agentId).to.not.equal(b.agentId);
    });
  });

  // ---------------------------------------------------------------------------
  // Signing (ephemeral, sync)
  // ---------------------------------------------------------------------------

  describe('signMessageSync on ephemeral', () => {
    (available ? it : it.skip)('should sign data and return SignedDocument', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const signed = client.signMessageSync({ action: 'test', value: 42 });

      expect(signed).to.have.property('raw');
      expect(signed).to.have.property('documentId').that.is.a('string').and.not.empty;
      expect(signed).to.have.property('agentId').that.is.a('string').and.not.empty;
      expect(signed).to.have.property('timestamp').that.is.a('string');

      const doc = JSON.parse(signed.raw);
      expect(doc).to.have.property('jacsSignature');
      expect(doc).to.have.property('jacsId');
    });

    (available ? it : it.skip)('should produce unique document IDs', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const s1 = client.signMessageSync({ seq: 1 });
      const s2 = client.signMessageSync({ seq: 2 });
      const s3 = client.signMessageSync({ seq: 3 });

      expect(s1.documentId).to.not.equal(s2.documentId);
      expect(s2.documentId).to.not.equal(s3.documentId);
    });
  });

  // ---------------------------------------------------------------------------
  // Signing (ephemeral, async)
  // ---------------------------------------------------------------------------

  describe('signMessage (async) on ephemeral', () => {
    (available ? it : it.skip)('should sign data and return SignedDocument (async)', async () => {
      const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
      const signed = await client.signMessage({ action: 'async-test', value: 99 });

      expect(signed).to.have.property('raw');
      expect(signed).to.have.property('documentId').that.is.a('string').and.not.empty;
      expect(signed).to.have.property('agentId').that.is.a('string').and.not.empty;

      const doc = JSON.parse(signed.raw);
      expect(doc).to.have.property('jacsSignature');
    });
  });

  // ---------------------------------------------------------------------------
  // Sign + verify (fixtures-based, sync)
  // ---------------------------------------------------------------------------

  describe('sign + verify round-trip (fixtures, sync)', () => {
    (available && fixturesLoadable ? it : it.skip)(
      'should sign and verify on fixture-loaded instance',
      () => {
        const client = new clientModule.JacsClient();
        const originalCwd = process.cwd();
        process.chdir(FIXTURES_DIR);
        try {
          client.loadSync(TEST_CONFIG);
          const signed = client.signMessageSync({ action: 'approve', value: 100 });

          const result = client.verifySync(signed.raw);
          expect(result.valid).to.equal(true);
          expect(result.errors).to.be.an('array').that.is.empty;
          expect(result.signerId).to.equal(signed.agentId);
        } finally {
          process.chdir(originalCwd);
        }
      },
    );

    (available && fixturesLoadable ? it : it.skip)(
      'two JacsClient instances loaded from same config should have same agent ID',
      () => {
        const originalCwd = process.cwd();
        process.chdir(FIXTURES_DIR);
        try {
          const a = new clientModule.JacsClient();
          a.loadSync(TEST_CONFIG);
          const b = new clientModule.JacsClient();
          b.loadSync(TEST_CONFIG);
          expect(a.agentId).to.equal(b.agentId);

          const sA = a.signMessageSync({ from: 'a' });
          const sB = b.signMessageSync({ from: 'b' });
          expect(sA.documentId).to.not.equal(sB.documentId);
        } finally {
          process.chdir(originalCwd);
        }
      },
    );
  });

  // ---------------------------------------------------------------------------
  // Sign + verify (fixtures-based, async)
  // ---------------------------------------------------------------------------

  describe('sign + verify round-trip (fixtures, async)', () => {
    (available && fixturesLoadable ? it : it.skip)(
      'should sign and verify on fixture-loaded instance (async)',
      async () => {
        const client = new clientModule.JacsClient();
        const originalCwd = process.cwd();
        process.chdir(FIXTURES_DIR);
        try {
          await client.load(TEST_CONFIG);
          const signed = await client.signMessage({ action: 'approve-async', value: 200 });

          const result = await client.verify(signed.raw);
          expect(result.valid).to.equal(true);
          expect(result.errors).to.be.an('array').that.is.empty;
          expect(result.signerId).to.equal(signed.agentId);
        } finally {
          process.chdir(originalCwd);
        }
      },
    );
  });

  // ---------------------------------------------------------------------------
  // Isolation
  // ---------------------------------------------------------------------------

  describe('isolation from global simple API', () => {
    (available && simpleModule ? it : it.skip)(
      'JacsClient instance should not affect simple module global state',
      () => {
        delete require.cache[require.resolve('../simple.js')];
        const freshSimple = require('../simple.js');
        freshSimple.reset();

        const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
        const signed = client.signMessageSync({ isolated: true });
        expect(signed.documentId).to.be.a('string').and.not.empty;

        expect(freshSimple.isLoaded()).to.be.false;
      },
    );
  });

  // ---------------------------------------------------------------------------
  // verifySelf
  // ---------------------------------------------------------------------------

  describe('verifySelfSync', () => {
    (available ? it : it.skip)('should verify ephemeral agent integrity', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const result = client.verifySelfSync();
      expect(result.valid).to.equal(true);
    });
  });

  describe('verifySelf (async)', () => {
    (available ? it : it.skip)('should verify ephemeral agent integrity (async)', async () => {
      const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
      const result = await client.verifySelf();
      expect(result.valid).to.equal(true);
    });
  });

  // ---------------------------------------------------------------------------
  // reset / dispose
  // ---------------------------------------------------------------------------

  describe('reset / dispose', () => {
    (available ? it : it.skip)('should clear internal state', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      expect(client.agentId).to.not.equal('');

      client.reset();

      expect(client.agentId).to.equal('');
      expect(() => client.signMessageSync({ fail: true })).to.throw(/No agent loaded/);
    });

    (available ? it : it.skip)('dispose should also clear state', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      client.dispose();
      expect(client.agentId).to.equal('');
    });

    (available ? it : it.skip)('simple.reset() should clear global state', () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      freshSimple.reset();
      expect(freshSimple.isLoaded()).to.be.false;
    });
  });

  // ---------------------------------------------------------------------------
  // Strict mode
  // ---------------------------------------------------------------------------

  describe('strict mode', () => {
    (available ? it : it.skip)('should return valid=false for tampered doc (non-strict)', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const signed = client.signMessageSync({ original: true });
      const doc = JSON.parse(signed.raw);
      doc.content = { tampered: true };
      const tampered = JSON.stringify(doc);

      const result = client.verifySync(tampered);
      expect(result.valid).to.equal(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Agreements (fixture-based, sync)
  // ---------------------------------------------------------------------------

  describe('agreements (fixture-based, sync)', () => {
    (available && fixturesLoadable ? it : it.skip)(
      'should create, sign, and check a single-agent agreement',
      () => {
        const client = new clientModule.JacsClient();
        const originalCwd = process.cwd();
        process.chdir(FIXTURES_DIR);
        try {
          client.loadSync(TEST_CONFIG);
          const agentId = client.agentId;

          const agreement = client.createAgreementSync(
            { proposal: 'approve budget', amount: 5000 },
            [agentId],
            { question: 'Do you approve?', context: 'Q4 budget review' },
          );

          expect(agreement).to.have.property('raw');
          expect(agreement.documentId).to.be.a('string').and.not.empty;

          let checkError = null;
          try {
            client.checkAgreementSync(agreement);
          } catch (e) {
            checkError = e;
          }
          expect(checkError).to.not.equal(null);
          expect(String(checkError)).to.match(/not all agents have signed/i);

          const signed = client.signAgreementSync(agreement);
          expect(signed.documentId).to.be.a('string').and.not.empty;

          const status = client.checkAgreementSync(signed);
          expect(status.complete).to.equal(true);
          expect(status.pending).to.be.an('array').that.is.empty;
        } finally {
          process.chdir(originalCwd);
        }
      },
    );

    (available && fixturesLoadable ? it : it.skip)(
      'should support agreement with options (quorum)',
      () => {
        const client = new clientModule.JacsClient();
        const originalCwd = process.cwd();
        process.chdir(FIXTURES_DIR);
        try {
          client.loadSync(TEST_CONFIG);
          const agentId = client.agentId;

          const agreement = client.createAgreementSync(
            { proposal: 'quorum test' },
            [agentId],
            { question: 'Approve?', quorum: 1 },
          );

          expect(agreement.documentId).to.be.a('string').and.not.empty;

          const signed = client.signAgreementSync(agreement);
          const status = client.checkAgreementSync(signed);
          expect(status.complete).to.equal(true);
        } finally {
          process.chdir(originalCwd);
        }
      },
    );
  });

  // ---------------------------------------------------------------------------
  // generateVerifyLink
  // ---------------------------------------------------------------------------

  describe('generateVerifyLink', () => {
    (available ? it : it.skip)('should be exported as a module-level function', () => {
      expect(clientModule.generateVerifyLink).to.be.a('function');
    });

    (available ? it : it.skip)('should produce a hai.ai URL with base64url-encoded document', () => {
      const doc = '{"jacsId":"test"}';
      const url = clientModule.generateVerifyLink(doc);
      expect(url).to.match(/^https:\/\/hai\.ai\/jacs\/verify\?s=/);
    });

    (available ? it : it.skip)('should be available as instance method on JacsClient', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const doc = '{"jacsId":"test"}';
      const url = client.generateVerifyLink(doc);
      expect(url).to.match(/^https:\/\/hai\.ai\/jacs\/verify\?s=/);
    });

    (available ? it : it.skip)('instance method should accept custom base URL', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const doc = '{"test": true}';
      const url = client.generateVerifyLink(doc, 'https://example.com');
      expect(url).to.match(/^https:\/\/example\.com\/jacs\/verify\?s=/);
    });

    (available ? it : it.skip)('should round-trip: decode produces original document', () => {
      const doc = '{"jacsId":"round-trip","content":"hi"}';
      const url = clientModule.generateVerifyLink(doc);
      const encoded = url.split('?s=')[1];
      let b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) b64 += '=';
      const decoded = Buffer.from(b64, 'base64').toString('utf8');
      expect(decoded).to.equal(doc);
    });

    (available ? it : it.skip)('should export MAX_VERIFY_URL_LEN and MAX_VERIFY_DOCUMENT_BYTES', () => {
      expect(clientModule.MAX_VERIFY_URL_LEN).to.equal(2048);
      expect(clientModule.MAX_VERIFY_DOCUMENT_BYTES).to.equal(1515);
    });

    (available ? it : it.skip)('should throw for oversized documents', () => {
      const bigDoc = JSON.stringify({ data: 'x'.repeat(2000) });
      expect(() => clientModule.generateVerifyLink(bigDoc)).to.throw(/max length/i);
    });
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    (available ? it : it.skip)('should throw for operations before loading', () => {
      const client = new clientModule.JacsClient();
      expect(() => client.signMessageSync({ data: 1 })).to.throw(/No agent loaded/);
      expect(() => client.verifySync('{}')).to.throw(/No agent loaded/);
      expect(() => client.verifySelfSync()).to.throw(/No agent loaded/);
    });

    (available ? it : it.skip)('should return valid=false for invalid JSON in verify', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const result = client.verifySync('not-json');
      expect(result.valid).to.equal(false);
      expect(result.errors).to.have.length.greaterThan(0);
    });

    (available ? it : it.skip)('should reject non-existent config in load', () => {
      const client = new clientModule.JacsClient();
      expect(() => client.loadSync('/nonexistent/jacs.config.json')).to.throw(
        /Config file not found/,
      );
    });
  });
});
