/**
 * Tests for JACS JacsClient (instance-based API)
 *
 * These tests verify that multiple JacsClient instances can coexist,
 * sign/verify independently, and support agreement options.
 *
 * Ephemeral agents can sign and verifySelf but cannot verify documents
 * (public key resolution requires disk or HAI key service).
 * Fixture-based tests require jacs/tests/scratch/ to be set up with a
 * matching JACS_PRIVATE_KEY_PASSWORD and are skipped if unavailable.
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
      probe.load(TEST_CONFIG);
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
  // Ephemeral factory
  // ---------------------------------------------------------------------------

  describe('ephemeral factory', () => {
    (available ? it : it.skip)('should create an ephemeral client with an agent ID', () => {
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
      expect(client.agentId).to.be.a('string').and.not.empty;
      expect(client.name).to.be.a('string');
    });

    (available ? it : it.skip)('two ephemeral clients should have different agent IDs', () => {
      const a = clientModule.JacsClient.ephemeral('ring-Ed25519');
      const b = clientModule.JacsClient.ephemeral('ring-Ed25519');
      expect(a.agentId).to.not.equal(b.agentId);
    });
  });

  // ---------------------------------------------------------------------------
  // Signing (ephemeral)
  // ---------------------------------------------------------------------------

  describe('signMessage on ephemeral', () => {
    (available ? it : it.skip)('should sign data and return SignedDocument', () => {
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
      const signed = client.signMessage({ action: 'test', value: 42 });

      expect(signed).to.have.property('raw');
      expect(signed).to.have.property('documentId').that.is.a('string').and.not.empty;
      expect(signed).to.have.property('agentId').that.is.a('string').and.not.empty;
      expect(signed).to.have.property('timestamp').that.is.a('string');

      const doc = JSON.parse(signed.raw);
      expect(doc).to.have.property('jacsSignature');
      expect(doc).to.have.property('jacsId');
    });

    (available ? it : it.skip)('should produce unique document IDs', () => {
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
      const s1 = client.signMessage({ seq: 1 });
      const s2 = client.signMessage({ seq: 2 });
      const s3 = client.signMessage({ seq: 3 });

      expect(s1.documentId).to.not.equal(s2.documentId);
      expect(s2.documentId).to.not.equal(s3.documentId);
    });
  });

  // ---------------------------------------------------------------------------
  // Sign + verify (fixtures-based, skipped if fixtures unavailable)
  // ---------------------------------------------------------------------------

  describe('sign + verify round-trip (fixtures)', () => {
    (available && fixturesLoadable ? it : it.skip)(
      'should sign and verify on fixture-loaded instance',
      () => {
        const client = new clientModule.JacsClient();
        const originalCwd = process.cwd();
        process.chdir(FIXTURES_DIR);
        try {
          client.load(TEST_CONFIG);
          const signed = client.signMessage({ action: 'approve', value: 100 });

          const result = client.verify(signed.raw);
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
          a.load(TEST_CONFIG);
          const b = new clientModule.JacsClient();
          b.load(TEST_CONFIG);
          expect(a.agentId).to.equal(b.agentId);

          const sA = a.signMessage({ from: 'a' });
          const sB = b.signMessage({ from: 'b' });
          expect(sA.documentId).to.not.equal(sB.documentId);
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

        const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = client.signMessage({ isolated: true });
        expect(signed.documentId).to.be.a('string').and.not.empty;

        expect(freshSimple.isLoaded()).to.be.false;
      },
    );
  });

  // ---------------------------------------------------------------------------
  // verifySelf
  // ---------------------------------------------------------------------------

  describe('verifySelf', () => {
    (available ? it : it.skip)('should verify ephemeral agent integrity', () => {
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
      const result = client.verifySelf();
      expect(result.valid).to.equal(true);
    });
  });

  // ---------------------------------------------------------------------------
  // reset / dispose
  // ---------------------------------------------------------------------------

  describe('reset / dispose', () => {
    (available ? it : it.skip)('should clear internal state', () => {
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
      expect(client.agentId).to.not.equal('');

      client.reset();

      expect(client.agentId).to.equal('');
      expect(() => client.signMessage({ fail: true })).to.throw(/No agent loaded/);
    });

    (available ? it : it.skip)('dispose should also clear state', () => {
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
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
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
      const signed = client.signMessage({ original: true });
      const doc = JSON.parse(signed.raw);
      doc.content = { tampered: true };
      const tampered = JSON.stringify(doc);

      const result = client.verify(tampered);
      expect(result.valid).to.equal(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Agreements (fixture-based)
  // ---------------------------------------------------------------------------

  describe('agreements (fixture-based)', () => {
    (available && fixturesLoadable ? it : it.skip)(
      'should create, sign, and check a single-agent agreement',
      () => {
        const client = new clientModule.JacsClient();
        const originalCwd = process.cwd();
        process.chdir(FIXTURES_DIR);
        try {
          client.load(TEST_CONFIG);
          const agentId = client.agentId;

          const agreement = client.createAgreement(
            { proposal: 'approve budget', amount: 5000 },
            [agentId],
            { question: 'Do you approve?', context: 'Q4 budget review' },
          );

          expect(agreement).to.have.property('raw');
          expect(agreement.documentId).to.be.a('string').and.not.empty;

          let checkError = null;
          try {
            client.checkAgreement(agreement);
          } catch (e) {
            checkError = e;
          }
          expect(checkError).to.not.equal(null);
          expect(String(checkError)).to.match(/not all agents have signed/i);

          const signed = client.signAgreement(agreement);
          expect(signed.documentId).to.be.a('string').and.not.empty;

          const status = client.checkAgreement(signed);
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
          client.load(TEST_CONFIG);
          const agentId = client.agentId;

          const agreement = client.createAgreement(
            { proposal: 'quorum test' },
            [agentId],
            { question: 'Approve?', quorum: 1 },
          );

          expect(agreement.documentId).to.be.a('string').and.not.empty;

          const signed = client.signAgreement(agreement);
          const status = client.checkAgreement(signed);
          expect(status.complete).to.equal(true);
        } finally {
          process.chdir(originalCwd);
        }
      },
    );
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    (available ? it : it.skip)('should throw for operations before loading', () => {
      const client = new clientModule.JacsClient();
      expect(() => client.signMessage({ data: 1 })).to.throw(/No agent loaded/);
      expect(() => client.verify('{}')).to.throw(/No agent loaded/);
      expect(() => client.verifySelf()).to.throw(/No agent loaded/);
    });

    (available ? it : it.skip)('should return valid=false for invalid JSON in verify', () => {
      const client = clientModule.JacsClient.ephemeral('ring-Ed25519');
      const result = client.verify('not-json');
      expect(result.valid).to.equal(false);
      expect(result.errors).to.have.length.greaterThan(0);
    });

    (available ? it : it.skip)('should reject non-existent config in load', () => {
      const client = new clientModule.JacsClient();
      expect(() => client.load('/nonexistent/jacs.config.json')).to.throw(
        /Config file not found/,
      );
    });
  });
});
