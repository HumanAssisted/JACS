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

function resolveConfigRelativePath(configPath, candidate) {
  return path.isAbsolute(candidate)
    ? fs.realpathSync(candidate)
    : fs.realpathSync(path.resolve(path.dirname(configPath), candidate));
}

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

  describe('quickstart factory', () => {
    (available ? it : it.skip)('should reject missing quickstart identity fields', async () => {
      let missingOptionsErr = null;
      try {
        await clientModule.JacsClient.quickstart();
      } catch (e) {
        missingOptionsErr = e;
      }
      expect(String(missingOptionsErr)).to.match(/requires options\.name and options\.domain/);

      let missingNameErr = null;
      try {
        await clientModule.JacsClient.quickstart({ domain: 'client-test.example.com' });
      } catch (e) {
        missingNameErr = e;
      }
      expect(String(missingNameErr)).to.match(/requires options\.name/);

      expect(() =>
        clientModule.JacsClient.quickstartSync({ name: 'client-test-agent' })
      ).to.throw(/requires options\.domain/);
    });

    (available ? it : it.skip)('should honor custom configPath when creating a persistent agent', async function () {
      this.timeout(30000);
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-client-quickstart-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      delete process.env.JACS_PRIVATE_KEY_PASSWORD;

      try {
        process.chdir(tmpDir);
        const client = await clientModule.JacsClient.quickstart({
          name: 'client-test-agent',
          domain: 'client-test.example.com',
          algorithm: 'ring-Ed25519',
          configPath: 'custom/jacs.config.json',
        });

        expect(client.agentId).to.be.a('string').and.not.empty;
        const configPath = path.join(tmpDir, 'custom', 'jacs.config.json');
        expect(fs.existsSync(configPath)).to.equal(true);
        expect(process.env.JACS_PRIVATE_KEY_PASSWORD).to.equal(undefined);

        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        const dataDir = resolveConfigRelativePath(configPath, config.jacs_data_directory);
        const keyDir = resolveConfigRelativePath(configPath, config.jacs_key_directory);
        expect(client.info.configPath).to.equal(fs.realpathSync(configPath));
        expect(client.info.dataDirectory).to.equal(dataDir);
        expect(client.info.keyDirectory).to.equal(keyDir);
        expect(fs.existsSync(dataDir)).to.equal(true);
        expect(fs.existsSync(keyDir)).to.equal(true);

        const signed = await client.signMessage({ quickstart: true });
        expect(signed.documentId).to.be.a('string').and.not.empty;
      } finally {
        process.chdir(originalCwd);
        if (previousPassword === undefined) {
          delete process.env.JACS_PRIVATE_KEY_PASSWORD;
        } else {
          process.env.JACS_PRIVATE_KEY_PASSWORD = previousPassword;
        }
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    (available && simpleModule ? it : it.skip)('should return the same resolved metadata through client and simple load paths', async function () {
      this.timeout(30000);
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-load-parity-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      process.env.JACS_PRIVATE_KEY_PASSWORD = 'TestP@ss123!#';

      try {
        process.chdir(tmpDir);
        await clientModule.JacsClient.quickstart({
          name: 'parity-agent',
          domain: 'parity.example.com',
          algorithm: 'ring-Ed25519',
          configPath: 'nested/jacs.config.json',
        });

        const configPath = path.join(tmpDir, 'nested', 'jacs.config.json');
        const client = new clientModule.JacsClient();
        const clientInfo = await client.load(configPath);
        simpleModule.reset();
        const simpleInfo = await simpleModule.load(configPath);

        expect(simpleInfo.agentId).to.equal(clientInfo.agentId);
        expect(simpleInfo.version).to.equal(clientInfo.version);
        expect(simpleInfo.algorithm).to.equal(clientInfo.algorithm);
        expect(simpleInfo.configPath).to.equal(clientInfo.configPath);
        expect(simpleInfo.publicKeyPath).to.equal(clientInfo.publicKeyPath);
        expect(simpleInfo.privateKeyPath).to.equal(clientInfo.privateKeyPath);
        expect(simpleInfo.dataDirectory).to.equal(clientInfo.dataDirectory);
        expect(simpleInfo.keyDirectory).to.equal(clientInfo.keyDirectory);
      } finally {
        process.chdir(originalCwd);
        if (previousPassword === undefined) {
          delete process.env.JACS_PRIVATE_KEY_PASSWORD;
        } else {
          process.env.JACS_PRIVATE_KEY_PASSWORD = previousPassword;
        }
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    (available ? it : it.skip)('should not reopen config in JS during client load when password is already resolved', async function () {
      this.timeout(30000);
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-client-native-load-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      process.env.JACS_PRIVATE_KEY_PASSWORD = 'TestP@ss123!#';

      try {
        process.chdir(tmpDir);
        await clientModule.JacsClient.quickstart({
          name: 'client-native-load',
          domain: 'client-native.example.com',
          algorithm: 'ring-Ed25519',
          configPath: 'native/jacs.config.json',
        });

        const configPath = path.join(tmpDir, 'native', 'jacs.config.json');
        const originalReadFileSync = fs.readFileSync;
        fs.readFileSync = function (filePath, ...args) {
          if (path.resolve(String(filePath)) === path.resolve(configPath)) {
            throw new Error('client load() should not reopen config in JS');
          }
          return originalReadFileSync.call(this, filePath, ...args);
        };

        try {
          const client = new clientModule.JacsClient();
          const info = await client.load(configPath);
          expect(info.agentId).to.be.a('string').and.not.empty;
        } finally {
          fs.readFileSync = originalReadFileSync;
        }
      } finally {
        process.chdir(originalCwd);
        if (previousPassword === undefined) {
          delete process.env.JACS_PRIVATE_KEY_PASSWORD;
        } else {
          process.env.JACS_PRIVATE_KEY_PASSWORD = previousPassword;
        }
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('verifyById', () => {
    (available ? it : it.skip)('should use native document lookup for metadata instead of JS filesystem reads', async function () {
      this.timeout(30000);
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-client-verify-by-id-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      process.env.JACS_PRIVATE_KEY_PASSWORD = 'TestP@ss123!#';

      try {
        process.chdir(tmpDir);
        const client = await clientModule.JacsClient.quickstart({
          name: 'verify-by-id-agent',
          domain: 'verify-by-id.example.com',
          algorithm: 'ring-Ed25519',
        });
        const storedRaw = await client._agent.createDocument(
          JSON.stringify({ jacsType: 'message', jacsLevel: 'raw', content: { verifyById: true } }),
          null,
          null,
          false,
          null,
          null,
        );
        const documentId = String(storedRaw).replace(/^saved\s+/, '');

        const originalReadFileSync = fs.readFileSync;
        fs.readFileSync = function (filePath, ...args) {
          const target = String(filePath);
          if (target.endsWith('jacs.config.json') || target.includes(`${path.sep}documents${path.sep}`)) {
            throw new Error('verifyById should not depend on JS filesystem reads');
          }
          return originalReadFileSync.call(this, filePath, ...args);
        };

        try {
          const result = await client.verifyById(documentId);
          expect(result.valid).to.equal(true);
          expect(result.signerId).to.equal(client.agentId);
          expect(result.timestamp).to.be.a('string').and.not.empty;
        } finally {
          fs.readFileSync = originalReadFileSync;
        }
      } finally {
        process.chdir(originalCwd);
        if (previousPassword === undefined) {
          delete process.env.JACS_PRIVATE_KEY_PASSWORD;
        } else {
          process.env.JACS_PRIVATE_KEY_PASSWORD = previousPassword;
        }
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('exportAgent', () => {
    (available ? it : it.skip)('should use native export instead of JS filesystem reads', async function () {
      this.timeout(30000);
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-client-export-agent-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      process.env.JACS_PRIVATE_KEY_PASSWORD = 'TestP@ss123!#';

      try {
        process.chdir(tmpDir);
        const client = await clientModule.JacsClient.quickstart({
          name: 'export-agent-client',
          domain: 'export-agent-client.example.com',
          algorithm: 'ring-Ed25519',
        });

        const originalReadFileSync = fs.readFileSync;
        fs.readFileSync = function (filePath, ...args) {
          const target = String(filePath);
          if (target.endsWith('jacs.config.json') || target.includes(`${path.sep}agent${path.sep}`)) {
            throw new Error('exportAgent should not depend on JS filesystem reads');
          }
          return originalReadFileSync.call(this, filePath, ...args);
        };

        try {
          const agentJson = client.exportAgent();
          const agent = JSON.parse(agentJson);
          expect(agent.jacsId).to.equal(client.agentId);
        } finally {
          fs.readFileSync = originalReadFileSync;
        }
      } finally {
        process.chdir(originalCwd);
        if (previousPassword === undefined) {
          delete process.env.JACS_PRIVATE_KEY_PASSWORD;
        } else {
          process.env.JACS_PRIVATE_KEY_PASSWORD = previousPassword;
        }
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
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

  describe('generateVerifyLink', () => {
    (available ? it : it.skip)('should return URL with default base', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const link = client.generateVerifyLink('{"hello":"world"}');
      expect(link).to.be.a('string');
      expect(link).to.match(/^https:\/\/hai\.ai\/jacs\/verify\?s=/);
    });

    (available ? it : it.skip)('should use custom baseUrl', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const link = client.generateVerifyLink('test', 'https://example.com/verify');
      expect(link).to.match(/^https:\/\/example\.com\/verify\?s=/);
    });

    (available ? it : it.skip)('should round-trip decode to original', () => {
      const client = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
      const original = '{"signed":"document","data":123}';
      const link = client.generateVerifyLink(original);
      const encoded = link.split('?s=')[1];
      const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
      expect(decoded).to.equal(original);
    });
  });
});
