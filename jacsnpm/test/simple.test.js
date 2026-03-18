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

let bindings;
try {
  bindings = require('../index.js');
} catch (e) {
  bindings = null;
}

// Path to test fixtures (use shared fixtures from jacs/tests/scratch)
const FIXTURES_DIR = path.resolve(__dirname, '../../jacs/tests/scratch');
const TEST_CONFIG = path.join(FIXTURES_DIR, 'jacs.config.json');
const TEST_PASSWORD = 'TestP@ss123!#';
const HEALTH_STATUSES = ['Healthy', 'Degraded', 'Unhealthy', 'Unavailable'];
const RISK_SEVERITIES = ['low', 'medium', 'high'];
const RISK_CATEGORIES = [
  'config',
  'secrets',
  'trust',
  'storage',
  'verification',
  'quarantine',
  'directories',
];

function resolveConfigRelativePath(configPath, candidate) {
  return path.isAbsolute(candidate)
    ? fs.realpathSync(candidate)
    : fs.realpathSync(path.resolve(path.dirname(configPath), candidate));
}

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

async function runInFixturesDirAsync(fn) {
  const originalCwd = process.cwd();
  process.chdir(FIXTURES_DIR);
  try {
    return await fn();
  } finally {
    process.chdir(originalCwd);
  }
}

function expectAuditReport(result) {
  expect(result).to.be.an('object');
  expect(result.overall_status).to.be.a('string');
  expect(HEALTH_STATUSES).to.include(result.overall_status);
  expect(result.summary).to.be.a('string').and.not.empty;
  expect(result.summary.includes('risk(s)') || result.summary.includes('risks: 0')).to.equal(true);
  expect(result.checked_at).to.be.a('number');

  expect(result.risks).to.be.an('array');
  expect(result.health_checks).to.be.an('array').and.not.empty;

  const firstHealth = result.health_checks[0];
  expect(firstHealth).to.include.all.keys('name', 'status', 'message');
  expect(firstHealth.name).to.be.a('string').and.not.empty;
  expect(HEALTH_STATUSES).to.include(firstHealth.status);
  expect(firstHealth.message).to.be.a('string').and.not.empty;

  if (result.risks.length > 0) {
    const firstRisk = result.risks[0];
    expect(firstRisk).to.include.all.keys('category', 'severity', 'message');
    expect(RISK_CATEGORIES).to.include(firstRisk.category);
    expect(RISK_SEVERITIES).to.include(firstRisk.severity);
    expect(firstRisk.message).to.be.a('string').and.not.empty;
  }
}

function seedPublicKeyCache(agentDir, agentJson, publicKeyPem) {
  const crypto = require('crypto');
  const agent = JSON.parse(agentJson);
  const signature = agent.jacsSignature || {};
  const keyHash = signature.publicKeyHash;
  const signingAlgorithm = signature.signingAlgorithm || 'RSA-PSS';
  const publicKeysDir = path.join(agentDir, 'jacs_data', 'public_keys');

  // Replicate Rust's hash_public_key: decode UTF-8, trim, remove \r, SHA-256 hex.
  function hashLikeRust(buf) {
    const text = buf.toString('utf8').trim().replace(/\r/g, '');
    return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
  }

  // Determine raw key bytes that match the signing-time hash.
  let rawBytes = Buffer.from(publicKeyPem, 'utf8');
  if (hashLikeRust(rawBytes) !== keyHash) {
    // PEM-armored binary key — decode the base64 body.
    const stripped = publicKeyPem.trim();
    if (stripped.startsWith('-----BEGIN')) {
      const body = stripped.split('\n').filter(l => !l.startsWith('-----')).join('');
      try {
        const decoded = Buffer.from(body, 'base64');
        if (hashLikeRust(decoded) === keyHash) {
          rawBytes = decoded;
        }
      } catch (_) { /* keep text bytes */ }
    }
  }

  fs.mkdirSync(publicKeysDir, { recursive: true });
  fs.writeFileSync(path.join(publicKeysDir, `${keyHash}.pem`), rawBytes);
  fs.writeFileSync(path.join(publicKeysDir, `${keyHash}.enc_type`), signingAlgorithm);
}

function buildStandaloneKeyCacheFromSigned(signedRaw) {
  const doc = JSON.parse(signedRaw);
  const sig = doc.jacsSignature || {};
  const keyHash = sig.publicKeyHash;
  const signingAlgorithm = sig.signingAlgorithm;
  if (!keyHash) {
    throw new Error('Signed document missing jacsSignature.publicKeyHash');
  }
  if (!signingAlgorithm) {
    throw new Error('Signed document missing jacsSignature.signingAlgorithm');
  }

  const config = JSON.parse(fs.readFileSync(TEST_CONFIG, 'utf8'));
  const keyDir = path.resolve(FIXTURES_DIR, config.jacs_key_directory || './jacs_keys');
  const publicKeyFile = config.jacs_agent_public_key_filename || 'jacs.public.pem';
  const publicKeyPath = path.join(keyDir, publicKeyFile);
  const publicKeyBytes = fs.readFileSync(publicKeyPath);

  const varDir = path.resolve(__dirname, '../var');
  fs.mkdirSync(varDir, { recursive: true });
  const cacheDir = fs.mkdtempSync(path.join(varDir, 'standalone-key-cache-'));
  const publicKeysDir = path.join(cacheDir, 'public_keys');
  fs.mkdirSync(publicKeysDir, { recursive: true });

  fs.writeFileSync(path.join(publicKeysDir, `${keyHash}.pem`), publicKeyBytes);
  fs.writeFileSync(path.join(publicKeysDir, `${keyHash}.enc_type`), signingAlgorithm);

  const rel = path.relative(process.cwd(), cacheDir) || '.';
  return { cacheDir, relPath: rel };
}

describe('JACS Simple API', function() {
  this.timeout(10000);

  const simpleExists = simple !== null;
  const fixturesExist = fs.existsSync(TEST_CONFIG);
  let originalPassword;

  before(function() {
    originalPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
    if (!originalPassword) {
      process.env.JACS_PRIVATE_KEY_PASSWORD = TEST_PASSWORD;
    }
    if (!simpleExists) {
      console.log('  Skipping simple API tests - simple.js not compiled');
      this.skip();
    }
  });

  after(() => {
    if (originalPassword === undefined) {
      delete process.env.JACS_PRIVATE_KEY_PASSWORD;
    } else {
      process.env.JACS_PRIVATE_KEY_PASSWORD = originalPassword;
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

  describe('quickstart', () => {
    (simpleExists ? it : it.skip)('should reject missing quickstart identity fields', async () => {
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');

      let missingOptionsErr = null;
      try {
        await freshSimple.quickstart();
      } catch (e) {
        missingOptionsErr = e;
      }
      expect(String(missingOptionsErr)).to.match(/requires options\.name and options\.domain/);

      let missingNameErr = null;
      try {
        await freshSimple.quickstart({ domain: 'simple-test.example.com' });
      } catch (e) {
        missingNameErr = e;
      }
      expect(String(missingNameErr)).to.match(/requires options\.name/);

      expect(() => freshSimple.quickstartSync({ name: 'simple-test-agent' }))
        .to.throw(/requires options\.domain/);
    });

    (simpleExists ? it : it.skip)('should create and load an agent at a custom configPath', async function () {
      this.timeout(30000);
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-simple-quickstart-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      delete process.env.JACS_PRIVATE_KEY_PASSWORD;

      try {
        process.chdir(tmpDir);
        const info = await freshSimple.quickstart({
          name: 'simple-test-agent',
          domain: 'simple-test.example.com',
          algorithm: 'ring-Ed25519',
          configPath: path.join('custom', 'jacs.config.json'),
        });
        expect(info).to.have.property('agentId').that.is.a('string').and.not.empty;
        expect(freshSimple.isLoaded()).to.equal(true);
        const configPath = path.join(tmpDir, 'custom', 'jacs.config.json');
        expect(fs.existsSync(configPath)).to.equal(true);
        expect(process.env.JACS_PRIVATE_KEY_PASSWORD).to.equal(undefined);

        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        const dataDir = resolveConfigRelativePath(configPath, config.jacs_data_directory);
        const keyDir = resolveConfigRelativePath(configPath, config.jacs_key_directory);
        expect(info.configPath).to.equal(fs.realpathSync(configPath));
        expect(info.dataDirectory).to.equal(dataDir);
        expect(info.keyDirectory).to.equal(keyDir);
        expect(fs.existsSync(dataDir)).to.equal(true);
        expect(fs.existsSync(keyDir)).to.equal(true);

        const signed = await freshSimple.signMessage({ quickstart: true });
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

    (simpleExists ? it : it.skip)('should not reopen config in JS during simple load when password is already resolved', async function () {
      this.timeout(30000);
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-simple-native-load-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      process.env.JACS_PRIVATE_KEY_PASSWORD = TEST_PASSWORD;

      try {
        process.chdir(tmpDir);
        await freshSimple.quickstart({
          name: 'simple-native-load',
          domain: 'simple-native.example.com',
          algorithm: 'ring-Ed25519',
          configPath: path.join('native', 'jacs.config.json'),
        });

        const configPath = path.join(tmpDir, 'native', 'jacs.config.json');
        const originalReadFileSync = fs.readFileSync;
        fs.readFileSync = function (filePath, ...args) {
          if (path.resolve(String(filePath)) === path.resolve(configPath)) {
            throw new Error('simple load() should not reopen config in JS');
          }
          return originalReadFileSync.call(this, filePath, ...args);
        };

        try {
          const info = await freshSimple.load(configPath);
          expect(info.agentId).to.be.a('string').and.not.empty;
        } finally {
          fs.readFileSync = originalReadFileSync;
          freshSimple.reset();
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
      const cache = buildStandaloneKeyCacheFromSigned(signed.raw);
      freshSimple.reset();

      delete require.cache[require.resolve('../simple.js')];
      const cleanSimple = require('../simple.js');
      expect(cleanSimple.isLoaded()).to.be.false;

      try {
        const result = cleanSimple.verifyStandalone(signed.raw, {
          keyResolution: 'local',
          dataDirectory: cache.relPath,
          keyDirectory: cache.relPath,
        });
        expect(result.valid).to.be.true;
        expect(result.signerId).to.be.a('string').and.not.empty;
      } finally {
        fs.rmSync(cache.cacheDir, { recursive: true, force: true });
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
      const cache = buildStandaloneKeyCacheFromSigned(signed.raw);
      freshSimple.reset();

      delete require.cache[require.resolve('../simple.js')];
      const cleanSimple = require('../simple.js');

      try {
        const result = cleanSimple.verifyStandalone(signed.raw, {
          keyResolution: 'local',
          dataDirectory: cache.relPath,
          keyDirectory: cache.relPath,
        });
        expect(result.valid).to.be.true;
        expect(result.signerId).to.be.a('string').and.not.empty;
      } finally {
        fs.rmSync(cache.cacheDir, { recursive: true, force: true });
      }
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

    (simpleExists ? it : it.skip)('should require both agents for two-party agreement completion', function() {
      this.timeout(30000);
      const modulePath = require.resolve('../simple.js');
      const password = 'TestP@ss123!#';
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-two-agent-'));
      const agent1Dir = path.join(root, 'agent1');
      const agent2Dir = path.join(root, 'agent2');
      const originalCwd = process.cwd();

      function freshSimpleModule() {
        delete require.cache[modulePath];
        return require('../simple.js');
      }

      try {
        process.chdir(root);
        fs.mkdirSync(agent1Dir, { recursive: true });
        fs.mkdirSync(agent2Dir, { recursive: true });

        const simpleA = freshSimpleModule();
        const simpleB = freshSimpleModule();

        process.chdir(agent1Dir);
        simpleA.createSync({
          name: 'mocha-agent-a',
          password,
          algorithm: 'RSA-PSS',
          dataDirectory: 'jacs_data',
          keyDirectory: 'keys',
          configPath: 'jacs.config.json',
        });

        process.chdir(agent2Dir);
        simpleB.createSync({
          name: 'mocha-agent-b',
          password,
          algorithm: 'RSA-PSS',
          dataDirectory: 'jacs_data',
          keyDirectory: 'keys',
          configPath: 'jacs.config.json',
        });

        process.chdir(agent1Dir);
        simpleA.loadSync('jacs.config.json');
        const agentAJson = simpleA.exportAgent();
        const agentAPublicKey = simpleA.getPublicKey();
        process.chdir(agent2Dir);
        simpleB.loadSync('jacs.config.json');
        simpleB.trustAgentWithKey(agentAJson, agentAPublicKey);
        seedPublicKeyCache(agent2Dir, agentAJson, agentAPublicKey);

        const infoA = simpleA.getAgentInfo();
        const infoB = simpleB.getAgentInfo();
        expect(infoA).to.be.an('object');
        expect(infoB).to.be.an('object');

        process.chdir(agent1Dir);
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

        process.chdir(agent2Dir);
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

  describe('verifyById / verifyByIdSync', () => {
    (simpleExists && fixturesExist ? it : it.skip)('verifyByIdSync should return invalid format error payload', () => {
      const freshSimple = loadSimpleInFixtures();
      const result = freshSimple.verifyByIdSync('not-a-versioned-id');

      expect(result.valid).to.be.false;
      expect(result.errors).to.be.an('array').that.is.not.empty;
      expect(result.errors[0]).to.match(/Document ID must be in 'uuid:version' format/);
    });

    (simpleExists && fixturesExist ? it : it.skip)('verifyById should return invalid format error payload', async () => {
      const freshSimple = loadSimpleInFixtures();
      const result = await freshSimple.verifyById('not-a-versioned-id');

      expect(result.valid).to.be.false;
      expect(result.errors).to.be.an('array').that.is.not.empty;
      expect(result.errors[0]).to.match(/Document ID must be in 'uuid:version' format/);
    });

    (simpleExists ? it : it.skip)('verifyById should use native document lookup for metadata instead of JS filesystem reads', async function () {
      this.timeout(30000);
      delete require.cache[require.resolve('../simple.js')];
      const freshSimple = require('../simple.js');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-simple-verify-by-id-'));
      const originalCwd = process.cwd();
      const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
      process.env.JACS_PRIVATE_KEY_PASSWORD = TEST_PASSWORD;

      try {
        process.chdir(tmpDir);
        await freshSimple.quickstart({
          name: 'simple-verify-by-id-agent',
          domain: 'simple-verify-by-id.example.com',
          algorithm: 'ring-Ed25519',
        });
        const info = freshSimple.getAgentInfo();
        const nativeAgent = new bindings.JacsAgent();
        await nativeAgent.load(path.resolve(info.configPath));
        const storedRaw = await nativeAgent.createDocument(
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
          const result = await freshSimple.verifyById(documentId);
          expect(result.valid).to.equal(true);
          expect(result.signerId).to.be.a('string').and.not.empty;
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

  describe('DNS helpers', () => {
    (simpleExists && fixturesExist ? it : it.skip)('getDnsRecord returns TXT line in expected format', () => {
      const freshSimple = loadSimpleInFixtures();
      const record = freshSimple.getDnsRecord('example.com', 3600);
      expect(record).to.be.a('string');
      expect(record).to.match(/^_v1\.agent\.jacs\.example\.com\.\s+3600\s+IN\s+TXT\s+"/);
      expect(record).to.include('v=jacs');
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
    (simpleExists && fixturesExist ? it : it.skip)('should return a structured audit report for a valid config', () => {
      const result = runInFixturesDir(() => simple.auditSync({ configPath: TEST_CONFIG, recentN: 1 }));
      expectAuditReport(result);
    });

    (simpleExists && fixturesExist ? it : it.skip)('should summarize component health in the report body', () => {
      const result = runInFixturesDir(() => simple.auditSync({ configPath: TEST_CONFIG, recentN: 1 }));
      expectAuditReport(result);
      expect(result.summary).to.include(`${result.health_checks[0].name}:`);
    });
  });

  describe('audit (async)', () => {
    (simpleExists && fixturesExist ? it : it.skip)('should return a structured audit report (async)', async () => {
      const result = await runInFixturesDirAsync(() => simple.audit({ configPath: TEST_CONFIG, recentN: 1 }));
      expectAuditReport(result);
    });
  });

  describe('generateVerifyLink', () => {
    (simpleExists ? it : it.skip)('should return URL with default base', () => {
      const link = simple.generateVerifyLink('{"hello":"world"}');
      expect(link).to.be.a('string');
      expect(link).to.match(/^https:\/\/hai\.ai\/jacs\/verify\?s=/);
    });

    (simpleExists ? it : it.skip)('should use custom baseUrl', () => {
      const link = simple.generateVerifyLink('test', 'https://example.com/verify');
      expect(link).to.match(/^https:\/\/example\.com\/verify\?s=/);
    });

    (simpleExists ? it : it.skip)('should round-trip decode to original', () => {
      const original = '{"signed":"document","data":123}';
      const link = simple.generateVerifyLink(original);
      const encoded = link.split('?s=')[1];
      const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
      expect(decoded).to.equal(original);
    });
  });
});
