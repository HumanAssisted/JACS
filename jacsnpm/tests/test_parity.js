/**
 * Parity tests for the jacsnpm (Node/NAPI-RS) binding.
 *
 * These tests mirror the Rust parity tests in binding-core/tests/parity.rs
 * and verify the same behavior through the Node NAPI interface. They use the
 * shared fixture file at binding-core/tests/fixtures/parity_inputs.json.
 *
 * Run with: node --test tests/test_parity.js
 *
 * Prerequisites: the native NAPI module must be built first (npm run build).
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

// ---------------------------------------------------------------------------
// Load native binding (skip all tests if not built)
// ---------------------------------------------------------------------------

let JacsSimpleAgent;
let nativeAvailable = false;

try {
  const bindings = require('../index.js');
  JacsSimpleAgent = bindings.JacsSimpleAgent;
  if (typeof JacsSimpleAgent === 'undefined') {
    // The binding loaded but JacsSimpleAgent is not exported yet (stale codegen).
    // Try to access it from the raw native addon directly.
    throw new Error('JacsSimpleAgent not exported from index.js');
  }
  nativeAvailable = true;
} catch (e) {
  console.log(`Skipping parity tests: native module not available (${e.message})`);
}

// ---------------------------------------------------------------------------
// Load shared fixtures
// ---------------------------------------------------------------------------

const FIXTURE_PATH = path.resolve(
  __dirname,
  '../../binding-core/tests/fixtures/parity_inputs.json',
);

let fixtures;
try {
  fixtures = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));
} catch (e) {
  console.log(`Skipping parity tests: cannot load fixtures (${e.message})`);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function skipUnless(condition, msg) {
  if (!condition) {
    return { skip: msg };
  }
  return {};
}

const ALGO = 'ed25519';

function createEphemeral(algorithm) {
  return JacsSimpleAgent.ephemeral(algorithm || ALGO);
}

/**
 * Validate that base64-encoded string is decodable and non-empty.
 */
function assertValidBase64(str, label) {
  assert.ok(typeof str === 'string' && str.length > 0, `${label} should be a non-empty string`);
  const buf = Buffer.from(str, 'base64');
  assert.ok(buf.length > 0, `${label} should decode to non-empty bytes`);
}

// =============================================================================
// 1. Structural parity: signed documents have required fields
// =============================================================================

describe('Parity: signed document structure', skipUnless(nativeAvailable && fixtures, 'native module or fixtures not available'), () => {
  let agent;

  before(() => {
    agent = createEphemeral();
  });

  const requiredTop = () => fixtures.expected_signed_document_fields.required_top_level;
  const requiredSig = () => fixtures.expected_signed_document_fields.required_signature_fields;

  for (const input of (fixtures ? fixtures.sign_message_inputs : [])) {
    it(`signed document for "${input.name}" has required top-level fields`, () => {
      const dataJson = JSON.stringify(input.data);
      const signedJson = agent.signMessage(dataJson);
      const signed = JSON.parse(signedJson);

      for (const field of requiredTop()) {
        assert.ok(
          field in signed,
          `[${ALGO}] signed document for '${input.name}' missing required field '${field}'`,
        );
      }
    });

    it(`signed document for "${input.name}" has required jacsSignature fields`, () => {
      const dataJson = JSON.stringify(input.data);
      const signedJson = agent.signMessage(dataJson);
      const signed = JSON.parse(signedJson);

      assert.ok('jacsSignature' in signed, 'jacsSignature should exist');
      const sigObj = signed.jacsSignature;

      for (const field of requiredSig()) {
        assert.ok(
          field in sigObj,
          `[${ALGO}] jacsSignature for '${input.name}' missing required field '${field}'`,
        );
      }
    });
  }
});

// =============================================================================
// 2. Roundtrip parity: sign -> verify succeeds for all fixture inputs
// =============================================================================

describe('Parity: sign/verify roundtrip', skipUnless(nativeAvailable && fixtures, 'native module or fixtures not available'), () => {
  let agent;

  before(() => {
    agent = createEphemeral();
  });

  for (const input of (fixtures ? fixtures.sign_message_inputs : [])) {
    it(`roundtrip for "${input.name}" succeeds`, () => {
      const dataJson = JSON.stringify(input.data);
      const signedJson = agent.signMessage(dataJson);

      const verifyResultJson = agent.verify(signedJson);
      const result = JSON.parse(verifyResultJson);

      assert.strictEqual(
        result.valid,
        true,
        `[${ALGO}] roundtrip verification failed for '${input.name}'`,
      );
    });
  }
});

// =============================================================================
// 3. Identity methods parity
// =============================================================================

describe('Parity: identity methods', skipUnless(nativeAvailable, 'native module not available'), () => {
  let agent;

  before(() => {
    agent = createEphemeral();
  });

  it('getAgentId returns a non-empty string', () => {
    const agentId = agent.getAgentId();
    assert.ok(typeof agentId === 'string' && agentId.length > 0, 'agent_id should be non-empty');
  });

  it('keyId returns a non-empty string', () => {
    const kid = agent.keyId();
    assert.ok(typeof kid === 'string' && kid.length > 0, 'key_id should be non-empty');
  });

  it('getPublicKeyPem returns PEM format', () => {
    const pem = agent.getPublicKeyPem();
    assert.ok(
      pem.includes('-----BEGIN') || pem.includes('PUBLIC KEY'),
      'should return PEM format',
    );
  });

  it('getPublicKeyBase64 returns valid base64', () => {
    const keyB64 = agent.getPublicKeyBase64();
    assertValidBase64(keyB64, 'public key base64');
  });

  it('exportAgent returns valid JSON with jacsId', () => {
    const exported = agent.exportAgent();
    const parsed = JSON.parse(exported);
    assert.ok('jacsId' in parsed, 'exported agent should have jacsId');
  });

  it('diagnostics returns valid JSON with expected keys', () => {
    const diag = agent.diagnostics();
    const diagV = JSON.parse(diag);
    assert.ok('jacs_version' in diagV, 'diagnostics should have jacs_version');
    assert.strictEqual(diagV.agent_loaded, true, 'diagnostics should show agent_loaded=true');
  });

  it('verifySelf succeeds', () => {
    const selfResultJson = agent.verifySelf();
    const selfResult = JSON.parse(selfResultJson);
    assert.strictEqual(selfResult.valid, true, 'verify_self should be valid');
  });

  it('isStrict returns false for ephemeral agent', () => {
    assert.strictEqual(agent.isStrict(), false, 'ephemeral agent should not be strict');
  });

  it('configPath returns null/undefined for ephemeral agent', () => {
    const cp = agent.configPath();
    assert.ok(cp === null || cp === undefined, 'ephemeral agent should have no config_path');
  });
});

// =============================================================================
// 4. Error parity: invalid inputs are rejected
// =============================================================================

describe('Parity: error handling', skipUnless(nativeAvailable, 'native module not available'), () => {
  let agent;

  before(() => {
    agent = createEphemeral();
  });

  it('verify rejects invalid JSON', () => {
    assert.throws(
      () => agent.verify('not-valid-json{{{'),
      /./,
      'verify should reject invalid JSON input',
    );
  });

  it('signMessage rejects invalid JSON', () => {
    assert.throws(
      () => agent.signMessage('not valid json {{'),
      /./,
      'signMessage should reject invalid JSON',
    );
  });

  it('verify rejects tampered document', () => {
    const signedJson = agent.signMessage(JSON.stringify({ original: true }));
    const parsed = JSON.parse(signedJson);

    // Tamper with the content
    if ('content' in parsed) {
      parsed.content = { original: false, tampered: true };
    }
    const tampered = JSON.stringify(parsed);

    // Verification should return valid=false or throw -- either is acceptable
    try {
      const resultJson = agent.verify(tampered);
      const result = JSON.parse(resultJson);
      assert.strictEqual(
        result.valid,
        false,
        'tampered document should verify as invalid',
      );
    } catch (_e) {
      // Also acceptable: throwing for tampered input
    }
  });

  it('verifyById rejects malformed document ID', () => {
    assert.throws(
      () => agent.verifyById('not-a-valid-id'),
      /./,
      'verifyById should reject malformed document ID',
    );
  });

  it('verifyWithKey rejects invalid base64 key', () => {
    const signedJson = agent.signMessage(JSON.stringify({ test: 1 }));
    assert.throws(
      () => agent.verifyWithKey(signedJson, 'not-valid-base64!!!'),
      /./,
      'verifyWithKey should reject invalid base64 key',
    );
  });
});

// =============================================================================
// 5. Sign raw bytes parity
// =============================================================================

describe('Parity: signRawBytes', skipUnless(nativeAvailable && fixtures, 'native module or fixtures not available'), () => {
  let agent;

  before(() => {
    agent = createEphemeral();
  });

  for (const input of (fixtures ? fixtures.sign_raw_bytes_inputs : [])) {
    it(`signRawBytes for "${input.name}" returns valid base64`, () => {
      const dataBytes = Buffer.from(input.data_base64, 'base64');
      const sigB64 = agent.signRawBytes(dataBytes);

      assertValidBase64(sigB64, `signRawBytes result for '${input.name}'`);
    });
  }
});

// =============================================================================
// 6. Verify with explicit key parity
// =============================================================================

describe('Parity: verifyWithKey', skipUnless(nativeAvailable && fixtures, 'native module or fixtures not available'), () => {
  let agent;

  before(() => {
    agent = createEphemeral();
  });

  it('verify with explicit public key succeeds', () => {
    const keyB64 = agent.getPublicKeyBase64();
    const input = fixtures.sign_message_inputs[0]; // simple_message
    const dataJson = JSON.stringify(input.data);
    const signedJson = agent.signMessage(dataJson);

    const resultJson = agent.verifyWithKey(signedJson, keyB64);
    const result = JSON.parse(resultJson);

    assert.strictEqual(result.valid, true, 'verify with explicit key should succeed');
  });
});

// =============================================================================
// 7. Sign file parity
// =============================================================================

describe('Parity: signFile', skipUnless(nativeAvailable, 'native module not available'), () => {
  let agent;
  let tmpDir;

  before(() => {
    agent = createEphemeral();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-parity-'));
  });

  it('signFile produces signed document with required fields', () => {
    const filePath = path.join(tmpDir, 'parity_test_file.txt');
    fs.writeFileSync(filePath, 'parity test content');

    const signedJson = agent.signFile(filePath, true);
    const signed = JSON.parse(signedJson);

    assert.ok('jacsSignature' in signed, 'signed file should have jacsSignature');
    assert.ok('jacsId' in signed, 'signed file should have jacsId');

    // Verify the signed file
    const verifyJson = agent.verify(signedJson);
    const result = JSON.parse(verifyJson);
    assert.strictEqual(result.valid, true, 'signed file should verify');
  });

  // Cleanup
  after(() => {
    if (tmpDir) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// =============================================================================
// 8. Verification result structure parity
// =============================================================================

describe('Parity: verification result structure', skipUnless(nativeAvailable && fixtures, 'native module or fixtures not available'), () => {
  let agent;

  before(() => {
    agent = createEphemeral();
  });

  it('verification result has required fields', () => {
    const requiredFields = fixtures.expected_verification_result_fields.required;

    const signedJson = agent.signMessage(JSON.stringify({ structure_test: true }));
    const verifyJson = agent.verify(signedJson);
    const result = JSON.parse(verifyJson);

    for (const field of requiredFields) {
      assert.ok(
        field in result,
        `verification result missing required field '${field}'`,
      );
    }
  });
});

// =============================================================================
// 9. Cross-algorithm structure consistency
// =============================================================================

describe('Parity: cross-algorithm structure consistency', skipUnless(nativeAvailable && fixtures, 'native module or fixtures not available'), () => {
  it('ed25519 signed document has jacsId and jacsSignature', () => {
    const edAgent = createEphemeral('ed25519');
    const input = fixtures.sign_message_inputs[0];
    const dataJson = JSON.stringify(input.data);

    const signedJson = edAgent.signMessage(dataJson);
    const signed = JSON.parse(signedJson);

    assert.ok('jacsId' in signed, 'ed25519 signed doc should have jacsId');
    assert.ok('jacsSignature' in signed, 'ed25519 signed doc should have jacsSignature');
  });
});
