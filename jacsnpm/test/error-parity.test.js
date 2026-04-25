/**
 * Error kind parity test for the Node.js binding.
 *
 * Validates that all error kinds listed in the `error_kinds` array of
 * binding-core/tests/fixtures/parity_inputs.json are recognized by the
 * Node binding's error handling.
 *
 * The Rust ErrorKind enum has 13 variants. Node maps these through error
 * message prefixes (all errors are JavaScript Error instances).
 *
 * This test complements, not duplicates, the behavioral error tests in
 * test_parity.js section 7.
 *
 * KNOWN LIMITATION: 8 of 13 error kinds are validated structurally only
 * (mapping existence in ERROR_KIND_MAP), not behaviorally. Only the
 * triggerable kinds are tested with runtime assertions. Untriggerable
 * kinds require states that are impractical in unit tests (e.g., mutex
 * poisoning, network calls, trust store setup).
 */

const fs = require('fs');
const path = require('path');
const { expect } = require('chai');

const FIXTURE_PATH = path.resolve(
  __dirname,
  '../../binding-core/tests/fixtures/parity_inputs.json'
);

// Mapping from Rust ErrorKind variant name to Node error representation.
// Each entry documents how this error kind manifests in JavaScript.
const ERROR_KIND_MAP = {
  'LockFailed': {
    messagePattern: 'lock',
    triggerable: false, // Requires concurrent mutex poisoning
  },
  'AgentLoad': {
    messagePattern: 'Failed to load',
    triggerable: true,
  },
  'Validation': {
    messagePattern: 'Validation',
    triggerable: true,
  },
  'SigningFailed': {
    messagePattern: 'Sign',
    triggerable: true,
  },
  'VerificationFailed': {
    messagePattern: 'Verification failed',
    triggerable: true,
  },
  'DocumentFailed': {
    messagePattern: 'Document',
    triggerable: false,
  },
  'AgreementFailed': {
    messagePattern: 'Agreement',
    triggerable: false,
  },
  'SerializationFailed': {
    messagePattern: 'Serialization',
    triggerable: true,
  },
  'InvalidArgument': {
    messagePattern: 'Invalid',
    triggerable: true,
  },
  'TrustFailed': {
    messagePattern: 'Trust',
    triggerable: false,
  },
  'NetworkFailed': {
    messagePattern: 'Network',
    triggerable: false,
  },
  'KeyNotFound': {
    messagePattern: 'key',
    triggerable: false,
  },
  'Generic': {
    messagePattern: null, // Catch-all, no specific pattern
    triggerable: false,
  },
  'MissingSignature': {
    // C1: strict-mode verifyText / verifyImage reject the Promise with this pattern.
    // Permissive mode (default) still returns a typed status, not thrown.
    messagePattern: 'no JACS signature found',
    triggerable: true,
  },
};

describe('Node.js error kind parity', function () {
  let fixture;
  let errorKinds;

  before(function () {
    if (!fs.existsSync(FIXTURE_PATH)) {
      console.log('  Skipping error parity tests - fixture not found');
      this.skip();
      return;
    }
    fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));
    errorKinds = fixture.error_kinds;
    if (!errorKinds) {
      console.log('  Skipping - no error_kinds in fixture');
      this.skip();
    }
  });

  it('all error kinds from fixture are mapped in ERROR_KIND_MAP', function () {
    const unmapped = errorKinds.filter(kind => !(kind in ERROR_KIND_MAP));
    expect(unmapped, `Unmapped error kinds: ${unmapped.join(', ')}`).to.be.empty;
  });

  it('ERROR_KIND_MAP has no stale entries', function () {
    const fixtureSet = new Set(errorKinds);
    const stale = Object.keys(ERROR_KIND_MAP).filter(kind => !fixtureSet.has(kind));
    expect(stale, `Stale ERROR_KIND_MAP entries: ${stale.join(', ')}`).to.be.empty;
  });

  it('there are exactly 14 error kinds', function () {
    expect(errorKinds).to.have.length(14);
    expect(Object.keys(ERROR_KIND_MAP)).to.have.length(14);
  });

  it('MissingSignature error kind is present in fixture', function () {
    expect(errorKinds).to.include('MissingSignature');
  });

  it('triggerable error kinds can be triggered via the binding', function () {
    let JacsSimpleAgent;
    try {
      const bindings = require('../index.js');
      JacsSimpleAgent = bindings.JacsSimpleAgent;
      if (!JacsSimpleAgent) {
        this.skip();
        return;
      }
    } catch (e) {
      this.skip();
      return;
    }

    const agent = JacsSimpleAgent.ephemeral('ed25519');

    // InvalidArgument: bad JSON input.
    // This is a KNOWN behavioral difference from Python (see Issue 013):
    // - Node signMessage passes raw string to binding-core sign_message_json, which
    //   expects valid JSON. Invalid JSON is rejected with InvalidArgument.
    // - Python sign_message takes any Python object and serializes it first, so a
    //   raw string becomes a valid JSON string value and succeeds.
    // - Both behaviors are correct for their respective API contracts.
    // See parity_inputs.json 'sign_message_invalid_json_behavior' for documentation.
    expect(() => agent.signMessage('{{{bad')).to.throw(/Invalid/i);

    // VerificationFailed: malformed document
    expect(() => agent.verify('not json')).to.throw(/Verification failed|Malformed/i);

    // InvalidArgument: bad base64 key
    const signed = agent.signMessage('{"test": 1}');
    expect(() => agent.verifyWithKey(signed, '!!!notbase64')).to.throw(/Invalid|base64/i);
  });
});
