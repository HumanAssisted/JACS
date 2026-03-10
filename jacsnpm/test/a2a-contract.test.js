/**
 * A2A Contract Tests — validates Node wrapper verification output against
 * the shared canonical schema (a2a-verification-result.schema.json).
 *
 * Run selectively: npx mocha test/a2a-contract.test.js
 */

const { expect } = require('chai');
const sinon = require('sinon');
const fs = require('fs');
const path = require('path');

const Ajv = require('ajv');

const {
  JACSA2AIntegration,
  TRUST_POLICIES,
} = require('../src/a2a');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'a2a_contract');
const SCHEMA_PATH = path.join(
  __dirname, '..', '..', 'jacs', 'schemas', 'a2a-verification-result.schema.json',
);

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, `${name}.json`), 'utf8'));
}

function loadSchema() {
  return JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
}

/**
 * Create a mock JacsClient whose native A2A verification methods return
 * canonical contract-shaped JSON.
 */
function createMockClient(valid = true) {
  const buildParentResults = (parentSignatures = []) => parentSignatures.map((parent, index) => ({
    index,
    artifactId: parent.jacsId || '',
    signerId: parent.jacsSignature?.agentID || '',
    status: parent.jacsSignature?.agentID === 'agent-self-001' ? 'SelfSigned' : 'Verified',
    verified: true,
  }));

  const buildGenericResult = (wrappedArtifact, policy = null) => {
    const signerId = wrappedArtifact.jacsSignature?.agentID || '';
    const result = {
      status: valid
        ? (signerId === 'agent-self-001' ? 'SelfSigned' : 'Verified')
        : { Invalid: { reason: 'signature mismatch' } },
      valid,
      signerId,
      signerVersion: wrappedArtifact.jacsSignature?.agentVersion || '',
      artifactType: wrappedArtifact.jacsType || '',
      timestamp: wrappedArtifact.jacsVersionDate || '',
      parentSignaturesValid: buildParentResults(wrappedArtifact.jacsParentSignatures).every((parent) => parent.verified),
      parentVerificationResults: buildParentResults(wrappedArtifact.jacsParentSignatures),
      originalArtifact: wrappedArtifact.a2aArtifact || {},
    };
    if (policy) {
      const trustLevel = String(wrappedArtifact.jacsType || '').startsWith('a2a-')
        ? 'JacsVerified'
        : 'Untrusted';
      result.trustLevel = trustLevel;
      result.trustAssessment = {
        allowed: policy === 'open' || trustLevel === 'JacsVerified',
        trustLevel,
        reason: policy === 'open'
          ? 'Open policy: all agents are allowed'
          : trustLevel === 'JacsVerified'
            ? 'Verified policy: agent has JACS provenance extension'
            : 'Verified policy: agent does not declare JACS provenance extension',
        jacsRegistered: trustLevel === 'JacsVerified',
        agentId: signerId,
        policy: policy[0].toUpperCase() + policy.slice(1),
      };
    }
    return result;
  };

  const verifyA2aArtifactSync = sinon.stub().callsFake((wrappedJson) => {
    const wrappedArtifact = JSON.parse(wrappedJson);
    const signerId = wrappedArtifact.jacsSignature?.agentID;
    const fixtureName = {
      'agent-self-001': 'self_signed_verified',
      'agent-foreign-002': 'foreign_verified',
      'agent-foreign-003': 'foreign_unverified',
      'agent-invalid-004': 'invalid_signature',
    }[signerId];
    return JSON.stringify(fixtureName ? loadFixture(fixtureName) : buildGenericResult(wrappedArtifact));
  });

  const verifyA2aArtifactWithPolicySync = sinon.stub().callsFake((wrappedJson, _cardJson, policy) => {
    const wrappedArtifact = JSON.parse(wrappedJson);
    const signerId = wrappedArtifact.jacsSignature?.agentID;
    if (signerId === 'agent-blocked-005' && policy === 'strict') {
      return JSON.stringify(loadFixture('trust_blocked'));
    }
    if (signerId === 'agent-foreign-002') {
      return JSON.stringify(loadFixture('foreign_verified'));
    }
    if (signerId === 'agent-foreign-003') {
      return JSON.stringify(loadFixture('foreign_unverified'));
    }
    if (signerId === 'agent-invalid-004') {
      return JSON.stringify(loadFixture('invalid_signature'));
    }
    return JSON.stringify(buildGenericResult(wrappedArtifact, policy));
  });

  return {
    _agent: {
      signRequest: sinon.stub().callsFake((json) => json),
      verifyResponse: sinon.stub().returns(valid),
      verifyA2aArtifactSync,
      verifyA2aArtifactWithPolicySync,
    },
    agentId: 'mock-agent-id',
    name: 'mock-agent',
  };
}

/**
 * Build a minimal wrapped artifact with the given field values.
 */
function makeWrappedArtifact({
  signerId = 'agent-test-001',
  signerVersion = 'v1',
  artifactType = 'a2a-task',
  timestamp = '2025-06-01T00:00:00Z',
  artifact = { name: 'test-artifact' },
} = {}) {
  return {
    jacsId: `${signerId}-artifact`,
    jacsType: artifactType,
    jacsVersionDate: timestamp,
    jacsSignature: { agentID: signerId, agentVersion: signerVersion },
    a2aArtifact: artifact,
  };
}

// ---------------------------------------------------------------------------
// Unit Tests — Verify Result Shape
// ---------------------------------------------------------------------------

describe('A2A Contract Tests', function () {
  this.timeout(10000);

  describe('Verify Result Shape', () => {
    let integration;

    beforeEach(() => {
      const client = createMockClient(true);
      integration = new JACSA2AIntegration(client);
    });

    it('should include status field in verification result', async () => {
      const wrapped = makeWrappedArtifact();
      const result = await integration.verifyWrappedArtifact(wrapped);

      expect(result).to.have.property('status');
      expect(typeof result.status === 'string' || typeof result.status === 'object')
        .to.equal(true, `status must be a string or object, got ${typeof result.status}`);
    });

    it('should use canonical status enum values for verified artifact', async () => {
      const client = createMockClient(true);
      const int = new JACSA2AIntegration(client);
      const wrapped = makeWrappedArtifact();
      const result = await int.verifyWrappedArtifact(wrapped);

      const validStatuses = ['Verified', 'SelfSigned'];
      const status = result.status;
      expect(validStatuses).to.include(status,
        `For a valid artifact, status must be one of ${validStatuses.join(', ')}, got ${JSON.stringify(status)}`);
    });

    it('should use canonical status enum values for invalid artifact', async () => {
      const client = createMockClient(false);
      const int = new JACSA2AIntegration(client);
      const wrapped = makeWrappedArtifact();
      const result = await int.verifyWrappedArtifact(wrapped);

      const status = result.status;
      // For invalid: should be {Invalid: {reason: "..."}} or {Unverified: {reason: "..."}}
      expect(status).to.not.be.null;
      expect(status).to.not.be.undefined;
      if (typeof status === 'object') {
        const keys = Object.keys(status);
        expect(keys.length).to.equal(1, 'status object must have exactly one key');
        expect(['Invalid', 'Unverified']).to.include(keys[0]);
      } else {
        expect.fail(`status must be a string or dict for invalid artifacts, got ${typeof status}`);
      }
    });

    it('should include trust block when policy assessment requested', async () => {
      const client = createMockClient(true);
      const int = new JACSA2AIntegration(client, 'verified');
      const wrapped = makeWrappedArtifact();
      const result = await int.verifyWrappedArtifact(wrapped);

      expect(result, 'Output must contain trustAssessment when trust policy is set')
        .to.have.property('trustAssessment');
    });

    it('should include trust.status as allowed|blocked|not_assessed via trustAssessment', async () => {
      const client = createMockClient(true);
      const int = new JACSA2AIntegration(client, 'verified');
      const wrapped = makeWrappedArtifact();
      const result = await int.verifyWrappedArtifact(wrapped);

      if (!result.trustAssessment) {
        expect.fail('Missing trustAssessment in output');
      }
      const ta = result.trustAssessment;
      expect(ta).to.have.property('allowed');
      expect(typeof ta.allowed).to.equal('boolean');
      expect(ta).to.have.property('policy');
    });

    it('should preserve valid boolean for backward compatibility', async () => {
      const wrapped = makeWrappedArtifact();
      const result = await integration.verifyWrappedArtifact(wrapped);

      expect(result).to.have.property('valid');
      expect(typeof result.valid).to.equal('boolean');
    });
  });

  // ---------------------------------------------------------------------------
  // Integration Tests — Fixture Conformance
  // ---------------------------------------------------------------------------

  describe('Fixture Conformance', () => {
    let schema;
    let ajv;
    let validate;

    before(function () {
      schema = loadSchema();
      ajv = new Ajv({ allErrors: true });
      validate = ajv.compile(schema);
    });

    it('should match self_signed_verified fixture schema', async () => {
      const expected = loadFixture('self_signed_verified');
      const client = createMockClient(true);
      const int = new JACSA2AIntegration(client);
      const wrapped = makeWrappedArtifact({
        signerId: expected.signerId,
        signerVersion: expected.signerVersion,
        artifactType: expected.artifactType,
        timestamp: expected.timestamp,
        artifact: expected.originalArtifact,
      });
      const result = await int.verifyWrappedArtifact(wrapped);

      const valid = validate(result);
      if (!valid) {
        const errors = validate.errors.map(e => `${e.instancePath} ${e.message}`).join('; ');
        expect.fail(`Output does not conform to schema: ${errors}`);
      }

      expect(result.valid).to.equal(expected.valid);
      expect(result.signerId).to.equal(expected.signerId);
    });

    it('should match foreign_verified fixture schema', async () => {
      const expected = loadFixture('foreign_verified');
      const client = createMockClient(true);
      const int = new JACSA2AIntegration(client);
      const wrapped = makeWrappedArtifact({
        signerId: expected.signerId,
        signerVersion: expected.signerVersion,
        artifactType: expected.artifactType,
        timestamp: expected.timestamp,
        artifact: expected.originalArtifact,
      });
      const result = await int.verifyWrappedArtifact(wrapped);

      const valid = validate(result);
      if (!valid) {
        const errors = validate.errors.map(e => `${e.instancePath} ${e.message}`).join('; ');
        expect.fail(`Output does not conform to schema: ${errors}`);
      }

      expect(result.valid).to.equal(expected.valid);
      expect(result.signerId).to.equal(expected.signerId);
    });

    it('should distinguish Unverified from Invalid in status field', async () => {
      const unverifiedExpected = loadFixture('foreign_unverified');
      const invalidExpected = loadFixture('invalid_signature');

      // Both fail verification but for different reasons
      const client = createMockClient(false);
      const int = new JACSA2AIntegration(client);

      const unverifiedWrapped = makeWrappedArtifact({
        signerId: unverifiedExpected.signerId,
        signerVersion: unverifiedExpected.signerVersion,
        artifactType: unverifiedExpected.artifactType,
        timestamp: unverifiedExpected.timestamp,
        artifact: unverifiedExpected.originalArtifact,
      });
      const unverifiedResult = await int.verifyWrappedArtifact(unverifiedWrapped);

      const invalidWrapped = makeWrappedArtifact({
        signerId: invalidExpected.signerId,
        signerVersion: invalidExpected.signerVersion,
        artifactType: invalidExpected.artifactType,
        timestamp: invalidExpected.timestamp,
        artifact: invalidExpected.originalArtifact,
      });
      const invalidResult = await int.verifyWrappedArtifact(invalidWrapped);

      // Both must be invalid
      expect(unverifiedResult.valid).to.equal(false);
      expect(invalidResult.valid).to.equal(false);

      // But they must have distinct status values
      expect(unverifiedResult).to.have.property('status');
      expect(invalidResult).to.have.property('status');

      expect(unverifiedResult.status).to.not.deep.equal(invalidResult.status,
        'Unverified and Invalid must produce distinct status values');

      // Unverified status: { Unverified: { reason: "..." } }
      if (typeof unverifiedResult.status === 'object') {
        expect(unverifiedResult.status).to.have.property('Unverified');
      }
      // Invalid status: { Invalid: { reason: "..." } }
      if (typeof invalidResult.status === 'object') {
        expect(invalidResult.status).to.have.property('Invalid');
      }
    });

    it('should match trust_blocked fixture schema', async () => {
      const expected = loadFixture('trust_blocked');
      const client = createMockClient(false);
      const int = new JACSA2AIntegration(client, 'strict');
      const wrapped = makeWrappedArtifact({
        signerId: expected.signerId,
        signerVersion: expected.signerVersion,
        artifactType: expected.artifactType,
        timestamp: expected.timestamp,
        artifact: expected.originalArtifact,
      });
      const result = await int.verifyWrappedArtifact(wrapped);

      const valid = validate(result);
      if (!valid) {
        const errors = validate.errors.map(e => `${e.instancePath} ${e.message}`).join('; ');
        expect.fail(`Output does not conform to schema: ${errors}`);
      }

      expect(result.valid).to.equal(expected.valid);
      expect(result).to.have.property('trustAssessment');
      if (result.trustAssessment) {
        expect(result.trustAssessment.allowed).to.equal(false);
      }
    });

    it('all fixture files themselves should conform to schema (meta-test)', () => {
      // This test validates the test data, not the wrapper implementation.
      const fixtures = [
        'self_signed_verified',
        'foreign_verified',
        'foreign_unverified',
        'invalid_signature',
        'trust_blocked',
      ];

      for (const name of fixtures) {
        const fixture = loadFixture(name);
        const valid = validate(fixture);
        if (!valid) {
          const errors = validate.errors.map(e => `${e.instancePath} ${e.message}`).join('; ');
          expect.fail(`Fixture '${name}.json' does not conform to schema: ${errors}`);
        }
      }
    });
  });
});
