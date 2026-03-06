/**
 * Tests for JACS Attestation API (Node.js bindings)
 *
 * These tests exercise the attestation surface exposed through:
 *   - JacsAgent (NAPI) createAttestation / verifyAttestation / liftToAttestation
 *   - JacsClient (TypeScript) convenience methods
 *
 * Tests are skipped when the native module was built without the 'attestation' feature.
 */

const { expect } = require('chai');

let clientModule;
try {
  clientModule = require('../client.js');
} catch (e) {
  clientModule = null;
}

// Feature detection: check if the native module exposes createAttestation
let hasAttestation = false;
if (clientModule) {
  try {
    const probe = clientModule.JacsClient.ephemeralSync('ring-Ed25519');
    // The requireAgent() call returns the underlying JacsAgent.
    // If createAttestation exists on JacsClient, attestation feature is compiled in.
    hasAttestation = typeof probe.createAttestation === 'function';
  } catch (_) {}
}

const available = clientModule !== null && hasAttestation;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSubject() {
  return {
    type: 'artifact',
    id: 'test-artifact-001',
    digests: { sha256: 'abc123def456' },
  };
}

function makeClaims() {
  return [
    {
      name: 'reviewed',
      value: true,
      confidence: 0.95,
      assuranceLevel: 'verified',
    },
  ];
}

// ===========================================================================
// JacsClient attestation tests (async, instance-based API)
// ===========================================================================

describe('Attestation', function () {
  this.timeout(15000);

  before(function () {
    if (!available) {
      console.log(
        '  Skipping attestation tests - native module not compiled with attestation feature',
      );
      this.skip();
    }
  });

  // -------------------------------------------------------------------------
  // createAttestation
  // -------------------------------------------------------------------------

  describe('createAttestation', () => {
    (available ? it : it.skip)(
      'should create an attestation and return a SignedDocument',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = await client.createAttestation({
          subject: makeSubject(),
          claims: makeClaims(),
        });

        expect(signed).to.have.property('raw').that.is.a('string');
        expect(signed).to.have.property('documentId').that.is.a('string').and.not.empty;
        expect(signed).to.have.property('agentId').that.is.a('string').and.not.empty;

        const doc = JSON.parse(signed.raw);
        expect(doc).to.have.property('attestation');
        expect(doc.attestation.subject.id).to.equal('test-artifact-001');
      },
    );

    (available ? it : it.skip)(
      'should reject empty claims array',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        let error = null;
        try {
          await client.createAttestation({
            subject: makeSubject(),
            claims: [],
          });
        } catch (e) {
          error = e;
        }
        expect(error).to.not.be.null;
      },
    );

    (available ? it : it.skip)(
      'should include policy context when provided',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = await client.createAttestation({
          subject: makeSubject(),
          claims: makeClaims(),
          policyContext: {
            policyId: 'policy-001',
            requiredTrustLevel: 'verified',
          },
        });

        const doc = JSON.parse(signed.raw);
        expect(doc.attestation.policyContext.policyId).to.equal('policy-001');
      },
    );
  });

  // -------------------------------------------------------------------------
  // verifyAttestation (local tier)
  // -------------------------------------------------------------------------

  describe('verifyAttestation (local)', () => {
    (available ? it : it.skip)(
      'should verify a created attestation locally and return valid',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = await client.createAttestation({
          subject: makeSubject(),
          claims: makeClaims(),
        });

        const result = await client.verifyAttestation(signed.raw);
        expect(result).to.have.property('valid', true);
        expect(result.crypto).to.have.property('signature_valid', true);
        expect(result.crypto).to.have.property('hash_valid', true);
      },
    );
  });

  // -------------------------------------------------------------------------
  // verifyAttestation (full tier)
  // -------------------------------------------------------------------------

  describe('verifyAttestation (full)', () => {
    (available ? it : it.skip)(
      'should verify a created attestation fully and return evidence list',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = await client.createAttestation({
          subject: makeSubject(),
          claims: makeClaims(),
        });

        const result = await client.verifyAttestation(signed.raw, { full: true });
        expect(result).to.have.property('valid', true);
        expect(result).to.have.property('evidence').that.is.an('array');
      },
    );
  });

  // -------------------------------------------------------------------------
  // liftToAttestation
  // -------------------------------------------------------------------------

  describe('liftToAttestation', () => {
    (available ? it : it.skip)(
      'should lift a signed document to an attestation',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = await client.signMessage({ content: 'Original document' });

        const att = await client.liftToAttestation(signed.raw, makeClaims());
        expect(att).to.have.property('raw').that.is.a('string');
        expect(att).to.have.property('documentId').that.is.a('string').and.not.empty;

        const doc = JSON.parse(att.raw);
        expect(doc).to.have.property('attestation');
        // The lifted attestation's subject ID should reference the original document
        expect(doc.attestation.subject.id).to.equal(signed.documentId);
      },
    );
  });

  // -------------------------------------------------------------------------
  // exportAttestationDsse
  // -------------------------------------------------------------------------

  describe('exportAttestationDsse', () => {
    (available ? it : it.skip)(
      'should export a DSSE envelope from a created attestation',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = await client.createAttestation({
          subject: makeSubject(),
          claims: makeClaims(),
        });

        const envelope = await client.exportAttestationDsse(signed.raw);
        expect(envelope).to.have.property('payloadType', 'application/vnd.in-toto+json');
        expect(envelope).to.have.property('signatures').that.is.an('array');
        expect(envelope.signatures.length).to.be.greaterThan(0);
      },
    );
  });

  // -------------------------------------------------------------------------
  // Error handling: non-existent document
  // -------------------------------------------------------------------------

  describe('error handling', () => {
    (available ? it : it.skip)(
      'should reject verification of a non-existent document key',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        // Fabricate a JSON with a jacsId/jacsVersion that was never stored
        const fakeJson = JSON.stringify({
          jacsId: 'non-existent-id',
          jacsVersion: 'v1',
        });

        let error = null;
        try {
          await client.verifyAttestation(fakeJson);
        } catch (e) {
          error = e;
        }
        expect(error).to.not.be.null;
      },
    );
  });

  // -------------------------------------------------------------------------
  // Round trip
  // -------------------------------------------------------------------------

  describe('round trip', () => {
    (available ? it : it.skip)(
      'should create, verify local, and verify full in sequence',
      async () => {
        const client = await clientModule.JacsClient.ephemeral('ring-Ed25519');
        const signed = await client.createAttestation({
          subject: makeSubject(),
          claims: makeClaims(),
        });

        const localResult = await client.verifyAttestation(signed.raw, { full: false });
        expect(localResult.valid).to.equal(true);

        const fullResult = await client.verifyAttestation(signed.raw, { full: true });
        expect(fullResult.valid).to.equal(true);
      },
    );
  });
});
