const { expect } = require('chai');

const {
  normalizeAgreementStatus,
  normalizeAttestationVerificationResult,
} = require('../verification.js');
const { JacsClient } = require('../client.js');

describe('security result normalization', () => {
  for (const malformed of ['false', 1, {}, null, undefined]) {
    it(`requires literal agreement booleans for ${JSON.stringify(malformed)}`, () => {
      const result = normalizeAgreementStatus({
        complete: malformed,
        signers: [{ agentId: 'agent-1', signed: malformed }],
        pending: ['agent-1'],
      });

      expect(result.complete).to.equal(false);
      expect(result.signers[0].signed).to.equal(false);
    });
  }

  it('recomputes attestation validity from exact nested booleans', () => {
    const result = normalizeAttestationVerificationResult({
      valid: 'false',
      crypto: { signatureValid: 'false', hashValid: 1 },
      evidence: [{ digestValid: {}, freshnessValid: 'true' }],
      chain: { valid: 'true', links: [{ valid: 1 }] },
      errors: [],
    });

    expect(result.valid).to.equal(false);
    expect(result.crypto.signatureValid).to.equal(false);
    expect(result.crypto.hashValid).to.equal(false);
    expect(result.evidence[0].digestValid).to.equal(false);
    expect(result.evidence[0].freshnessValid).to.equal(false);
    expect(result.chain.valid).to.equal(false);
    expect(result.chain.links[0].valid).to.equal(false);
  });

  it('preserves a coherent successful attestation result', () => {
    const result = normalizeAttestationVerificationResult({
      valid: true,
      crypto: { signatureValid: true, hashValid: true },
      evidence: [],
      chain: null,
      errors: [],
    });

    expect(result.valid).to.equal(true);
  });

  it('wires fail-closed normalization through JacsClient methods', async () => {
    const client = Object.create(JacsClient.prototype);
    client.agent = {
      checkAgreement: async () => JSON.stringify({
        complete: 'false',
        signers: [{ agentId: 'agent-1', signed: 'false' }],
        pending: ['agent-1'],
      }),
      verifyAttestation: async () => JSON.stringify({
        valid: 'false',
        crypto: { signatureValid: 'false', hashValid: 'false' },
        evidence: [],
        chain: null,
        errors: [],
      }),
    };

    const agreement = await client.checkAgreement('{}');
    const attestation = await client.verifyAttestation(
      '{"jacsId":"attestation","jacsVersion":"1"}',
    );

    expect(agreement.complete).to.equal(false);
    expect(agreement.signers[0].signed).to.equal(false);
    expect(attestation.valid).to.equal(false);
    expect(attestation.crypto.signatureValid).to.equal(false);
  });
});
