const { expect } = require('chai');

let policyModule;
try {
  policyModule = require('../output-policy.js');
} catch {
  policyModule = null;
}

describe('unsigned output policy', () => {
  function validSignedDocument() {
    return {
      jacsId: 'doc-1',
      jacsVersion: 'version-1',
      jacsSignature: {
        agentID: 'agent-1',
        agentVersion: 'agent-version-1',
        date: '2026-07-10T00:00:00Z',
        publicKeyHash: 'abc123',
        signature: 'signed-bytes',
        signatureContentVersion: 'jacs-signature-v2',
      },
    };
  }

  it('allows unsigned output only for literal true', () => {
    expect(policyModule).to.not.equal(null);

    for (const value of [undefined, null, false, 'true', 1, {}, []]) {
      expect(policyModule.allowUnsignedOutput(value), String(value)).to.equal(false);
    }
    expect(policyModule.allowUnsignedOutput(true)).to.equal(true);
  });

  it('lets strict mode override an explicit unsigned-output opt-in', () => {
    expect(policyModule.allowUnsignedOutput(true, true)).to.equal(false);
    expect(policyModule.allowUnsignedOutput(true, false)).to.equal(true);
    expect(policyModule.allowUnsignedOutput(true, 'true')).to.equal(true);
  });

  it('accepts only portable raw documents with signature metadata', () => {
    const raw = JSON.stringify(validSignedDocument());
    expect(policyModule.requireSignedRaw({ raw }, 'test')).to.equal(raw);
    expect(policyModule.requireSignedEnvelope(raw, 'test')).to.equal(raw);
    expect(() => policyModule.requireSignedRaw({ raw: '{"result":"plain"}' }, 'test'))
      .to.throw(/signature metadata/i);
    expect(() => policyModule.requireSignedRaw({ raw: 'not-json' }, 'test'))
      .to.throw(/JSON portable/i);
  });

  it('rejects malformed, legacy, and incomplete pseudo-signatures', () => {
    const cases = [
      ['empty signature object', (doc) => { doc.jacsSignature = {}; }],
      ['legacy-v1', (doc) => { doc.jacsSignature.signatureContentVersion = 'jacs-signature-v1'; }],
      ['missing content version', (doc) => { delete doc.jacsSignature.signatureContentVersion; }],
      ['missing signature', (doc) => { delete doc.jacsSignature.signature; }],
      ['blank signature', (doc) => { doc.jacsSignature.signature = '  '; }],
      ['missing signer', (doc) => { delete doc.jacsSignature.agentID; }],
      ['missing agent version', (doc) => { delete doc.jacsSignature.agentVersion; }],
      ['missing public key hash', (doc) => { delete doc.jacsSignature.publicKeyHash; }],
      ['missing date', (doc) => { delete doc.jacsSignature.date; }],
      ['missing document ID', (doc) => { delete doc.jacsId; }],
      ['missing document version', (doc) => { delete doc.jacsVersion; }],
    ];

    for (const [name, mutate] of cases) {
      const document = validSignedDocument();
      mutate(document);
      const raw = JSON.stringify(document);
      expect(
        () => policyModule.requireSignedRaw({ raw }, name),
        name,
      ).to.throw(/portable v2 signature metadata/i);
      expect(
        () => policyModule.requireSignedEnvelope(raw, name),
        name,
      ).to.throw(/portable v2 signature metadata/i);
    }
  });
});
