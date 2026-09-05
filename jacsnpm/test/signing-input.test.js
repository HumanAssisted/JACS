const { expect } = require('chai');
const { createHash } = require('crypto');
const { readFileSync } = require('fs');
const { join } = require('path');

describe('native-free frozen document signature input', () => {
  let signing;
  let fixture;

  before(async () => {
    signing = await import('../browser/signing.js');
    fixture = JSON.parse(readFileSync(
      join(__dirname, '../../jacs-core/tests/fixtures/prepared_document_v2.json'),
      'utf8',
    ));
  });

  it('matches the shared Rust/browser parity fixture byte for byte', () => {
    const input = signing.buildDocumentSignatureInputV2(fixture.envelope);
    expect(Buffer.from(input).toString('utf8')).to.equal(fixture.signatureInputUtf8);
    expect(Buffer.from(input).toString('base64')).to.equal(fixture.signatureInputBase64);

    const digestPreimage = signing.buildHaiSignatureInputDigestPreimageV1(fixture.envelope);
    expect(Buffer.from(digestPreimage).toString('base64'))
      .to.equal(fixture.haiDigestPreimageBase64);
    expect(`sha256:${createHash('sha256').update(digestPreimage).digest('hex')}`)
      .to.equal(fixture.signatureInputDigest);
  });

  it('recomputes from the envelope instead of trusting the supplied hash', () => {
    const changed = structuredClone(fixture.envelope);
    changed.content.amount = 43;
    const changedPreimage = signing.buildHaiSignatureInputDigestPreimageV1(changed);
    const changedDigest = `sha256:${createHash('sha256').update(changedPreimage).digest('hex')}`;
    expect(changedDigest).not.to.equal(fixture.signatureInputDigest);
  });

  it('fails closed on incomplete field coverage and malformed Unicode', () => {
    const omitted = structuredClone(fixture.envelope);
    omitted.jacsSignature.fields = ['jacsLevel', 'jacsType'];
    expect(() => signing.buildDocumentSignatureInputV2(omitted))
      .to.throw('complete sorted non-reserved document field set');

    const malformed = structuredClone(fixture.envelope);
    malformed.content.note = '\ud800';
    expect(() => signing.buildDocumentSignatureInputV2(malformed))
      .to.throw('unpaired high surrogate');
  });

  it('rejects completed envelopes and non-interoperable integers', () => {
    const completed = structuredClone(fixture.envelope);
    completed.jacsSignature.signature = 'not-a-prepared-envelope';
    expect(() => signing.buildDocumentSignatureInputV2(completed))
      .to.throw('signature must be empty');

    const unsafe = structuredClone(fixture.envelope);
    unsafe.content.amount = Number.MAX_SAFE_INTEGER + 1;
    expect(() => signing.buildDocumentSignatureInputV2(unsafe))
      .to.throw('outside the I-JSON safe range');
  });
});
