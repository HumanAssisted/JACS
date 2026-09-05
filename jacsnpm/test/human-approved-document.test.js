// Set JACS_TEST_HUMAN_APPROVAL=1 for the feature-enabled gate: a missing
// verifier then fails, while ordinary feature-disabled suites stay usable.
// All fixture material is public.
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { JacsSimpleAgent } = require('../index.js');

const fixturePath = path.resolve(
  __dirname, '../../binding-core/tests/fixtures/human_approved_document_v1.json',
);
const errorKindPrefix = JSON.parse(fs.readFileSync(path.resolve(
  __dirname, '../../binding-core/tests/fixtures/parity_inputs.json',
), 'utf8')).portable_error_contract.message_prefix;

const describeFeature = process.env.JACS_TEST_HUMAN_APPROVAL === '1'
  || typeof JacsSimpleAgent.verifyHumanApprovedDocument === 'function' ? describe : describe.skip;

describeFeature('public human-approved document verification', function () {
  let fixture;

  beforeEach(function () {
    fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  });

  function args(value) {
    return ['bundle', 'expected', 'authority', 'provenance'].map(
      (name) => JSON.stringify(value[name]),
    );
  }

  it('returns the complete native report without an agent or signing key', function () {
    const originalCwd = process.cwd();
    const originalPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-public-proof-'));
    try {
      process.chdir(temporary);
      delete process.env.JACS_PRIVATE_KEY_PASSWORD;
      // Static invocation: do not construct even an ephemeral agent.
      const raw = JacsSimpleAgent.verifyHumanApprovedDocument(...args(fixture));
      expect(raw).to.be.a('string');
      const report = JSON.parse(raw);
      expect(report).to.deep.equal(fixture.report);
      expect(report.provenanceSignatureValid).to.equal(true);
      expect(report.approval.proofValid).to.equal(true);
      expect(report.approval.userVerified).to.equal(true);
      expect(report.current).to.equal('not_evaluated');
      expect(report.approval.current).to.equal('not_evaluated');
      expect(fs.readdirSync(temporary)).to.deep.equal([]);
    } finally {
      process.chdir(originalCwd);
      if (originalPassword === undefined) delete process.env.JACS_PRIVATE_KEY_PASSWORD;
      else process.env.JACS_PRIVATE_KEY_PASSWORD = originalPassword;
      fs.rmdirSync(temporary);
    }
  });

  for (const field of ['expected', 'authority', 'provenance']) {
    it(`requires the independently selected ${field}`, function () {
      if (field === 'expected') fixture[field].humanId += '-other';
      else fixture[field].agentId += '-other';
      expect(() => JacsSimpleAgent.verifyHumanApprovedDocument(...args(fixture))).to.throw()
        .with.property('message').that.includes(`${errorKindPrefix}VerificationFailed:`);
    });
  }

  for (let position = 0; position < 4; position += 1) {
    it(`rejects malformed JSON in argument ${position + 1}`, function () {
      const inputs = args(fixture);
      inputs[position] = '{';
      const kind = position === 0 ? 'VerificationFailed' : 'InvalidArgument';
      expect(() => JacsSimpleAgent.verifyHumanApprovedDocument(...inputs)).to.throw()
        .with.property('message').that.includes(`${errorKindPrefix}${kind}:`);
    });
  }
});
