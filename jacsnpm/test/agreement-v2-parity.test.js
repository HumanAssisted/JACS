const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

const FIXTURE = JSON.parse(fs.readFileSync(
  path.resolve(__dirname, '../../binding-core/tests/fixtures/agreement_v2_scenarios.json'),
  'utf8',
));
const EXPECTED = FIXTURE.expected;

describe('Node.js agreement v2 behavioral parity', function () {
  let JacsSimpleAgent;

  before(function () {
    try {
      ({ JacsSimpleAgent } = require('../index.js'));
      if (!JacsSimpleAgent) this.skip();
    } catch (_err) {
      this.skip();
    }
  });

  function ephemeral() {
    const agent = JacsSimpleAgent.ephemeral('ed25519');
    return { agent, agentId: agent.getAgentId() };
  }

  function baseInput(agentId) {
    const input = JSON.parse(JSON.stringify(FIXTURE.base_input));
    input.parties = [{ agentId, agentType: 'ai', role: 'signer' }];
    input.controllers = [agentId];
    return input;
  }

  function createAgreement(agent, agentId) {
    return agent.createAgreementV2Sync(JSON.stringify(baseInput(agentId)));
  }

  function transcriptRef(name) {
    return JSON.parse(JSON.stringify(FIXTURE.transcript_refs[name]));
  }

  function apply(agent, document, mutation) {
    return agent.applyAgreementV2Sync(document, JSON.stringify(mutation));
  }

  it('creates, signs, and verifies an agreement through async wrappers', async function () {
    const { agent, agentId } = ephemeral();

    const created = await agent.createAgreementV2(JSON.stringify(baseInput(agentId)));
    const signed = await agent.signAgreementV2(created, 'signer');
    const report = await agent.verifyAgreementV2(signed);

    expect(report.valid).to.equal(EXPECTED.verify.valid);
    expect(report.expectedStatus).to.equal(EXPECTED.verify.expectedStatus);
    expect(report.signerCount).to.equal(EXPECTED.verify.signerCount);
  });

  it('supports notary signatures as a distinct agreement role', function () {
    const { agent: signer, agentId: signerId } = ephemeral();
    const { agent: notary, agentId: notaryId } = ephemeral();
    const input = baseInput(signerId);
    input.parties = [
      { agentId: signerId, agentType: 'ai', role: 'signer' },
      { agentId: notaryId, agentType: 'ai', role: 'notary' },
    ];
    input.signaturePolicy.notaryRequired = 1;

    const created = signer.createAgreementV2Sync(JSON.stringify(input));
    const notarized = JSON.parse(notary.signAgreementV2Sync(created, 'notary'));

    expect(notarized.agreementSignatures[0].role).to.equal(EXPECTED.notary.role);
  });

  it('auto-merges transcript-only branches', function () {
    const { agent, agentId } = ephemeral();
    const base = createAgreement(agent, agentId);
    const left = apply(agent, base, {
      type: 'appendTranscript',
      entry: transcriptRef('left'),
    });
    const right = apply(agent, base, {
      type: 'appendTranscript',
      entry: transcriptRef('right'),
    });

    const analysis = agent.detectAgreementV2BranchConflictSync(base, left, right);
    expect(analysis.sameDocument).to.equal(EXPECTED.transcriptMerge.sameDocument);
    expect(analysis.sameParent).to.equal(EXPECTED.transcriptMerge.sameParent);
    expect(analysis.autoMergeable).to.equal(EXPECTED.transcriptMerge.autoMergeable);

    const merged = JSON.parse(agent.mergeAgreementV2TranscriptBranchesSync(base, left, right));
    expect(merged.transcript).to.have.length(EXPECTED.transcriptMerge.mergedTranscriptLength);
  });

  it('resolves terms conflicts with an explicit successor mutation', function () {
    const { agent, agentId } = ephemeral();
    const base = createAgreement(agent, agentId);
    const left = apply(agent, base, { type: 'updateTerms', terms: FIXTURE.terms_conflict.left });
    const right = apply(agent, base, { type: 'updateTerms', terms: FIXTURE.terms_conflict.right });

    const analysis = agent.detectAgreementV2BranchConflictSync(base, left, right);
    expect(analysis.autoMergeable).to.equal(EXPECTED.termsConflict.autoMergeable);
    expect(analysis.conflictFields).to.include(EXPECTED.termsConflict.conflictField);

    const resolved = JSON.parse(
      agent.resolveAgreementV2BranchConflictSync(
        base,
        left,
        right,
        JSON.stringify({ type: 'updateTerms', terms: FIXTURE.terms_conflict.resolved }),
      ),
    );
    const rightDoc = JSON.parse(right);

    expect(resolved.terms).to.equal(FIXTURE.terms_conflict.resolved);
    // Resolution links also carry jacsSha256 (content-hash binding of the
    // resolved branch), so assert the identity fields as a subset.
    expect(resolved.links[0]).to.include({
      jacsId: rightDoc.jacsId,
      jacsVersion: rightDoc.jacsVersion,
    });
    expect(resolved.links[0].jacsSha256).to.be.a('string').and.have.length(64);
  });
});
