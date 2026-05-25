const { expect } = require('chai');

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
    return {
      title: 'Agreement v2 parity',
      description: 'Portable agreement v2 workflow test.',
      terms: 'The binding must delegate agreement v2 behavior to Rust core.',
      termsFormat: 'text/plain',
      status: 'proposed',
      parties: [{ agentId, agentType: 'ai', role: 'signer' }],
      signaturePolicy: {
        partyQuorum: 'all',
        witnessRequired: 0,
        notaryRequired: 0,
        requiredAlgorithms: ['ring-Ed25519'],
        minimumStrength: 'classical',
      },
      controllers: [agentId],
    };
  }

  function createAgreement(agent, agentId) {
    return agent.createAgreementV2Sync(JSON.stringify(baseInput(agentId)));
  }

  function documentRef(agent, message) {
    const raw = JSON.parse(agent.signMessage(JSON.stringify({ message })));
    return {
      jacsId: raw.jacsId,
      jacsVersion: raw.jacsVersion,
      jacsSha256: raw.jacsSha256,
    };
  }

  function apply(agent, document, mutation) {
    return agent.applyAgreementV2Sync(document, JSON.stringify(mutation));
  }

  it('creates, signs, and verifies an agreement through async wrappers', async function () {
    const { agent, agentId } = ephemeral();

    const created = await agent.createAgreementV2(JSON.stringify(baseInput(agentId)));
    const signed = await agent.signAgreementV2(created, 'signer');
    const report = await agent.verifyAgreementV2(signed);

    expect(report.valid).to.equal(true);
    expect(report.expectedStatus).to.equal('final');
    expect(report.signerCount).to.equal(1);
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

    expect(notarized.agreementSignatures[0].role).to.equal('notary');
  });

  it('auto-merges transcript-only branches', function () {
    const { agent, agentId } = ephemeral();
    const base = createAgreement(agent, agentId);
    const left = apply(agent, base, {
      type: 'appendTranscript',
      entry: documentRef(agent, 'left transcript'),
    });
    const right = apply(agent, base, {
      type: 'appendTranscript',
      entry: documentRef(agent, 'right transcript'),
    });

    const analysis = agent.detectAgreementV2BranchConflictSync(base, left, right);
    expect(analysis.sameDocument).to.equal(true);
    expect(analysis.sameParent).to.equal(true);
    expect(analysis.autoMergeable).to.equal(true);

    const merged = JSON.parse(agent.mergeAgreementV2TranscriptBranchesSync(base, left, right));
    expect(merged.transcript).to.have.length(2);
  });

  it('resolves terms conflicts with an explicit successor mutation', function () {
    const { agent, agentId } = ephemeral();
    const base = createAgreement(agent, agentId);
    const left = apply(agent, base, { type: 'updateTerms', terms: 'Left branch terms.' });
    const right = apply(agent, base, { type: 'updateTerms', terms: 'Right branch terms.' });

    const analysis = agent.detectAgreementV2BranchConflictSync(base, left, right);
    expect(analysis.autoMergeable).to.equal(false);
    expect(analysis.conflictFields).to.include('terms');

    const resolved = JSON.parse(
      agent.resolveAgreementV2BranchConflictSync(
        base,
        left,
        right,
        JSON.stringify({ type: 'updateTerms', terms: 'Resolved terms.' }),
      ),
    );
    const rightDoc = JSON.parse(right);

    expect(resolved.terms).to.equal('Resolved terms.');
    expect(resolved.links[0]).to.deep.equal({
      jacsId: rightDoc.jacsId,
      jacsVersion: rightDoc.jacsVersion,
    });
  });
});
