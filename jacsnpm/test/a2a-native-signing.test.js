const { expect } = require('chai');
const sinon = require('sinon');
const { JACSA2AIntegration } = require('../a2a.js');

function nativeArtifact(artifact, artifactType, parents = null) {
  return {
    jacsId: 'native-artifact-id',
    jacsVersion: 'native-version',
    jacsType: `a2a-${artifactType}`,
    jacsVersionDate: '2026-07-10T00:00:00Z',
    a2aArtifact: artifact,
    ...(parents ? { jacsParentSignatures: parents } : {}),
    jacsSignature: {
      agentID: 'native-agent',
      agentVersion: '1',
      date: '2026-07-10T00:00:00Z',
      publicKeyHash: 'sha256-native-public-key',
      signature: 'proof',
      signatureContentVersion: 'jacs-signature-v2',
    },
  };
}

function clientWithNativeSigner() {
  const agent = {
    signRequest: sinon.stub().throws(new Error('generic signRequest must not be used')),
    signArtifactSync: sinon.stub().callsFake((artifactJson, artifactType, parentsJson) => {
      return JSON.stringify(nativeArtifact(
        JSON.parse(artifactJson),
        artifactType,
        parentsJson ? JSON.parse(parentsJson) : null,
      ));
    }),
  };
  return { client: { _agent: agent, agentId: 'native-agent', name: 'Native' }, agent };
}

describe('A2A native artifact signing boundary', () => {
  it('uses only native signArtifactSync and returns the direct canonical document', async () => {
    const { client, agent } = clientWithNativeSigner();
    const integration = new JACSA2AIntegration(client);
    const artifact = { action: 'approve' };

    const signed = await integration.signArtifact(artifact, 'task');

    expect(agent.signRequest.called).to.equal(false);
    expect(agent.signArtifactSync.calledOnce).to.equal(true);
    expect(agent.signArtifactSync.firstCall.args).to.deep.equal([
      JSON.stringify(artifact), 'task', null,
    ]);
    expect(signed.jacsType).to.equal('a2a-task');
    expect(signed.a2aArtifact).to.deep.equal(artifact);
    expect(signed.jacsSignature.agentID).to.equal('native-agent');
    expect(signed).to.not.have.property('jacs_payload');
  });

  it('passes parent documents through the native canonical signer', async () => {
    const { client, agent } = clientWithNativeSigner();
    const parent = nativeArtifact({ step: 1 }, 'task');

    const signed = await new JACSA2AIntegration(client)
      .signArtifact({ step: 2 }, 'task', [parent]);

    expect(agent.signArtifactSync.firstCall.args[2]).to.equal(JSON.stringify([parent]));
    expect(signed.jacsParentSignatures).to.deep.equal([parent]);
  });

  for (const injectedParents of [
    [nativeArtifact({ injected: true }, 'task')],
    null,
  ]) {
    it(`rejects native parent injection when caller requested none: ${JSON.stringify(injectedParents)}`, async () => {
      const { client, agent } = clientWithNativeSigner();
      const returned = nativeArtifact({ step: 1 }, 'task');
      returned.jacsParentSignatures = injectedParents;
      agent.signArtifactSync.returns(JSON.stringify(returned));

      let error;
      try {
        await new JACSA2AIntegration(client).signArtifact({ step: 1 }, 'task');
      } catch (err) {
        error = err;
      }

      expect(error).to.be.an('error');
      expect(error.message).to.match(/parent chain/i);
    });
  }

  it('allows an absent or empty returned parent chain only when caller requested none', async () => {
    const { client, agent } = clientWithNativeSigner();
    const returned = nativeArtifact({ step: 1 }, 'task');
    returned.jacsParentSignatures = [];
    agent.signArtifactSync.returns(JSON.stringify(returned));

    const signed = await new JACSA2AIntegration(client).signArtifact({ step: 1 }, 'task');
    expect(signed.jacsParentSignatures).to.deep.equal([]);
  });

  for (const mutation of ['drop', 'reorder', 'change', 'append']) {
    it(`rejects a native parent-chain ${mutation} mutation`, async () => {
      const { client, agent } = clientWithNativeSigner();
      const first = nativeArtifact({ step: 1 }, 'task');
      const second = nativeArtifact({ step: 2 }, 'task');
      const returnedParents = JSON.parse(JSON.stringify([first, second]));
      const returned = nativeArtifact({ step: 3 }, 'task', returnedParents);
      if (mutation === 'drop') delete returned.jacsParentSignatures;
      if (mutation === 'reorder') returned.jacsParentSignatures = [second, first];
      if (mutation === 'change') returned.jacsParentSignatures[0].a2aArtifact = { changed: true };
      if (mutation === 'append') {
        returned.jacsParentSignatures.push(nativeArtifact({ injected: true }, 'task'));
      }
      agent.signArtifactSync.returns(JSON.stringify(returned));

      let error;
      try {
        await new JACSA2AIntegration(client)
          .signArtifact({ step: 3 }, 'task', [first, second]);
      } catch (err) {
        error = err;
      }

      expect(error).to.be.an('error');
      expect(error.message).to.match(/parent chain/i);
    });
  }

  for (const missingField of [
    'jacsId',
    'jacsVersion',
    'jacsSignature.signatureContentVersion',
    'jacsSignature.signature',
    'jacsSignature.agentID',
    'jacsSignature.agentVersion',
    'jacsSignature.publicKeyHash',
    'jacsSignature.date',
  ]) {
    it(`rejects native signing output missing portable v2 field ${missingField}`, async () => {
      const { client, agent } = clientWithNativeSigner();
      const returned = nativeArtifact({}, 'task');
      if (missingField.startsWith('jacsSignature.')) {
        delete returned.jacsSignature[missingField.slice('jacsSignature.'.length)];
      } else {
        delete returned[missingField];
      }
      agent.signArtifactSync.returns(JSON.stringify(returned));

      let error;
      try {
        await new JACSA2AIntegration(client).signArtifact({}, 'task');
      } catch (err) {
        error = err;
      }

      expect(error).to.be.an('error');
      expect(error.message).to.match(/portable v2 signature metadata/i);
    });
  }

  it('fails closed when the native signer is unavailable', async () => {
    const integration = new JACSA2AIntegration({
      _agent: { signRequest: sinon.stub() }, agentId: 'legacy', name: 'Legacy',
    });
    let error;
    try {
      await integration.signArtifact({ action: 'approve' }, 'task');
    } catch (err) {
      error = err;
    }
    expect(error).to.be.an('error');
    expect(error.message).to.match(/native signArtifactSync.*required/i);
  });

  for (const malformed of [
    '',
    'not-json',
    '{"jacsType":"a2a-task"}',
    '{"jacsType":"a2a-other","a2aArtifact":{},"jacsSignature":{}}',
  ]) {
    it(`rejects malformed native signing output ${JSON.stringify(malformed)}`, async () => {
      const { client, agent } = clientWithNativeSigner();
      agent.signArtifactSync.returns(malformed);
      let error;
      try {
        await new JACSA2AIntegration(client).signArtifact({}, 'task');
      } catch (err) {
        error = err;
      }
      expect(error).to.be.an('error');
      expect(error.message).to.match(/native A2A signing|canonical|JSON|signature/i);
    });
  }

  it('rejects non-object and cyclic artifacts before calling native code', async () => {
    const { client, agent } = clientWithNativeSigner();
    const cyclic = {};
    cyclic.self = cyclic;

    for (const artifact of [null, [], cyclic, { nonFinite: Number.NaN }]) {
      let error;
      try {
        await new JACSA2AIntegration(client).signArtifact(artifact, 'task');
      } catch (err) {
        error = err;
      }
      expect(error).to.be.an('error');
    }
    expect(agent.signArtifactSync.called).to.equal(false);
  });
});
