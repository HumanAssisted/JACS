const { expect } = require('chai');
const sinon = require('sinon');
const {
  JACSA2AIntegration,
  TRUST_POLICIES,
} = require('../src/a2a');

function wrappedArtifact({ parents = [] } = {}) {
  const wrapped = {
    jacsId: 'artifact-fail-closed',
    jacsVersion: 'artifact-version-1',
    jacsType: 'a2a-task',
    jacsVersionDate: '2026-07-10T00:00:00Z',
    a2aArtifact: { action: 'verify' },
    jacsSignature: {
      agentID: 'remote-agent',
      agentVersion: 'remote-version-1',
    },
  };
  if (parents.length > 0) wrapped.jacsParentSignatures = parents;
  return wrapped;
}

function identityBoundCard(agentId = 'remote-agent') {
  return {
    name: 'Remote Agent',
    description: 'Identity-bound remote Agent Card used for trust-policy verification',
    version: '1',
    protocolVersions: ['0.4.0'],
    supportedInterfaces: [{ url: 'https://remote.example/a2a', protocolBinding: 'jsonrpc' }],
    capabilities: { extensions: [{ uri: 'urn:jacs:provenance-v1', required: false }] },
    skills: [],
    metadata: { jacsId: agentId, jacsVersion: 'remote-version-1' },
  };
}

function legacyClient(rawResult) {
  return {
    _agent: {
      verifyResponse: sinon.stub().returns(rawResult),
    },
    agentId: 'local-agent',
    name: 'local-agent',
  };
}

function allowedTrustAssessment(policy) {
  return {
    allowed: true,
    trustLevel: policy === 'Strict' ? 'ExplicitlyTrusted' : 'JacsVerified',
    jacsRegistered: true,
    reason: `${policy} native trust accepted`,
    policy,
    agentId: 'remote-agent',
    firstContact: false,
  };
}

function canonicalSuccess(overrides = {}) {
  return {
    valid: true,
    status: 'Verified',
    signerId: 'remote-agent',
    signerVersion: 'remote-version-1',
    artifactType: 'a2a-task',
    timestamp: '2026-07-10T00:00:00Z',
    originalArtifact: { action: 'verify' },
    parentSignaturesValid: true,
    parentVerificationResults: [],
    trustAssessment: allowedTrustAssessment('Verified'),
    ...overrides,
  };
}

function policyClient(canonicalResult) {
  return {
    _agent: {
      verifyA2aArtifactWithPolicySync: sinon.stub().returns(JSON.stringify(canonicalResult)),
    },
    agentId: 'local-agent',
    name: 'local-agent',
  };
}

describe('A2A artifact verification fail-closed boundaries', () => {
  for (const [label, rawResult] of [
    ['literal true', true],
    ['empty object', {}],
    ['object with valid false', { valid: false }],
    ['object with valid true', { valid: true }],
    ['truthy string', 'true'],
  ]) {
    it(`rejects a legacy verifyResponse ${label}`, async () => {
      const client = legacyClient(rawResult);
      const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);

      const result = await integration.verifyWrappedArtifact(wrappedArtifact());

      expect(result.valid).to.equal(false);
      expect(result.status).to.have.property('Invalid');
      expect(result.status.Invalid.reason).to.include('canonical native');
      expect(result.signerId).to.equal('');
      expect(result.signerVersion).to.equal('');
      expect(result.artifactType).to.equal('');
      expect(result.timestamp).to.equal('');
      expect(result.originalArtifact).to.deep.equal({});
      expect(result.parentSignaturesValid).to.equal(false);
      expect(result).to.not.have.property('trustAssessment');
      expect(result).to.not.have.property('trustLevel');
      expect(client._agent.verifyResponse.called).to.equal(false);
    });
  }

  it('does not elevate open-policy trust when only legacy verification exists', async () => {
    const client = legacyClient(true);
    const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);

    const result = await integration.verifyWrappedArtifact(
      wrappedArtifact(),
      identityBoundCard(),
    );

    expect(result.valid).to.equal(false);
    expect(result.signerId).to.equal('');
    expect(result.originalArtifact).to.deep.equal({});
    expect(result.trustAssessment.allowed).to.equal(false);
    expect(result.trustAssessment.trustLevel).to.equal('Untrusted');
    expect(result.trustAssessment.reason).to.include('cannot elevate trust');
    expect(client._agent.verifyResponse.called).to.equal(false);
  });

  it('requires canonical valid to be the literal boolean true', async () => {
    const client = {
      _agent: {
        verifyA2aArtifactSync: sinon.stub().returns(JSON.stringify({
          valid: 'true',
          status: 'Verified',
          parentSignaturesValid: true,
          parentVerificationResults: [],
        })),
      },
      agentId: 'local-agent',
      name: 'local-agent',
    };
    const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);

    const result = await integration.verifyWrappedArtifact(wrappedArtifact());

    expect(result.valid).to.equal(false);
    expect(result.status).to.have.property('Invalid');
  });

  it('requires canonical parentSignaturesValid to be the literal boolean true', async () => {
    const client = {
      _agent: {
        verifyA2aArtifactSync: sinon.stub().returns(JSON.stringify({
          valid: true,
          status: 'Verified',
          parentSignaturesValid: 'true',
          parentVerificationResults: [],
        })),
      },
      agentId: 'local-agent',
      name: 'local-agent',
    };
    const integration = new JACSA2AIntegration(client, TRUST_POLICIES.OPEN);

    const result = await integration.verifyWrappedArtifact(wrappedArtifact());

    expect(result.valid).to.equal(false);
    expect(result.parentSignaturesValid).to.equal(false);
    expect(result.status).to.have.property('Invalid');
  });

  it('rejects canonical success when the parent aggregate is missing', async () => {
    const canonical = canonicalSuccess();
    delete canonical.parentSignaturesValid;
    const integration = new JACSA2AIntegration(
      policyClient(canonical),
      TRUST_POLICIES.VERIFIED,
    );

    const result = await integration.verifyWrappedArtifact(
      wrappedArtifact(),
      identityBoundCard(),
    );

    expect(result.valid).to.equal(false);
    expect(result.parentSignaturesValid).to.equal(false);
    expect(result.status).to.have.property('Invalid');
  });

  for (const policy of [TRUST_POLICIES.VERIFIED, TRUST_POLICIES.STRICT]) {
    it(`${policy} rejects when the canonical policy verifier is unavailable`, async () => {
      const client = legacyClient(true);
      const integration = new JACSA2AIntegration(client, policy);

      const result = await integration.verifyWrappedArtifact(
        wrappedArtifact(),
        identityBoundCard(),
      );

      expect(result.valid).to.equal(false);
      expect(result.trustAssessment).to.exist;
      expect(result.trustAssessment.allowed).to.equal(false);
      expect(result.trustAssessment.reason).to.include('canonical native A2A verification');
      expect(client._agent.verifyResponse.called).to.equal(false);
    });
  }

  it('rejects a parent result whose verified flag is missing', async () => {
    const parent = {
      jacsId: 'parent-artifact',
      jacsType: 'a2a-task',
      a2aArtifact: { parent: true },
      jacsSignature: { agentID: 'parent-agent', agentVersion: 'parent-version' },
    };
    const client = {
      _agent: {
        verifyA2aArtifactWithPolicySync: sinon.stub().returns(JSON.stringify({
          valid: true,
          status: 'Verified',
          signerId: 'remote-agent',
          signerVersion: 'remote-version-1',
          artifactType: 'a2a-task',
          timestamp: '2026-07-10T00:00:00Z',
          originalArtifact: { action: 'verify' },
          parentSignaturesValid: true,
          parentVerificationResults: [{
            index: 0,
            artifactId: 'parent-artifact',
            signerId: 'parent-agent',
            status: 'Verified',
            // Deliberately omit verified. Missing evidence must not default true.
          }],
          trustAssessment: allowedTrustAssessment('Verified'),
        })),
      },
      agentId: 'local-agent',
      name: 'local-agent',
    };
    const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

    const result = await integration.verifyWrappedArtifact(
      wrappedArtifact({ parents: [parent] }),
      identityBoundCard(),
    );

    expect(result.valid).to.equal(false);
    expect(result.parentSignaturesValid).to.equal(false);
    expect(result.parentVerificationResults).to.have.length(1);
    expect(result.parentVerificationResults[0].verified).to.equal(false);
    expect(result.status).to.have.property('Invalid');
  });

  for (const [field, expectedFailureValue] of [
    ['signerId', ''],
    ['signerVersion', ''],
    ['artifactType', ''],
    ['timestamp', ''],
    ['originalArtifact', {}],
  ]) {
    it(`rejects canonical success missing authenticated ${field} without raw fallback`, async () => {
      const canonical = canonicalSuccess();
      delete canonical[field];
      const integration = new JACSA2AIntegration(
        policyClient(canonical),
        TRUST_POLICIES.VERIFIED,
      );

      const result = await integration.verifyWrappedArtifact(
        wrappedArtifact(),
        identityBoundCard(),
      );

      expect(result.valid).to.equal(false);
      expect(result.status).to.have.property('Invalid');
      expect(result[field]).to.deep.equal(expectedFailureValue);
    });
  }

  for (const allowed of [false, 'true']) {
    it(`rejects canonical success when trustAssessment.allowed is ${JSON.stringify(allowed)}`, async () => {
      const canonical = canonicalSuccess({
        trustAssessment: {
          ...allowedTrustAssessment('Verified'),
          allowed,
        },
      });
      const integration = new JACSA2AIntegration(
        policyClient(canonical),
        TRUST_POLICIES.VERIFIED,
      );

      const result = await integration.verifyWrappedArtifact(
        wrappedArtifact(),
        identityBoundCard(),
      );

      expect(result.valid).to.equal(false);
      expect(result.trustAssessment.allowed).to.equal(false);
      expect(result.status).to.have.property('Invalid');
    });
  }

  it('cannot report ExplicitlyTrusted or in-store when trust allowed is false', async () => {
    const canonical = canonicalSuccess({
      trustAssessment: {
        ...allowedTrustAssessment('Strict'),
        allowed: false,
        trustLevel: 'ExplicitlyTrusted',
      },
    });
    const integration = new JACSA2AIntegration(
      policyClient(canonical),
      TRUST_POLICIES.STRICT,
    );

    const result = await integration.verifyWrappedArtifact(
      wrappedArtifact(),
      identityBoundCard(),
    );

    expect(result.valid).to.equal(false);
    expect(result.trustLevel).to.equal('Untrusted');
    expect(result.trustAssessment.allowed).to.equal(false);
    expect(result.trustAssessment.trustLevel).to.equal('Untrusted');
    expect(result.trustAssessment.inTrustStore).to.equal(false);
    expect(result.status).to.have.property('Invalid');
  });

  it('rejects a malformed truthy trustAssessment instead of bypassing policy synthesis', async () => {
    const canonical = canonicalSuccess({ trustAssessment: 'allowed' });
    const integration = new JACSA2AIntegration(
      policyClient(canonical),
      TRUST_POLICIES.VERIFIED,
    );

    const result = await integration.verifyWrappedArtifact(
      wrappedArtifact(),
      identityBoundCard(),
    );

    expect(result.valid).to.equal(false);
    expect(result.trustAssessment.allowed).to.equal(false);
    expect(result.status).to.have.property('Invalid');
  });

  for (const [label, parentSignaturesValid, parentResult] of [
    [
      'aggregate true but parent verified false',
      true,
      { status: 'Verified', verified: false },
    ],
    [
      'aggregate false but parent verified true',
      false,
      { status: 'Verified', verified: true },
    ],
    [
      'parent verified true but status invalid',
      true,
      { status: { Invalid: { reason: 'bad parent signature' } }, verified: true },
    ],
  ]) {
    it(`rejects contradictory parent evidence: ${label}`, async () => {
      const parent = {
        jacsId: 'parent-artifact',
        jacsType: 'a2a-task',
        a2aArtifact: { parent: true },
        jacsSignature: { agentID: 'parent-agent', agentVersion: 'parent-version' },
      };
      const canonical = canonicalSuccess({
        parentSignaturesValid,
        parentVerificationResults: [{
          index: 0,
          artifactId: 'parent-artifact',
          signerId: 'parent-agent',
          ...parentResult,
        }],
      });
      const integration = new JACSA2AIntegration(
        policyClient(canonical),
        TRUST_POLICIES.VERIFIED,
      );

      const result = await integration.verifyWrappedArtifact(
        wrappedArtifact({ parents: [parent] }),
        identityBoundCard(),
      );

      expect(result.valid).to.equal(false);
      expect(result.parentSignaturesValid).to.equal(false);
      expect(result.status).to.have.property('Invalid');
    });
  }

  it('accepts a complete canonical native result with literal true flags', async () => {
    const client = {
      _agent: {
        verifyA2aArtifactWithPolicySync: sinon.stub().returns(JSON.stringify({
          valid: true,
          status: 'Verified',
          signerId: 'remote-agent',
          signerVersion: 'remote-version-1',
          artifactType: 'a2a-task',
          timestamp: '2026-07-10T00:00:00Z',
          originalArtifact: { action: 'verify' },
          parentSignaturesValid: true,
          parentVerificationResults: [],
          trustAssessment: allowedTrustAssessment('Verified'),
        })),
      },
      agentId: 'local-agent',
      name: 'local-agent',
    };
    const integration = new JACSA2AIntegration(client, TRUST_POLICIES.VERIFIED);

    const result = await integration.verifyWrappedArtifact(
      wrappedArtifact(),
      identityBoundCard(),
    );

    expect(result.valid).to.equal(true);
    expect(result.parentSignaturesValid).to.equal(true);
    expect(result.status).to.equal('Verified');
  });
});
