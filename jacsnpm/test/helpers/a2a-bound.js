function boundWellKnownPairs(options = {}) {
  const agentId = options.agentId || 'test-agent-id';
  const name = options.name || 'test-agent';
  const skills = options.skills || [];
  const interfaceUrl = options.interfaceUrl || 'https://agent.example.com/agent';
  const keyAlgorithm = options.keyAlgorithm || 'pq2025';
  const kid = 'compat-kid';
  const bindingHash = 'binding-hash';
  const documents = {
    '/.well-known/agent-card.json': {
      name,
      description: `JACS agent ${name}`,
      version: '1',
      protocolVersions: ['0.4.0'],
      supportedInterfaces: [{ url: interfaceUrl, protocolBinding: 'jsonrpc' }],
      skills,
      metadata: {
        jacsId: agentId,
        jacsVersion: '1',
        jacsCompatKid: kid,
        jacsCompatBindingHash: bindingHash,
        jacsCompatBindingPath: '/.well-known/jacs-compat-binding.json',
      },
      capabilities: {
        streaming: false,
        extensions: [{ uri: 'urn:jacs:provenance-v1', required: false }],
      },
      signatures: [{ keyId: kid, jws: 'native-es256-jws' }],
    },
    '/.well-known/jwks.json': {
      keys: [{ kid, alg: 'ES256', use: 'sig' }],
    },
    '/.well-known/jacs-compat-binding.json': {
      jacsSha256: bindingHash,
      jacsSignature: { agentID: agentId, signingAlgorithm: keyAlgorithm },
    },
    '/.well-known/jacs-agent.json': {
      agentId,
      agentVersion: '1',
      keyAlgorithm,
      publicKeyHash: options.publicKeyHash || 'native-public-key-hash',
      capabilities: {
        signing: true,
        verification: true,
        verificationAlgorithms: ['ring-Ed25519', 'pq2025'],
        postQuantum: keyAlgorithm === 'pq2025',
      },
      schemas: {
        agent: 'https://jacs.sh/schemas/agent/v1/agent.schema.json',
        header: 'https://jacs.sh/schemas/header/v1/header.schema.json',
        signature: 'https://jacs.sh/schemas/components/signature/v1/signature.schema.json',
      },
    },
    '/.well-known/jacs-pubkey.json': {
      agentId,
      algorithm: keyAlgorithm,
      publicKeyHash: options.publicKeyHash || 'native-public-key-hash',
    },
    '/.well-known/jacs-extension.json': {
      uri: 'urn:jacs:provenance-v1',
      capabilities: {
        documentSigning: { signingAlgorithm: keyAlgorithm },
        documentVerification: {
          algorithms: ['ring-Ed25519', 'pq2025'],
          offlineCapable: true,
        },
        postQuantumCrypto: { algorithms: ['pq2025'] },
      },
    },
  };
  return Object.entries(documents).map(([path, document]) => ({ path, document }));
}

function configureNativeGenerator(agent, options = {}) {
  agent.generateWellKnownDocumentsSync = () => JSON.stringify(boundWellKnownPairs(options));
  return agent;
}

function cardHasJacsExtension(card) {
  return Array.isArray(card?.capabilities?.extensions)
    && card.capabilities.extensions.some((extension) => extension?.uri === 'urn:jacs:provenance-v1');
}

function canonicalAssessment(card, policy = 'verified', trustedAgentIds = []) {
  const normalizedPolicy = String(policy).toLowerCase();
  const agentId = typeof card?.metadata?.jacsId === 'string' ? card.metadata.jacsId : null;
  const jacsRegistered = cardHasJacsExtension(card);
  const explicitlyTrusted = jacsRegistered && agentId !== null && trustedAgentIds.includes(agentId);
  const allowed = normalizedPolicy === 'open'
    || (normalizedPolicy === 'verified' && jacsRegistered)
    || (normalizedPolicy === 'strict' && explicitlyTrusted);
  const trustLevel = allowed && explicitlyTrusted
    ? 'ExplicitlyTrusted'
    : allowed && jacsRegistered
      ? 'JacsVerified'
      : 'Untrusted';
  const reason = normalizedPolicy === 'open'
    ? 'Open policy: all agents are allowed'
    : !jacsRegistered
      ? `${normalizedPolicy === 'strict' ? 'Strict' : 'Verified'} policy: agent does not declare JACS extension`
      : normalizedPolicy === 'strict' && !explicitlyTrusted
        ? 'Strict policy: native identity is not explicitly trusted'
        : 'Verified policy: native Agent Card binding verified';

  return {
    allowed,
    trustLevel,
    jacsRegistered,
    reason,
    policy: normalizedPolicy[0].toUpperCase() + normalizedPolicy.slice(1),
    agentId,
    firstContact: false,
  };
}

function configureNativeAssessor(agent, options = {}) {
  const trustedAgentIds = options.trustedAgentIds || [];
  const assess = (cardJson, policy) => JSON.stringify(
    canonicalAssessment(JSON.parse(cardJson), policy, trustedAgentIds),
  );
  agent.assessA2aAgentSync = assess;
  agent.assessA2aAgent = async (cardJson, policy) => assess(cardJson, policy);
  return agent;
}

function canonicalArtifactResult(wrapped, policy, agentCard, trustedAgentIds = []) {
  const parents = Array.isArray(wrapped.jacsParentSignatures) ? wrapped.jacsParentSignatures : [];
  const parentVerificationResults = parents.map((parent, index) => ({
    index,
    artifactId: parent.jacsId || '',
    signerId: parent.jacsSignature?.agentID || '',
    status: 'Verified',
    verified: true,
  }));
  const result = {
    status: 'Verified',
    valid: true,
    signerId: wrapped.jacsSignature?.agentID || '',
    signerVersion: wrapped.jacsSignature?.agentVersion || '',
    artifactType: wrapped.jacsType || '',
    timestamp: wrapped.jacsVersionDate || '',
    parentSignaturesValid: parentVerificationResults.every((parent) => parent.verified === true),
    parentVerificationResults,
    originalArtifact: wrapped.a2aArtifact || {},
  };
  if (policy) {
    const trustAssessment = canonicalAssessment(agentCard, policy, trustedAgentIds);
    result.trustLevel = trustAssessment.trustLevel;
    result.trustAssessment = trustAssessment;
  }
  return result;
}

function configureCanonicalArtifactVerifier(agent, options = {}) {
  const trustedAgentIds = options.trustedAgentIds || [];
  const verifyCanonical = (wrappedJson) => JSON.stringify(
    canonicalArtifactResult(JSON.parse(wrappedJson)),
  );
  const verifyWithPolicy = (wrappedJson, cardJson, policy) => JSON.stringify(
    canonicalArtifactResult(
      JSON.parse(wrappedJson),
      policy,
      JSON.parse(cardJson),
      trustedAgentIds,
    ),
  );
  if (agent.verifyA2aArtifactSync && typeof agent.verifyA2aArtifactSync.callsFake === 'function') {
    agent.verifyA2aArtifactSync.callsFake(verifyCanonical);
  } else {
    agent.verifyA2aArtifactSync = verifyCanonical;
  }
  if (
    agent.verifyA2aArtifactWithPolicySync
    && typeof agent.verifyA2aArtifactWithPolicySync.callsFake === 'function'
  ) {
    agent.verifyA2aArtifactWithPolicySync.callsFake(verifyWithPolicy);
  } else {
    agent.verifyA2aArtifactWithPolicySync = verifyWithPolicy;
  }
  return agent;
}

function configureNativeArtifactSigner(agent, options = {}) {
  const agentId = options.agentId || 'test-agent-id';
  const implementation = (artifactJson, artifactType, parentsJson) => JSON.stringify({
    jacsId: `${agentId}-artifact`,
    jacsVersion: '1',
    jacsType: `a2a-${artifactType}`,
    jacsVersionDate: '2026-07-10T00:00:00Z',
    a2aArtifact: JSON.parse(artifactJson),
    ...(parentsJson ? { jacsParentSignatures: JSON.parse(parentsJson) } : {}),
    jacsSignature: {
      agentID: agentId,
      agentVersion: '1',
      date: '2026-07-10T00:00:00Z',
      publicKeyHash: 'native-public-key-hash',
      signature: 'native-proof',
      signatureContentVersion: 'jacs-signature-v2',
    },
  });
  if (agent.signArtifactSync && typeof agent.signArtifactSync.callsFake === 'function') {
    agent.signArtifactSync.callsFake(implementation);
  } else {
    agent.signArtifactSync = implementation;
  }
  return agent;
}

module.exports = {
  boundWellKnownPairs,
  configureNativeGenerator,
  canonicalAssessment,
  configureNativeAssessor,
  configureCanonicalArtifactVerifier,
  configureNativeArtifactSigner,
};
