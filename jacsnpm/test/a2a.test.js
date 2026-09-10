/**
 * Tests for JACS A2A (Agent-to-Agent) Protocol Integration (v0.4.0)
 *
 * Updated for Phase 2: JACSA2AIntegration now accepts a JacsClient instance.
 * wrapArtifactWithProvenance and verifyWrappedArtifact are async.
 * Uses canonical native A2A signing and verification entry points.
 * hashString replaced with crypto.createHash('sha256').
 */

const { expect } = require('chai');
const sinon = require('sinon');
const {
  JACSA2AIntegration,
  A2AAgentSkill,
  A2AAgentExtension,
  A2AAgentCapabilities,
  A2AAgentCard,
  A2AAgentInterface,
  A2AAgentCardSignature,
  A2A_PROTOCOL_VERSION,
  JACS_EXTENSION_URI,
  JACS_ALGORITHMS,
  TRUST_POLICIES,
} = require('../src/a2a');
const {
  configureNativeGenerator,
  configureNativeArtifactSigner,
  configureCanonicalArtifactVerifier,
} = require('./helpers/a2a-bound');

/**
 * Create a mock JacsClient with a mock _agent.
 */
function createMockClient() {
  const agent = configureNativeGenerator({
    signRequest: sinon.stub(),
    signArtifactSync: sinon.stub(),
    verifyResponse: sinon.stub(),
    verifyA2aArtifactSync: sinon.stub(),
    verifyA2aArtifactWithPolicySync: sinon.stub(),
  }, { agentId: 'mock-agent-id', name: 'mock-agent' });
  configureNativeArtifactSigner(agent, { agentId: 'mock-agent-id' });
  configureCanonicalArtifactVerifier(agent);
  return {
    _agent: agent,
    agentId: 'mock-agent-id',
    name: 'mock-agent',
  };
}

describe('JACS A2A Integration (v0.4.0)', () => {
  let a2aIntegration;
  let mockClient;
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
    mockClient = createMockClient();
    a2aIntegration = new JACSA2AIntegration(mockClient);
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('exportAgentCard', () => {
    it('should export JACS agent to A2A Agent Card (v0.4.0)', () => {
      const agentData = {
        jacsId: 'test-agent-123',
        jacsVersion: 'v1.0.0',
        jacsName: 'Test Agent',
        jacsDescription: 'A test agent for A2A integration',
        jacsAgentType: 'ai',
        skills: [{
          id: 'test-function',
          name: 'test_function',
          description: 'A test function',
          tags: ['jacs', 'test'],
        }]
      };

      const agentCard = a2aIntegration.exportAgentCard(agentData);

      // Verify v0.4.0 properties
      expect(agentCard.protocolVersions).to.deep.equal(['0.4.0']);
      expect(agentCard.name).to.equal('Test Agent');
      expect(agentCard.description).to.equal('A test agent for A2A integration');
      expect(agentCard.version).to.equal('v1.0.0');

      // Verify supported interfaces (replaces top-level url)
      expect(agentCard.supportedInterfaces).to.have.lengthOf(1);
      expect(agentCard.supportedInterfaces[0].url).to.equal('https://agent-test-agent-123.example.com');
      expect(agentCard.supportedInterfaces[0].protocolBinding).to.equal('jsonrpc');

      // Verify default I/O modes
      expect(agentCard.defaultInputModes).to.include('text/plain');
      expect(agentCard.defaultOutputModes).to.include('application/json');

      // Verify skills have v0.4.0 fields (id, tags, no endpoint/schemas)
      expect(agentCard.skills).to.have.lengthOf(1);
      const skill = agentCard.skills[0];
      expect(skill.name).to.equal('test_function');
      expect(skill.description).to.equal('A test function');
      expect(skill.id).to.equal('test-function');
      expect(skill.tags).to.be.an('array');
      expect(skill.tags).to.include('jacs');

      // Verify security schemes as keyed map (v0.4.0)
      expect(agentCard.securitySchemes).to.be.an('object');
      expect(agentCard.securitySchemes).to.have.property('bearer-jwt');
      expect(agentCard.securitySchemes).to.have.property('api-key');
      expect(agentCard.securitySchemes['bearer-jwt'].type).to.equal('http');
      expect(agentCard.securitySchemes['api-key'].type).to.equal('apiKey');

      // Verify JACS extension (no params in v0.4.0)
      expect(agentCard.capabilities.extensions).to.have.lengthOf(1);
      const extension = agentCard.capabilities.extensions[0];
      expect(extension.uri).to.equal(JACS_EXTENSION_URI);
      expect(extension.required).to.be.false;

      // Verify metadata
      expect(agentCard.metadata).to.exist;
      expect(agentCard.metadata.jacsId).to.equal('test-agent-123');
      expect(agentCard.metadata.jacsVersion).to.equal('v1.0.0');
    });

    it('should handle minimal agent without services', () => {
      const minimalAgent = {
        jacsId: 'minimal-agent',
        jacsAgentType: 'ai'
      };

      const agentCard = a2aIntegration.exportAgentCard(minimalAgent);

      // Should have default verification skill with v0.4.0 fields
      expect(agentCard.skills).to.have.lengthOf(1);
      expect(agentCard.skills[0].name).to.equal('verify_signature');
      expect(agentCard.skills[0].id).to.equal('verify-signature');
      expect(agentCard.skills[0].tags).to.be.an('array');
    });
  });

  describe('_normalizeA2ASkills', () => {
    it('should normalize explicit A2A skills (v0.4.0)', () => {
      const rawSkills = [
        {
          id: 'tool1',
          name: 'tool1',
          description: 'Tool 1',
          tags: ['jacs', 'tool1'],
        },
        {
          name: 'Tool 2',
          description: 'Tool 2',
        }
      ];

      const skills = a2aIntegration._normalizeA2ASkills(rawSkills);

      expect(skills).to.have.lengthOf(2);
      expect(skills[0].name).to.equal('tool1');
      expect(skills[0].id).to.equal('tool1');
      expect(skills[1].name).to.equal('Tool 2');
      expect(skills[1].id).to.equal('tool-2');

      // All skills should have tags
      for (const skill of skills) {
        expect(skill.tags).to.be.an('array');
        expect(skill.tags).to.include('jacs');
      }
    });
  });

  describe('createExtensionDescriptor', () => {
    it('should create JACS extension descriptor', () => {
      const descriptor = a2aIntegration.createExtensionDescriptor();

      expect(descriptor.uri).to.equal(JACS_EXTENSION_URI);
      expect(descriptor.name).to.equal('JACS Document Provenance');
      expect(descriptor.version).to.equal('1.0');
      expect(descriptor.a2aProtocolVersion).to.equal('0.4.0');

      // Verify capabilities use correct JACS_ALGORITHMS
      expect(descriptor.capabilities).to.have.all.keys('documentSigning', 'documentVerification', 'postQuantumCrypto');
      expect(descriptor.capabilities.documentSigning.algorithms).to.deep.equal(JACS_ALGORITHMS);
      expect(descriptor.capabilities.postQuantumCrypto.algorithms).to.deep.equal(['pq2025']);

      // Verify endpoints
      expect(descriptor.endpoints).to.have.all.keys('sign', 'verify', 'publicKey');
      expect(descriptor.endpoints.sign.path).to.equal('/jacs/sign');
      expect(descriptor.endpoints.verify.path).to.equal('/jacs/verify');
    });
  });

  describe('wrapArtifactWithProvenance', () => {
    it('should wrap A2A artifact with JACS provenance (async)', async () => {
      const artifact = {
        taskId: 'task-123',
        operation: 'test',
        data: { key: 'value' }
      };

      const wrapped = await a2aIntegration.wrapArtifactWithProvenance(artifact, 'task');

      expect(wrapped.jacsType).to.equal('a2a-task');
      expect(wrapped.a2aArtifact).to.deep.equal(artifact);
      expect(wrapped.jacsSignature).to.exist;
      expect(mockClient._agent.signArtifactSync.calledOnce).to.be.true;
      expect(mockClient._agent.signRequest.called).to.be.false;
    });

    it('should include parent signatures when provided', async () => {
      const artifact = { step: 'step2' };
      const parentSig = { jacsId: 'parent-123', jacsSignature: { agentID: 'parent-agent' } };

      const wrapped = await a2aIntegration.wrapArtifactWithProvenance(artifact, 'workflow-step', [parentSig]);

      expect(wrapped.jacsParentSignatures).to.exist;
      expect(wrapped.jacsParentSignatures).to.deep.equal([parentSig]);
    });
  });

  describe('verifyWrappedArtifact', () => {
    it('should verify JACS-wrapped artifact (async)', async () => {
      const wrappedArtifact = {
        jacsId: 'artifact-123',
        jacsType: 'a2a-task',
        jacsVersionDate: '2024-01-15T10:00:00Z',
        a2aArtifact: { data: 'test' },
        jacsSignature: {
          agentID: 'signer-agent',
          agentVersion: 'v1.0',
          publicKeyHash: 'abc123'
        }
      };

      mockClient._agent.verifyResponse.returns(true);
      a2aIntegration.trustPolicy = TRUST_POLICIES.OPEN;

      const result = await a2aIntegration.verifyWrappedArtifact(wrappedArtifact);

      expect(result.valid).to.be.true;
      expect(typeof result.valid).to.equal('boolean');
      expect(result.signerId).to.equal('signer-agent');
      expect(result.signerVersion).to.equal('v1.0');
      expect(result.artifactType).to.equal('a2a-task');
      expect(result.timestamp).to.equal('2024-01-15T10:00:00Z');
      expect(result.originalArtifact).to.deep.equal({ data: 'test' });
      expect(mockClient._agent.verifyA2aArtifactSync.calledOnce).to.equal(true);
      expect(mockClient._agent.verifyResponse.called).to.be.false;
      const arg = mockClient._agent.verifyA2aArtifactSync.firstCall.args[0];
      expect(typeof arg).to.equal('string');
    });

    it('should reject non-canonical object results from legacy verifyResponse', async () => {
      const wrappedArtifact = {
        jacsId: 'artifact-obj-verify',
        jacsType: 'a2a-task',
        jacsVersionDate: '2024-01-15T10:00:00Z',
        a2aArtifact: { data: 'test' },
        jacsSignature: {
          agentID: 'signer-agent',
          agentVersion: 'v1.0',
        },
      };

      const nativeResult = { payload: { ok: true, source: 'native' } };
      delete mockClient._agent.verifyA2aArtifactSync;
      delete mockClient._agent.verifyA2aArtifactWithPolicySync;
      mockClient._agent.verifyResponse.returns(nativeResult);
      a2aIntegration.trustPolicy = TRUST_POLICIES.OPEN;

      const result = await a2aIntegration.verifyWrappedArtifact(wrappedArtifact);

      expect(result.valid).to.equal(false);
      expect(typeof result.valid).to.equal('boolean');
      expect(result.verifiedPayload).to.equal(undefined);
      expect(result.verificationResult).to.not.deep.equal(nativeResult);
      expect(result.signerId).to.equal('');
      expect(result.signerVersion).to.equal('');
      expect(result.artifactType).to.equal('');
      expect(result.timestamp).to.equal('');
      expect(result.originalArtifact).to.deep.equal({});
      expect(mockClient._agent.verifyResponse.called).to.be.false;
    });

    it('should handle artifacts with parent signatures', async () => {
      const wrappedArtifact = {
        jacsId: 'child-artifact',
        jacsType: 'a2a-task',
        jacsVersionDate: '2024-01-15T10:00:00Z',
        jacsSignature: { agentID: 'agent', agentVersion: 'v1' },
        jacsParentSignatures: [
          {
            jacsId: 'p1',
            jacsType: 'a2a-task',
            jacsVersionDate: '2024-01-15T09:00:00Z',
            jacsSignature: { agentID: 'a1', agentVersion: 'v1' },
            a2aArtifact: {},
          },
          {
            jacsId: 'p2',
            jacsType: 'a2a-task',
            jacsVersionDate: '2024-01-15T09:30:00Z',
            jacsSignature: { agentID: 'a2', agentVersion: 'v1' },
            a2aArtifact: {},
          }
        ],
        a2aArtifact: {}
      };

      mockClient._agent.verifyResponse.returns(true);
      a2aIntegration.trustPolicy = TRUST_POLICIES.OPEN;

      const result = await a2aIntegration.verifyWrappedArtifact(wrappedArtifact);

      expect(result.parentSignaturesCount).to.equal(2);
      expect(result.parentSignaturesValid).to.be.true;
    });
  });

  describe('createChainOfCustody', () => {
    it('should create chain of custody document', () => {
      const artifacts = [
        {
          jacsId: 'step1',
          jacsType: 'workflow-step',
          jacsVersionDate: '2024-01-15T10:00:00Z',
          jacsSignature: {
            agentID: 'agent1',
            agentVersion: 'v1',
            publicKeyHash: 'hash1'
          }
        },
        {
          jacsId: 'step2',
          jacsType: 'workflow-step',
          jacsVersionDate: '2024-01-15T10:01:00Z',
          jacsSignature: {
            agentID: 'agent2',
            agentVersion: 'v1',
            publicKeyHash: 'hash2'
          }
        }
      ];

      const chain = a2aIntegration.createChainOfCustody(artifacts);

      expect(chain.chainOfCustody).to.exist;
      expect(chain.created).to.exist;
      expect(chain.totalArtifacts).to.equal(2);

      const custody = chain.chainOfCustody;
      expect(custody).to.have.lengthOf(2);
      expect(custody[0].artifactId).to.equal('step1');
      expect(custody[0].agentId).to.equal('agent1');
      expect(custody[1].artifactId).to.equal('step2');
      expect(custody[1].agentId).to.equal('agent2');
    });
  });

  describe('generateWellKnownDocuments', () => {
    it('should generate all well-known documents (v0.4.0)', () => {
      const agentCard = new A2AAgentCard({
        name: 'Test',
        description: 'Test',
        version: '1.0.0',
        protocolVersions: ['0.4.0'],
        supportedInterfaces: [
          new A2AAgentInterface('https://example.com', 'jsonrpc')
        ],
        defaultInputModes: ['text/plain'],
        defaultOutputModes: ['text/plain'],
        capabilities: new A2AAgentCapabilities(),
        skills: []
      });

      const agentData = {
        jacsId: 'agent-123',
        jacsVersion: 'v1',
        jacsAgentType: 'ai',
        keyAlgorithm: 'ring-Ed25519'
      };

      const documents = a2aIntegration.generateWellKnownDocuments(
        agentCard,
        'mock-jws-signature',
        'bW9jay1wdWJsaWMta2V5',
        agentData
      );

      // Verify v0.4.0 well-known path (agent-card.json, not agent.json)
      expect(documents).to.have.all.keys(
        '/.well-known/agent-card.json',
        '/.well-known/jwks.json',
        '/.well-known/jacs-compat-binding.json',
        '/.well-known/jacs-agent.json',
        '/.well-known/jacs-pubkey.json',
        '/.well-known/jacs-extension.json'
      );

      // Caller-provided signatures cannot replace the native bound card.
      const agentDoc = documents['/.well-known/agent-card.json'];
      expect(agentDoc.signatures).to.exist;
      expect(agentDoc.signatures[0].jws).to.equal('native-es256-jws');

      // Native descriptors and compatibility binding are preserved.
      const jacsDesc = documents['/.well-known/jacs-agent.json'];
      expect(jacsDesc.agentId).to.equal('mock-agent-id');
      expect(jacsDesc.keyAlgorithm).to.equal('pq2025');
      expect(documents['/.well-known/jacs-compat-binding.json'].jacsSha256)
        .to.equal('binding-hash');

      // Verify JWKS is present for A2A verifiers
      const jwksDoc = documents['/.well-known/jwks.json'];
      expect(jwksDoc).to.have.property('keys');
      expect(jwksDoc.keys).to.be.an('array');
    });
  });
});

describe('A2A v0.4.0 Data Classes', () => {
  it('should create A2AAgentSkill instance (v0.4.0)', () => {
    const skill = new A2AAgentSkill({
      id: 'test-skill',
      name: 'test_skill',
      description: 'A test skill',
      tags: ['jacs', 'test'],
      examples: ['Example usage'],
      inputModes: ['application/json'],
      outputModes: ['application/json'],
    });

    expect(skill.id).to.equal('test-skill');
    expect(skill.name).to.equal('test_skill');
    expect(skill.description).to.equal('A test skill');
    expect(skill.tags).to.deep.equal(['jacs', 'test']);
    expect(skill.examples).to.deep.equal(['Example usage']);
    expect(skill.inputModes).to.deep.equal(['application/json']);
    expect(skill.outputModes).to.deep.equal(['application/json']);
  });

  it('should create A2AAgentExtension instance (v0.4.0 - no params)', () => {
    const extension = new A2AAgentExtension(
      'test:extension',
      'Test extension',
      true
    );

    expect(extension.uri).to.equal('test:extension');
    expect(extension.description).to.equal('Test extension');
    expect(extension.required).to.be.true;
  });

  it('should create A2AAgentCard instance (v0.4.0)', () => {
    const agentCard = new A2AAgentCard({
      name: 'Test Agent',
      description: 'Test description',
      version: '1.0.0',
      protocolVersions: ['0.4.0'],
      supportedInterfaces: [
        new A2AAgentInterface('https://example.com', 'jsonrpc')
      ],
      defaultInputModes: ['text/plain'],
      defaultOutputModes: ['text/plain'],
      capabilities: new A2AAgentCapabilities(),
      skills: [],
      metadata: { version: '1.0' }
    });

    expect(agentCard.name).to.equal('Test Agent');
    expect(agentCard.protocolVersions).to.deep.equal(['0.4.0']);
    expect(agentCard.supportedInterfaces).to.have.lengthOf(1);
    expect(agentCard.supportedInterfaces[0].url).to.equal('https://example.com');
    expect(agentCard.metadata.version).to.equal('1.0');
  });

  it('should create A2AAgentInterface instance', () => {
    const iface = new A2AAgentInterface('https://example.com', 'jsonrpc', 'tenant-123');

    expect(iface.url).to.equal('https://example.com');
    expect(iface.protocolBinding).to.equal('jsonrpc');
    expect(iface.tenant).to.equal('tenant-123');
  });

  it('should create A2AAgentCardSignature instance', () => {
    const sig = new A2AAgentCardSignature('eyJhbGciOiJSUzI1NiJ9.payload.signature', 'key-123');

    expect(sig.jws).to.equal('eyJhbGciOiJSUzI1NiJ9.payload.signature');
    expect(sig.keyId).to.equal('key-123');
  });

  it('should create A2AAgentCapabilities instance (v0.4.0)', () => {
    const caps = new A2AAgentCapabilities({
      streaming: true,
      pushNotifications: false,
      extendedAgentCard: true,
      extensions: [new A2AAgentExtension('test:ext', 'Test')]
    });

    expect(caps.streaming).to.be.true;
    expect(caps.pushNotifications).to.be.false;
    expect(caps.extendedAgentCard).to.be.true;
    expect(caps.extensions).to.have.lengthOf(1);
  });
});
