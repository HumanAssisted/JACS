/**
 * Tests for JACS A2A (Agent-to-Agent) Protocol Integration
 */

const { expect } = require('chai');
const sinon = require('sinon');
const {
  JACSA2AIntegration,
  A2ASkill,
  A2ASecurityScheme,
  A2AExtension,
  A2ACapabilities,
  A2AAgentCard,
  A2A_PROTOCOL_VERSION,
  JACS_EXTENSION_URI
} = require('../src/a2a');
const jacs = require('../src/index');

describe('JACS A2A Integration', () => {
  let a2aIntegration;
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
    a2aIntegration = new JACSA2AIntegration();
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('exportAgentCard', () => {
    it('should export JACS agent to A2A Agent Card', () => {
      const agentData = {
        jacsId: 'test-agent-123',
        jacsVersion: 'v1.0.0',
        jacsName: 'Test Agent',
        jacsDescription: 'A test agent for A2A integration',
        jacsAgentType: 'ai',
        jacsServices: [{
          name: 'Test Service',
          serviceDescription: 'A test service',
          successDescription: 'Service completed successfully',
          failureDescription: 'Service failed',
          tools: [{
            url: '/api/test',
            function: {
              name: 'test_function',
              description: 'A test function',
              parameters: {
                type: 'object',
                properties: {
                  input: { type: 'string' }
                },
                required: ['input']
              }
            }
          }]
        }]
      };

      const agentCard = a2aIntegration.exportAgentCard(agentData);

      // Verify basic properties
      expect(agentCard.protocolVersion).to.equal('1.0');
      expect(agentCard.name).to.equal('Test Agent');
      expect(agentCard.description).to.equal('A test agent for A2A integration');
      expect(agentCard.url).to.equal('https://agent-test-agent-123.example.com');

      // Verify skills
      expect(agentCard.skills).to.have.lengthOf(1);
      const skill = agentCard.skills[0];
      expect(skill.name).to.equal('test_function');
      expect(skill.description).to.equal('A test function');
      expect(skill.endpoint).to.equal('/api/test');
      expect(skill.input_schema).to.exist;

      // Verify security schemes
      expect(agentCard.securitySchemes).to.have.lengthOf(2);
      expect(agentCard.securitySchemes[0].type).to.equal('http');
      expect(agentCard.securitySchemes[0].scheme).to.equal('bearer');
      expect(agentCard.securitySchemes[1].type).to.equal('apiKey');

      // Verify JACS extension
      expect(agentCard.capabilities.extensions).to.have.lengthOf(1);
      const extension = agentCard.capabilities.extensions[0];
      expect(extension.uri).to.equal(JACS_EXTENSION_URI);
      expect(extension.required).to.be.false;
      expect(extension.params.supportedAlgorithms).to.include.members(['dilithium', 'rsa', 'ecdsa']);

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

      // Should have default verification skill
      expect(agentCard.skills).to.have.lengthOf(1);
      expect(agentCard.skills[0].name).to.equal('verify_signature');
      expect(agentCard.skills[0].endpoint).to.equal('/jacs/verify');
    });
  });

  describe('_convertServicesToSkills', () => {
    it('should convert multiple services with tools to skills', () => {
      const services = [
        {
          name: 'Service 1',
          serviceDescription: 'First service',
          tools: [{
            url: '/api/tool1',
            function: {
              name: 'tool1',
              description: 'Tool 1'
            }
          }, {
            url: '/api/tool2',
            function: {
              name: 'tool2',
              description: 'Tool 2'
            }
          }]
        },
        {
          name: 'Service 2',
          serviceDescription: 'Second service without tools'
        }
      ];

      const skills = a2aIntegration._convertServicesToSkills(services);

      expect(skills).to.have.lengthOf(3); // 2 tools + 1 service
      expect(skills[0].name).to.equal('tool1');
      expect(skills[1].name).to.equal('tool2');
      expect(skills[2].name).to.equal('Service 2');
      expect(skills[2].endpoint).to.equal('/api/service/service_2');
    });
  });

  describe('createExtensionDescriptor', () => {
    it('should create JACS extension descriptor', () => {
      const descriptor = a2aIntegration.createExtensionDescriptor();

      expect(descriptor.uri).to.equal(JACS_EXTENSION_URI);
      expect(descriptor.name).to.equal('JACS Document Provenance');
      expect(descriptor.version).to.equal('1.0');

      // Verify capabilities
      expect(descriptor.capabilities).to.have.all.keys('documentSigning', 'documentVerification', 'postQuantumCrypto');
      expect(descriptor.capabilities.documentSigning.algorithms).to.include.members(['dilithium', 'rsa', 'ecdsa']);
      expect(descriptor.capabilities.postQuantumCrypto.algorithms).to.include.members(['dilithium', 'falcon', 'sphincs+']);

      // Verify endpoints
      expect(descriptor.endpoints).to.have.all.keys('sign', 'verify', 'publicKey');
      expect(descriptor.endpoints.sign.path).to.equal('/jacs/sign');
      expect(descriptor.endpoints.verify.path).to.equal('/jacs/verify');
    });
  });

  describe('wrapArtifactWithProvenance', () => {
    it('should wrap A2A artifact with JACS provenance', () => {
      const artifact = {
        taskId: 'task-123',
        operation: 'test',
        data: { key: 'value' }
      };

      // Mock jacs.signRequest
      const signedResult = {
        jacsId: 'wrapped-123',
        jacsVersion: 'v1',
        jacsType: 'a2a-task',
        a2aArtifact: artifact,
        jacsSignature: {
          agentID: 'test-agent',
          signature: 'mock-signature'
        }
      };
      sandbox.stub(jacs, 'signRequest').returns(signedResult);

      const wrapped = a2aIntegration.wrapArtifactWithProvenance(artifact, 'task');

      expect(wrapped.jacsType).to.equal('a2a-task');
      expect(wrapped.a2aArtifact).to.deep.equal(artifact);
      expect(wrapped.jacsSignature).to.exist;
      expect(jacs.signRequest.calledOnce).to.be.true;
    });

    it('should include parent signatures when provided', () => {
      const artifact = { step: 'step2' };
      const parentSig = { jacsId: 'parent-123', jacsSignature: { agentID: 'parent-agent' } };

      const signedResult = {
        jacsId: 'wrapped-456',
        a2aArtifact: artifact,
        jacsParentSignatures: [parentSig],
        jacsSignature: { agentID: 'test-agent' }
      };
      sandbox.stub(jacs, 'signRequest').returns(signedResult);

      const wrapped = a2aIntegration.wrapArtifactWithProvenance(artifact, 'workflow-step', [parentSig]);

      expect(wrapped.jacsParentSignatures).to.exist;
      expect(wrapped.jacsParentSignatures).to.deep.equal([parentSig]);
    });
  });

  describe('verifyWrappedArtifact', () => {
    it('should verify JACS-wrapped artifact', () => {
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

      sandbox.stub(jacs, 'verifyRequest').returns(true);

      const result = a2aIntegration.verifyWrappedArtifact(wrappedArtifact);

      expect(result.valid).to.be.true;
      expect(result.signerId).to.equal('signer-agent');
      expect(result.signerVersion).to.equal('v1.0');
      expect(result.artifactType).to.equal('a2a-task');
      expect(result.timestamp).to.equal('2024-01-15T10:00:00Z');
      expect(result.originalArtifact).to.deep.equal({ data: 'test' });
      expect(jacs.verifyRequest.calledWith(wrappedArtifact)).to.be.true;
    });

    it('should handle artifacts with parent signatures', () => {
      const wrappedArtifact = {
        jacsSignature: { agentID: 'agent' },
        jacsParentSignatures: [{ sig: 1 }, { sig: 2 }],
        a2aArtifact: {}
      };

      sandbox.stub(jacs, 'verifyRequest').returns(true);

      const result = a2aIntegration.verifyWrappedArtifact(wrappedArtifact);

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
    it('should generate all well-known documents', () => {
      const agentCard = new A2AAgentCard({
        protocolVersion: '1.0',
        url: 'https://example.com',
        name: 'Test',
        description: 'Test',
        skills: [],
        securitySchemes: [],
        capabilities: new A2ACapabilities()
      });

      const agentData = {
        jacsId: 'agent-123',
        jacsVersion: 'v1',
        jacsAgentType: 'ai',
        keyAlgorithm: 'RSA-PSS'
      };

      sandbox.stub(jacs, 'hashPublicKey').returns('mocked-hash');

      const documents = a2aIntegration.generateWellKnownDocuments(
        agentCard,
        'mock-jws-signature',
        'mock-public-key-b64',
        agentData
      );

      // Verify all required documents are generated
      expect(documents).to.have.all.keys(
        '/.well-known/agent.json',
        '/.well-known/jacs-agent.json',
        '/.well-known/jacs-pubkey.json',
        '/.well-known/jacs-extension.json'
      );

      // Verify agent card document
      const agentDoc = documents['/.well-known/agent.json'];
      expect(agentDoc.agentCard).to.equal(agentCard);
      expect(agentDoc.signature).to.equal('mock-jws-signature');
      expect(agentDoc.signatureFormat).to.equal('JWS');

      // Verify JACS descriptor
      const jacsDesc = documents['/.well-known/jacs-agent.json'];
      expect(jacsDesc.agentId).to.equal('agent-123');
      expect(jacsDesc.keyAlgorithm).to.equal('RSA-PSS');
      expect(jacsDesc.publicKeyHash).to.equal('mocked-hash');

      // Verify public key document
      const pubkeyDoc = documents['/.well-known/jacs-pubkey.json'];
      expect(pubkeyDoc.publicKey).to.equal('mock-public-key-b64');
      expect(pubkeyDoc.algorithm).to.equal('RSA-PSS');
    });
  });
});

describe('A2A Data Classes', () => {
  it('should create A2ASkill instance', () => {
    const skill = new A2ASkill(
      'test_skill',
      'A test skill',
      '/api/test',
      { type: 'object' },
      { type: 'object' }
    );

    expect(skill.name).to.equal('test_skill');
    expect(skill.description).to.equal('A test skill');
    expect(skill.endpoint).to.equal('/api/test');
    expect(skill.input_schema).to.exist;
    expect(skill.output_schema).to.exist;
  });

  it('should create A2ASecurityScheme instance', () => {
    const scheme = new A2ASecurityScheme('http', 'bearer', 'JWT');

    expect(scheme.type).to.equal('http');
    expect(scheme.scheme).to.equal('bearer');
    expect(scheme.bearer_format).to.equal('JWT');
  });

  it('should create A2AExtension instance', () => {
    const extension = new A2AExtension(
      'test:extension',
      'Test extension',
      true,
      { param1: 'value1' }
    );

    expect(extension.uri).to.equal('test:extension');
    expect(extension.required).to.be.true;
    expect(extension.params.param1).to.equal('value1');
  });

  it('should create A2AAgentCard instance', () => {
    const agentCard = new A2AAgentCard({
      protocolVersion: '1.0',
      url: 'https://example.com',
      name: 'Test Agent',
      description: 'Test description',
      skills: [],
      securitySchemes: [],
      capabilities: new A2ACapabilities(),
      metadata: { version: '1.0' }
    });

    expect(agentCard.protocolVersion).to.equal('1.0');
    expect(agentCard.name).to.equal('Test Agent');
    expect(agentCard.metadata.version).to.equal('1.0');
  });
});
