/**
 * JACS A2A (Agent-to-Agent) Protocol Integration for Node.js
 * 
 * This module provides Node.js bindings for JACS's A2A protocol integration,
 * enabling JACS agents to participate in Google's Agent-to-Agent communication protocol.
 */

const { v4: uuidv4 } = require('uuid');
const jacs = require('./index');

/**
 * A2A protocol version
 */
const A2A_PROTOCOL_VERSION = '1.0';

/**
 * JACS extension URI for A2A
 */
const JACS_EXTENSION_URI = 'urn:hai.ai:jacs-provenance-v1';

/**
 * A2A Skill representation
 */
class A2ASkill {
  constructor(name, description, endpoint, inputSchema = null, outputSchema = null) {
    this.name = name;
    this.description = description;
    this.endpoint = endpoint;
    this.input_schema = inputSchema;
    this.output_schema = outputSchema;
  }
}

/**
 * A2A Security Scheme
 */
class A2ASecurityScheme {
  constructor(type, scheme, bearerFormat = null) {
    this.type = type;
    this.scheme = scheme;
    if (bearerFormat) {
      this.bearer_format = bearerFormat;
    }
  }
}

/**
 * A2A Extension
 */
class A2AExtension {
  constructor(uri, description, required, params) {
    this.uri = uri;
    this.description = description;
    this.required = required;
    this.params = params;
  }
}

/**
 * A2A Capabilities
 */
class A2ACapabilities {
  constructor(extensions = null) {
    if (extensions) {
      this.extensions = extensions;
    }
  }
}

/**
 * A2A Agent Card
 */
class A2AAgentCard {
  constructor({
    protocolVersion,
    url,
    name,
    description,
    skills,
    securitySchemes,
    capabilities,
    metadata = null
  }) {
    this.protocolVersion = protocolVersion;
    this.url = url;
    this.name = name;
    this.description = description;
    this.skills = skills;
    this.securitySchemes = securitySchemes;
    this.capabilities = capabilities;
    if (metadata) {
      this.metadata = metadata;
    }
  }
}

/**
 * JACS A2A Integration class
 */
class JACSA2AIntegration {
  constructor(jacsConfigPath = null) {
    if (jacsConfigPath) {
      jacs.load(jacsConfigPath);
    }
  }

  /**
   * Export a JACS agent as an A2A Agent Card
   * @param {Object} agentData - JACS agent data
   * @returns {A2AAgentCard} A2A Agent Card
   */
  exportAgentCard(agentData) {
    // Extract agent information
    const agentId = agentData.jacsId || 'unknown';
    const agentName = agentData.jacsName || 'Unnamed JACS Agent';
    const agentDescription = agentData.jacsDescription || 'JACS-enabled agent';

    // Convert JACS services to A2A skills
    const skills = this._convertServicesToSkills(agentData.jacsServices || []);

    // Create security schemes
    const securitySchemes = [
      new A2ASecurityScheme('http', 'bearer', 'JWT'),
      new A2ASecurityScheme('apiKey', 'X-API-Key')
    ];

    // Create JACS extension
    const jacsExtension = new A2AExtension(
      JACS_EXTENSION_URI,
      'JACS cryptographic document signing and verification',
      false,
      {
        jacsDescriptorUrl: `https://agent-${agentId}.example.com/.well-known/jacs-agent.json`,
        signatureType: 'JACS_PQC',
        supportedAlgorithms: ['dilithium', 'rsa', 'ecdsa'],
        verificationEndpoint: '/jacs/verify',
        signatureEndpoint: '/jacs/sign',
        publicKeyEndpoint: '/.well-known/jacs-pubkey.json'
      }
    );

    const capabilities = new A2ACapabilities([jacsExtension]);

    // Create metadata
    const metadata = {
      jacsAgentType: agentData.jacsAgentType,
      jacsId: agentId,
      jacsVersion: agentData.jacsVersion
    };

    // Create Agent Card
    return new A2AAgentCard({
      protocolVersion: A2A_PROTOCOL_VERSION,
      url: `https://agent-${agentId}.example.com`,
      name: agentName,
      description: agentDescription,
      skills,
      securitySchemes,
      capabilities,
      metadata
    });
  }

  /**
   * Convert JACS services to A2A skills
   * @private
   */
  _convertServicesToSkills(services) {
    const skills = [];

    for (const service of services) {
      const serviceName = service.name || service.serviceDescription || 'unnamed_service';
      const serviceDesc = service.serviceDescription || 'No description';

      // Convert tools to skills
      const tools = service.tools || [];
      if (tools.length > 0) {
        for (const tool of tools) {
          if (tool.function) {
            const skill = new A2ASkill(
              tool.function.name || serviceName,
              tool.function.description || serviceDesc,
              tool.url || '/api/tool',
              tool.function.parameters || null,
              null // JACS doesn't define output schemas
            );
            skills.push(skill);
          }
        }
      } else {
        // Create a skill for the service itself
        const skill = new A2ASkill(
          serviceName,
          serviceDesc,
          `/api/service/${serviceName.toLowerCase().replace(/\s+/g, '_')}`
        );
        skills.push(skill);
      }
    }

    // Add default verification skill if none exist
    if (skills.length === 0) {
      skills.push(new A2ASkill(
        'verify_signature',
        'Verify JACS document signatures',
        '/jacs/verify',
        {
          type: 'object',
          properties: {
            document: {
              type: 'object',
              description: 'The JACS document to verify'
            }
          },
          required: ['document']
        },
        {
          type: 'object',
          properties: {
            valid: {
              type: 'boolean',
              description: 'Whether the signature is valid'
            },
            signerInfo: {
              type: 'object',
              description: 'Information about the signer'
            }
          }
        }
      ));
    }

    return skills;
  }

  /**
   * Create JACS extension descriptor for A2A
   * @returns {Object} Extension descriptor
   */
  createExtensionDescriptor() {
    return {
      uri: JACS_EXTENSION_URI,
      name: 'JACS Document Provenance',
      version: '1.0',
      description: 'Provides cryptographic document signing and verification with post-quantum support',
      specification: 'https://hai.ai/jacs/specs/a2a-extension',
      capabilities: {
        documentSigning: {
          description: 'Sign documents with JACS signatures',
          algorithms: ['dilithium', 'falcon', 'sphincs+', 'rsa', 'ecdsa'],
          formats: ['jacs-v1', 'jws-detached']
        },
        documentVerification: {
          description: 'Verify JACS signatures on documents',
          offlineCapable: true,
          chainOfCustody: true
        },
        postQuantumCrypto: {
          description: 'Support for quantum-resistant signatures',
          algorithms: ['dilithium', 'falcon', 'sphincs+']
        }
      },
      endpoints: {
        sign: {
          path: '/jacs/sign',
          method: 'POST',
          description: 'Sign a document with JACS'
        },
        verify: {
          path: '/jacs/verify',
          method: 'POST',
          description: 'Verify a JACS signature'
        },
        publicKey: {
          path: '/.well-known/jacs-pubkey.json',
          method: 'GET',
          description: "Retrieve agent's public key"
        }
      }
    };
  }

  /**
   * Wrap an A2A artifact with JACS provenance signature
   * @param {Object} artifact - The A2A artifact to wrap
   * @param {string} artifactType - Type of artifact (e.g., "task", "message")
   * @param {Array} parentSignatures - Optional parent signatures for chain of custody
   * @returns {Object} JACS-wrapped artifact with signature
   */
  wrapArtifactWithProvenance(artifact, artifactType, parentSignatures = null) {
    // Create JACS header
    const wrapped = {
      jacsId: uuidv4(),
      jacsVersion: uuidv4(),
      jacsType: `a2a-${artifactType}`,
      jacsLevel: 'artifact',
      jacsVersionDate: new Date().toISOString(),
      $schema: 'https://hai.ai/schemas/header/v1/header.schema.json',
      a2aArtifact: artifact
    };

    // Add parent signatures if provided
    if (parentSignatures) {
      wrapped.jacsParentSignatures = parentSignatures;
    }

    // Sign with JACS
    return jacs.signRequest(wrapped);
  }

  /**
   * Verify a JACS-wrapped A2A artifact
   * @param {Object} wrappedArtifact - The wrapped artifact to verify
   * @returns {Object} Verification result
   */
  verifyWrappedArtifact(wrappedArtifact) {
    // Verify JACS signature
    const isValid = jacs.verifyRequest(wrappedArtifact);

    // Extract signature info
    const signatureInfo = wrappedArtifact.jacsSignature || {};

    const result = {
      valid: isValid,
      signerId: signatureInfo.agentID || 'unknown',
      signerVersion: signatureInfo.agentVersion || 'unknown',
      artifactType: wrappedArtifact.jacsType || 'unknown',
      timestamp: wrappedArtifact.jacsVersionDate || '',
      originalArtifact: wrappedArtifact.a2aArtifact || {}
    };

    // Check parent signatures if present
    if (wrappedArtifact.jacsParentSignatures) {
      result.parentSignaturesCount = wrappedArtifact.jacsParentSignatures.length;
      // In a full implementation, we would verify each parent
      result.parentSignaturesValid = true;
    }

    return result;
  }

  /**
   * Create a chain of custody document for multi-agent workflows
   * @param {Array} artifacts - List of JACS-wrapped artifacts
   * @returns {Object} Chain of custody document
   */
  createChainOfCustody(artifacts) {
    const chain = [];

    for (const artifact of artifacts) {
      if (artifact.jacsSignature) {
        const entry = {
          artifactId: artifact.jacsId,
          artifactType: artifact.jacsType,
          timestamp: artifact.jacsVersionDate,
          agentId: artifact.jacsSignature.agentID,
          agentVersion: artifact.jacsSignature.agentVersion,
          signatureHash: artifact.jacsSignature.publicKeyHash
        };
        chain.push(entry);
      }
    }

    return {
      chainOfCustody: chain,
      created: new Date().toISOString(),
      totalArtifacts: chain.length
    };
  }

  /**
   * Generate .well-known documents for A2A integration
   * @param {A2AAgentCard} agentCard - The A2A Agent Card
   * @param {string} jwsSignature - JWS signature of the Agent Card
   * @param {string} publicKeyB64 - Base64-encoded public key
   * @param {Object} agentData - JACS agent data
   * @returns {Object} Map of paths to document contents
   */
  generateWellKnownDocuments(agentCard, jwsSignature, publicKeyB64, agentData) {
    const documents = {};

    // 1. Agent Card (signed)
    documents['/.well-known/agent.json'] = {
      agentCard: agentCard,
      signature: jwsSignature,
      signatureFormat: 'JWS',
      timestamp: new Date().toISOString()
    };

    // 2. JACS Agent Descriptor
    documents['/.well-known/jacs-agent.json'] = {
      jacsVersion: '1.0',
      agentId: agentData.jacsId,
      agentVersion: agentData.jacsVersion,
      agentType: agentData.jacsAgentType,
      publicKeyHash: jacs.hashPublicKey(Buffer.from(publicKeyB64, 'base64')),
      keyAlgorithm: agentData.keyAlgorithm || 'RSA-PSS',
      capabilities: {
        signing: true,
        verification: true,
        postQuantum: false // Update based on algorithm
      },
      schemas: {
        agent: 'https://hai.ai/schemas/agent/v1/agent.schema.json',
        header: 'https://hai.ai/schemas/header/v1/header.schema.json',
        signature: 'https://hai.ai/schemas/components/signature/v1/signature.schema.json'
      },
      endpoints: {
        verify: '/jacs/verify',
        sign: '/jacs/sign',
        agent: '/jacs/agent'
      }
    };

    // 3. JACS Public Key
    documents['/.well-known/jacs-pubkey.json'] = {
      publicKey: publicKeyB64,
      publicKeyHash: jacs.hashPublicKey(Buffer.from(publicKeyB64, 'base64')),
      algorithm: agentData.keyAlgorithm || 'RSA-PSS',
      agentId: agentData.jacsId,
      agentVersion: agentData.jacsVersion,
      timestamp: new Date().toISOString()
    };

    // 4. Extension descriptor
    documents['/.well-known/jacs-extension.json'] = this.createExtensionDescriptor();

    return documents;
  }
}

// Export classes and functions
module.exports = {
  JACSA2AIntegration,
  A2ASkill,
  A2ASecurityScheme,
  A2AExtension,
  A2ACapabilities,
  A2AAgentCard,
  A2A_PROTOCOL_VERSION,
  JACS_EXTENSION_URI
};
