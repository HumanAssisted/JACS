/**
 * JACS A2A (Agent-to-Agent) Protocol Integration for Node.js
 *
 * This module provides Node.js bindings for JACS's A2A protocol integration,
 * enabling JACS agents to participate in the Agent-to-Agent communication protocol.
 *
 * Implements A2A protocol v0.4.0 (September 2025).
 */

const { v4: uuidv4 } = require('uuid');
const { createPublicKey } = require('crypto');
const jacs = require('../index');

/**
 * A2A protocol version (v0.4.0)
 */
const A2A_PROTOCOL_VERSION = '0.4.0';

/**
 * JACS extension URI for A2A
 */
const JACS_EXTENSION_URI = 'urn:hai.ai:jacs-provenance-v1';

/**
 * A2A Agent Interface (v0.4.0)
 */
class A2AAgentInterface {
  constructor(url, protocolBinding, tenant = null) {
    this.url = url;
    this.protocolBinding = protocolBinding;
    if (tenant) {
      this.tenant = tenant;
    }
  }
}

/**
 * A2A Agent Skill (v0.4.0)
 */
class A2AAgentSkill {
  constructor({ id, name, description, tags, examples = null, inputModes = null, outputModes = null, security = null }) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.tags = tags;
    if (examples) this.examples = examples;
    if (inputModes) this.inputModes = inputModes;
    if (outputModes) this.outputModes = outputModes;
    if (security) this.security = security;
  }
}

/**
 * A2A Agent Extension (v0.4.0)
 */
class A2AAgentExtension {
  constructor(uri, description = null, required = null) {
    this.uri = uri;
    if (description !== null) this.description = description;
    if (required !== null) this.required = required;
  }
}

/**
 * A2A Agent Capabilities (v0.4.0)
 */
class A2AAgentCapabilities {
  constructor({ streaming = null, pushNotifications = null, extendedAgentCard = null, extensions = null } = {}) {
    if (streaming !== null) this.streaming = streaming;
    if (pushNotifications !== null) this.pushNotifications = pushNotifications;
    if (extendedAgentCard !== null) this.extendedAgentCard = extendedAgentCard;
    if (extensions) this.extensions = extensions;
  }
}

/**
 * A2A Agent Card Signature (v0.4.0)
 */
class A2AAgentCardSignature {
  constructor(jws, keyId = null) {
    this.jws = jws;
    if (keyId) this.keyId = keyId;
  }
}

/**
 * A2A Agent Card (v0.4.0)
 *
 * Published at /.well-known/agent-card.json for zero-config discovery.
 */
class A2AAgentCard {
  constructor({
    name,
    description,
    version,
    protocolVersions,
    supportedInterfaces,
    defaultInputModes,
    defaultOutputModes,
    capabilities,
    skills,
    provider = null,
    documentationUrl = null,
    iconUrl = null,
    securitySchemes = null,
    security = null,
    signatures = null,
    metadata = null
  }) {
    this.name = name;
    this.description = description;
    this.version = version;
    this.protocolVersions = protocolVersions;
    this.supportedInterfaces = supportedInterfaces;
    this.defaultInputModes = defaultInputModes;
    this.defaultOutputModes = defaultOutputModes;
    this.capabilities = capabilities;
    this.skills = skills;
    if (provider) this.provider = provider;
    if (documentationUrl) this.documentationUrl = documentationUrl;
    if (iconUrl) this.iconUrl = iconUrl;
    if (securitySchemes) this.securitySchemes = securitySchemes;
    if (security) this.security = security;
    if (signatures) this.signatures = signatures;
    if (metadata) this.metadata = metadata;
  }
}

/**
 * JACS A2A Integration class (v0.4.0)
 */
class JACSA2AIntegration {
  constructor(jacsConfigPath = null) {
    if (jacsConfigPath) {
      jacs.load(jacsConfigPath);
    }
  }

  /**
   * Export a JACS agent as an A2A Agent Card (v0.4.0)
   * @param {Object} agentData - JACS agent data
   * @returns {A2AAgentCard} A2A Agent Card
   */
  exportAgentCard(agentData) {
    const agentId = agentData.jacsId || 'unknown';
    const agentName = agentData.jacsName || 'Unnamed JACS Agent';
    const agentDescription = agentData.jacsDescription || 'JACS-enabled agent';
    const agentVersion = agentData.jacsVersion || '1';

    // Build supported interfaces from jacsAgentDomain or agent ID
    const domain = agentData.jacsAgentDomain;
    const baseUrl = domain
      ? `https://${domain}/agent/${agentId}`
      : `https://agent-${agentId}.example.com`;

    const supportedInterfaces = [
      new A2AAgentInterface(baseUrl, 'jsonrpc')
    ];

    // Convert JACS services to A2A skills
    const skills = this._convertServicesToSkills(agentData.jacsServices || []);

    // Define security schemes as a keyed map
    const securitySchemes = {
      'bearer-jwt': {
        type: 'http',
        scheme: 'Bearer',
        bearerFormat: 'JWT'
      },
      'api-key': {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key'
      }
    };

    // Create JACS extension
    const jacsExtension = new A2AAgentExtension(
      JACS_EXTENSION_URI,
      'JACS cryptographic document signing and verification',
      false
    );

    const capabilities = new A2AAgentCapabilities({
      extensions: [jacsExtension]
    });

    // Create metadata
    const metadata = {
      jacsAgentType: agentData.jacsAgentType,
      jacsId: agentId,
      jacsVersion: agentData.jacsVersion
    };

    return new A2AAgentCard({
      name: agentName,
      description: agentDescription,
      version: String(agentVersion),
      protocolVersions: [A2A_PROTOCOL_VERSION],
      supportedInterfaces,
      defaultInputModes: ['text/plain', 'application/json'],
      defaultOutputModes: ['text/plain', 'application/json'],
      capabilities,
      skills,
      securitySchemes,
      metadata
    });
  }

  /**
   * Convert JACS services to A2A skills (v0.4.0)
   * @private
   */
  _convertServicesToSkills(services) {
    const skills = [];

    for (const service of services) {
      const serviceName = service.name || service.serviceDescription || 'unnamed_service';
      const serviceDesc = service.serviceDescription || 'No description';

      const tools = service.tools || [];
      if (tools.length > 0) {
        for (const tool of tools) {
          if (tool.function) {
            const fnName = tool.function.name || serviceName;
            const fnDesc = tool.function.description || serviceDesc;

            skills.push(new A2AAgentSkill({
              id: this._slugify(fnName),
              name: fnName,
              description: fnDesc,
              tags: this._deriveTags(serviceName, fnName),
            }));
          }
        }
      } else {
        skills.push(new A2AAgentSkill({
          id: this._slugify(serviceName),
          name: serviceName,
          description: serviceDesc,
          tags: this._deriveTags(serviceName, serviceName),
        }));
      }
    }

    // Add default verification skill if none exist
    if (skills.length === 0) {
      skills.push(new A2AAgentSkill({
        id: 'verify-signature',
        name: 'verify_signature',
        description: 'Verify JACS document signatures',
        tags: ['jacs', 'verification', 'cryptography'],
        examples: [
          'Verify a signed JACS document',
          'Check document signature integrity'
        ],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
      }));
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
      a2aProtocolVersion: A2A_PROTOCOL_VERSION,
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
    const wrapped = {
      jacsId: uuidv4(),
      jacsVersion: uuidv4(),
      jacsType: `a2a-${artifactType}`,
      jacsLevel: 'artifact',
      jacsVersionDate: new Date().toISOString(),
      $schema: 'https://hai.ai/schemas/header/v1/header.schema.json',
      a2aArtifact: artifact
    };

    if (parentSignatures) {
      wrapped.jacsParentSignatures = parentSignatures;
    }

    return jacs.signRequest(wrapped);
  }

  /**
   * Verify a JACS-wrapped A2A artifact
   * @param {Object} wrappedArtifact - The wrapped artifact to verify
   * @returns {Object} Verification result
   */
  verifyWrappedArtifact(wrappedArtifact) {
    return this._verifyWrappedArtifactInternal(wrappedArtifact, new Set());
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
   * Generate .well-known documents for A2A integration (v0.4.0)
   * @param {A2AAgentCard} agentCard - The A2A Agent Card
   * @param {string} jwsSignature - JWS signature of the Agent Card
   * @param {string} publicKeyB64 - Base64-encoded public key
   * @param {Object} agentData - JACS agent data
   * @returns {Object} Map of paths to document contents
   */
  generateWellKnownDocuments(agentCard, jwsSignature, publicKeyB64, agentData) {
    const documents = {};
    const keyAlgorithm = agentData.keyAlgorithm || 'RSA-PSS';
    const postQuantum = /(pq|dilithium|falcon|sphincs|ml-dsa|pq2025)/i.test(keyAlgorithm);

    // 1. Agent Card with embedded signature (v0.4.0)
    const cardObj = JSON.parse(JSON.stringify(agentCard));
    cardObj.signatures = [{ jws: jwsSignature }];
    documents['/.well-known/agent-card.json'] = cardObj;

    // 2. JWK Set for A2A verifiers
    documents['/.well-known/jwks.json'] = this._buildJwks(publicKeyB64, agentData);

    // 3. JACS Agent Descriptor
    documents['/.well-known/jacs-agent.json'] = {
      jacsVersion: '1.0',
      agentId: agentData.jacsId,
      agentVersion: agentData.jacsVersion,
      agentType: agentData.jacsAgentType,
      publicKeyHash: jacs.hashString(publicKeyB64),
      keyAlgorithm,
      capabilities: {
        signing: true,
        verification: true,
        postQuantum
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

    // 4. JACS Public Key
    documents['/.well-known/jacs-pubkey.json'] = {
      publicKey: publicKeyB64,
      publicKeyHash: jacs.hashString(publicKeyB64),
      algorithm: keyAlgorithm,
      agentId: agentData.jacsId,
      agentVersion: agentData.jacsVersion,
      timestamp: new Date().toISOString()
    };

    // 5. Extension descriptor
    documents['/.well-known/jacs-extension.json'] = this.createExtensionDescriptor();

    return documents;
  }

  /**
   * Internal recursive verifier with cycle protection for parent signature chains.
   * @private
   */
  _verifyWrappedArtifactInternal(wrappedArtifact, visited) {
    const artifactId = wrappedArtifact && wrappedArtifact.jacsId;
    if (artifactId && visited.has(artifactId)) {
      throw new Error(`Cycle detected in parent signature chain at artifact ${artifactId}`);
    }
    if (artifactId) {
      visited.add(artifactId);
    }

    try {
      const isValid = jacs.verifyResponse(wrappedArtifact);
      const signatureInfo = wrappedArtifact.jacsSignature || {};

      const result = {
        valid: isValid,
        signerId: signatureInfo.agentID || 'unknown',
        signerVersion: signatureInfo.agentVersion || 'unknown',
        artifactType: wrappedArtifact.jacsType || 'unknown',
        timestamp: wrappedArtifact.jacsVersionDate || '',
        originalArtifact: wrappedArtifact.a2aArtifact || {}
      };

      const parents = wrappedArtifact.jacsParentSignatures;
      if (Array.isArray(parents) && parents.length > 0) {
        const parentResults = parents.map((parent, index) => {
          try {
            const parentResult = this._verifyWrappedArtifactInternal(parent, visited);
            return {
              index,
              artifactId: parent.jacsId || 'unknown',
              valid: !!parentResult.valid,
              parentSignaturesValid: parentResult.parentSignaturesValid !== false
            };
          } catch (error) {
            return {
              index,
              artifactId: parent && parent.jacsId ? parent.jacsId : 'unknown',
              valid: false,
              parentSignaturesValid: false,
              error: error instanceof Error ? error.message : String(error)
            };
          }
        });

        result.parentSignaturesCount = parentResults.length;
        result.parentVerificationResults = parentResults;
        result.parentSignaturesValid = parentResults.every(
          (entry) => entry.valid && entry.parentSignaturesValid
        );
      }

      return result;
    } finally {
      if (artifactId) {
        visited.delete(artifactId);
      }
    }
  }

  /**
   * Build a JWKS document from a base64-encoded public key.
   * @private
   */
  _buildJwks(publicKeyB64, agentData = {}) {
    if (agentData.jwks && Array.isArray(agentData.jwks.keys)) {
      return agentData.jwks;
    }
    if (agentData.jwk && typeof agentData.jwk === 'object') {
      return { keys: [agentData.jwk] };
    }

    const keyAlgorithm = String(agentData.keyAlgorithm || '').toLowerCase();
    const kid = String(agentData.jacsId || 'jacs-agent');

    try {
      const keyBytes = Buffer.from(publicKeyB64, 'base64');
      if (keyBytes.length === 32) {
        return {
          keys: [{
            kty: 'OKP',
            crv: 'Ed25519',
            x: keyBytes.toString('base64url'),
            kid,
            use: 'sig',
            alg: 'EdDSA'
          }]
        };
      }

      let keyObject;
      try {
        keyObject = createPublicKey({ key: keyBytes, format: 'der', type: 'spki' });
      } catch {
        keyObject = createPublicKey(keyBytes.toString('utf8'));
      }

      const jwk = keyObject.export({ format: 'jwk' });
      const alg = this._inferJwsAlg(keyAlgorithm, jwk);
      return {
        keys: [{
          ...jwk,
          kid,
          use: 'sig',
          ...(alg ? { alg } : {})
        }]
      };
    } catch {
      return { keys: [] };
    }
  }

  /**
   * Infer a JWS `alg` for a generated JWK.
   * @private
   */
  _inferJwsAlg(keyAlgorithm, jwk) {
    if (keyAlgorithm.includes('ring-ed25519') || keyAlgorithm.includes('ed25519')) {
      return 'EdDSA';
    }
    if (keyAlgorithm.includes('rsa')) {
      return 'RS256';
    }
    if (keyAlgorithm.includes('ecdsa') || keyAlgorithm.includes('es256')) {
      return 'ES256';
    }
    if (jwk && jwk.kty === 'RSA') {
      return 'RS256';
    }
    if (jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
      return 'EdDSA';
    }
    if (jwk && jwk.kty === 'EC' && jwk.crv === 'P-256') {
      return 'ES256';
    }
    return undefined;
  }

  /**
   * Convert a name to a URL-friendly slug for skill IDs.
   * @private
   */
  _slugify(name) {
    return name
      .toLowerCase()
      .replace(/[\s_]+/g, '-')
      .replace(/[^a-z0-9-]/g, '');
  }

  /**
   * Derive tags from service/function context.
   * @private
   */
  _deriveTags(serviceName, fnName) {
    const tags = ['jacs'];
    const serviceSlug = this._slugify(serviceName);
    const fnSlug = this._slugify(fnName);
    if (serviceSlug !== fnSlug) {
      tags.push(serviceSlug);
    }
    tags.push(fnSlug);
    return tags;
  }
}

// Export classes and functions
module.exports = {
  JACSA2AIntegration,
  A2AAgentInterface,
  A2AAgentSkill,
  A2AAgentExtension,
  A2AAgentCapabilities,
  A2AAgentCardSignature,
  A2AAgentCard,
  A2A_PROTOCOL_VERSION,
  JACS_EXTENSION_URI
};
