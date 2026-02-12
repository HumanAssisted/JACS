"use strict";
/**
 * JACS A2A (Agent-to-Agent) Protocol Integration for Node.js
 *
 * This module provides Node.js bindings for JACS's A2A protocol integration,
 * enabling JACS agents to participate in the Agent-to-Agent communication protocol.
 *
 * Implements A2A protocol v0.4.0 (September 2025).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.JACSA2AIntegration = exports.A2AAgentCard = exports.A2AAgentCardSignature = exports.A2AAgentCapabilities = exports.A2AAgentExtension = exports.A2AAgentSkill = exports.A2AAgentInterface = exports.DEFAULT_TRUST_POLICY = exports.TRUST_POLICIES = exports.JACS_ALGORITHMS = exports.JACS_EXTENSION_URI = exports.A2A_PROTOCOL_VERSION = void 0;
exports.sha256 = sha256;
const uuid_1 = require("uuid");
const crypto_1 = require("crypto");
// =============================================================================
// Constants
// =============================================================================
exports.A2A_PROTOCOL_VERSION = '0.4.0';
exports.JACS_EXTENSION_URI = 'urn:hai.ai:jacs-provenance-v1';
exports.JACS_ALGORITHMS = [
    'ring-Ed25519',
    'RSA-PSS',
    'pq-dilithium',
    'pq2025',
];
exports.TRUST_POLICIES = {
    OPEN: 'open',
    VERIFIED: 'verified',
    STRICT: 'strict',
};
exports.DEFAULT_TRUST_POLICY = exports.TRUST_POLICIES.VERIFIED;
// =============================================================================
// Utility
// =============================================================================
function sha256(data) {
    return (0, crypto_1.createHash)('sha256').update(data).digest('hex');
}
// =============================================================================
// A2A Data Types (v0.4.0)
// =============================================================================
class A2AAgentInterface {
    constructor(url, protocolBinding, tenant = null) {
        this.url = url;
        this.protocolBinding = protocolBinding;
        if (tenant) {
            this.tenant = tenant;
        }
    }
}
exports.A2AAgentInterface = A2AAgentInterface;
class A2AAgentSkill {
    constructor({ id, name, description, tags, examples = null, inputModes = null, outputModes = null, security = null, }) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.tags = tags;
        if (examples)
            this.examples = examples;
        if (inputModes)
            this.inputModes = inputModes;
        if (outputModes)
            this.outputModes = outputModes;
        if (security)
            this.security = security;
    }
}
exports.A2AAgentSkill = A2AAgentSkill;
class A2AAgentExtension {
    constructor(uri, description = null, required = null) {
        this.uri = uri;
        if (description !== null)
            this.description = description;
        if (required !== null)
            this.required = required;
    }
}
exports.A2AAgentExtension = A2AAgentExtension;
class A2AAgentCapabilities {
    constructor({ streaming = null, pushNotifications = null, extendedAgentCard = null, extensions = null, } = {}) {
        if (streaming !== null)
            this.streaming = streaming;
        if (pushNotifications !== null)
            this.pushNotifications = pushNotifications;
        if (extendedAgentCard !== null)
            this.extendedAgentCard = extendedAgentCard;
        if (extensions)
            this.extensions = extensions;
    }
}
exports.A2AAgentCapabilities = A2AAgentCapabilities;
class A2AAgentCardSignature {
    constructor(jws, keyId = null) {
        this.jws = jws;
        if (keyId)
            this.keyId = keyId;
    }
}
exports.A2AAgentCardSignature = A2AAgentCardSignature;
class A2AAgentCard {
    constructor({ name, description, version, protocolVersions, supportedInterfaces, defaultInputModes, defaultOutputModes, capabilities, skills, provider = null, documentationUrl = null, iconUrl = null, securitySchemes = null, security = null, signatures = null, metadata = null, }) {
        this.name = name;
        this.description = description;
        this.version = version;
        this.protocolVersions = protocolVersions;
        this.supportedInterfaces = supportedInterfaces;
        this.defaultInputModes = defaultInputModes;
        this.defaultOutputModes = defaultOutputModes;
        this.capabilities = capabilities;
        this.skills = skills;
        if (provider)
            this.provider = provider;
        if (documentationUrl)
            this.documentationUrl = documentationUrl;
        if (iconUrl)
            this.iconUrl = iconUrl;
        if (securitySchemes)
            this.securitySchemes = securitySchemes;
        if (security)
            this.security = security;
        if (signatures)
            this.signatures = signatures;
        if (metadata)
            this.metadata = metadata;
    }
}
exports.A2AAgentCard = A2AAgentCard;
// =============================================================================
// JACS A2A Integration
// =============================================================================
class JACSA2AIntegration {
    constructor(client, trustPolicy) {
        this.client = client;
        this.trustPolicy = trustPolicy || exports.DEFAULT_TRUST_POLICY;
    }
    static async quickstart(options = {}) {
        const { url, name, skills, trustPolicy, algorithm, configPath } = options;
        let JacsClientCtor;
        try {
            JacsClientCtor = require('./client').JacsClient;
        }
        catch {
            JacsClientCtor = require('./client.js').JacsClient;
        }
        const client = await JacsClientCtor.quickstart({
            algorithm: algorithm || undefined,
            configPath: configPath || undefined,
            name: name || undefined,
        });
        const integration = new JACSA2AIntegration(client, trustPolicy || exports.DEFAULT_TRUST_POLICY);
        integration.defaultUrl = url || null;
        integration.defaultSkills = skills || null;
        return integration;
    }
    /**
     * Start a minimal Express discovery server for this agent.
     *
     * Pass `port = 0` to let the OS pick an available ephemeral port.
     */
    listen(port = 8080) {
        let express;
        try {
            express = require('express');
        }
        catch {
            throw new Error('listen() requires express. Install it with: npm install express');
        }
        const app = express();
        const agentData = {
            jacsId: this.client.agentId || 'unknown',
            jacsName: this.client.name || 'JACS A2A Agent',
            jacsDescription: `JACS agent ${this.client.name || this.client.agentId}`,
        };
        if (this.defaultUrl) {
            agentData.jacsAgentDomain = this.defaultUrl;
        }
        const card = this.exportAgentCard(agentData);
        const cardJson = JSON.parse(JSON.stringify(card));
        const extensionJson = this.createExtensionDescriptor();
        if (this.defaultSkills && Array.isArray(this.defaultSkills)) {
            cardJson.skills = this.defaultSkills.map((s) => {
                if (s instanceof A2AAgentSkill)
                    return s;
                return new A2AAgentSkill({
                    id: s.id || this._slugify(s.name || 'unnamed'),
                    name: s.name || 'unnamed',
                    description: s.description || '',
                    tags: s.tags || ['jacs'],
                });
            });
        }
        app.get('/.well-known/agent-card.json', (_req, res) => {
            res.json(cardJson);
        });
        app.get('/.well-known/jacs-extension.json', (_req, res) => {
            res.json(extensionJson);
        });
        const server = app.listen(port, () => {
            const address = server.address();
            const boundPort = typeof address === 'object' && address ? address.port : port;
            const requested = port === 0 ? ' (requested random port)' : '';
            console.log(`Your agent is discoverable at http://localhost:${boundPort}/.well-known/agent-card.json${requested}`);
        });
        return server;
    }
    exportAgentCard(agentData) {
        const agentId = agentData.jacsId || 'unknown';
        const agentName = agentData.jacsName || 'Unnamed JACS Agent';
        const agentDescription = agentData.jacsDescription || 'JACS-enabled agent';
        const agentVersion = agentData.jacsVersion || '1';
        const domain = agentData.jacsAgentDomain;
        const baseUrl = domain
            ? `https://${domain}/agent/${agentId}`
            : `https://agent-${agentId}.example.com`;
        const supportedInterfaces = [new A2AAgentInterface(baseUrl, 'jsonrpc')];
        const skills = this._convertServicesToSkills(agentData.jacsServices || []);
        const securitySchemes = {
            'bearer-jwt': { type: 'http', scheme: 'Bearer', bearerFormat: 'JWT' },
            'api-key': { type: 'apiKey', in: 'header', name: 'X-API-Key' },
        };
        const jacsExtension = new A2AAgentExtension(exports.JACS_EXTENSION_URI, 'JACS cryptographic document signing and verification', false);
        const capabilities = new A2AAgentCapabilities({ extensions: [jacsExtension] });
        const metadata = {
            jacsAgentType: agentData.jacsAgentType,
            jacsId: agentId,
            jacsVersion: agentData.jacsVersion,
        };
        return new A2AAgentCard({
            name: agentName,
            description: agentDescription,
            version: String(agentVersion),
            protocolVersions: [exports.A2A_PROTOCOL_VERSION],
            supportedInterfaces,
            defaultInputModes: ['text/plain', 'application/json'],
            defaultOutputModes: ['text/plain', 'application/json'],
            capabilities,
            skills,
            securitySchemes,
            metadata,
        });
    }
    createExtensionDescriptor() {
        return {
            uri: exports.JACS_EXTENSION_URI,
            name: 'JACS Document Provenance',
            version: '1.0',
            a2aProtocolVersion: exports.A2A_PROTOCOL_VERSION,
            description: 'Provides cryptographic document signing and verification with post-quantum support',
            specification: 'https://hai.ai/jacs/specs/a2a-extension',
            capabilities: {
                documentSigning: {
                    description: 'Sign documents with JACS signatures',
                    algorithms: [...exports.JACS_ALGORITHMS],
                    formats: ['jacs-v1', 'jws-detached'],
                },
                documentVerification: {
                    description: 'Verify JACS signatures on documents',
                    offlineCapable: true,
                    chainOfCustody: true,
                },
                postQuantumCrypto: {
                    description: 'Support for quantum-resistant signatures',
                    algorithms: ['pq-dilithium', 'pq2025'],
                },
            },
            endpoints: {
                sign: { path: '/jacs/sign', method: 'POST', description: 'Sign a document with JACS' },
                verify: { path: '/jacs/verify', method: 'POST', description: 'Verify a JACS signature' },
                publicKey: {
                    path: '/.well-known/jacs-pubkey.json',
                    method: 'GET',
                    description: "Retrieve agent's public key",
                },
            },
        };
    }
    /**
     * Assess a remote agent's trust level based on the configured trust policy.
     *
     * - open: allows all agents
     * - verified: requires JACS extension in the agent card
     * - strict: requires the agent to be in the local JACS trust store
     */
    assessRemoteAgent(agentCardJson) {
        const card = typeof agentCardJson === 'string'
            ? JSON.parse(agentCardJson)
            : agentCardJson;
        const jacsRegistered = this._hasJacsExtension(card);
        const agentId = (card.metadata && card.metadata.jacsId);
        let inTrustStore = false;
        if (agentId) {
            try {
                inTrustStore = this.client.isTrusted(agentId);
            }
            catch {
                inTrustStore = false;
            }
        }
        const trustLevel = inTrustStore
            ? 'trusted'
            : jacsRegistered
                ? 'jacs_registered'
                : 'untrusted';
        switch (this.trustPolicy) {
            case 'open':
                return { allowed: true, trustLevel, jacsRegistered, inTrustStore, reason: 'Open policy: all agents accepted' };
            case 'verified':
                if (jacsRegistered) {
                    return { allowed: true, trustLevel, jacsRegistered, inTrustStore, reason: 'Agent declares JACS extension' };
                }
                return { allowed: false, trustLevel, jacsRegistered, inTrustStore, reason: 'Verified policy: agent does not declare JACS extension' };
            case 'strict':
                if (inTrustStore) {
                    return { allowed: true, trustLevel, jacsRegistered, inTrustStore, reason: 'Agent is in local trust store' };
                }
                return { allowed: false, trustLevel, jacsRegistered, inTrustStore, reason: 'Strict policy: agent not in local trust store' };
            default:
                return { allowed: false, trustLevel, jacsRegistered, inTrustStore, reason: `Unknown trust policy: ${this.trustPolicy}` };
        }
    }
    /**
     * Convenience method to add an A2A agent to the JACS trust store.
     * Accepts a raw agent card JSON string or object.
     */
    trustA2AAgent(agentCardJson) {
        const cardStr = typeof agentCardJson === 'string'
            ? agentCardJson
            : JSON.stringify(agentCardJson);
        return this.client.trustAgent(cardStr);
    }
    async signArtifact(artifact, artifactType, parentSignatures = null) {
        const wrapped = {
            jacsId: (0, uuid_1.v4)(),
            jacsVersion: (0, uuid_1.v4)(),
            jacsType: `a2a-${artifactType}`,
            jacsLevel: 'artifact',
            jacsVersionDate: new Date().toISOString(),
            $schema: 'https://hai.ai/schemas/header/v1/header.schema.json',
            a2aArtifact: artifact,
        };
        if (parentSignatures) {
            wrapped.jacsParentSignatures = parentSignatures;
        }
        return this.client._agent.signRequest(wrapped);
    }
    /** @deprecated Use signArtifact() instead. */
    async wrapArtifactWithProvenance(artifact, artifactType, parentSignatures = null) {
        return this.signArtifact(artifact, artifactType, parentSignatures);
    }
    async verifyWrappedArtifact(wrappedArtifact) {
        const result = this._verifyWrappedArtifactInternal(wrappedArtifact, new Set());
        // Attach trust assessment based on the signer's identity
        const signerId = result.signerId;
        if (signerId && signerId !== 'unknown') {
            let inTrustStore = false;
            try {
                inTrustStore = this.client.isTrusted(signerId);
            }
            catch {
                inTrustStore = false;
            }
            const trustLevel = inTrustStore ? 'trusted' : 'jacs_registered';
            const allowed = this.trustPolicy === 'open'
                || this.trustPolicy === 'verified'
                || (this.trustPolicy === 'strict' && inTrustStore);
            result.trustAssessment = {
                allowed,
                trustLevel,
                jacsRegistered: true, // has a valid JACS signature
                inTrustStore,
                reason: allowed
                    ? (inTrustStore ? 'Signer is in local trust store' : `Signer has valid JACS signature (${this.trustPolicy} policy)`)
                    : `Strict policy: signer ${signerId} not in local trust store`,
            };
        }
        return result;
    }
    createChainOfCustody(artifacts) {
        const chain = [];
        for (const artifact of artifacts) {
            const sig = artifact.jacsSignature;
            if (sig) {
                chain.push({
                    artifactId: artifact.jacsId,
                    artifactType: artifact.jacsType,
                    timestamp: artifact.jacsVersionDate,
                    agentId: sig.agentID,
                    agentVersion: sig.agentVersion,
                    signatureHash: sig.publicKeyHash,
                });
            }
        }
        return {
            chainOfCustody: chain,
            created: new Date().toISOString(),
            totalArtifacts: chain.length,
        };
    }
    generateWellKnownDocuments(agentCard, jwsSignature, publicKeyB64, agentData) {
        const documents = {};
        const keyAlgorithm = agentData.keyAlgorithm || 'RSA-PSS';
        const postQuantum = /(pq|dilithium|falcon|sphincs|ml-dsa|pq2025)/i.test(keyAlgorithm);
        const cardObj = JSON.parse(JSON.stringify(agentCard));
        cardObj.signatures = [{ jws: jwsSignature }];
        documents['/.well-known/agent-card.json'] = cardObj;
        documents['/.well-known/jwks.json'] = this._buildJwks(publicKeyB64, agentData);
        documents['/.well-known/jacs-agent.json'] = {
            jacsVersion: '1.0',
            agentId: agentData.jacsId,
            agentVersion: agentData.jacsVersion,
            agentType: agentData.jacsAgentType,
            publicKeyHash: sha256(publicKeyB64),
            keyAlgorithm,
            capabilities: { signing: true, verification: true, postQuantum },
            schemas: {
                agent: 'https://hai.ai/schemas/agent/v1/agent.schema.json',
                header: 'https://hai.ai/schemas/header/v1/header.schema.json',
                signature: 'https://hai.ai/schemas/components/signature/v1/signature.schema.json',
            },
            endpoints: { verify: '/jacs/verify', sign: '/jacs/sign', agent: '/jacs/agent' },
        };
        documents['/.well-known/jacs-pubkey.json'] = {
            publicKey: publicKeyB64,
            publicKeyHash: sha256(publicKeyB64),
            algorithm: keyAlgorithm,
            agentId: agentData.jacsId,
            agentVersion: agentData.jacsVersion,
            timestamp: new Date().toISOString(),
        };
        documents['/.well-known/jacs-extension.json'] = this.createExtensionDescriptor();
        return documents;
    }
    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------
    _hasJacsExtension(card) {
        const capabilities = card.capabilities;
        const extensions = capabilities?.extensions;
        if (!Array.isArray(extensions))
            return false;
        return extensions.some((ext) => ext && ext.uri === exports.JACS_EXTENSION_URI);
    }
    _normalizeVerifyResponse(rawVerificationResult) {
        if (typeof rawVerificationResult === 'boolean') {
            return {
                valid: rawVerificationResult,
                verificationResult: rawVerificationResult,
            };
        }
        if (rawVerificationResult && typeof rawVerificationResult === 'object') {
            const rawObj = rawVerificationResult;
            const payload = rawObj.payload;
            return {
                valid: true,
                verifiedPayload: payload && typeof payload === 'object'
                    ? payload
                    : undefined,
                verificationResult: rawObj,
            };
        }
        return {
            valid: false,
            verificationResult: false,
        };
    }
    _verifyWrappedArtifactInternal(wrappedArtifact, visited) {
        const artifactId = wrappedArtifact.jacsId;
        if (artifactId && visited.has(artifactId)) {
            throw new Error(`Cycle detected in parent signature chain at artifact ${artifactId}`);
        }
        if (artifactId) {
            visited.add(artifactId);
        }
        try {
            const rawVerificationResult = this.client._agent.verifyResponse(JSON.stringify(wrappedArtifact));
            const normalized = this._normalizeVerifyResponse(rawVerificationResult);
            const signatureInfo = (wrappedArtifact.jacsSignature || {});
            const payload = wrappedArtifact.jacs_payload && typeof wrappedArtifact.jacs_payload === 'object'
                ? wrappedArtifact.jacs_payload
                : null;
            const result = {
                valid: normalized.valid,
                verificationResult: normalized.verificationResult,
                signerId: signatureInfo.agentID || 'unknown',
                signerVersion: signatureInfo.agentVersion || 'unknown',
                artifactType: wrappedArtifact.jacsType || 'unknown',
                timestamp: wrappedArtifact.jacsVersionDate || '',
                originalArtifact: (wrappedArtifact.a2aArtifact || payload?.a2aArtifact || {}),
            };
            if (normalized.verifiedPayload) {
                result.verifiedPayload = normalized.verifiedPayload;
            }
            const parents = wrappedArtifact.jacsParentSignatures;
            if (Array.isArray(parents) && parents.length > 0) {
                const parentResults = parents.map((parent, index) => {
                    try {
                        const parentResult = this._verifyWrappedArtifactInternal(parent, visited);
                        return {
                            index,
                            artifactId: parent.jacsId || 'unknown',
                            valid: !!parentResult.valid,
                            parentSignaturesValid: parentResult.parentSignaturesValid !== false,
                        };
                    }
                    catch (error) {
                        return {
                            index,
                            artifactId: parent && parent.jacsId ? parent.jacsId : 'unknown',
                            valid: false,
                            parentSignaturesValid: false,
                            error: error instanceof Error ? error.message : String(error),
                        };
                    }
                });
                result.parentSignaturesCount = parentResults.length;
                result.parentVerificationResults = parentResults;
                result.parentSignaturesValid = parentResults.every((entry) => entry.valid && entry.parentSignaturesValid);
            }
            return result;
        }
        finally {
            if (artifactId) {
                visited.delete(artifactId);
            }
        }
    }
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
                    keys: [
                        {
                            kty: 'OKP',
                            crv: 'Ed25519',
                            x: keyBytes.toString('base64url'),
                            kid,
                            use: 'sig',
                            alg: 'EdDSA',
                        },
                    ],
                };
            }
            let keyObject;
            try {
                keyObject = (0, crypto_1.createPublicKey)({ key: keyBytes, format: 'der', type: 'spki' });
            }
            catch {
                keyObject = (0, crypto_1.createPublicKey)(keyBytes.toString('utf8'));
            }
            const jwk = keyObject.export({ format: 'jwk' });
            const alg = this._inferJwsAlg(keyAlgorithm, jwk);
            return {
                keys: [{ ...jwk, kid, use: 'sig', ...(alg ? { alg } : {}) }],
            };
        }
        catch {
            return { keys: [] };
        }
    }
    _inferJwsAlg(keyAlgorithm, jwk) {
        if (keyAlgorithm.includes('ring-ed25519') || keyAlgorithm.includes('ed25519'))
            return 'EdDSA';
        if (keyAlgorithm.includes('rsa'))
            return 'RS256';
        if (keyAlgorithm.includes('ecdsa') || keyAlgorithm.includes('es256'))
            return 'ES256';
        if (jwk?.kty === 'RSA')
            return 'RS256';
        if (jwk?.kty === 'OKP' && jwk?.crv === 'Ed25519')
            return 'EdDSA';
        if (jwk?.kty === 'EC' && jwk?.crv === 'P-256')
            return 'ES256';
        return undefined;
    }
    _slugify(name) {
        return name
            .toLowerCase()
            .replace(/[\s_]+/g, '-')
            .replace(/[^a-z0-9-]/g, '');
    }
    _deriveTags(serviceName, fnName) {
        const tags = ['jacs'];
        const serviceSlug = this._slugify(serviceName);
        const fnSlug = this._slugify(fnName);
        if (serviceSlug !== fnSlug)
            tags.push(serviceSlug);
        tags.push(fnSlug);
        return tags;
    }
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
            }
            else {
                skills.push(new A2AAgentSkill({
                    id: this._slugify(serviceName),
                    name: serviceName,
                    description: serviceDesc,
                    tags: this._deriveTags(serviceName, serviceName),
                }));
            }
        }
        if (skills.length === 0) {
            skills.push(new A2AAgentSkill({
                id: 'verify-signature',
                name: 'verify_signature',
                description: 'Verify JACS document signatures',
                tags: ['jacs', 'verification', 'cryptography'],
                examples: ['Verify a signed JACS document', 'Check document signature integrity'],
                inputModes: ['application/json'],
                outputModes: ['application/json'],
            }));
        }
        return skills;
    }
}
exports.JACSA2AIntegration = JACSA2AIntegration;
//# sourceMappingURL=a2a.js.map
