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
const index_js_1 = require("./index.js");
const deprecation_js_1 = require("./deprecation.js");
const output_policy_js_1 = require("./output-policy.js");
// =============================================================================
// Constants
// =============================================================================
exports.A2A_PROTOCOL_VERSION = '0.4.0';
exports.JACS_EXTENSION_URI = 'urn:jacs:provenance-v1';
exports.JACS_ALGORITHMS = [
    'ring-Ed25519',
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
    return (0, index_js_1.hashString)(data);
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
/** Map binding-core's canonical trustAssessment to the wrapper's trust block. */
function buildTrustBlock(trustAssessment) {
    return {
        policy: trustAssessment.policy ?? null,
        status: trustAssessment.allowed ? 'allowed' : 'blocked',
        reason: trustAssessment.reason ?? '',
    };
}
function canonicalPolicyName(policy) {
    if (!policy)
        return undefined;
    switch (policy.toLowerCase()) {
        case 'open':
            return 'Open';
        case 'verified':
            return 'Verified';
        case 'strict':
            return 'Strict';
        default:
            return policy;
    }
}
function canonicalTrustLevel(level) {
    switch (String(level)) {
        case 'ExplicitlyTrusted':
        case 'explicitly_trusted':
        case 'trusted':
            return 'ExplicitlyTrusted';
        case 'JacsVerified':
        case 'jacs_verified':
        case 'jacs_registered':
            return 'JacsVerified';
        default:
            return 'Untrusted';
    }
}
function legacyTrustLevel(level) {
    switch (canonicalTrustLevel(level)) {
        case 'ExplicitlyTrusted':
            return 'trusted';
        case 'JacsVerified':
            return 'jacs_registered';
        default:
            return 'untrusted';
    }
}
function normalizeVerificationStatus(status, valid, reason = '') {
    if (valid && (status === 'Verified' || status === 'SelfSigned')) {
        return status;
    }
    if (status && typeof status === 'object') {
        const statusObj = status;
        const unverified = statusObj.Unverified;
        if (unverified && typeof unverified === 'object') {
            return { Unverified: { reason: String(unverified.reason ?? reason) } };
        }
        const invalid = statusObj.Invalid;
        if (invalid && typeof invalid === 'object') {
            return { Invalid: { reason: String(invalid.reason ?? reason) } };
        }
    }
    if (status === 'Unverified') {
        return { Unverified: { reason: reason || 'verification could not be completed' } };
    }
    if (status === 'Invalid') {
        return { Invalid: { reason: reason || 'signature verification failed' } };
    }
    return valid
        ? 'Verified'
        : { Invalid: { reason: reason || 'signature verification failed' } };
}
function defineHiddenProperty(target, key, value) {
    Object.defineProperty(target, key, {
        configurable: true,
        enumerable: false,
        writable: true,
        value,
    });
}
function stableJsonValue(value) {
    if (Array.isArray(value)) {
        return `[${value.map((item) => stableJsonValue(item)).join(',')}]`;
    }
    if (value && typeof value === 'object') {
        return `{${Object.entries(value)
            .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
            .map(([key, item]) => `${JSON.stringify(key)}:${stableJsonValue(item)}`)
            .join(',')}}`;
    }
    if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new TypeError('A2A artifact must contain only finite JSON numbers');
    }
    const serialized = JSON.stringify(value);
    if (typeof serialized !== 'string') {
        throw new TypeError('A2A artifact must contain only JSON values');
    }
    return serialized;
}
// =============================================================================
// JACS A2A Integration
// =============================================================================
class JACSA2AIntegration {
    constructor(client, trustPolicy) {
        this.client = client;
        this.trustPolicy = trustPolicy || exports.DEFAULT_TRUST_POLICY;
    }
    static async quickstart(options = {}) {
        const { url, name, domain, description, skills, trustPolicy, algorithm, configPath } = options;
        if (skills != null && (!Array.isArray(skills) || skills.length > 0)) {
            throw new Error('A2A quickstart skills are deprecated: wrapper-supplied skills cannot be added after '
                + 'the native Agent Card is signed. Persist skills in the native agent/card workflow '
                + 'before generating discovery documents.');
        }
        let JacsClientCtor;
        try {
            JacsClientCtor = require('./client').JacsClient;
        }
        catch {
            JacsClientCtor = require('./client.js').JacsClient;
        }
        const derivedDomain = domain || (url ? (() => {
            try {
                return new URL(url).hostname;
            }
            catch {
                return 'localhost';
            }
        })() : 'localhost');
        const client = await JacsClientCtor.quickstart({
            algorithm: algorithm || undefined,
            configPath: configPath || undefined,
            name: name || 'jacs-agent',
            domain: derivedDomain,
            description: description || 'JACS A2A agent',
        });
        const integration = new JACSA2AIntegration(client, trustPolicy || exports.DEFAULT_TRUST_POLICY);
        integration.defaultUrl = url || null;
        integration.defaultSkills = null;
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
        const documents = this.generateWellKnownDocuments(cardJson, '', '', agentData);
        const nativeCard = documents['/.well-known/agent-card.json'];
        if (this.defaultSkills
            && JSON.stringify(nativeCard.skills || []) !== JSON.stringify(cardJson.skills || [])) {
            throw new Error("Cannot override A2A skills after the Agent Card is signed; configure the agent's skills before listen()");
        }
        const signedInterfaceUrl = nativeCard.supportedInterfaces?.[0]?.url;
        if (this.defaultUrl) {
            let requestedOrigin;
            let signedOrigin;
            try {
                requestedOrigin = new URL(this.defaultUrl).origin;
                signedOrigin = new URL(String(signedInterfaceUrl)).origin;
            }
            catch (error) {
                throw new Error(`Invalid configured or signed A2A public URL: ${String(error)}`);
            }
            if (requestedOrigin !== signedOrigin) {
                throw new Error(`Configured A2A public origin '${requestedOrigin}' does not match the signed Agent Card origin '${signedOrigin}'`);
            }
        }
        for (const [path, document] of Object.entries(documents)) {
            app.get(path, (_req, res) => {
                res.set('Access-Control-Allow-Origin', '*');
                res.json(document);
            });
        }
        const server = app.listen(port, () => {
            const address = server.address();
            const boundPort = typeof address === 'object' && address ? address.port : port;
            const requested = port === 0 ? ' (requested random port)' : '';
            const publicOrigin = typeof signedInterfaceUrl === 'string'
                ? new URL(signedInterfaceUrl).origin
                : 'unavailable';
            console.log(`A2A listener http://localhost:${boundPort}${requested}; signed public discovery origin ${publicOrigin}`);
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
        const skills = this._normalizeA2ASkills(agentData.skills || agentData.a2aSkills || []);
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
            specification: 'https://jacs.ai/specs/a2a-extension',
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
                    algorithms: ['pq2025'],
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
     * - verified: requires native JWS/JWKS verification plus durable TOFU pinning
     * - strict: additionally requires an explicitly trusted native root and its
     *   valid compatibility binding for the exact ES256 card key
     */
    assessRemoteAgent(agentCardJson) {
        const cardJson = typeof agentCardJson === 'string'
            ? agentCardJson
            : JSON.stringify(agentCardJson);
        const card = JSON.parse(cardJson);
        const nativeAssess = this.client._agent?.assessA2aAgentSync;
        if (typeof nativeAssess === 'function') {
            const canonicalJson = nativeAssess.call(this.client._agent, cardJson, this.trustPolicy);
            const canonical = JSON.parse(canonicalJson);
            return {
                allowed: canonical.allowed === true,
                trustLevel: legacyTrustLevel(canonical.trustLevel),
                jacsRegistered: canonical.jacsRegistered === true,
                inTrustStore: canonicalTrustLevel(canonical.trustLevel) === 'ExplicitlyTrusted',
                reason: String(canonical.reason ?? ''),
                firstContact: canonical.firstContact === true,
            };
        }
        return this._legacyAssessRemoteAgent(card, this.trustPolicy);
    }
    /**
     * Explicitly trust the native JACS identity used by A2A strict mode.
     *
     * An Agent Card is self-advertised discovery metadata and is never enough
     * to create native identity trust. Obtain the full self-signed native JACS
     * agent document and its public key through an authenticated out-of-band
     * channel. The native trust API verifies the document before persisting it.
     */
    trustA2AAgent(agentDocumentJson, publicKeyPem) {
        if (typeof publicKeyPem !== 'string' || publicKeyPem.trim().length === 0) {
            throw new Error('Cannot establish A2A identity trust without an explicit public key');
        }
        const documentString = typeof agentDocumentJson === 'string'
            ? agentDocumentJson
            : JSON.stringify(agentDocumentJson);
        let document;
        try {
            document = JSON.parse(documentString);
        }
        catch (error) {
            throw new Error(`Invalid native JACS agent document JSON: ${String(error)}`);
        }
        if (!document
            || typeof document !== 'object'
            || !('jacsId' in document)
            || !('jacsVersion' in document)
            || !('jacsSignature' in document)) {
            throw new Error('trustA2AAgent requires the full native JACS agent document, not an unauthenticated Agent Card');
        }
        const trustWithKey = this.client.trustAgentWithKey;
        if (typeof trustWithKey !== 'function') {
            throw new Error('The configured JacsClient does not expose trustAgentWithKey; strict A2A trust cannot be established');
        }
        return trustWithKey.call(this.client, documentString, publicKeyPem);
    }
    /**
     * Sign through the native canonical A2A primitive and return the direct
     * `a2a-*` document. Generic request-envelope fallback is never used. The
     * returned portable-v2 metadata and parent chain must exactly match the
     * requested artifact contract before any result is released.
     */
    async signArtifact(artifact, artifactType, parentSignatures = null) {
        if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
            throw new TypeError('A2A artifact must be a non-null JSON object');
        }
        if (typeof artifactType !== 'string' || artifactType.trim().length === 0) {
            throw new TypeError('A2A artifact type must be a non-empty string');
        }
        if (parentSignatures != null && !Array.isArray(parentSignatures)) {
            throw new TypeError('A2A parent signatures must be an array or null');
        }
        // Validate JSON compatibility before crossing the native boundary. This
        // rejects cycles and values whose serialized meaning would differ.
        stableJsonValue(artifact);
        if (parentSignatures)
            stableJsonValue(parentSignatures);
        const nativeAgent = this.client._agent;
        const nativeSign = nativeAgent?.signArtifactSync;
        if (typeof nativeSign !== 'function') {
            throw new Error('Native signArtifactSync is required for canonical A2A artifact signing; '
                + 'generic signRequest fallback is disabled');
        }
        let raw;
        try {
            raw = nativeSign.call(nativeAgent, JSON.stringify(artifact), artifactType, parentSignatures ? JSON.stringify(parentSignatures) : null);
        }
        catch (error) {
            throw new Error(`Native A2A signing failed: ${String(error)}`);
        }
        if (typeof raw !== 'string' || raw.trim().length === 0) {
            throw new TypeError('Native A2A signing returned no canonical JSON document');
        }
        let parsed;
        try {
            parsed = JSON.parse(raw);
        }
        catch (error) {
            throw new TypeError(`Native A2A signing returned invalid JSON: ${String(error)}`);
        }
        const signed = (0, output_policy_js_1.requirePortableV2SignedDocument)(parsed, 'Native A2A signing');
        if (signed.jacsType !== `a2a-${artifactType}`) {
            throw new TypeError('Native A2A signing returned a mismatched canonical artifact type');
        }
        if (stableJsonValue(signed.a2aArtifact) !== stableJsonValue(artifact)) {
            throw new TypeError('Native A2A signing returned a document that does not bind the artifact');
        }
        const returnedParents = signed.jacsParentSignatures;
        const parentChainMatches = parentSignatures === null
            ? returnedParents === undefined
                || (Array.isArray(returnedParents) && returnedParents.length === 0)
            : Array.isArray(returnedParents)
                && stableJsonValue(returnedParents) === stableJsonValue(parentSignatures);
        if (!parentChainMatches) {
            throw new TypeError('Native A2A signing returned a mismatched parent chain');
        }
        return signed;
    }
    /** @deprecated Use signArtifact() instead. */
    async wrapArtifactWithProvenance(artifact, artifactType, parentSignatures = null) {
        (0, deprecation_js_1.warnDeprecated)('wrapArtifactWithProvenance', 'signArtifact');
        return this.signArtifact(artifact, artifactType, parentSignatures);
    }
    /**
     * Verify artifact cryptography and its parent chain. Supply the real remote
     * Agent Card to additionally enforce this integration's trust policy.
     * Affirmative verification requires the native canonical
     * verifyA2aArtifactSync contract. Legacy verifyResponse is never used as an
     * A2A fallback and cannot project provenance or elevate trust.
     */
    async verifyWrappedArtifact(wrappedArtifact, agentCard) {
        // Cryptographic artifact validity is available without an Agent Card.
        // Trust-policy assessment is a separate operation and requires the real,
        // identity-bound remote card; never synthesize one from artifact claims.
        const options = agentCard
            ? { policy: this.trustPolicy, agentCard }
            : { policy: this.trustPolicy };
        return this._verifyWrappedArtifactInternal(wrappedArtifact, new Set(), options);
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
        // These parameters remain for source compatibility only. Identity-bearing
        // discovery documents must come from the native generator as one
        // card/JWKS/binding unit; wrapper inputs can never replace signed fields.
        void agentCard;
        void jwsSignature;
        void publicKeyB64;
        void agentData;
        const nativeGenerate = this.client._agent?.generateWellKnownDocumentsSync;
        if (typeof nativeGenerate !== 'function') {
            throw new Error('Identity-bound A2A discovery requires the native JACS generator; '
                + 'legacy wrapper-generated keys and signatures are not trusted');
        }
        let nativePairs;
        try {
            const nativeJson = nativeGenerate.call(this.client._agent);
            nativePairs = JSON.parse(nativeJson);
        }
        catch (error) {
            throw new Error(`Identity-bound A2A discovery generation failed: ${String(error)}`);
        }
        if (!Array.isArray(nativePairs)) {
            throw new Error('Native A2A discovery result must be an array of path/document pairs');
        }
        const documents = {};
        for (const item of nativePairs) {
            if (!item
                || typeof item !== 'object'
                || typeof item.path !== 'string'
                || !item.document
                || typeof item.document !== 'object'
                || Array.isArray(item.document)) {
                throw new Error('Native A2A discovery returned a malformed path/document pair');
            }
            const path = item.path;
            if (Object.prototype.hasOwnProperty.call(documents, path)) {
                throw new Error(`Native A2A discovery returned duplicate path '${path}'`);
            }
            documents[path] = item.document;
        }
        const requiredPaths = [
            '/.well-known/agent-card.json',
            '/.well-known/jwks.json',
            '/.well-known/jacs-compat-binding.json',
            '/.well-known/jacs-agent.json',
            '/.well-known/jacs-pubkey.json',
            '/.well-known/jacs-extension.json',
        ];
        const missing = requiredPaths.filter((path) => !Object.prototype.hasOwnProperty.call(documents, path));
        if (missing.length > 0) {
            throw new Error(`Native A2A discovery omitted identity-bound documents: ${missing.join(', ')}`);
        }
        const card = documents['/.well-known/agent-card.json'];
        const metadata = card.metadata;
        const signatures = card.signatures;
        if (!metadata
            || metadata.jacsCompatBindingPath !== '/.well-known/jacs-compat-binding.json'
            || !Array.isArray(signatures)
            || signatures.length === 0
            || typeof signatures[0]?.jws !== 'string'
            || !signatures[0].jws
            || signatures[0].keyId !== metadata.jacsCompatKid) {
            throw new Error('Native A2A Agent Card is missing its bound ES256 signature metadata');
        }
        const jwks = documents['/.well-known/jwks.json'].keys;
        if (!Array.isArray(jwks)
            || !jwks.some((key) => (key?.kid === metadata.jacsCompatKid
                && key.alg === 'ES256'
                && key.use === 'sig'))) {
            throw new Error("Native A2A JWKS does not contain the card's ES256 signing key");
        }
        const binding = documents['/.well-known/jacs-compat-binding.json'];
        if (binding.jacsSha256 !== metadata.jacsCompatBindingHash) {
            throw new Error('Native A2A compatibility binding hash does not match the Agent Card');
        }
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
    _legacyAssessRemoteAgent(card, policy) {
        const metadata = card.metadata;
        const agentId = typeof metadata?.jacsId === 'string' ? metadata.jacsId : null;
        const jacsRegistered = this._hasJacsExtension(card);
        let allowed;
        let reason;
        switch (policy) {
            case exports.TRUST_POLICIES.OPEN:
                allowed = true;
                reason = 'Open policy: agent allowed without native cryptographic assessment; no identity assurance is claimed';
                break;
            case exports.TRUST_POLICIES.STRICT:
            case exports.TRUST_POLICIES.VERIFIED:
            default:
                allowed = false;
                reason = `${canonicalPolicyName(policy)} policy: native cryptographic assessment is unavailable; `
                    + 'an Agent Card extension or local trust-store name alone does not prove identity';
                break;
        }
        return {
            allowed,
            trustLevel: 'untrusted',
            jacsRegistered,
            inTrustStore: false,
            reason,
            firstContact: false,
        };
    }
    _buildCanonicalTrustAssessment(agentCard, policy) {
        const legacy = this._legacyAssessRemoteAgent(agentCard, policy);
        const trustAssessment = {
            allowed: legacy.allowed,
            trustLevel: canonicalTrustLevel(legacy.trustLevel),
            jacsRegistered: legacy.jacsRegistered,
            reason: legacy.reason,
            policy: canonicalPolicyName(policy),
            agentId: legacy.agentId ?? null,
            firstContact: legacy.firstContact === true,
        };
        defineHiddenProperty(trustAssessment, 'inTrustStore', trustAssessment.trustLevel === 'ExplicitlyTrusted');
        return trustAssessment;
    }
    _normalizeTrustAssessment(trustAssessment, fallbackPolicy) {
        const allowed = trustAssessment.allowed === true;
        const reportedTrustLevel = canonicalTrustLevel(trustAssessment.trustLevel);
        const normalized = {
            allowed,
            // A denied or malformed assessment cannot simultaneously present a
            // trusted identity in compatibility fields.
            trustLevel: allowed ? reportedTrustLevel : 'Untrusted',
            jacsRegistered: trustAssessment.jacsRegistered === true,
            reason: String(trustAssessment.reason ?? ''),
            policy: canonicalPolicyName(String(trustAssessment.policy ?? fallbackPolicy)),
            agentId: typeof trustAssessment.agentId === 'string' || trustAssessment.agentId === null
                ? trustAssessment.agentId
                : null,
            firstContact: trustAssessment.firstContact === true,
        };
        defineHiddenProperty(normalized, 'inTrustStore', normalized.trustLevel === 'ExplicitlyTrusted');
        return normalized;
    }
    _normalizeParentVerificationResult(parentResult, index) {
        const canonicalParent = parentResult && typeof parentResult === 'object' && !Array.isArray(parentResult)
            ? parentResult
            : {};
        // Parent-chain integrity is affirmative evidence, not a default. Missing,
        // string, numeric, compatibility-alias, and status-contradictory values all
        // fail closed.
        const parentStatusIsVerified = canonicalParent.status === 'Verified'
            || canonicalParent.status === 'SelfSigned';
        const verified = canonicalParent.verified === true && parentStatusIsVerified;
        const normalized = {
            index: Number.isInteger(canonicalParent.index) ? canonicalParent.index : index,
            artifactId: String(canonicalParent.artifactId ?? ''),
            signerId: String(canonicalParent.signerId ?? ''),
            status: normalizeVerificationStatus(canonicalParent.status, verified),
            verified,
        };
        defineHiddenProperty(normalized, 'valid', normalized.verified);
        return normalized;
    }
    _canonicalResultFromWrappedArtifact(wrappedArtifact, canonical, fallbackPolicy) {
        const wrappedParents = Array.isArray(wrappedArtifact.jacsParentSignatures)
            ? wrappedArtifact.jacsParentSignatures
            : [];
        const parentResults = Array.isArray(canonical.parentVerificationResults)
            ? canonical.parentVerificationResults.map((parent, index) => this._normalizeParentVerificationResult(parent, index))
            : [];
        const parentSignaturesValid = canonical.parentSignaturesValid === true
            && parentResults.length === wrappedParents.length
            && parentResults.every((parent) => parent.verified === true);
        const signerId = typeof canonical.signerId === 'string' ? canonical.signerId : '';
        const signerVersion = typeof canonical.signerVersion === 'string' ? canonical.signerVersion : '';
        const artifactType = typeof canonical.artifactType === 'string' ? canonical.artifactType : '';
        const timestamp = typeof canonical.timestamp === 'string' ? canonical.timestamp : '';
        const originalArtifact = canonical.originalArtifact
            && typeof canonical.originalArtifact === 'object'
            && !Array.isArray(canonical.originalArtifact)
            ? canonical.originalArtifact
            : {};
        const canonicalProvenanceComplete = signerId.trim().length > 0
            && signerVersion.trim().length > 0
            && artifactType.trim().length > 0
            && timestamp.trim().length > 0
            && canonical.originalArtifact !== null
            && typeof canonical.originalArtifact === 'object'
            && !Array.isArray(canonical.originalArtifact);
        const canonicalStatusIsVerified = canonical.status === 'Verified'
            || canonical.status === 'SelfSigned';
        const canonicalValid = canonical.valid === true
            && canonicalStatusIsVerified
            && canonicalProvenanceComplete;
        const canonicalFailureReason = !canonicalProvenanceComplete
            ? 'canonical native verification omitted authenticated provenance or originalArtifact'
            : !canonicalStatusIsVerified
                ? 'canonical native verification returned a success flag with a non-success status'
                : 'signature verification failed';
        const result = {
            valid: canonicalValid,
            status: normalizeVerificationStatus(canonical.status, canonicalValid, canonicalFailureReason),
            signerId,
            signerVersion,
            artifactType,
            timestamp,
            originalArtifact,
            parentSignaturesValid,
            parentVerificationResults: parentResults,
        };
        if (!parentSignaturesValid && canonical.valid === true) {
            result.valid = false;
            result.status = {
                Invalid: {
                    reason: 'parent signature verification failed or returned incomplete canonical evidence',
                },
            };
        }
        if (canonical.trustAssessment
            && typeof canonical.trustAssessment === 'object'
            && !Array.isArray(canonical.trustAssessment)) {
            result.trustAssessment = this._normalizeTrustAssessment(canonical.trustAssessment, fallbackPolicy);
            result.trustLevel = canonicalTrustLevel(result.trustAssessment.trustLevel);
            if (!result.trustAssessment.allowed) {
                result.valid = false;
                result.status = { Invalid: { reason: result.trustAssessment.reason } };
            }
        }
        return result;
    }
    _attachCompatibilityAliases(result, options = {}) {
        defineHiddenProperty(result, 'parentSignaturesCount', result.parentVerificationResults.length);
        if (options.rawVerificationResult !== undefined) {
            defineHiddenProperty(result, 'verificationResult', options.rawVerificationResult);
        }
        if (options.verifiedPayload) {
            defineHiddenProperty(result, 'verifiedPayload', options.verifiedPayload);
        }
        if (result.trustAssessment) {
            defineHiddenProperty(result, 'trust', buildTrustBlock(result.trustAssessment));
        }
        return result;
    }
    _verifyWrappedArtifactInternal(wrappedArtifact, visited, options) {
        const artifactId = wrappedArtifact.jacsId;
        if (artifactId && visited.has(artifactId)) {
            throw new Error(`Cycle detected in parent signature chain at artifact ${artifactId}`);
        }
        if (artifactId) {
            visited.add(artifactId);
        }
        try {
            const wrappedJson = JSON.stringify(wrappedArtifact);
            const nativeAgent = this.client._agent;
            const verifyWithPolicy = nativeAgent?.verifyA2aArtifactWithPolicySync;
            const verifyCanonical = nativeAgent?.verifyA2aArtifactSync;
            const verifyLegacy = nativeAgent?.verifyResponse;
            let canonical;
            let canonicalIsNative = false;
            const requestedPolicy = options?.policy?.toLowerCase();
            const requiresPolicyVerifier = requestedPolicy === exports.TRUST_POLICIES.VERIFIED
                || requestedPolicy === exports.TRUST_POLICIES.STRICT;
            if (requiresPolicyVerifier && typeof verifyWithPolicy !== 'function') {
                const reason = `${canonicalPolicyName(options?.policy)} policy requires the canonical native `
                    + 'verifyA2aArtifactWithPolicySync() verifier; legacy verifyResponse() fallback is not trusted';
                canonical = {
                    valid: false,
                    status: { Invalid: { reason } },
                    signerId: '',
                    signerVersion: '',
                    artifactType: '',
                    timestamp: '',
                    originalArtifact: {},
                    parentSignaturesValid: false,
                    parentVerificationResults: [],
                };
            }
            else if (options?.policy && options.agentCard && typeof verifyWithPolicy === 'function') {
                const canonicalJson = verifyWithPolicy.call(nativeAgent, wrappedJson, JSON.stringify(options.agentCard), options.policy);
                canonical = JSON.parse(canonicalJson);
                canonicalIsNative = true;
            }
            else if (typeof verifyCanonical === 'function') {
                const canonicalJson = verifyCanonical.call(nativeAgent, wrappedJson);
                canonical = JSON.parse(canonicalJson);
                canonicalIsNative = true;
            }
            else if (typeof verifyLegacy === 'function') {
                // Generic document verification has no canonical A2A output contract.
                // Even literal true cannot authenticate parsed provenance fields or a
                // parent chain, so never invoke verifyResponse() as an A2A fallback.
                canonical = {
                    valid: false,
                    status: {
                        Invalid: {
                            reason: 'A2A verification requires the canonical native verifyA2aArtifactSync() '
                                + 'verifier; legacy verifyResponse() cannot establish A2A validity',
                        },
                    },
                    signerId: '',
                    signerVersion: '',
                    artifactType: '',
                    timestamp: '',
                    originalArtifact: {},
                    parentVerificationResults: [],
                    parentSignaturesValid: false,
                };
            }
            else {
                throw new Error('A2A verification requires verifyA2aArtifactWithPolicySync(), '
                    + 'or verifyA2aArtifactSync() on client._agent.');
            }
            const hasCanonicalTrustAssessment = canonical.trustAssessment
                && typeof canonical.trustAssessment === 'object'
                && !Array.isArray(canonical.trustAssessment);
            if (options?.policy && options.agentCard && !hasCanonicalTrustAssessment) {
                const trustAssessment = canonicalIsNative
                    ? this._buildCanonicalTrustAssessment(options.agentCard, options.policy)
                    : {
                        allowed: false,
                        trustLevel: 'Untrusted',
                        jacsRegistered: false,
                        reason: 'canonical native A2A verification is unavailable; '
                            + 'legacy verification cannot elevate trust',
                        policy: canonicalPolicyName(options.policy),
                        agentId: null,
                        firstContact: false,
                    };
                canonical = {
                    ...canonical,
                    trustLevel: canonicalTrustLevel(trustAssessment.trustLevel),
                    trustAssessment,
                };
            }
            const result = this._canonicalResultFromWrappedArtifact(wrappedArtifact, canonical, options?.policy ?? this.trustPolicy);
            return this._attachCompatibilityAliases(result, {
                rawVerificationResult: canonical,
            });
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
            return JSON.parse((0, index_js_1.buildJwkSetFromPublicKey)(publicKeyB64, keyAlgorithm, kid));
        }
        catch {
            return { keys: [] };
        }
    }
    _slugify(name) {
        return name
            .toLowerCase()
            .replace(/[\s_]+/g, '-')
            .replace(/[^a-z0-9-]/g, '');
    }
    _normalizeA2ASkills(rawSkills) {
        const skills = [];
        for (const rawSkill of rawSkills) {
            if (rawSkill instanceof A2AAgentSkill) {
                skills.push(rawSkill);
                continue;
            }
            const name = String(rawSkill.name || rawSkill.id || 'unnamed');
            skills.push(new A2AAgentSkill({
                id: String(rawSkill.id || this._slugify(name)),
                name,
                description: String(rawSkill.description || ''),
                tags: Array.isArray(rawSkill.tags) ? rawSkill.tags.map(String) : ['jacs'],
                examples: Array.isArray(rawSkill.examples) ? rawSkill.examples.map(String) : null,
                inputModes: Array.isArray(rawSkill.inputModes) ? rawSkill.inputModes.map(String) : null,
                outputModes: Array.isArray(rawSkill.outputModes) ? rawSkill.outputModes.map(String) : null,
                security: Array.isArray(rawSkill.security) ? rawSkill.security : null,
            }));
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