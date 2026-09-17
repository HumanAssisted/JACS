/**
 * JACS A2A (Agent-to-Agent) Protocol Integration for Node.js
 *
 * This module provides Node.js bindings for JACS's A2A protocol integration,
 * enabling JACS agents to participate in the Agent-to-Agent communication protocol.
 *
 * Implements A2A protocol v0.4.0 (September 2025).
 */

import {
  hashString,
  hashPublicKeyBase64,
  buildJwkSetFromPublicKey,
} from './index.js';
import type { JacsClient } from './client.js';
import type { Server } from 'http';
import { warnDeprecated } from './deprecation.js';
import { requirePortableV2SignedDocument } from './output-policy.js';

// =============================================================================
// Constants
// =============================================================================

export const A2A_PROTOCOL_VERSION = '0.4.0';

export const JACS_EXTENSION_URI = 'urn:jacs:provenance-v1';

export const JACS_ALGORITHMS: readonly string[] = [
  'ring-Ed25519',
  'pq2025',
] as const;

export const TRUST_POLICIES = {
  OPEN: 'open' as const,
  VERIFIED: 'verified' as const,
  STRICT: 'strict' as const,
};

export type TrustPolicy = 'open' | 'verified' | 'strict';

export const DEFAULT_TRUST_POLICY: TrustPolicy = TRUST_POLICIES.VERIFIED;

// =============================================================================
// Utility
// =============================================================================

export function sha256(data: string): string {
  return hashString(data);
}

// =============================================================================
// A2A Data Types (v0.4.0)
// =============================================================================

export class A2AAgentInterface {
  url: string;
  protocolBinding: string;
  tenant?: string;

  constructor(url: string, protocolBinding: string, tenant: string | null = null) {
    this.url = url;
    this.protocolBinding = protocolBinding;
    if (tenant) {
      this.tenant = tenant;
    }
  }
}

export interface A2AAgentSkillOptions {
  id: string;
  name: string;
  description: string;
  tags: string[];
  examples?: string[] | null;
  inputModes?: string[] | null;
  outputModes?: string[] | null;
  security?: unknown[] | null;
}

export class A2AAgentSkill {
  id: string;
  name: string;
  description: string;
  tags: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
  security?: unknown[];

  constructor({
    id,
    name,
    description,
    tags,
    examples = null,
    inputModes = null,
    outputModes = null,
    security = null,
  }: A2AAgentSkillOptions) {
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

export class A2AAgentExtension {
  uri: string;
  description?: string;
  required?: boolean;

  constructor(uri: string, description: string | null = null, required: boolean | null = null) {
    this.uri = uri;
    if (description !== null) this.description = description;
    if (required !== null) this.required = required;
  }
}

export interface A2AAgentCapabilitiesOptions {
  streaming?: boolean | null;
  pushNotifications?: boolean | null;
  extendedAgentCard?: boolean | null;
  extensions?: A2AAgentExtension[] | null;
}

export class A2AAgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  extendedAgentCard?: boolean;
  extensions?: A2AAgentExtension[];

  constructor({
    streaming = null,
    pushNotifications = null,
    extendedAgentCard = null,
    extensions = null,
  }: A2AAgentCapabilitiesOptions = {}) {
    if (streaming !== null) this.streaming = streaming;
    if (pushNotifications !== null) this.pushNotifications = pushNotifications;
    if (extendedAgentCard !== null) this.extendedAgentCard = extendedAgentCard;
    if (extensions) this.extensions = extensions;
  }
}

export class A2AAgentCardSignature {
  jws: string;
  keyId?: string;

  constructor(jws: string, keyId: string | null = null) {
    this.jws = jws;
    if (keyId) this.keyId = keyId;
  }
}

export interface A2AAgentCardOptions {
  name: string;
  description: string;
  version: string;
  protocolVersions: string[];
  supportedInterfaces: A2AAgentInterface[];
  defaultInputModes: string[];
  defaultOutputModes: string[];
  capabilities: A2AAgentCapabilities;
  skills: A2AAgentSkill[];
  provider?: unknown;
  documentationUrl?: string | null;
  iconUrl?: string | null;
  securitySchemes?: Record<string, unknown> | null;
  security?: unknown[] | null;
  signatures?: A2AAgentCardSignature[] | null;
  metadata?: Record<string, unknown> | null;
}

export class A2AAgentCard {
  name: string;
  description: string;
  version: string;
  protocolVersions: string[];
  supportedInterfaces: A2AAgentInterface[];
  defaultInputModes: string[];
  defaultOutputModes: string[];
  capabilities: A2AAgentCapabilities;
  skills: A2AAgentSkill[];
  provider?: unknown;
  documentationUrl?: string;
  iconUrl?: string;
  securitySchemes?: Record<string, unknown>;
  security?: unknown[];
  signatures?: A2AAgentCardSignature[];
  metadata?: Record<string, unknown>;

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
    metadata = null,
  }: A2AAgentCardOptions) {
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

// =============================================================================
// Verification Result
// =============================================================================

export interface TrustBlock {
  policy: string | null;
  status: 'allowed' | 'blocked' | 'not_assessed';
  reason: string;
}

export type VerificationStatus =
  | 'Verified'
  | 'SelfSigned'
  | { Unverified: { reason: string } }
  | { Invalid: { reason: string } };

export interface ParentVerificationResult {
  index: number;
  artifactId: string;
  signerId: string;
  status: VerificationStatus;
  verified: boolean;
  /** Backward-compatibility alias exposed as a non-enumerable property at runtime. */
  valid?: boolean;
}

export interface ArtifactVerificationResult {
  valid: boolean;
  status: VerificationStatus;
  /**
   * @deprecated Canonical A2A verification exposes authenticated payload data
   * through originalArtifact. Legacy verifyResponse() output is never
   * projected into an A2A verification result.
   */
  verifiedPayload?: Record<string, unknown>;
  /**
   * Backward-compatibility field: raw verification output.
   */
  verificationResult?: boolean | Record<string, unknown>;
  signerId: string;
  signerVersion: string;
  artifactType: string;
  timestamp: string;
  originalArtifact: Record<string, unknown>;
  trustLevel?: 'Untrusted' | 'JacsVerified' | 'ExplicitlyTrusted';
  parentSignaturesValid: boolean;
  parentVerificationResults: ParentVerificationResult[];
  parentSignaturesCount?: number;
  /** Trust assessment block, present when policy-aware verify is used. */
  trust?: TrustBlock;
  trustAssessment?: TrustAssessment;
}

// =============================================================================
// Trust Assessment
// =============================================================================

export interface TrustAssessment {
  allowed: boolean;
  trustLevel:
    | 'ExplicitlyTrusted'
    | 'JacsVerified'
    | 'Untrusted'
    | 'trusted'
    | 'jacs_registered'
    | 'untrusted';
  jacsRegistered: boolean;
  inTrustStore: boolean;
  reason: string;
  policy?: string;
  agentId?: string | null;
  /** True only when the verifying origin key was pinned during this assessment. */
  firstContact: boolean;
}

/** Map binding-core's canonical trustAssessment to the wrapper's trust block. */
function buildTrustBlock(trustAssessment: Record<string, unknown>): TrustBlock {
  return {
    policy: (trustAssessment.policy as string) ?? null,
    status: trustAssessment.allowed ? 'allowed' : 'blocked',
    reason: (trustAssessment.reason as string) ?? '',
  };
}

function canonicalPolicyName(policy: string | undefined): string | undefined {
  if (!policy) return undefined;
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

function canonicalTrustLevel(level: unknown): 'ExplicitlyTrusted' | 'JacsVerified' | 'Untrusted' {
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

function legacyTrustLevel(level: unknown): 'trusted' | 'jacs_registered' | 'untrusted' {
  switch (canonicalTrustLevel(level)) {
    case 'ExplicitlyTrusted':
      return 'trusted';
    case 'JacsVerified':
      return 'jacs_registered';
    default:
      return 'untrusted';
  }
}

function normalizeVerificationStatus(
  status: unknown,
  valid: boolean,
  reason = '',
): VerificationStatus {
  if (valid && (status === 'Verified' || status === 'SelfSigned')) {
    return status;
  }
  if (status && typeof status === 'object') {
    const statusObj = status as Record<string, unknown>;
    const unverified = statusObj.Unverified as Record<string, unknown> | undefined;
    if (unverified && typeof unverified === 'object') {
      return { Unverified: { reason: String(unverified.reason ?? reason) } };
    }
    const invalid = statusObj.Invalid as Record<string, unknown> | undefined;
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

function defineHiddenProperty<T extends object, K extends PropertyKey>(
  target: T,
  key: K,
  value: unknown,
): void {
  Object.defineProperty(target, key, {
    configurable: true,
    enumerable: false,
    writable: true,
    value,
  });
}

function stableJsonValue(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJsonValue(item)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
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
// Quickstart Options
// =============================================================================

export interface A2AQuickstartOptions {
  url?: string;
  name?: string;
  domain?: string;
  description?: string;
  /**
   * @deprecated Wrapper-supplied skills cannot be added after the native Agent
   * Card is signed. Non-empty values fail immediately; persist skills through
   * the native agent/card configuration before generating discovery documents.
   */
  skills?: Array<{ id: string; name: string; description: string; tags: string[] }>;
  trustPolicy?: TrustPolicy;
  algorithm?: string;
  configPath?: string;
}

// =============================================================================
// Agent Data
// =============================================================================

export interface AgentData {
  jacsId?: string;
  jacsName?: string;
  jacsDescription?: string;
  jacsVersion?: string;
  jacsAgentType?: string;
  jacsAgentDomain?: string;
  skills?: Array<A2AAgentSkill | (Partial<A2AAgentSkillOptions> & { [key: string]: unknown })>;
  a2aSkills?: Array<A2AAgentSkill | (Partial<A2AAgentSkillOptions> & { [key: string]: unknown })>;
  keyAlgorithm?: string;
  jwks?: { keys: unknown[] };
  jwk?: Record<string, unknown>;
  [key: string]: unknown;
}

// =============================================================================
// JACS A2A Integration
// =============================================================================

export class JACSA2AIntegration {
  client: JacsClient;
  trustPolicy: TrustPolicy;
  defaultUrl?: string | null;
  /** Compatibility assertion only; cannot mutate the native signed Agent Card. */
  defaultSkills?: Array<{ id: string; name: string; description: string; tags: string[] }> | null;

  constructor(client: JacsClient, trustPolicy?: TrustPolicy) {
    this.client = client;
    this.trustPolicy = trustPolicy || DEFAULT_TRUST_POLICY;
  }

  static async quickstart(options: A2AQuickstartOptions = {}): Promise<JACSA2AIntegration> {
    const { url, name, domain, description, skills, trustPolicy, algorithm, configPath } = options;
    if (skills != null && (!Array.isArray(skills) || skills.length > 0)) {
      throw new Error(
        'A2A quickstart skills are deprecated: wrapper-supplied skills cannot be added after '
        + 'the native Agent Card is signed. Persist skills in the native agent/card workflow '
        + 'before generating discovery documents.',
      );
    }
    let JacsClientCtor: typeof JacsClient;
    try {
      JacsClientCtor = require('./client').JacsClient;
    } catch {
      JacsClientCtor = require('./client.js').JacsClient;
    }

    const derivedDomain = domain || (url ? (() => {
      try {
        return new URL(url).hostname;
      } catch {
        return 'localhost';
      }
    })() : 'localhost');

    const client = await JacsClientCtor.quickstart({
      algorithm: algorithm || undefined,
      configPath: configPath || undefined,
      name: name || 'jacs-agent',
      domain: derivedDomain,
      description: description || 'JACS A2A agent',
    } as any);

    const integration = new JACSA2AIntegration(client, trustPolicy || DEFAULT_TRUST_POLICY);
    integration.defaultUrl = url || null;
    integration.defaultSkills = null;
    return integration;
  }

  /**
   * Start a minimal Express discovery server for this agent.
   *
   * Pass `port = 0` to let the OS pick an available ephemeral port.
   */
  listen(port: number = 8080): Server {
    let express: any;
    try {
      express = require('express');
    } catch {
      throw new Error('listen() requires express. Install it with: npm install express');
    }

    const app = express();

    const agentData: AgentData = {
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
      cardJson.skills = this.defaultSkills.map((s: any) => {
        if (s instanceof A2AAgentSkill) return s;
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
    if (
      this.defaultSkills
      && JSON.stringify(nativeCard.skills || []) !== JSON.stringify(cardJson.skills || [])
    ) {
      throw new Error(
        "Cannot override A2A skills after the Agent Card is signed; configure the agent's skills before listen()",
      );
    }
    const signedInterfaceUrl = (nativeCard.supportedInterfaces as Array<Record<string, unknown>> | undefined)
      ?.[0]?.url;
    if (this.defaultUrl) {
      let requestedOrigin: string;
      let signedOrigin: string;
      try {
        requestedOrigin = new URL(this.defaultUrl).origin;
        signedOrigin = new URL(String(signedInterfaceUrl)).origin;
      } catch (error) {
        throw new Error(`Invalid configured or signed A2A public URL: ${String(error)}`);
      }
      if (requestedOrigin !== signedOrigin) {
        throw new Error(
          `Configured A2A public origin '${requestedOrigin}' does not match the signed Agent Card origin '${signedOrigin}'`,
        );
      }
    }

    for (const [path, document] of Object.entries(documents)) {
      app.get(path, (_req: any, res: any) => {
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
      console.log(
        `A2A listener http://localhost:${boundPort}${requested}; signed public discovery origin ${publicOrigin}`,
      );
    });

    return server;
  }

  exportAgentCard(agentData: AgentData): A2AAgentCard {
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

    const securitySchemes: Record<string, unknown> = {
      'bearer-jwt': { type: 'http', scheme: 'Bearer', bearerFormat: 'JWT' },
      'api-key': { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    };

    const jacsExtension = new A2AAgentExtension(
      JACS_EXTENSION_URI,
      'JACS cryptographic document signing and verification',
      false,
    );

    const capabilities = new A2AAgentCapabilities({ extensions: [jacsExtension] });

    const metadata: Record<string, unknown> = {
      jacsAgentType: agentData.jacsAgentType,
      jacsId: agentId,
      jacsVersion: agentData.jacsVersion,
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
      metadata,
    });
  }

  createExtensionDescriptor(): Record<string, unknown> {
    return {
      uri: JACS_EXTENSION_URI,
      name: 'JACS Document Provenance',
      version: '1.0',
      a2aProtocolVersion: A2A_PROTOCOL_VERSION,
      description:
        'Provides cryptographic document signing and verification with post-quantum support',
      specification: 'https://jacs.ai/specs/a2a-extension',
      capabilities: {
        documentSigning: {
          description: 'Sign documents with JACS signatures',
          algorithms: [...JACS_ALGORITHMS],
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
  assessRemoteAgent(agentCardJson: string | Record<string, unknown>): TrustAssessment {
    const cardJson = typeof agentCardJson === 'string'
      ? agentCardJson
      : JSON.stringify(agentCardJson);
    const card = JSON.parse(cardJson) as Record<string, unknown>;
    const nativeAssess = (this.client as any)._agent?.assessA2aAgentSync;
    if (typeof nativeAssess === 'function') {
      const canonicalJson = nativeAssess.call((this.client as any)._agent, cardJson, this.trustPolicy);
      const canonical = JSON.parse(canonicalJson) as Record<string, unknown>;
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
  trustA2AAgent(
    agentDocumentJson: string | Record<string, unknown>,
    publicKeyPem: string,
  ): string {
    if (typeof publicKeyPem !== 'string' || publicKeyPem.trim().length === 0) {
      throw new Error('Cannot establish A2A identity trust without an explicit public key');
    }
    const documentString = typeof agentDocumentJson === 'string'
      ? agentDocumentJson
      : JSON.stringify(agentDocumentJson);
    let document: Record<string, unknown>;
    try {
      document = JSON.parse(documentString) as Record<string, unknown>;
    } catch (error) {
      throw new Error(`Invalid native JACS agent document JSON: ${String(error)}`);
    }
    if (
      !document
      || typeof document !== 'object'
      || !('jacsId' in document)
      || !('jacsVersion' in document)
      || !('jacsSignature' in document)
    ) {
      throw new Error(
        'trustA2AAgent requires the full native JACS agent document, not an unauthenticated Agent Card',
      );
    }
    const trustWithKey = (this.client as any).trustAgentWithKey;
    if (typeof trustWithKey !== 'function') {
      throw new Error(
        'The configured JacsClient does not expose trustAgentWithKey; strict A2A trust cannot be established',
      );
    }
    return trustWithKey.call(this.client, documentString, publicKeyPem);
  }

  /**
   * Sign through the native canonical A2A primitive and return the direct
   * `a2a-*` document. Generic request-envelope fallback is never used. The
   * returned portable-v2 metadata and parent chain must exactly match the
   * requested artifact contract before any result is released.
   */
  async signArtifact(
    artifact: Record<string, unknown>,
    artifactType: string,
    parentSignatures: Record<string, unknown>[] | null = null,
  ): Promise<Record<string, unknown>> {
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
    if (parentSignatures) stableJsonValue(parentSignatures);

    const nativeAgent = (this.client as any)._agent;
    const nativeSign = nativeAgent?.signArtifactSync;
    if (typeof nativeSign !== 'function') {
      throw new Error(
        'Native signArtifactSync is required for canonical A2A artifact signing; '
        + 'generic signRequest fallback is disabled',
      );
    }

    let raw: unknown;
    try {
      raw = nativeSign.call(
        nativeAgent,
        JSON.stringify(artifact),
        artifactType,
        parentSignatures ? JSON.stringify(parentSignatures) : null,
      );
    } catch (error) {
      throw new Error(`Native A2A signing failed: ${String(error)}`);
    }
    if (typeof raw !== 'string' || raw.trim().length === 0) {
      throw new TypeError('Native A2A signing returned no canonical JSON document');
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new TypeError(`Native A2A signing returned invalid JSON: ${String(error)}`);
    }
    const signed = requirePortableV2SignedDocument(parsed, 'Native A2A signing');
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
  async wrapArtifactWithProvenance(
    artifact: Record<string, unknown>,
    artifactType: string,
    parentSignatures: Record<string, unknown>[] | null = null,
  ): Promise<Record<string, unknown>> {
    warnDeprecated('wrapArtifactWithProvenance', 'signArtifact');
    return this.signArtifact(artifact, artifactType, parentSignatures);
  }

  /**
   * Verify artifact cryptography and its parent chain. Supply the real remote
   * Agent Card to additionally enforce this integration's trust policy.
   * Affirmative verification requires the native canonical
   * verifyA2aArtifactSync contract. Legacy verifyResponse is never used as an
   * A2A fallback and cannot project provenance or elevate trust.
   */
  async verifyWrappedArtifact(
    wrappedArtifact: Record<string, unknown>,
    agentCard?: Record<string, unknown>,
  ): Promise<ArtifactVerificationResult> {
    // Cryptographic artifact validity is available without an Agent Card.
    // Trust-policy assessment is a separate operation and requires the real,
    // identity-bound remote card; never synthesize one from artifact claims.
    const options = agentCard
      ? { policy: this.trustPolicy, agentCard }
      : { policy: this.trustPolicy };
    return this._verifyWrappedArtifactInternal(wrappedArtifact, new Set<string>(), options);
  }

  createChainOfCustody(artifacts: Record<string, unknown>[]): Record<string, unknown> {
    const chain: Record<string, unknown>[] = [];

    for (const artifact of artifacts) {
      const sig = artifact.jacsSignature as Record<string, unknown> | undefined;
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

  generateWellKnownDocuments(
    agentCard: A2AAgentCard,
    jwsSignature: string,
    publicKeyB64: string,
    agentData: AgentData,
  ): Record<string, Record<string, unknown>> {
    // These parameters remain for source compatibility only. Identity-bearing
    // discovery documents must come from the native generator as one
    // card/JWKS/binding unit; wrapper inputs can never replace signed fields.
    void agentCard;
    void jwsSignature;
    void publicKeyB64;
    void agentData;

    const nativeGenerate = (this.client as any)._agent?.generateWellKnownDocumentsSync;
    if (typeof nativeGenerate !== 'function') {
      throw new Error(
        'Identity-bound A2A discovery requires the native JACS generator; '
        + 'legacy wrapper-generated keys and signatures are not trusted',
      );
    }

    let nativePairs: unknown;
    try {
      const nativeJson = nativeGenerate.call((this.client as any)._agent);
      nativePairs = JSON.parse(nativeJson);
    } catch (error) {
      throw new Error(`Identity-bound A2A discovery generation failed: ${String(error)}`);
    }
    if (!Array.isArray(nativePairs)) {
      throw new Error('Native A2A discovery result must be an array of path/document pairs');
    }

    const documents: Record<string, Record<string, unknown>> = {};
    for (const item of nativePairs) {
      if (
        !item
        || typeof item !== 'object'
        || typeof (item as any).path !== 'string'
        || !(item as any).document
        || typeof (item as any).document !== 'object'
        || Array.isArray((item as any).document)
      ) {
        throw new Error('Native A2A discovery returned a malformed path/document pair');
      }
      const path = (item as any).path as string;
      if (Object.prototype.hasOwnProperty.call(documents, path)) {
        throw new Error(`Native A2A discovery returned duplicate path '${path}'`);
      }
      documents[path] = (item as any).document as Record<string, unknown>;
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
    const metadata = card.metadata as Record<string, unknown> | undefined;
    const signatures = card.signatures as Array<Record<string, unknown>> | undefined;
    if (
      !metadata
      || metadata.jacsCompatBindingPath !== '/.well-known/jacs-compat-binding.json'
      || !Array.isArray(signatures)
      || signatures.length === 0
      || typeof signatures[0]?.jws !== 'string'
      || !signatures[0].jws
      || signatures[0].keyId !== metadata.jacsCompatKid
    ) {
      throw new Error('Native A2A Agent Card is missing its bound ES256 signature metadata');
    }

    const jwks = documents['/.well-known/jwks.json'].keys as Array<Record<string, unknown>> | undefined;
    if (
      !Array.isArray(jwks)
      || !jwks.some((key) => (
        key?.kid === metadata.jacsCompatKid
        && key.alg === 'ES256'
        && key.use === 'sig'
      ))
    ) {
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

  private _hasJacsExtension(card: Record<string, unknown>): boolean {
    const capabilities = card.capabilities as Record<string, unknown> | undefined;
    const extensions = capabilities?.extensions as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(extensions)) return false;
    return extensions.some((ext) => ext && ext.uri === JACS_EXTENSION_URI);
  }

  private _legacyAssessRemoteAgent(
    card: Record<string, unknown>,
    policy: TrustPolicy,
  ): TrustAssessment {
    const metadata = card.metadata as Record<string, unknown> | undefined;
    const agentId = typeof metadata?.jacsId === 'string' ? metadata.jacsId : null;
    const jacsRegistered = this._hasJacsExtension(card);

    let allowed: boolean;
    let reason: string;
    switch (policy) {
      case TRUST_POLICIES.OPEN:
        allowed = true;
        reason = 'Open policy: agent allowed without native cryptographic assessment; no identity assurance is claimed';
        break;
      case TRUST_POLICIES.STRICT:
      case TRUST_POLICIES.VERIFIED:
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

  private _buildCanonicalTrustAssessment(
    agentCard: Record<string, unknown>,
    policy: string,
  ): TrustAssessment {
    const legacy = this._legacyAssessRemoteAgent(agentCard, policy as TrustPolicy);
    const trustAssessment = {
      allowed: legacy.allowed,
      trustLevel: canonicalTrustLevel(legacy.trustLevel),
      jacsRegistered: legacy.jacsRegistered,
      reason: legacy.reason,
      policy: canonicalPolicyName(policy),
      agentId: legacy.agentId ?? null,
      firstContact: legacy.firstContact === true,
    } as TrustAssessment;
    defineHiddenProperty(
      trustAssessment,
      'inTrustStore',
      trustAssessment.trustLevel === 'ExplicitlyTrusted',
    );
    return trustAssessment;
  }

  private _normalizeTrustAssessment(
    trustAssessment: Record<string, unknown>,
    fallbackPolicy: string,
  ): TrustAssessment {
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
        ? trustAssessment.agentId as string | null
        : null,
      firstContact: trustAssessment.firstContact === true,
    } as TrustAssessment;
    defineHiddenProperty(
      normalized,
      'inTrustStore',
      normalized.trustLevel === 'ExplicitlyTrusted',
    );
    return normalized;
  }

  private _normalizeParentVerificationResult(
    parentResult: unknown,
    index: number,
  ): ParentVerificationResult {
    const canonicalParent = parentResult && typeof parentResult === 'object' && !Array.isArray(parentResult)
      ? parentResult as Record<string, unknown>
      : {};
    // Parent-chain integrity is affirmative evidence, not a default. Missing,
    // string, numeric, compatibility-alias, and status-contradictory values all
    // fail closed.
    const parentStatusIsVerified = canonicalParent.status === 'Verified'
      || canonicalParent.status === 'SelfSigned';
    const verified = canonicalParent.verified === true && parentStatusIsVerified;
    const normalized: ParentVerificationResult = {
      index: Number.isInteger(canonicalParent.index) ? canonicalParent.index as number : index,
      artifactId: String(canonicalParent.artifactId ?? ''),
      signerId: String(canonicalParent.signerId ?? ''),
      status: normalizeVerificationStatus(canonicalParent.status, verified),
      verified,
    };
    defineHiddenProperty(normalized, 'valid', normalized.verified);
    return normalized;
  }

  private _canonicalResultFromWrappedArtifact(
    wrappedArtifact: Record<string, unknown>,
    canonical: Record<string, unknown>,
    fallbackPolicy: string,
  ): ArtifactVerificationResult {
    const wrappedParents = Array.isArray(wrappedArtifact.jacsParentSignatures)
      ? wrappedArtifact.jacsParentSignatures
      : [];
    const parentResults = Array.isArray(canonical.parentVerificationResults)
      ? canonical.parentVerificationResults.map(
        (parent, index) => this._normalizeParentVerificationResult(parent, index),
      )
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
      ? canonical.originalArtifact as Record<string, unknown>
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
    const result: ArtifactVerificationResult = {
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

    if (
      canonical.trustAssessment
      && typeof canonical.trustAssessment === 'object'
      && !Array.isArray(canonical.trustAssessment)
    ) {
      result.trustAssessment = this._normalizeTrustAssessment(
        canonical.trustAssessment as Record<string, unknown>,
        fallbackPolicy,
      );
      result.trustLevel = canonicalTrustLevel(result.trustAssessment.trustLevel);
      if (!result.trustAssessment.allowed) {
        result.valid = false;
        result.status = { Invalid: { reason: result.trustAssessment.reason } };
      }
    }

    return result;
  }

  private _attachCompatibilityAliases(
    result: ArtifactVerificationResult,
    options: {
      rawVerificationResult?: boolean | Record<string, unknown>;
      verifiedPayload?: Record<string, unknown>;
    } = {},
  ): ArtifactVerificationResult {
    defineHiddenProperty(result, 'parentSignaturesCount', result.parentVerificationResults.length);
    if (options.rawVerificationResult !== undefined) {
      defineHiddenProperty(result, 'verificationResult', options.rawVerificationResult);
    }
    if (options.verifiedPayload) {
      defineHiddenProperty(result, 'verifiedPayload', options.verifiedPayload);
    }
    if (result.trustAssessment) {
      defineHiddenProperty(
        result,
        'trust',
        buildTrustBlock(result.trustAssessment as unknown as Record<string, unknown>),
      );
    }
    return result;
  }

  private _verifyWrappedArtifactInternal(
    wrappedArtifact: Record<string, unknown>,
    visited: Set<string>,
    options?: { policy?: string; agentCard?: Record<string, unknown> },
  ): ArtifactVerificationResult {
    const artifactId = wrappedArtifact.jacsId as string | undefined;
    if (artifactId && visited.has(artifactId)) {
      throw new Error(`Cycle detected in parent signature chain at artifact ${artifactId}`);
    }
    if (artifactId) {
      visited.add(artifactId);
    }

    try {
      const wrappedJson = JSON.stringify(wrappedArtifact);
      const nativeAgent = (this.client as any)._agent;
      const verifyWithPolicy = nativeAgent?.verifyA2aArtifactWithPolicySync;
      const verifyCanonical = nativeAgent?.verifyA2aArtifactSync;
      const verifyLegacy = nativeAgent?.verifyResponse;

      let canonical: Record<string, unknown>;
      let canonicalIsNative = false;
      const requestedPolicy = options?.policy?.toLowerCase();
      const requiresPolicyVerifier = requestedPolicy === TRUST_POLICIES.VERIFIED
        || requestedPolicy === TRUST_POLICIES.STRICT;

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
      } else if (options?.policy && options.agentCard && typeof verifyWithPolicy === 'function') {
        const canonicalJson = verifyWithPolicy.call(
          nativeAgent,
          wrappedJson,
          JSON.stringify(options.agentCard),
          options.policy,
        );
        canonical = JSON.parse(canonicalJson) as Record<string, unknown>;
        canonicalIsNative = true;
      } else if (typeof verifyCanonical === 'function') {
        const canonicalJson = verifyCanonical.call(nativeAgent, wrappedJson);
        canonical = JSON.parse(canonicalJson) as Record<string, unknown>;
        canonicalIsNative = true;
      } else if (typeof verifyLegacy === 'function') {
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
      } else {
        throw new Error(
          'A2A verification requires verifyA2aArtifactWithPolicySync(), '
          + 'or verifyA2aArtifactSync() on client._agent.',
        );
      }

      const hasCanonicalTrustAssessment = canonical.trustAssessment
        && typeof canonical.trustAssessment === 'object'
        && !Array.isArray(canonical.trustAssessment);
      if (options?.policy && options.agentCard && !hasCanonicalTrustAssessment) {
        const trustAssessment = canonicalIsNative
          ? this._buildCanonicalTrustAssessment(options.agentCard, options.policy)
          : {
            allowed: false,
            trustLevel: 'Untrusted' as const,
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

      const result = this._canonicalResultFromWrappedArtifact(
        wrappedArtifact,
        canonical,
        options?.policy ?? this.trustPolicy,
      );
      return this._attachCompatibilityAliases(result, {
        rawVerificationResult: canonical,
      });
    } finally {
      if (artifactId) {
        visited.delete(artifactId);
      }
    }
  }

  private _buildJwks(
    publicKeyB64: string,
    agentData: AgentData = {},
  ): Record<string, unknown> {
    if (agentData.jwks && Array.isArray(agentData.jwks.keys)) {
      return agentData.jwks;
    }
    if (agentData.jwk && typeof agentData.jwk === 'object') {
      return { keys: [agentData.jwk] };
    }

    const keyAlgorithm = String(agentData.keyAlgorithm || '').toLowerCase();
    const kid = String(agentData.jacsId || 'jacs-agent');

    try {
      return JSON.parse(buildJwkSetFromPublicKey(publicKeyB64, keyAlgorithm, kid));
    } catch {
      return { keys: [] };
    }
  }

  _slugify(name: string): string {
    return name
      .toLowerCase()
      .replace(/[\s_]+/g, '-')
      .replace(/[^a-z0-9-]/g, '');
  }

  private _normalizeA2ASkills(
    rawSkills: NonNullable<AgentData['skills']>,
  ): A2AAgentSkill[] {
    const skills: A2AAgentSkill[] = [];

    for (const rawSkill of rawSkills) {
      if (rawSkill instanceof A2AAgentSkill) {
        skills.push(rawSkill);
        continue;
      }
      const name = String(rawSkill.name || rawSkill.id || 'unnamed');
      skills.push(
        new A2AAgentSkill({
          id: String(rawSkill.id || this._slugify(name)),
          name,
          description: String(rawSkill.description || ''),
          tags: Array.isArray(rawSkill.tags) ? rawSkill.tags.map(String) : ['jacs'],
          examples: Array.isArray(rawSkill.examples) ? rawSkill.examples.map(String) : null,
          inputModes: Array.isArray(rawSkill.inputModes) ? rawSkill.inputModes.map(String) : null,
          outputModes: Array.isArray(rawSkill.outputModes) ? rawSkill.outputModes.map(String) : null,
          security: Array.isArray(rawSkill.security) ? rawSkill.security : null,
        }),
      );
    }

    if (skills.length === 0) {
      skills.push(
        new A2AAgentSkill({
          id: 'verify-signature',
          name: 'verify_signature',
          description: 'Verify JACS document signatures',
          tags: ['jacs', 'verification', 'cryptography'],
          examples: ['Verify a signed JACS document', 'Check document signature integrity'],
          inputModes: ['application/json'],
          outputModes: ['application/json'],
        }),
      );
    }

    return skills;
  }
}
