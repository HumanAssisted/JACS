/**
 * JACS A2A (Agent-to-Agent) Protocol Integration for Node.js
 *
 * This module provides Node.js bindings for JACS's A2A protocol integration,
 * enabling JACS agents to participate in the Agent-to-Agent communication protocol.
 *
 * Implements A2A protocol v0.4.0 (September 2025).
 */

import { v4 as uuidv4 } from 'uuid';
import { createPublicKey, createHash, type KeyObject } from 'crypto';
import type { JacsClient } from './client.js';
import type { Server } from 'http';

// =============================================================================
// Constants
// =============================================================================

export const A2A_PROTOCOL_VERSION = '0.4.0';

export const JACS_EXTENSION_URI = 'urn:hai.ai:jacs-provenance-v1';

export const JACS_ALGORITHMS: readonly string[] = [
  'ring-Ed25519',
  'RSA-PSS',
  'pq-dilithium',
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
  return createHash('sha256').update(data).digest('hex');
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

export interface ArtifactVerificationResult {
  valid: boolean;
  /**
   * Extracted payload returned by native verifyResponse() when available.
   */
  verifiedPayload?: Record<string, unknown>;
  /**
   * Backward-compatibility field for one release: raw native verifyResponse() output.
   */
  verificationResult?: boolean | Record<string, unknown>;
  signerId: string;
  signerVersion: string;
  artifactType: string;
  timestamp: string;
  originalArtifact: Record<string, unknown>;
  parentSignaturesCount?: number;
  parentVerificationResults?: Array<{
    index: number;
    artifactId: string;
    valid: boolean;
    parentSignaturesValid: boolean;
    error?: string;
  }>;
  parentSignaturesValid?: boolean;
  trustAssessment?: TrustAssessment;
}

// =============================================================================
// Trust Assessment
// =============================================================================

export interface TrustAssessment {
  allowed: boolean;
  trustLevel: 'trusted' | 'jacs_registered' | 'untrusted';
  jacsRegistered: boolean;
  inTrustStore: boolean;
  reason: string;
}

// =============================================================================
// Quickstart Options
// =============================================================================

export interface A2AQuickstartOptions {
  url?: string;
  name?: string;
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
  jacsServices?: Array<{
    name?: string;
    serviceDescription?: string;
    tools?: Array<{
      function?: { name?: string; description?: string };
    }>;
  }>;
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
  defaultSkills?: Array<{ id: string; name: string; description: string; tags: string[] }> | null;

  constructor(client: JacsClient, trustPolicy?: TrustPolicy) {
    this.client = client;
    this.trustPolicy = trustPolicy || DEFAULT_TRUST_POLICY;
  }

  static async quickstart(options: A2AQuickstartOptions = {}): Promise<JACSA2AIntegration> {
    const { url, name, skills, trustPolicy, algorithm, configPath } = options;
    let JacsClientCtor: typeof JacsClient;
    try {
      JacsClientCtor = require('./client').JacsClient;
    } catch {
      JacsClientCtor = require('./client.js').JacsClient;
    }

    const client = await JacsClientCtor.quickstart({
      algorithm: algorithm || undefined,
      configPath: configPath || undefined,
      name: name || undefined,
    } as any);

    const integration = new JACSA2AIntegration(client, trustPolicy || DEFAULT_TRUST_POLICY);
    integration.defaultUrl = url || null;
    integration.defaultSkills = skills || null;
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
    const extensionJson = this.createExtensionDescriptor();

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

    app.get('/.well-known/agent-card.json', (_req: any, res: any) => {
      res.json(cardJson);
    });

    app.get('/.well-known/jacs-extension.json', (_req: any, res: any) => {
      res.json(extensionJson);
    });

    const server = app.listen(port, () => {
      const address = server.address();
      const boundPort = typeof address === 'object' && address ? address.port : port;
      const requested = port === 0 ? ' (requested random port)' : '';
      console.log(
        `Your agent is discoverable at http://localhost:${boundPort}/.well-known/agent-card.json${requested}`,
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

    const skills = this._convertServicesToSkills(agentData.jacsServices || []);

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
      specification: 'https://hai.ai/jacs/specs/a2a-extension',
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
  assessRemoteAgent(agentCardJson: string | Record<string, unknown>): TrustAssessment {
    const card = typeof agentCardJson === 'string'
      ? JSON.parse(agentCardJson)
      : agentCardJson;

    const jacsRegistered = this._hasJacsExtension(card);
    const agentId = (card.metadata && (card.metadata as Record<string, unknown>).jacsId) as string | undefined;

    let inTrustStore = false;
    if (agentId) {
      try {
        inTrustStore = this.client.isTrusted(agentId);
      } catch {
        inTrustStore = false;
      }
    }

    const trustLevel: TrustAssessment['trustLevel'] = inTrustStore
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
  trustA2AAgent(agentCardJson: string | Record<string, unknown>): string {
    const cardStr = typeof agentCardJson === 'string'
      ? agentCardJson
      : JSON.stringify(agentCardJson);
    return this.client.trustAgent(cardStr);
  }

  async signArtifact(
    artifact: Record<string, unknown>,
    artifactType: string,
    parentSignatures: Record<string, unknown>[] | null = null,
  ): Promise<Record<string, unknown>> {
    const wrapped: Record<string, unknown> = {
      jacsId: uuidv4(),
      jacsVersion: uuidv4(),
      jacsType: `a2a-${artifactType}`,
      jacsLevel: 'artifact',
      jacsVersionDate: new Date().toISOString(),
      $schema: 'https://hai.ai/schemas/header/v1/header.schema.json',
      a2aArtifact: artifact,
    };

    if (parentSignatures) {
      wrapped.jacsParentSignatures = parentSignatures;
    }

    return (this.client as any)._agent.signRequest(wrapped);
  }

  /** @deprecated Use signArtifact() instead. */
  async wrapArtifactWithProvenance(
    artifact: Record<string, unknown>,
    artifactType: string,
    parentSignatures: Record<string, unknown>[] | null = null,
  ): Promise<Record<string, unknown>> {
    return this.signArtifact(artifact, artifactType, parentSignatures);
  }

  async verifyWrappedArtifact(
    wrappedArtifact: Record<string, unknown>,
  ): Promise<ArtifactVerificationResult> {
    const result = this._verifyWrappedArtifactInternal(wrappedArtifact, new Set<string>());

    // Attach trust assessment based on the signer's identity
    const signerId = result.signerId;
    if (signerId && signerId !== 'unknown') {
      let inTrustStore = false;
      try {
        inTrustStore = this.client.isTrusted(signerId);
      } catch {
        inTrustStore = false;
      }

      const trustLevel: TrustAssessment['trustLevel'] = inTrustStore ? 'trusted' : 'jacs_registered';
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
    const documents: Record<string, Record<string, unknown>> = {};
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

  private _hasJacsExtension(card: Record<string, unknown>): boolean {
    const capabilities = card.capabilities as Record<string, unknown> | undefined;
    const extensions = capabilities?.extensions as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(extensions)) return false;
    return extensions.some((ext) => ext && ext.uri === JACS_EXTENSION_URI);
  }

  private _normalizeVerifyResponse(
    rawVerificationResult: unknown,
  ): {
    valid: boolean;
    verifiedPayload?: Record<string, unknown>;
    verificationResult: boolean | Record<string, unknown>;
  } {
    if (typeof rawVerificationResult === 'boolean') {
      return {
        valid: rawVerificationResult,
        verificationResult: rawVerificationResult,
      };
    }

    if (rawVerificationResult && typeof rawVerificationResult === 'object') {
      const rawObj = rawVerificationResult as Record<string, unknown>;
      const payload = rawObj.payload;
      return {
        valid: true,
        verifiedPayload: payload && typeof payload === 'object'
          ? payload as Record<string, unknown>
          : undefined,
        verificationResult: rawObj,
      };
    }

    return {
      valid: false,
      verificationResult: false,
    };
  }

  private _verifyWrappedArtifactInternal(
    wrappedArtifact: Record<string, unknown>,
    visited: Set<string>,
  ): ArtifactVerificationResult {
    const artifactId = wrappedArtifact.jacsId as string | undefined;
    if (artifactId && visited.has(artifactId)) {
      throw new Error(`Cycle detected in parent signature chain at artifact ${artifactId}`);
    }
    if (artifactId) {
      visited.add(artifactId);
    }

    try {
      const rawVerificationResult = (this.client as any)._agent.verifyResponse(
        JSON.stringify(wrappedArtifact),
      );
      const normalized = this._normalizeVerifyResponse(rawVerificationResult);
      const signatureInfo = (wrappedArtifact.jacsSignature || {}) as Record<string, unknown>;
      const payload = wrappedArtifact.jacs_payload && typeof wrappedArtifact.jacs_payload === 'object'
        ? wrappedArtifact.jacs_payload as Record<string, unknown>
        : null;

      const result: ArtifactVerificationResult = {
        valid: normalized.valid,
        verificationResult: normalized.verificationResult,
        signerId: (signatureInfo.agentID as string) || 'unknown',
        signerVersion: (signatureInfo.agentVersion as string) || 'unknown',
        artifactType: (wrappedArtifact.jacsType as string) || 'unknown',
        timestamp: (wrappedArtifact.jacsVersionDate as string) || '',
        originalArtifact: (
          wrappedArtifact.a2aArtifact
          || payload?.a2aArtifact
          || {}
        ) as Record<string, unknown>,
      };
      if (normalized.verifiedPayload) {
        result.verifiedPayload = normalized.verifiedPayload;
      }

      const parents = wrappedArtifact.jacsParentSignatures as Record<string, unknown>[] | undefined;
      if (Array.isArray(parents) && parents.length > 0) {
        const parentResults = parents.map((parent, index) => {
          try {
            const parentResult = this._verifyWrappedArtifactInternal(parent, visited);
            return {
              index,
              artifactId: (parent.jacsId as string) || 'unknown',
              valid: !!parentResult.valid,
              parentSignaturesValid: parentResult.parentSignaturesValid !== false,
            };
          } catch (error) {
            return {
              index,
              artifactId: parent && parent.jacsId ? (parent.jacsId as string) : 'unknown',
              valid: false,
              parentSignaturesValid: false,
              error: error instanceof Error ? error.message : String(error),
            };
          }
        });

        result.parentSignaturesCount = parentResults.length;
        result.parentVerificationResults = parentResults;
        result.parentSignaturesValid = parentResults.every(
          (entry) => entry.valid && entry.parentSignaturesValid,
        );
      }

      return result;
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

      let keyObject: KeyObject;
      try {
        keyObject = createPublicKey({ key: keyBytes, format: 'der', type: 'spki' });
      } catch {
        keyObject = createPublicKey(keyBytes.toString('utf8'));
      }

      const jwk = keyObject.export({ format: 'jwk' });
      const alg = this._inferJwsAlg(keyAlgorithm, jwk);
      return {
        keys: [{ ...jwk, kid, use: 'sig', ...(alg ? { alg } : {}) }],
      };
    } catch {
      return { keys: [] };
    }
  }

  private _inferJwsAlg(
    keyAlgorithm: string,
    jwk: Record<string, unknown>,
  ): string | undefined {
    if (keyAlgorithm.includes('ring-ed25519') || keyAlgorithm.includes('ed25519')) return 'EdDSA';
    if (keyAlgorithm.includes('rsa')) return 'RS256';
    if (keyAlgorithm.includes('ecdsa') || keyAlgorithm.includes('es256')) return 'ES256';
    if (jwk?.kty === 'RSA') return 'RS256';
    if (jwk?.kty === 'OKP' && jwk?.crv === 'Ed25519') return 'EdDSA';
    if (jwk?.kty === 'EC' && jwk?.crv === 'P-256') return 'ES256';
    return undefined;
  }

  _slugify(name: string): string {
    return name
      .toLowerCase()
      .replace(/[\s_]+/g, '-')
      .replace(/[^a-z0-9-]/g, '');
  }

  private _deriveTags(serviceName: string, fnName: string): string[] {
    const tags = ['jacs'];
    const serviceSlug = this._slugify(serviceName);
    const fnSlug = this._slugify(fnName);
    if (serviceSlug !== fnSlug) tags.push(serviceSlug);
    tags.push(fnSlug);
    return tags;
  }

  private _convertServicesToSkills(
    services: NonNullable<AgentData['jacsServices']>,
  ): A2AAgentSkill[] {
    const skills: A2AAgentSkill[] = [];

    for (const service of services) {
      const serviceName = service.name || service.serviceDescription || 'unnamed_service';
      const serviceDesc = service.serviceDescription || 'No description';

      const tools = service.tools || [];
      if (tools.length > 0) {
        for (const tool of tools) {
          if (tool.function) {
            const fnName = tool.function.name || serviceName;
            const fnDesc = tool.function.description || serviceDesc;
            skills.push(
              new A2AAgentSkill({
                id: this._slugify(fnName),
                name: fnName,
                description: fnDesc,
                tags: this._deriveTags(serviceName, fnName),
              }),
            );
          }
        }
      } else {
        skills.push(
          new A2AAgentSkill({
            id: this._slugify(serviceName),
            name: serviceName,
            description: serviceDesc,
            tags: this._deriveTags(serviceName, serviceName),
          }),
        );
      }
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
