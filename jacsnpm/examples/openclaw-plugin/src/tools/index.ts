/**
 * JACS Agent Tools
 *
 * Tools that AI agents can use to sign and verify documents.
 */

import { hashString, verifyString, JacsAgent } from "jacsnpm";
import * as dns from "dns";
import { promisify } from "util";
import type { OpenClawPluginAPI } from "../index";

const resolveTxt = promisify(dns.resolveTxt);

// Cache for fetched public keys (domain -> key info)
interface CachedKey {
  key: string;
  algorithm: string;
  agentId?: string;
  publicKeyHash?: string;
  fetchedAt: number;
}
const pubkeyCache: Map<string, CachedKey> = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Export CachedKey for use by CLI
export type { CachedKey };

export interface ToolResult {
  result?: any;
  error?: string;
}

/**
 * Get the JACS agent instance from the API runtime
 */
function getAgent(api: OpenClawPluginAPI): JacsAgent | null {
  return api.runtime.jacs?.getAgent() || null;
}

/**
 * Parse JACS DNS TXT record
 * Format: v=hai.ai; jacs_agent_id=UUID; alg=SHA-256; enc=base64; jac_public_key_hash=HASH
 */
export function parseDnsTxt(txt: string): {
  v?: string;
  jacsAgentId?: string;
  alg?: string;
  enc?: string;
  publicKeyHash?: string;
} {
  const result: Record<string, string> = {};
  const parts = txt.split(";").map((s) => s.trim());
  for (const part of parts) {
    const [key, value] = part.split("=").map((s) => s.trim());
    if (key && value) {
      result[key] = value;
    }
  }
  return {
    v: result["v"],
    jacsAgentId: result["jacs_agent_id"],
    alg: result["alg"],
    enc: result["enc"],
    publicKeyHash: result["jac_public_key_hash"],
  };
}

/**
 * Resolve DNS TXT record for JACS agent
 */
export async function resolveDnsRecord(
  domain: string
): Promise<{ txt: string; parsed: ReturnType<typeof parseDnsTxt> } | null> {
  const owner = `_v1.agent.jacs.${domain.replace(/\.$/, "")}`;
  try {
    const records = await resolveTxt(owner);
    // TXT records come as arrays of strings, join them
    const txt = records.map((r) => r.join("")).join("");
    if (!txt) return null;
    return { txt, parsed: parseDnsTxt(txt) };
  } catch {
    return null;
  }
}

/**
 * Fetch public key from domain's well-known endpoint
 */
export async function fetchPublicKey(
  domain: string,
  skipCache = false
): Promise<{ data: CachedKey; cached: boolean } | { error: string }> {
  const cacheKey = domain.toLowerCase();

  // Check cache
  if (!skipCache) {
    const cached = pubkeyCache.get(cacheKey);
    if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
      return { data: cached, cached: true };
    }
  }

  try {
    const url = `https://${domain}/.well-known/jacs-pubkey.json`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      return { error: `HTTP ${response.status} from ${domain}` };
    }

    const data = (await response.json()) as {
      publicKey?: string;
      algorithm?: string;
      agentId?: string;
      publicKeyHash?: string;
    };

    if (!data.publicKey) {
      return { error: `Missing publicKey in response from ${domain}` };
    }

    const keyInfo: CachedKey = {
      key: data.publicKey,
      algorithm: data.algorithm || "unknown",
      agentId: data.agentId,
      publicKeyHash: data.publicKeyHash,
      fetchedAt: Date.now(),
    };

    pubkeyCache.set(cacheKey, keyInfo);
    return { data: keyInfo, cached: false };
  } catch (err: any) {
    if (err.name === "TimeoutError") {
      return { error: `Timeout fetching from ${domain}` };
    }
    return { error: err.message };
  }
}

/**
 * Extract signer domain from a JACS document
 * Looks for jacsAgentDomain in the document or signature metadata
 */
function extractSignerDomain(doc: any): string | null {
  // Check document-level domain
  if (doc.jacsAgentDomain) return doc.jacsAgentDomain;

  // Check signature metadata
  if (doc.jacsSignature?.agentDomain) return doc.jacsSignature.agentDomain;

  return null;
}

/**
 * Register JACS tools with OpenClaw
 */
export function registerTools(api: OpenClawPluginAPI): void {
  // Tool: Sign a document
  api.registerTool({
    name: "jacs_sign",
    description:
      "Sign a document with JACS cryptographic provenance. Use this to create verifiable, tamper-proof documents that can be traced back to this agent.",
    parameters: {
      type: "object",
      properties: {
        document: {
          type: "object",
          description: "The document or data to sign (any JSON object)",
        },
      },
      required: ["document"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const agent = getAgent(api);
      if (!agent) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const signed = agent.signRequest(params.document);
        return { result: JSON.parse(signed) };
      } catch (err: any) {
        return { error: `Failed to sign: ${err.message}` };
      }
    },
  });

  // Tool: Verify a document
  api.registerTool({
    name: "jacs_verify",
    description:
      "Verify a JACS-signed document. Use this to check if a document was signed by a valid agent and has not been tampered with.",
    parameters: {
      type: "object",
      properties: {
        document: {
          type: "object",
          description: "The signed document to verify",
        },
      },
      required: ["document"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const agent = getAgent(api);
      if (!agent) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = agent.verifyResponse(JSON.stringify(params.document));
        return { result };
      } catch (err: any) {
        return { error: `Verification failed: ${err.message}` };
      }
    },
  });

  // Tool: Create agreement
  api.registerTool({
    name: "jacs_create_agreement",
    description:
      "Create a multi-party agreement that requires signatures from multiple agents. Use this when multiple parties need to sign off on a decision or document.",
    parameters: {
      type: "object",
      properties: {
        document: {
          type: "object",
          description: "The document to create agreement on",
        },
        agentIds: {
          type: "array",
          items: { type: "string" },
          description: "List of agent IDs required to sign",
        },
        question: {
          type: "string",
          description: "The question or purpose of the agreement",
        },
        context: {
          type: "string",
          description: "Additional context for signers",
        },
      },
      required: ["document", "agentIds"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const agent = getAgent(api);
      if (!agent) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = agent.createAgreement(
          JSON.stringify(params.document),
          params.agentIds,
          params.question,
          params.context
        );
        return { result: JSON.parse(result) };
      } catch (err: any) {
        return { error: `Failed to create agreement: ${err.message}` };
      }
    },
  });

  // Tool: Sign agreement
  api.registerTool({
    name: "jacs_sign_agreement",
    description:
      "Sign an existing agreement document. Use this when you need to add your signature to a multi-party agreement.",
    parameters: {
      type: "object",
      properties: {
        document: {
          type: "object",
          description: "The agreement document to sign",
        },
        agreementFieldname: {
          type: "string",
          description: "Name of the agreement field (optional)",
        },
      },
      required: ["document"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const agent = getAgent(api);
      if (!agent) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = agent.signAgreement(
          JSON.stringify(params.document),
          params.agreementFieldname
        );
        return { result: JSON.parse(result) };
      } catch (err: any) {
        return { error: `Failed to sign agreement: ${err.message}` };
      }
    },
  });

  // Tool: Check agreement status
  api.registerTool({
    name: "jacs_check_agreement",
    description:
      "Check the status of a multi-party agreement. Use this to see which parties have signed and which are still pending.",
    parameters: {
      type: "object",
      properties: {
        document: {
          type: "object",
          description: "The agreement document to check",
        },
        agreementFieldname: {
          type: "string",
          description: "Name of the agreement field (optional)",
        },
      },
      required: ["document"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const agent = getAgent(api);
      if (!agent) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = agent.checkAgreement(
          JSON.stringify(params.document),
          params.agreementFieldname
        );
        return { result: JSON.parse(result) };
      } catch (err: any) {
        return { error: `Failed to check agreement: ${err.message}` };
      }
    },
  });

  // Tool: Hash content
  api.registerTool({
    name: "jacs_hash",
    description:
      "Create a cryptographic hash of content. Use this to create a unique fingerprint of data for verification purposes.",
    parameters: {
      type: "object",
      properties: {
        content: {
          type: "string",
          description: "The content to hash",
        },
      },
      required: ["content"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      try {
        const hash = hashString(params.content);
        return { result: { hash, algorithm: "SHA-256" } };
      } catch (err: any) {
        return { error: `Failed to hash: ${err.message}` };
      }
    },
  });

  // Tool: Get agent identity
  api.registerTool({
    name: "jacs_identity",
    description:
      "Get the current agent's JACS identity information. Use this to share your identity with other agents.",
    parameters: {
      type: "object",
      properties: {},
    },
    handler: async (): Promise<ToolResult> => {
      if (!api.runtime.jacs?.isInitialized()) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      const config = api.config;
      return {
        result: {
          agentId: config.agentId,
          agentName: config.agentName,
          agentDescription: config.agentDescription,
          agentDomain: config.agentDomain,
          algorithm: config.keyAlgorithm,
          publicKeyHash: config.agentId
            ? hashString(api.runtime.jacs.getPublicKey())
            : undefined,
        },
      };
    },
  });

  // Tool: Fetch another agent's public key
  api.registerTool({
    name: "jacs_fetch_pubkey",
    description:
      "Fetch another agent's public key from their domain. Use this before verifying documents from other agents. Keys are fetched from https://<domain>/.well-known/jacs-pubkey.json",
    parameters: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "The domain of the agent whose public key to fetch (e.g., 'example.com')",
        },
        skipCache: {
          type: "boolean",
          description: "Force fetch even if key is cached (default: false)",
        },
      },
      required: ["domain"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const domain = params.domain.replace(/^https?:\/\//, "").replace(/\/$/, "");
      const cacheKey = domain.toLowerCase();

      // Check cache first
      if (!params.skipCache) {
        const cached = pubkeyCache.get(cacheKey);
        if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
          return {
            result: {
              domain,
              publicKey: cached.key,
              algorithm: cached.algorithm,
              cached: true,
              fetchedAt: new Date(cached.fetchedAt).toISOString(),
            },
          };
        }
      }

      try {
        const url = `https://${domain}/.well-known/jacs-pubkey.json`;
        const response = await fetch(url, {
          headers: { Accept: "application/json" },
          signal: AbortSignal.timeout(10000), // 10 second timeout
        });

        if (!response.ok) {
          return {
            error: `Failed to fetch public key from ${domain}: HTTP ${response.status}`,
          };
        }

        const data = (await response.json()) as {
          publicKey?: string;
          algorithm?: string;
          agentId?: string;
          agentName?: string;
        };

        if (!data.publicKey) {
          return { error: `Invalid response from ${domain}: missing publicKey field` };
        }

        // Cache the key
        pubkeyCache.set(cacheKey, {
          key: data.publicKey,
          algorithm: data.algorithm || "unknown",
          fetchedAt: Date.now(),
        });

        return {
          result: {
            domain,
            publicKey: data.publicKey,
            algorithm: data.algorithm || "unknown",
            agentId: data.agentId,
            agentName: data.agentName,
            cached: false,
            fetchedAt: new Date().toISOString(),
          },
        };
      } catch (err: any) {
        if (err.name === "TimeoutError") {
          return { error: `Timeout fetching public key from ${domain}` };
        }
        return { error: `Failed to fetch public key from ${domain}: ${err.message}` };
      }
    },
  });

  // Tool: Verify a document with a specific public key
  api.registerTool({
    name: "jacs_verify_with_key",
    description:
      "Verify a signed document using another agent's public key. Use jacs_fetch_pubkey first to get the key, then use this to verify documents from that agent.",
    parameters: {
      type: "object",
      properties: {
        document: {
          type: "object",
          description: "The signed document to verify",
        },
        publicKey: {
          type: "string",
          description: "The PEM-encoded public key of the signing agent",
        },
        algorithm: {
          type: "string",
          description: "The key algorithm (e.g., 'pq2025', 'ed25519'). Default: 'pq2025'",
        },
      },
      required: ["document", "publicKey"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      try {
        const doc = params.document;
        const sig = doc.jacsSignature || doc.signature;

        if (!sig) {
          return { error: "Document does not contain a signature field (jacsSignature or signature)" };
        }

        // Get the actual signature string
        const signatureValue = typeof sig === "object" ? sig.signature : sig;
        if (!signatureValue) {
          return { error: "Could not extract signature value from document" };
        }

        // Determine algorithm from signature or parameter
        const algorithm = params.algorithm || sig.signingAlgorithm || "pq2025";

        // Convert public key to Buffer
        const publicKeyBuffer = Buffer.from(params.publicKey, "utf-8");

        // Build the data that was signed (document without signature fields)
        const docWithoutSig = { ...doc };
        delete docWithoutSig.jacsSignature;
        delete docWithoutSig.signature;
        delete docWithoutSig.jacsHash;
        const dataToVerify = JSON.stringify(docWithoutSig);

        // Use JACS verifyString to verify (static function)
        const isValid = verifyString(dataToVerify, signatureValue, publicKeyBuffer, algorithm);

        return {
          result: {
            valid: isValid,
            algorithm,
            agentId: sig.agentID || doc.jacsAgentId,
            agentVersion: sig.agentVersion,
            signedAt: sig.date,
            publicKeyHash: sig.publicKeyHash,
            documentId: doc.jacsId,
          },
        };
      } catch (err: any) {
        return { error: `Verification failed: ${err.message}` };
      }
    },
  });

  // Tool: Seamless verification with auto-fetch
  api.registerTool({
    name: "jacs_verify_auto",
    description:
      "Automatically verify a JACS-signed document by fetching the signer's public key. This is the easiest way to verify documents from other agents - just provide the document and optionally the signer's domain.",
    parameters: {
      type: "object",
      properties: {
        document: {
          type: "object",
          description: "The signed document to verify",
        },
        domain: {
          type: "string",
          description:
            "The domain of the signing agent (e.g., 'agent.example.com'). If not provided, will try to extract from document.",
        },
        verifyDns: {
          type: "boolean",
          description:
            "Also verify the public key hash against DNS TXT record (default: false). Provides stronger verification.",
        },
      },
      required: ["document"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const doc = params.document;
      const sig = doc.jacsSignature || doc.signature;

      if (!sig) {
        return { error: "Document does not contain a signature" };
      }

      // Determine domain
      let domain = params.domain;
      if (!domain) {
        domain = extractSignerDomain(doc);
      }

      if (!domain) {
        return {
          error:
            "Could not determine signer domain. Please provide the 'domain' parameter or ensure the document contains 'jacsAgentDomain'.",
        };
      }

      // Fetch public key
      const keyResult = await fetchPublicKey(domain);
      if ("error" in keyResult) {
        return { error: `Failed to fetch public key: ${keyResult.error}` };
      }

      const keyInfo = keyResult.data;
      let dnsVerified = false;
      let dnsError: string | undefined;

      // Optional DNS verification
      if (params.verifyDns) {
        const dnsResult = await resolveDnsRecord(domain);
        if (dnsResult) {
          const dnsHash = dnsResult.parsed.publicKeyHash;
          // Compare public key hash
          const localHash = hashString(keyInfo.key);
          if (dnsHash === localHash || dnsHash === keyInfo.publicKeyHash) {
            dnsVerified = true;
          } else {
            dnsError = "DNS public key hash does not match fetched key";
          }

          // Also verify agent ID if present
          if (dnsResult.parsed.jacsAgentId && sig.agentID) {
            if (dnsResult.parsed.jacsAgentId !== sig.agentID) {
              dnsError = "DNS agent ID does not match document signer";
            }
          }
        } else {
          dnsError = "DNS TXT record not found";
        }
      }

      // Get signature value
      const signatureValue = typeof sig === "object" ? sig.signature : sig;
      if (!signatureValue) {
        return { error: "Could not extract signature value" };
      }

      // Determine algorithm
      const algorithm = sig.signingAlgorithm || keyInfo.algorithm || "pq2025";

      // Build data to verify
      const docWithoutSig = { ...doc };
      delete docWithoutSig.jacsSignature;
      delete docWithoutSig.signature;
      delete docWithoutSig.jacsHash;
      const dataToVerify = JSON.stringify(docWithoutSig);

      try {
        const publicKeyBuffer = Buffer.from(keyInfo.key, "utf-8");
        const isValid = verifyString(dataToVerify, signatureValue, publicKeyBuffer, algorithm);

        return {
          result: {
            valid: isValid,
            domain,
            algorithm,
            agentId: sig.agentID || keyInfo.agentId,
            agentVersion: sig.agentVersion,
            signedAt: sig.date,
            keyFromCache: keyResult.cached,
            dnsVerified: params.verifyDns ? dnsVerified : undefined,
            dnsError: params.verifyDns ? dnsError : undefined,
            documentId: doc.jacsId,
          },
        };
      } catch (err: any) {
        return { error: `Signature verification failed: ${err.message}` };
      }
    },
  });

  // Tool: DNS lookup for agent verification
  api.registerTool({
    name: "jacs_dns_lookup",
    description:
      "Look up a JACS agent's DNS TXT record. This provides the public key hash published in DNS for additional verification. The DNS record is at _v1.agent.jacs.<domain>.",
    parameters: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "The domain to look up (e.g., 'agent.example.com')",
        },
      },
      required: ["domain"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const domain = params.domain.replace(/^https?:\/\//, "").replace(/\/$/, "");
      const owner = `_v1.agent.jacs.${domain}`;

      const result = await resolveDnsRecord(domain);

      if (!result) {
        return {
          result: {
            found: false,
            domain,
            owner,
            message: `No JACS DNS TXT record found at ${owner}`,
          },
        };
      }

      return {
        result: {
          found: true,
          domain,
          owner,
          rawTxt: result.txt,
          ...result.parsed,
        },
      };
    },
  });

  // Tool: Lookup agent info (combines DNS + well-known)
  api.registerTool({
    name: "jacs_lookup_agent",
    description:
      "Look up complete information about a JACS agent by domain. Fetches both the public key from /.well-known/jacs-pubkey.json and the DNS TXT record.",
    parameters: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "The domain of the agent (e.g., 'agent.example.com')",
        },
      },
      required: ["domain"],
    },
    handler: async (params: any): Promise<ToolResult> => {
      const domain = params.domain.replace(/^https?:\/\//, "").replace(/\/$/, "");

      // Fetch public key and DNS in parallel
      const [keyResult, dnsResult] = await Promise.all([
        fetchPublicKey(domain, true), // skip cache for fresh lookup
        resolveDnsRecord(domain),
      ]);

      const result: any = {
        domain,
        wellKnown: null as any,
        dns: null as any,
        verified: false,
      };

      // Process well-known result
      if ("error" in keyResult) {
        result.wellKnown = { error: keyResult.error };
      } else {
        result.wellKnown = {
          publicKey: keyResult.data.key.substring(0, 100) + "...", // truncate for display
          publicKeyHash: keyResult.data.publicKeyHash || hashString(keyResult.data.key),
          algorithm: keyResult.data.algorithm,
          agentId: keyResult.data.agentId,
        };
      }

      // Process DNS result
      if (dnsResult) {
        result.dns = {
          owner: `_v1.agent.jacs.${domain}`,
          agentId: dnsResult.parsed.jacsAgentId,
          publicKeyHash: dnsResult.parsed.publicKeyHash,
          algorithm: dnsResult.parsed.alg,
          encoding: dnsResult.parsed.enc,
        };

        // Verify DNS matches well-known
        if (result.wellKnown && !result.wellKnown.error) {
          const localHash = result.wellKnown.publicKeyHash;
          const dnsHash = dnsResult.parsed.publicKeyHash;
          result.verified = localHash === dnsHash;
          if (!result.verified) {
            result.verificationError = "Public key hash from well-known endpoint does not match DNS";
          }
        }
      } else {
        result.dns = { error: "No DNS TXT record found" };
      }

      return { result };
    },
  });
}
