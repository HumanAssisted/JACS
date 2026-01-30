/**
 * JACS Agent Tools
 *
 * Tools that AI agents can use to sign and verify documents.
 */

import * as jacs from "jacsnpm";
import type { OpenClawPluginAPI } from "../index";

export interface ToolResult {
  result?: any;
  error?: string;
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
      if (!api.runtime.jacs?.isInitialized()) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const signed = jacs.signRequest(params.document);
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
      if (!api.runtime.jacs?.isInitialized()) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = jacs.verifyResponse(JSON.stringify(params.document));
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
      if (!api.runtime.jacs?.isInitialized()) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = jacs.createAgreement(
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
      if (!api.runtime.jacs?.isInitialized()) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = jacs.signAgreement(
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
      if (!api.runtime.jacs?.isInitialized()) {
        return { error: "JACS not initialized. Run 'openclaw jacs init' first." };
      }

      try {
        const result = jacs.checkAgreement(
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
        const hash = jacs.hashString(params.content);
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
            ? jacs.hashString(api.runtime.jacs.getPublicKey())
            : undefined,
        },
      };
    },
  });
}
