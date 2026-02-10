/**
 * JACS LangChain.js Adapter
 *
 * Provides full JACS capabilities for LangChain.js agents: cryptographic
 * signing, verification, multi-party agreements, trust store, and audit.
 * All `@langchain/core` and `@langchain/langgraph` imports are lazy so this
 * module can be imported without those packages installed.
 *
 * Two integration patterns:
 *
 * **A. Full JACS toolkit** — give your LangChain agent access to all JACS
 * operations (sign, verify, agreements, trust, audit):
 *
 *   `createJacsTools(options)` -- Returns an array of LangChain tools that
 *   wrap the full JacsClient API. Bind these to your agent/LLM so it can
 *   call JACS operations as part of its reasoning.
 *
 * **B. Auto-signing wrappers** — transparently sign tool outputs:
 *
 *   `signedTool(tool, options)` -- Wraps a BaseTool to auto-sign output.
 *   `jacsToolNode(tools, options)` -- ToolNode with auto-signed tools.
 *   `jacsWrapToolCall(options)` -- Manual tool execution with signing.
 *
 * @example
 * ```typescript
 * import { JacsClient } from '@hai.ai/jacs/client';
 * import { createJacsTools, signedTool } from '@hai.ai/jacs/langchain';
 *
 * const client = await JacsClient.quickstart();
 *
 * // Full toolkit — agent can sign, verify, create agreements, etc.
 * const jacsTools = createJacsTools({ client });
 * const allTools = [...myTools, ...jacsTools];
 *
 * // Or just wrap existing tools for auto-signing
 * const signed = signedTool(myTool, { client });
 * ```
 */

import type { JacsClient } from './client.js';

// =============================================================================
// Public types
// =============================================================================

export interface JacsToolOptions {
  /** An initialized JacsClient instance. */
  client: JacsClient;
  /** Throw on signing failure instead of logging and passing through. Default: false. */
  strict?: boolean;
}

// =============================================================================
// signedTool -- wrap a BaseTool to auto-sign its output
// =============================================================================

/**
 * Wrap a LangChain BaseTool so its output is automatically signed with JACS.
 *
 * Returns a new `DynamicStructuredTool` that delegates to the original tool
 * and signs the result before returning it.
 *
 * @param tool - A LangChain `BaseTool` instance (or any object with
 *   `name`, `description`, `schema`, and `invoke`).
 * @param options - JACS signing options.
 * @returns A new `DynamicStructuredTool` with signed output.
 */
export function signedTool(tool: any, options: JacsToolOptions): any {
  let DynamicStructuredTool: any;
  try {
    DynamicStructuredTool = require('@langchain/core/tools').DynamicStructuredTool;
  } catch {
    throw new Error(
      "@langchain/core is required for signedTool. " +
      "Install it with: npm install @langchain/core"
    );
  }

  const originalName: string = tool.name || 'jacs_tool';
  const originalDescription: string = tool.description || '';
  const originalSchema = tool.schema;

  const wrapped = new DynamicStructuredTool({
    name: originalName,
    description: originalDescription,
    schema: originalSchema,
    func: async (input: any) => {
      const result = await tool.invoke(input);
      const resultStr = typeof result === 'string' ? result : JSON.stringify(result);
      try {
        const signed = await options.client.signMessage({
          tool: originalName,
          result: resultStr,
        });
        return signed.raw;
      } catch (err) {
        if (options.strict) throw err;
        console.error('[jacs/langchain] signing failed:', err);
        return resultStr;
      }
    },
  });

  // Stash a reference to the original tool for introspection.
  wrapped._innerTool = tool;
  return wrapped;
}

// =============================================================================
// jacsWrapToolCall -- returns an async wrapper for manual tool execution
// =============================================================================

/**
 * Create an async function that executes a tool call and signs the result.
 *
 * The returned function has the signature
 * `(toolCall, runnable) => Promise<ToolMessage>` and can be used in custom
 * LangGraph workflows where you control tool execution.
 *
 * @param options - JACS signing options.
 * @returns An async wrapper function.
 */
export function jacsWrapToolCall(
  options: JacsToolOptions,
): (toolCall: any, runnable: any) => Promise<any> {
  return async (toolCall: any, runnable: any): Promise<any> => {
    const result = await runnable.invoke(toolCall);

    // result is expected to be a ToolMessage (has .content, .tool_call_id, .name)
    if (!result || typeof result.content === 'undefined') {
      return result;
    }

    const contentStr =
      typeof result.content === 'string'
        ? result.content
        : JSON.stringify(result.content);

    try {
      const signed = await options.client.signMessage({
        tool: toolCall.name || result.name || 'unknown',
        content: contentStr,
      });

      let ToolMessage: any;
      try {
        ToolMessage = require('@langchain/core/messages').ToolMessage;
      } catch {
        // If ToolMessage is not available, mutate in place as fallback.
        result.content = signed.raw;
        return result;
      }

      return new ToolMessage({
        content: signed.raw,
        tool_call_id: result.tool_call_id || '',
        name: result.name,
      });
    } catch (err) {
      if (options.strict) throw err;
      console.error('[jacs/langchain] signing failed:', err);
      return result;
    }
  };
}

// =============================================================================
// jacsToolNode -- convenience ToolNode with signed tools
// =============================================================================

/**
 * Create a LangGraph `ToolNode` where every tool's output is signed with JACS.
 *
 * Since the JavaScript `ToolNode` does not support a `wrap_tool_call`
 * parameter (unlike the Python version), this function wraps each tool
 * individually with {@link signedTool} before passing them to `ToolNode`.
 *
 * @param tools - Array of LangChain tools.
 * @param options - JACS signing options.
 * @returns A `ToolNode` instance with all tools auto-signing their output.
 */
export function jacsToolNode(tools: any[], options: JacsToolOptions): any {
  let ToolNode: any;
  try {
    ToolNode = require('@langchain/langgraph/prebuilt').ToolNode;
  } catch {
    throw new Error(
      "@langchain/langgraph is required for jacsToolNode. " +
      "Install it with: npm install @langchain/langgraph"
    );
  }

  const wrappedTools = tools.map((t) => signedTool(t, options));

  return new ToolNode({
    tools: wrappedTools,
    handleToolErrors: true,
  });
}

// =============================================================================
// createJacsTools -- full JACS toolkit as LangChain tools
// =============================================================================

/**
 * Create an array of LangChain tools that expose the full JACS API.
 *
 * Returns `DynamicStructuredTool` instances for: signing, verification,
 * multi-party agreements, trust store operations, and audit. Bind these
 * to your LangChain agent so it can call JACS operations directly.
 *
 * @param options - JACS tool options (client required).
 * @returns Array of LangChain `DynamicStructuredTool` instances.
 *
 * @example
 * ```typescript
 * const tools = createJacsTools({ client });
 * const llm = model.bindTools(tools);
 * ```
 */
export function createJacsTools(options: JacsToolOptions): any[] {
  let DynamicStructuredTool: any;
  let z: any;
  try {
    DynamicStructuredTool = require('@langchain/core/tools').DynamicStructuredTool;
    z = require('zod');
  } catch {
    throw new Error(
      "@langchain/core is required for createJacsTools. " +
      "Install it with: npm install @langchain/core"
    );
  }

  const { client, strict } = options;

  function handleError(err: any, fallback: string): string {
    if (strict) throw err;
    return JSON.stringify({ error: String(err), fallback });
  }

  return [
    // ----- Sign -----
    new DynamicStructuredTool({
      name: 'jacs_sign',
      description:
        'Sign arbitrary JSON data with JACS cryptographic provenance. ' +
        'Returns a signed document with documentId, agentId, and timestamp.',
      schema: z.object({
        data: z.string().describe('JSON string of the data to sign'),
      }),
      func: async ({ data }: { data: string }) => {
        try {
          const parsed = JSON.parse(data);
          const signed = await client.signMessage(parsed);
          return JSON.stringify({
            documentId: signed.documentId,
            agentId: signed.agentId,
            timestamp: signed.timestamp,
            raw: signed.raw,
          });
        } catch (err) {
          return handleError(err, 'signing failed');
        }
      },
    }),

    // ----- Verify -----
    new DynamicStructuredTool({
      name: 'jacs_verify',
      description:
        'Verify a JACS-signed document. Returns whether the signature is valid, ' +
        'the signer ID, timestamp, and any verification errors.',
      schema: z.object({
        document: z.string().describe('The full signed JSON document string to verify'),
      }),
      func: async ({ document }: { document: string }) => {
        try {
          const result = await client.verify(document);
          return JSON.stringify({
            valid: result.valid,
            signerId: result.signerId,
            timestamp: result.timestamp,
            data: result.data,
            errors: result.errors,
          });
        } catch (err) {
          return handleError(err, 'verification failed');
        }
      },
    }),

    // ----- Create Agreement -----
    new DynamicStructuredTool({
      name: 'jacs_create_agreement',
      description:
        'Create a multi-party agreement that requires signatures from specified agents. ' +
        'Supports optional timeout (ISO 8601), quorum (M-of-N), and algorithm constraints.',
      schema: z.object({
        document: z.string().describe('JSON string of the document to agree on'),
        agentIds: z.array(z.string()).describe('Array of agent IDs who must sign'),
        question: z.string().optional().describe('Question or prompt for signers'),
        timeout: z.string().optional().describe('ISO 8601 deadline for signatures'),
        quorum: z.number().optional().describe('Minimum number of signatures required (M-of-N)'),
      }),
      func: async (input: { document: string; agentIds: string[]; question?: string; timeout?: string; quorum?: number }) => {
        try {
          const parsed = JSON.parse(input.document);
          const agreementOpts: any = {};
          if (input.question) agreementOpts.question = input.question;
          if (input.timeout) agreementOpts.timeout = input.timeout;
          if (input.quorum !== undefined) agreementOpts.quorum = input.quorum;
          const signed = await client.createAgreement(parsed, input.agentIds, agreementOpts);
          return JSON.stringify({
            documentId: signed.documentId,
            agentId: signed.agentId,
            timestamp: signed.timestamp,
            raw: signed.raw,
          });
        } catch (err) {
          return handleError(err, 'create agreement failed');
        }
      },
    }),

    // ----- Sign Agreement -----
    new DynamicStructuredTool({
      name: 'jacs_sign_agreement',
      description:
        'Sign an existing multi-party agreement. Pass the full agreement document.',
      schema: z.object({
        document: z.string().describe('The full agreement JSON document to sign'),
      }),
      func: async ({ document }: { document: string }) => {
        try {
          const signed = await client.signAgreement(document);
          return JSON.stringify({
            documentId: signed.documentId,
            agentId: signed.agentId,
            timestamp: signed.timestamp,
            raw: signed.raw,
          });
        } catch (err) {
          return handleError(err, 'sign agreement failed');
        }
      },
    }),

    // ----- Check Agreement -----
    new DynamicStructuredTool({
      name: 'jacs_check_agreement',
      description:
        'Check the status of a multi-party agreement: how many signatures collected, ' +
        'whether it is complete, and who has signed.',
      schema: z.object({
        document: z.string().describe('The full agreement JSON document to check'),
      }),
      func: async ({ document }: { document: string }) => {
        try {
          const status = await client.checkAgreement(document);
          return JSON.stringify(status);
        } catch (err) {
          return handleError(err, 'check agreement failed');
        }
      },
    }),

    // ----- Verify Self -----
    new DynamicStructuredTool({
      name: 'jacs_verify_self',
      description:
        "Verify this agent's own cryptographic integrity. Returns valid/invalid status.",
      schema: z.object({}),
      func: async () => {
        try {
          const result = await client.verifySelf();
          return JSON.stringify({
            valid: result.valid,
            signerId: result.signerId,
            errors: result.errors,
          });
        } catch (err) {
          return handleError(err, 'self-verification failed');
        }
      },
    }),

    // ----- Trust Agent -----
    new DynamicStructuredTool({
      name: 'jacs_trust_agent',
      description:
        'Add an agent to the local trust store. Pass the agent JSON document.',
      schema: z.object({
        agentJson: z.string().describe('The agent JSON document to trust'),
      }),
      func: async ({ agentJson }: { agentJson: string }) => {
        try {
          const result = client.trustAgent(agentJson);
          return JSON.stringify({ success: true, result });
        } catch (err) {
          return handleError(err, 'trust agent failed');
        }
      },
    }),

    // ----- List Trusted Agents -----
    new DynamicStructuredTool({
      name: 'jacs_list_trusted',
      description:
        'List all agent IDs in the local trust store.',
      schema: z.object({}),
      func: async () => {
        try {
          const agents = client.listTrustedAgents();
          return JSON.stringify({ trustedAgents: agents });
        } catch (err) {
          return handleError(err, 'list trusted failed');
        }
      },
    }),

    // ----- Is Trusted -----
    new DynamicStructuredTool({
      name: 'jacs_is_trusted',
      description:
        'Check whether a specific agent ID is in the local trust store.',
      schema: z.object({
        agentId: z.string().describe('The agent ID to check'),
      }),
      func: async ({ agentId }: { agentId: string }) => {
        try {
          const trusted = client.isTrusted(agentId);
          return JSON.stringify({ agentId, trusted });
        } catch (err) {
          return handleError(err, 'is trusted check failed');
        }
      },
    }),

    // ----- Audit -----
    new DynamicStructuredTool({
      name: 'jacs_audit',
      description:
        'Run a JACS security audit. Returns audit results including document integrity, ' +
        'key status, and configuration health.',
      schema: z.object({
        recentN: z.number().optional().describe('Number of recent documents to audit'),
      }),
      func: async (input: { recentN?: number }) => {
        try {
          const result = await client.audit(
            input.recentN !== undefined ? { recentN: input.recentN } : undefined,
          );
          return JSON.stringify(result);
        } catch (err) {
          return handleError(err, 'audit failed');
        }
      },
    }),

    // ----- Get Agent Info -----
    new DynamicStructuredTool({
      name: 'jacs_agent_info',
      description:
        'Get the current JACS agent ID and name. Useful for knowing your own identity ' +
        'when creating agreements or sharing with other agents.',
      schema: z.object({}),
      func: async () => {
        return JSON.stringify({
          agentId: client.agentId,
          name: client.name,
          strict: client.strict,
        });
      },
    }),
  ];
}
