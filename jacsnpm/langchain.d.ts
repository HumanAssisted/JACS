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
export interface JacsToolOptions {
    /** An initialized JacsClient instance. */
    client: JacsClient;
    /** Throw on signing failure instead of logging and passing through. Default: false. */
    strict?: boolean;
}
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
export declare function signedTool(tool: any, options: JacsToolOptions): any;
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
export declare function jacsWrapToolCall(options: JacsToolOptions): (toolCall: any, runnable: any) => Promise<any>;
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
export declare function jacsToolNode(tools: any[], options: JacsToolOptions): any;
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
export declare function createJacsTools(options: JacsToolOptions): any[];
