/**
 * JACS Vercel AI SDK Adapter
 *
 * Provides cryptographic provenance signing for AI model outputs
 * using the Vercel AI SDK's LanguageModelV3Middleware pattern.
 *
 * @example
 * ```typescript
 * import { JacsClient } from '@hai.ai/jacs/client';
 * import { withProvenance } from '@hai.ai/jacs/vercel-ai';
 * import { openai } from '@ai-sdk/openai';
 * import { generateText } from 'ai';
 *
 * const client = await JacsClient.quickstart();
 * const model = withProvenance(openai('gpt-4'), { client });
 *
 * const { text, providerMetadata } = await generateText({
 *   model,
 *   prompt: 'Hello!',
 * });
 *
 * console.log(providerMetadata?.jacs?.documentId);
 * ```
 */

import type { JacsClient } from './client.js';

// Lazy-loaded types from @ai-sdk/provider. We declare local interfaces
// that mirror the subset we need so the module can be imported without
// the peer dependency installed. At runtime the middleware object is
// consumed by the AI SDK which owns these types.

interface LanguageModelV3Middleware {
  specificationVersion: 'v3';
  transformParams?: (opts: any) => Promise<any>;
  wrapGenerate?: (opts: any) => Promise<any>;
  wrapStream?: (opts: any) => Promise<any>;
}

// =============================================================================
// Public types
// =============================================================================

export interface ProvenanceOptions {
  /** An initialized JacsClient instance. */
  client: JacsClient;
  /** Sign generated text output. Default: true. */
  signText?: boolean;
  /** Sign tool call results. Default: true. */
  signToolResults?: boolean;
  /** Throw on signing failure instead of logging. Default: false. */
  strict?: boolean;
  /** Additional metadata to include in provenance records. */
  metadata?: Record<string, unknown>;
}

export interface ProvenanceRecord {
  signed: boolean;
  documentId: string;
  agentId: string;
  timestamp: string;
  error?: string;
  metadata?: Record<string, unknown>;
}

// =============================================================================
// Helpers
// =============================================================================

async function signContent(
  client: JacsClient,
  content: unknown,
  opts: ProvenanceOptions,
): Promise<ProvenanceRecord> {
  try {
    const signed = await client.signMessage(
      opts.metadata
        ? { content, provenance: opts.metadata }
        : content,
    );
    return {
      signed: true,
      documentId: signed.documentId,
      agentId: signed.agentId,
      timestamp: signed.timestamp,
      metadata: opts.metadata,
    };
  } catch (err) {
    if (opts.strict) {
      throw err;
    }
    const message = err instanceof Error ? err.message : String(err);
    console.error('[jacs/vercel-ai] signing failed:', message);
    return {
      signed: false,
      documentId: '',
      agentId: '',
      timestamp: '',
      error: message,
      metadata: opts.metadata,
    };
  }
}

function extractTextFromContent(content: any[]): string {
  if (!Array.isArray(content)) return '';
  return content
    .filter((part: any) => part.type === 'text')
    .map((part: any) => part.text)
    .join('');
}

// =============================================================================
// jacsProvenance — returns a LanguageModelV3Middleware
// =============================================================================

export function jacsProvenance(options: ProvenanceOptions): LanguageModelV3Middleware {
  const signText = options.signText !== false;
  const signToolResults = options.signToolResults !== false;

  const middleware: LanguageModelV3Middleware = {
    specificationVersion: 'v3',

    wrapGenerate: async ({ doGenerate, params }) => {
      const result = await doGenerate();

      if (!signText && !signToolResults) {
        return result;
      }

      const provenance: Record<string, ProvenanceRecord> = {};

      // Sign text content
      if (signText) {
        const text = extractTextFromContent(result.content);
        if (text) {
          provenance.text = await signContent(options.client, text, options);
        }
      }

      // Sign tool results if present in params prompt
      if (signToolResults && params.prompt) {
        const toolResults = params.prompt.filter(
          (part: any) => part.role === 'tool',
        );
        if (toolResults.length > 0) {
          const toolData = toolResults.map((tr: any) => ({
            role: tr.role,
            content: tr.content,
          }));
          provenance.toolResults = await signContent(
            options.client,
            toolData,
            options,
          );
        }
      }

      // Attach provenance to provider metadata
      return {
        ...result,
        providerMetadata: {
          ...result.providerMetadata,
          jacs: provenance as any,
        },
      };
    },

    wrapStream: async ({ doStream, params }) => {
      const streamResult = await doStream();

      if (!signText) {
        return streamResult;
      }

      // Accumulate text chunks, sign on stream completion
      let accumulatedText = '';

      const originalStream = streamResult.stream;
      const transform = new TransformStream({
        transform(chunk: any, controller: any) {
          if (chunk.type === 'text-delta') {
            accumulatedText += chunk.textDelta;
          }
          controller.enqueue(chunk);
        },
        async flush(controller: any) {
          if (accumulatedText) {
            const provenance = await signContent(
              options.client,
              accumulatedText,
              options,
            );
            controller.enqueue({
              type: 'provider-metadata',
              providerMetadata: {
                jacs: { text: provenance } as any,
              },
            });
          }
        },
      });

      return {
        ...streamResult,
        stream: originalStream.pipeThrough(transform),
      };
    },
  };

  return middleware;
}

// =============================================================================
// withProvenance — convenience wrapper
// =============================================================================

export function withProvenance(model: any, options: ProvenanceOptions): any {
  // Lazy import of wrapLanguageModel from 'ai'
  let wrapLanguageModel: any;
  try {
    wrapLanguageModel = require('ai').wrapLanguageModel;
  } catch {
    throw new Error(
      "Could not import 'ai' package. Install it as a dependency: npm install ai",
    );
  }

  return wrapLanguageModel({
    model,
    middleware: jacsProvenance(options),
  });
}
