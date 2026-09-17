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
 * const client = await JacsClient.quickstart({
 *   name: 'vercel-agent',
 *   domain: 'vercel.local',
 * });
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
import { allowUnsignedOutput, requireSignedRaw } from './output-policy.js';

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
  /** Force fail-closed output even if allowUnsignedOutput is true. */
  strict?: boolean;
  /**
   * DANGEROUS: release generation output after signing fails. Enabled only by
   * literal `true`; default is fail closed.
   */
  allowUnsignedOutput?: boolean;
  /**
   * DANGEROUS: release stream chunks before the final signature is available.
   * Requires allowUnsignedOutput=true. Default: false (bounded buffering).
   */
  allowPostHocStreaming?: boolean;
  /** Buffered stream limit in bytes. Default: 1 MiB; maximum: 16 MiB. */
  maxBufferedStreamBytes?: number;
  /** Additional metadata to include in provenance records. */
  metadata?: Record<string, unknown>;
  /**
   * Include an A2A agent card and a dedicated provenance record whose portable
   * signedDocument binds that exact card. This is a signed self-assertion, not
   * configured trust or proof of real-world identity. Default: false.
   */
  a2a?: boolean;
}

export interface SignedProvenanceRecord {
  signed: true;
  documentId: string;
  agentId: string;
  timestamp: string;
  /** Full portable JACS document binding the exact output and metadata. */
  signedDocument: string;
  metadata?: Record<string, unknown>;
}

export interface UnsignedProvenanceRecord {
  signed: false;
  documentId: '';
  agentId: '';
  timestamp: '';
  error: string;
  metadata?: Record<string, unknown>;
}

export type ProvenanceRecord = SignedProvenanceRecord | UnsignedProvenanceRecord;

// =============================================================================
// Helpers
// =============================================================================

async function signContent(
  client: JacsClient,
  content: unknown,
  opts: ProvenanceOptions,
): Promise<ProvenanceRecord> {
  const binding = {
    output: content,
    metadata: opts.metadata ?? {},
  };
  try {
    const signed = await client.signMessage(binding);
    const signedDocument = requireSignedRaw(signed, 'JACS Vercel AI provenance signing');
    if (
      typeof signed.documentId !== 'string' || signed.documentId.length === 0
      || typeof signed.agentId !== 'string' || signed.agentId.length === 0
      || typeof signed.timestamp !== 'string' || signed.timestamp.length === 0
    ) {
      throw new TypeError('JACS Vercel AI provenance signing returned incomplete provenance');
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(signedDocument);
    } catch {
      throw new TypeError('JACS Vercel AI provenance signing returned invalid JSON');
    }
    if (
      !parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || !(parsed as Record<string, unknown>).jacsSignature
      || typeof (parsed as Record<string, unknown>).jacsSignature !== 'object'
    ) {
      throw new TypeError('JACS Vercel AI provenance signing returned no signature metadata');
    }
    const document = parsed as Record<string, unknown>;
    const signature = document.jacsSignature as Record<string, unknown>;
    if (
      document.jacsId !== signed.documentId
      || (signature.agentID ?? signature.agentId) !== signed.agentId
      || signature.date !== signed.timestamp
    ) {
      throw new TypeError('JACS Vercel AI provenance summary does not match signedDocument');
    }
    if (stableJson(document.content) !== stableJson(binding)) {
      throw new TypeError('JACS Vercel AI signedDocument does not bind the exact output and metadata');
    }

    return {
      signed: true,
      documentId: signed.documentId,
      agentId: signed.agentId,
      timestamp: signed.timestamp,
      signedDocument,
      metadata: opts.metadata,
    };
  } catch (err) {
    if (!allowUnsignedOutput(opts.allowUnsignedOutput, opts.strict)) {
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

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`);
    return `{${entries.join(',')}}`;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError('JACS Vercel AI provenance values must contain finite JSON numbers');
  }
  const serialized = JSON.stringify(value);
  if (typeof serialized !== 'string') {
    throw new TypeError('JACS Vercel AI provenance value is not JSON serializable');
  }
  return serialized;
}

function extractTextFromContent(content: any[]): string {
  if (!Array.isArray(content)) {
    throw new TypeError('Vercel AI generation content must be an array');
  }
  return content
    .filter((part: any) => part.type === 'text')
    .map((part: any) => {
      if (typeof part.text !== 'string') {
        throw new TypeError('Vercel AI text content must contain a string');
      }
      return part.text;
    })
    .join('');
}

const DEFAULT_STREAM_BUFFER_BYTES = 1024 * 1024;
const MAX_STREAM_BUFFER_BYTES = 16 * 1024 * 1024;

function resolveStreamBufferBytes(value: unknown): number {
  if (typeof value === 'undefined') return DEFAULT_STREAM_BUFFER_BYTES;
  if (
    typeof value !== 'number' || !Number.isSafeInteger(value)
    || value <= 0 || value > MAX_STREAM_BUFFER_BYTES
  ) {
    throw new RangeError(
      `maxBufferedStreamBytes must be an integer from 1 to ${MAX_STREAM_BUFFER_BYTES}`,
    );
  }
  return value;
}

function serializedChunkBytes(chunk: unknown): number {
  const serialized = JSON.stringify(chunk);
  if (typeof serialized !== 'string') {
    throw new TypeError('Vercel AI stream chunk is not JSON serializable');
  }
  return new TextEncoder().encode(serialized).byteLength;
}

function snapshotStreamChunk(chunk: unknown): { value: unknown; bytes: number } {
  let value: unknown;
  try {
    if (typeof globalThis.structuredClone === 'function') {
      value = globalThis.structuredClone(chunk);
    } else {
      const serialized = JSON.stringify(chunk);
      if (typeof serialized !== 'string') {
        throw new TypeError('not JSON serializable');
      }
      value = JSON.parse(serialized);
    }
  } catch {
    throw new TypeError('Vercel AI stream chunk could not be safely snapshotted');
  }
  return { value, bytes: serializedChunkBytes(value) };
}

function appendTextDelta(chunk: any, accumulated: string): string {
  if (chunk && chunk.type === 'text-delta') {
    if (typeof chunk.textDelta !== 'string') {
      throw new TypeError('Vercel AI text-delta chunk must contain string textDelta');
    }
    return accumulated + chunk.textDelta;
  }
  return accumulated;
}

// =============================================================================
// jacsProvenance — returns a LanguageModelV3Middleware
// =============================================================================

export function jacsProvenance(options: ProvenanceOptions): LanguageModelV3Middleware {
  const signText = options.signText !== false;
  const signToolResults = options.signToolResults !== false;
  const includeA2A = options.a2a === true;
  const unsignedOutputAllowed = allowUnsignedOutput(
    options.allowUnsignedOutput,
    options.strict,
  );
  const postHocStreaming = options.allowPostHocStreaming === true;
  const streamBufferBytes = resolveStreamBufferBytes(options.maxBufferedStreamBytes);

  if (postHocStreaming && !unsignedOutputAllowed) {
    throw new Error(
      'Dangerous post-hoc streaming requires allowUnsignedOutput=true and strict mode disabled',
    );
  }

  // Lazily build and cache the A2A agent card.
  let cachedAgentCard: Record<string, unknown> | null = null;
  function getAgentCard(): Record<string, unknown> | null {
    if (!includeA2A) return null;
    if (cachedAgentCard) return cachedAgentCard;
    try {
      const { JACSA2AIntegration } = require('./a2a');
      const a2a = new JACSA2AIntegration(options.client);
      const card = a2a.exportAgentCard({
        jacsId: options.client.agentId,
        jacsName: options.client.name,
        jacsDescription: `JACS agent ${options.client.name || options.client.agentId}`,
      });
      cachedAgentCard = JSON.parse(JSON.stringify(card));
      return cachedAgentCard;
    } catch (error) {
      if (!unsignedOutputAllowed) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`JACS Vercel AI A2A metadata generation failed: ${message}`);
      }
      console.error(
        '[jacs/vercel-ai] A2A metadata generation failed: explicitly omitting requested metadata:',
        error,
      );
      return null;
    }
  }

  async function addSignedAgentCard(
    jacsMetadata: Record<string, any>,
  ): Promise<void> {
    const agentCard = getAgentCard();
    if (!agentCard) return;

    const a2aProvenance = await signContent(options.client, agentCard, options);
    jacsMetadata.a2a = a2aProvenance;
    if (a2aProvenance.signed === true) {
      // Emit the same object that the dedicated portable document binds. A
      // consumer can compare `a2a.signedDocument.content.output` with this card
      // before treating it as the signer's self-asserted discovery metadata.
      jacsMetadata.agentCard = agentCard;
    }
  }

  const middleware: LanguageModelV3Middleware = {
    specificationVersion: 'v3',

    wrapGenerate: async ({ doGenerate, params }) => {
      const result = await doGenerate();

      if (!signText && !signToolResults && !includeA2A) {
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
      const jacsMetadata: Record<string, any> = { ...provenance };
      if (includeA2A) {
        await addSignedAgentCard(jacsMetadata);
      }

      return {
        ...result,
        providerMetadata: {
          ...result.providerMetadata,
          jacs: jacsMetadata,
        },
      };
    },

    wrapStream: async ({ doStream, params }) => {
      const streamResult = await doStream();

      if (!signText && !includeA2A) {
        return streamResult;
      }

      // Default mode buffers every chunk. Nothing (including text) is exposed
      // before the complete output has a portable signature.
      let accumulatedText = '';
      let bufferedBytes = 0;
      const bufferedChunks: any[] = [];

      const originalStream = streamResult.stream;
      const transform = new TransformStream({
        transform(chunk: any, controller: any) {
          // Snapshot before extracting text or buffering. A provider may retain
          // and later mutate the object it enqueued; releasing that same
          // reference would let output diverge from the bytes chosen to sign.
          const snapshot = snapshotStreamChunk(chunk);
          bufferedBytes += snapshot.bytes;
          if (bufferedBytes > streamBufferBytes) {
            throw new RangeError(
              `Vercel AI stream buffer exceeded ${streamBufferBytes} byte limit`,
            );
          }
          accumulatedText = appendTextDelta(snapshot.value, accumulatedText);

          if (postHocStreaming) {
            controller.enqueue(snapshot.value);
          } else {
            bufferedChunks.push(snapshot.value);
          }
        },
        async flush(controller: any) {
          let textProvenance: ProvenanceRecord | undefined;
          if (accumulatedText) {
            textProvenance = await signContent(
              options.client,
              accumulatedText,
              options,
            );
          }

          let finalMetadataChunk: Record<string, unknown> | undefined;
          if (accumulatedText || includeA2A) {
            const jacsStreamMeta: Record<string, any> = {};

            if (textProvenance) {
              jacsStreamMeta.text = textProvenance;
            }

            if (includeA2A) {
              await addSignedAgentCard(jacsStreamMeta);
            }

            finalMetadataChunk = {
              type: 'provider-metadata',
              providerMetadata: {
                jacs: jacsStreamMeta as any,
              },
            };
          }

          // In buffered mode, construct every requested proof and identity
          // artifact before releasing any model output. A late A2A failure
          // must not turn a nominally fail-closed stream into raw output.
          if (!postHocStreaming) {
            for (const chunk of bufferedChunks) {
              controller.enqueue(chunk);
            }
          }
          if (finalMetadataChunk) {
            controller.enqueue(finalMetadataChunk);
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
