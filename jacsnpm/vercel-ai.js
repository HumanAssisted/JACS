"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.jacsProvenance = jacsProvenance;
exports.withProvenance = withProvenance;
// =============================================================================
// Helpers
// =============================================================================
async function signContent(client, content, opts) {
    try {
        const signed = await client.signMessage(opts.metadata
            ? { content, provenance: opts.metadata }
            : content);
        return {
            signed: true,
            documentId: signed.documentId,
            agentId: signed.agentId,
            timestamp: signed.timestamp,
            metadata: opts.metadata,
        };
    }
    catch (err) {
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
function extractTextFromContent(content) {
    if (!Array.isArray(content))
        return '';
    return content
        .filter((part) => part.type === 'text')
        .map((part) => part.text)
        .join('');
}
// =============================================================================
// jacsProvenance — returns a LanguageModelV3Middleware
// =============================================================================
function jacsProvenance(options) {
    const signText = options.signText !== false;
    const signToolResults = options.signToolResults !== false;
    const includeA2A = options.a2a === true;
    // Lazily build and cache the A2A agent card.
    let cachedAgentCard = null;
    function getAgentCard() {
        if (!includeA2A)
            return null;
        if (cachedAgentCard)
            return cachedAgentCard;
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
        }
        catch {
            return null;
        }
    }
    const middleware = {
        specificationVersion: 'v3',
        wrapGenerate: async ({ doGenerate, params }) => {
            const result = await doGenerate();
            if (!signText && !signToolResults && !includeA2A) {
                return result;
            }
            const provenance = {};
            // Sign text content
            if (signText) {
                const text = extractTextFromContent(result.content);
                if (text) {
                    provenance.text = await signContent(options.client, text, options);
                }
            }
            // Sign tool results if present in params prompt
            if (signToolResults && params.prompt) {
                const toolResults = params.prompt.filter((part) => part.role === 'tool');
                if (toolResults.length > 0) {
                    const toolData = toolResults.map((tr) => ({
                        role: tr.role,
                        content: tr.content,
                    }));
                    provenance.toolResults = await signContent(options.client, toolData, options);
                }
            }
            // Attach provenance to provider metadata
            const jacsMetadata = { ...provenance };
            const agentCard = getAgentCard();
            if (agentCard) {
                jacsMetadata.agentCard = agentCard;
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
            // Accumulate text chunks, sign on stream completion
            let accumulatedText = '';
            const originalStream = streamResult.stream;
            const transform = new TransformStream({
                transform(chunk, controller) {
                    if (chunk.type === 'text-delta') {
                        accumulatedText += chunk.textDelta;
                    }
                    controller.enqueue(chunk);
                },
                async flush(controller) {
                    if (accumulatedText || includeA2A) {
                        const jacsStreamMeta = {};
                        if (accumulatedText) {
                            jacsStreamMeta.text = await signContent(options.client, accumulatedText, options);
                        }
                        const agentCard = getAgentCard();
                        if (agentCard) {
                            jacsStreamMeta.agentCard = agentCard;
                        }
                        controller.enqueue({
                            type: 'provider-metadata',
                            providerMetadata: {
                                jacs: jacsStreamMeta,
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
function withProvenance(model, options) {
    // Lazy import of wrapLanguageModel from 'ai'
    let wrapLanguageModel;
    try {
        wrapLanguageModel = require('ai').wrapLanguageModel;
    }
    catch {
        throw new Error("Could not import 'ai' package. Install it as a dependency: npm install ai");
    }
    return wrapLanguageModel({
        model,
        middleware: jacsProvenance(options),
    });
}
//# sourceMappingURL=vercel-ai.js.map