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
Object.defineProperty(exports, "__esModule", { value: true });
exports.jacsProvenance = jacsProvenance;
exports.withProvenance = withProvenance;
const output_policy_js_1 = require("./output-policy.js");
// =============================================================================
// Helpers
// =============================================================================
async function signContent(client, content, opts) {
    const binding = {
        output: content,
        metadata: opts.metadata ?? {},
    };
    try {
        const signed = await client.signMessage(binding);
        const signedDocument = (0, output_policy_js_1.requireSignedRaw)(signed, 'JACS Vercel AI provenance signing');
        if (typeof signed.documentId !== 'string' || signed.documentId.length === 0
            || typeof signed.agentId !== 'string' || signed.agentId.length === 0
            || typeof signed.timestamp !== 'string' || signed.timestamp.length === 0) {
            throw new TypeError('JACS Vercel AI provenance signing returned incomplete provenance');
        }
        let parsed;
        try {
            parsed = JSON.parse(signedDocument);
        }
        catch {
            throw new TypeError('JACS Vercel AI provenance signing returned invalid JSON');
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
            || !parsed.jacsSignature
            || typeof parsed.jacsSignature !== 'object') {
            throw new TypeError('JACS Vercel AI provenance signing returned no signature metadata');
        }
        const document = parsed;
        const signature = document.jacsSignature;
        if (document.jacsId !== signed.documentId
            || (signature.agentID ?? signature.agentId) !== signed.agentId
            || signature.date !== signed.timestamp) {
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
    }
    catch (err) {
        if (!(0, output_policy_js_1.allowUnsignedOutput)(opts.allowUnsignedOutput, opts.strict)) {
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
function stableJson(value) {
    if (Array.isArray(value)) {
        return `[${value.map((item) => stableJson(item)).join(',')}]`;
    }
    if (value && typeof value === 'object') {
        const entries = Object.entries(value)
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
function extractTextFromContent(content) {
    if (!Array.isArray(content)) {
        throw new TypeError('Vercel AI generation content must be an array');
    }
    return content
        .filter((part) => part.type === 'text')
        .map((part) => {
        if (typeof part.text !== 'string') {
            throw new TypeError('Vercel AI text content must contain a string');
        }
        return part.text;
    })
        .join('');
}
const DEFAULT_STREAM_BUFFER_BYTES = 1024 * 1024;
const MAX_STREAM_BUFFER_BYTES = 16 * 1024 * 1024;
function resolveStreamBufferBytes(value) {
    if (typeof value === 'undefined')
        return DEFAULT_STREAM_BUFFER_BYTES;
    if (typeof value !== 'number' || !Number.isSafeInteger(value)
        || value <= 0 || value > MAX_STREAM_BUFFER_BYTES) {
        throw new RangeError(`maxBufferedStreamBytes must be an integer from 1 to ${MAX_STREAM_BUFFER_BYTES}`);
    }
    return value;
}
function serializedChunkBytes(chunk) {
    const serialized = JSON.stringify(chunk);
    if (typeof serialized !== 'string') {
        throw new TypeError('Vercel AI stream chunk is not JSON serializable');
    }
    return new TextEncoder().encode(serialized).byteLength;
}
function snapshotStreamChunk(chunk) {
    let value;
    try {
        if (typeof globalThis.structuredClone === 'function') {
            value = globalThis.structuredClone(chunk);
        }
        else {
            const serialized = JSON.stringify(chunk);
            if (typeof serialized !== 'string') {
                throw new TypeError('not JSON serializable');
            }
            value = JSON.parse(serialized);
        }
    }
    catch {
        throw new TypeError('Vercel AI stream chunk could not be safely snapshotted');
    }
    return { value, bytes: serializedChunkBytes(value) };
}
function appendTextDelta(chunk, accumulated) {
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
function jacsProvenance(options) {
    const signText = options.signText !== false;
    const signToolResults = options.signToolResults !== false;
    const includeA2A = options.a2a === true;
    const unsignedOutputAllowed = (0, output_policy_js_1.allowUnsignedOutput)(options.allowUnsignedOutput, options.strict);
    const postHocStreaming = options.allowPostHocStreaming === true;
    const streamBufferBytes = resolveStreamBufferBytes(options.maxBufferedStreamBytes);
    if (postHocStreaming && !unsignedOutputAllowed) {
        throw new Error('Dangerous post-hoc streaming requires allowUnsignedOutput=true and strict mode disabled');
    }
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
        catch (error) {
            if (!unsignedOutputAllowed) {
                const message = error instanceof Error ? error.message : String(error);
                throw new Error(`JACS Vercel AI A2A metadata generation failed: ${message}`);
            }
            console.error('[jacs/vercel-ai] A2A metadata generation failed: explicitly omitting requested metadata:', error);
            return null;
        }
    }
    async function addSignedAgentCard(jacsMetadata) {
        const agentCard = getAgentCard();
        if (!agentCard)
            return;
        const a2aProvenance = await signContent(options.client, agentCard, options);
        jacsMetadata.a2a = a2aProvenance;
        if (a2aProvenance.signed === true) {
            // Emit the same object that the dedicated portable document binds. A
            // consumer can compare `a2a.signedDocument.content.output` with this card
            // before treating it as the signer's self-asserted discovery metadata.
            jacsMetadata.agentCard = agentCard;
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
            const bufferedChunks = [];
            const originalStream = streamResult.stream;
            const transform = new TransformStream({
                transform(chunk, controller) {
                    // Snapshot before extracting text or buffering. A provider may retain
                    // and later mutate the object it enqueued; releasing that same
                    // reference would let output diverge from the bytes chosen to sign.
                    const snapshot = snapshotStreamChunk(chunk);
                    bufferedBytes += snapshot.bytes;
                    if (bufferedBytes > streamBufferBytes) {
                        throw new RangeError(`Vercel AI stream buffer exceeded ${streamBufferBytes} byte limit`);
                    }
                    accumulatedText = appendTextDelta(snapshot.value, accumulatedText);
                    if (postHocStreaming) {
                        controller.enqueue(snapshot.value);
                    }
                    else {
                        bufferedChunks.push(snapshot.value);
                    }
                },
                async flush(controller) {
                    let textProvenance;
                    if (accumulatedText) {
                        textProvenance = await signContent(options.client, accumulatedText, options);
                    }
                    let finalMetadataChunk;
                    if (accumulatedText || includeA2A) {
                        const jacsStreamMeta = {};
                        if (textProvenance) {
                            jacsStreamMeta.text = textProvenance;
                        }
                        if (includeA2A) {
                            await addSignedAgentCard(jacsStreamMeta);
                        }
                        finalMetadataChunk = {
                            type: 'provider-metadata',
                            providerMetadata: {
                                jacs: jacsStreamMeta,
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