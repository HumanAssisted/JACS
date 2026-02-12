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
interface LanguageModelV3Middleware {
    specificationVersion: 'v3';
    transformParams?: (opts: any) => Promise<any>;
    wrapGenerate?: (opts: any) => Promise<any>;
    wrapStream?: (opts: any) => Promise<any>;
}
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
    /** Include A2A agent card in provenance metadata. Default: false. */
    a2a?: boolean;
}
export interface ProvenanceRecord {
    signed: boolean;
    documentId: string;
    agentId: string;
    timestamp: string;
    error?: string;
    metadata?: Record<string, unknown>;
}
export declare function jacsProvenance(options: ProvenanceOptions): LanguageModelV3Middleware;
export declare function withProvenance(model: any, options: ProvenanceOptions): any;
export {};
