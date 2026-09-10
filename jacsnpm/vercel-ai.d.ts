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
export declare function jacsProvenance(options: ProvenanceOptions): LanguageModelV3Middleware;
export declare function withProvenance(model: any, options: ProvenanceOptions): any;
export {};
