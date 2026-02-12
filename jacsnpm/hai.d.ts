/**
 * JACS HAI.ai Integration Module
 *
 * Provides methods for integrating JACS agents with HAI.ai platform:
 * - hello(): Verify connectivity with JACS-signed hello world exchange
 * - verifyHaiMessage(): Verify any HAI-signed message
 * - register(): Register an existing agent with HAI.ai
 * - freeChaoticRun(): Run a free chaotic benchmark
 * - baselineRun(): Run a $5 baseline benchmark
 * - submitResponse(): Submit a mediation response for a benchmark job
 * - onBenchmarkJob(): Convenience callback for benchmark job events
 * - connect(): Connect to HAI.ai SSE or WebSocket stream
 *
 * @example
 * ```typescript
 * import { HaiClient } from '@hai.ai/jacs/hai';
 * import { JacsClient } from '@hai.ai/jacs/client';
 *
 * const jacs = await JacsClient.quickstart();
 * const hai = new HaiClient(jacs, 'https://hai.ai');
 *
 * const result = await hai.hello();
 * console.log(`HAI says: ${result.message}`);
 * console.log(`Your IP: ${result.clientIp}`);
 * ```
 */
import { JacsClient } from './client';
/** Result of a hello world exchange with HAI.ai. */
export interface HelloWorldResult {
    /** Whether the exchange succeeded. */
    success: boolean;
    /** ISO 8601 timestamp from HAI's response. */
    timestamp: string;
    /** The caller's IP address as seen by HAI. */
    clientIp: string;
    /** HAI's public key fingerprint. */
    haiPublicKeyFingerprint: string;
    /** Human-readable acknowledgment message from HAI. */
    message: string;
    /** Whether HAI's signature on the ACK was verified. */
    haiSignatureValid: boolean;
    /** Full response from the API. */
    rawResponse: Record<string, unknown>;
}
/** An event received from HAI.ai SSE or WebSocket stream. */
export interface HaiEvent {
    /** Type of event (e.g., "benchmark_job", "heartbeat", "connected"). */
    eventType: string;
    /** Event payload as parsed JSON. */
    data: unknown;
    /** Event ID if provided. */
    id?: string;
    /** Raw event data string. */
    raw: string;
}
/** Result of registering an agent with HAI.ai. */
export interface HaiRegistrationResult {
    success: boolean;
    agentId: string;
    haiSignature: string;
    registrationId: string;
    registeredAt: string;
    rawResponse: Record<string, unknown>;
}
/** A single message in a benchmark transcript. */
export interface TranscriptMessage {
    /** Speaker role ("party_a", "party_b", "mediator", "system"). */
    role: string;
    /** Message text content. */
    content: string;
    /** ISO 8601 timestamp of the message. */
    timestamp: string;
    /** Structural annotations (e.g., "Dispute escalated"). */
    annotations: string[];
}
/** Result of a free chaotic benchmark run. No score, transcript only. */
export interface FreeChaoticResult {
    /** Whether the run completed. */
    success: boolean;
    /** Unique ID for this benchmark run. */
    runId: string;
    /** List of transcript messages. */
    transcript: TranscriptMessage[];
    /** CTA message for paid tiers. */
    upsellMessage: string;
    /** Full response from the API. */
    rawResponse: Record<string, unknown>;
}
/** Result of a $5 baseline benchmark run. Single score, no breakdown. */
export interface BaselineRunResult {
    /** Whether the run completed. */
    success: boolean;
    /** Unique ID for this benchmark run. */
    runId: string;
    /** Single aggregate score (0-100). */
    score: number;
    /** List of transcript messages. */
    transcript: TranscriptMessage[];
    /** ID of the Stripe payment used. */
    paymentId: string;
    /** Full response from the API. */
    rawResponse: Record<string, unknown>;
}
/** Result of submitting a benchmark job response. */
export interface JobResponseResult {
    /** Whether the response was accepted. */
    success: boolean;
    /** The job ID that was responded to. */
    jobId: string;
    /** Acknowledgment message from HAI. */
    message: string;
    /** Full response from the API. */
    rawResponse: Record<string, unknown>;
}
/** A benchmark job received from HAI.ai via SSE or WebSocket. */
export interface BenchmarkJob {
    /** Unique run/job ID. */
    runId: string;
    /** Scenario description or prompt for the mediator. */
    scenario: unknown;
    /** Full event data. */
    data: Record<string, unknown>;
}
/** Options for HaiClient constructor. */
export interface HaiClientOptions {
    /** Request timeout in milliseconds. Default: 30000. */
    timeout?: number;
    /** Maximum retry attempts. Default: 3. */
    maxRetries?: number;
}
export declare class HaiError extends Error {
    statusCode?: number;
    responseData?: Record<string, unknown>;
    constructor(message: string, statusCode?: number, responseData?: Record<string, unknown>);
}
export declare class AuthenticationError extends HaiError {
    constructor(message: string, statusCode?: number);
}
export declare class HaiConnectionError extends HaiError {
    constructor(message: string);
}
export declare class WebSocketError extends HaiError {
    constructor(message: string, statusCode?: number);
}
/** Options for HaiClient.connect(). */
export interface ConnectOptions {
    /** Transport protocol: "sse" (default) or "ws" (WebSocket). */
    transport?: 'sse' | 'ws';
    /** Callback function called for each event. */
    onEvent?: (event: HaiEvent) => void;
}
/** Options for HaiClient.onBenchmarkJob(). */
export interface OnBenchmarkJobOptions {
    /** API key for authentication (or HAI_API_KEY env var). */
    apiKey?: string;
    /** Transport protocol: "sse" (default) or "ws". */
    transport?: 'sse' | 'ws';
}
/**
 * Client for interacting with HAI.ai platform.
 *
 * Requires a JacsClient instance for JACS signing operations and
 * a base URL for the HAI.ai server.
 *
 * @example
 * ```typescript
 * const jacs = await JacsClient.quickstart();
 * const hai = new HaiClient(jacs, 'https://hai.ai');
 *
 * // Hello world
 * const result = await hai.hello();
 * if (result.success) {
 *   console.log(`HAI says: ${result.message}`);
 * }
 * ```
 */
export declare class HaiClient {
    private jacsClient;
    private baseUrl;
    private timeout;
    private maxRetries;
    private _shouldDisconnect;
    private _connected;
    private _wsConnection;
    private _lastEventId;
    constructor(jacsClient: JacsClient, baseUrl?: string, options?: HaiClientOptions);
    /** Whether the client is currently connected to an event stream. */
    get isConnected(): boolean;
    private makeUrl;
    /**
     * Perform a hello world exchange with HAI.ai.
     *
     * Sends a JACS-signed request to the HAI hello endpoint. HAI responds
     * with a signed ACK containing the caller's IP and a timestamp.
     *
     * @param includeTest - If true, request a test scenario preview
     * @returns HelloWorldResult with HAI's signed acknowledgment
     * @throws AuthenticationError if JACS signature is rejected
     * @throws HaiConnectionError if cannot connect to HAI.ai
     */
    hello(includeTest?: boolean): Promise<HelloWorldResult>;
    /**
     * Verify a message signed by HAI.ai.
     *
     * Generic verification for any HAI-signed message. If the message
     * is a JACS-signed document (contains jacsSignature), delegates to
     * JacsClient.verify(). Otherwise attempts raw signature verification.
     *
     * @param message - The message string that was signed
     * @param signature - The signature to verify (base64-encoded)
     * @param haiPublicKey - HAI's public key (PEM or base64)
     * @returns true if signature is valid, false otherwise
     */
    verifyHaiMessage(message: string, signature: string, haiPublicKey?: string): boolean;
    /**
     * Register a JACS agent with HAI.ai.
     *
     * @param apiKey - API key for authentication (or HAI_API_KEY env var)
     * @returns HaiRegistrationResult with registration details
     */
    register(apiKey?: string): Promise<HaiRegistrationResult>;
    private parseTranscript;
    /**
     * Run a free chaotic benchmark.
     *
     * Connects to HAI.ai and runs the canonical baseline scenario with
     * a cheap model. No judge evaluation, no scoring. Returns the raw
     * conversation transcript with structural annotations.
     *
     * Rate limited to 3 runs per JACS keypair per 24 hours.
     *
     * @param options - Optional: apiKey, transport
     * @returns FreeChaoticResult with transcript and annotations
     * @throws AuthenticationError if authentication fails
     * @throws HaiError on 429 (rate limited) or other errors
     */
    freeChaoticRun(options?: {
        apiKey?: string;
        transport?: 'sse' | 'ws';
    }): Promise<FreeChaoticResult>;
    /**
     * Run a $5 baseline benchmark.
     *
     * Flow:
     * 1. Creates a Stripe Checkout session via the API
     * 2. Returns the checkout URL (caller handles browser opening)
     * 3. Polls for payment confirmation
     * 4. Runs the benchmark with quality models
     * 5. Returns single aggregate score (no category breakdown)
     *
     * @param options - apiKey, transport, pollInterval, pollTimeout
     * @returns BaselineRunResult with score and transcript
     * @throws AuthenticationError if authentication fails
     * @throws HaiError on payment failure or benchmark errors
     */
    baselineRun(options?: {
        apiKey?: string;
        transport?: 'sse' | 'ws';
        /** Milliseconds between payment status checks. Default: 2000. */
        pollIntervalMs?: number;
        /** Max milliseconds to wait for payment. Default: 300000 (5 min). */
        pollTimeoutMs?: number;
        /** Callback with checkout URL (e.g., to open in browser). */
        onCheckoutUrl?: (url: string) => void;
    }): Promise<BaselineRunResult>;
    /**
     * Submit a moderation response for a benchmark job.
     *
     * After receiving a benchmark_job event via SSE/WS, agents call this
     * method to submit their mediation response back to HAI.ai.
     *
     * @param jobId - The job/run ID from the benchmark_job event
     * @param message - The mediator's response message
     * @param options - Optional: metadata, processingTimeMs, apiKey
     * @returns JobResponseResult with acknowledgment
     * @throws AuthenticationError if authentication fails
     * @throws HaiError if job not found or response rejected
     *
     * @example
     * ```typescript
     * for await (const event of hai.connect()) {
     *   if (event.eventType === 'benchmark_job') {
     *     const job = event.data as Record<string, unknown>;
     *     const result = await hai.submitResponse(
     *       job.run_id as string,
     *       'I understand both perspectives. Let me suggest...',
     *       { processingTimeMs: 1500 },
     *     );
     *     console.log(result.message);
     *   }
     * }
     * ```
     */
    submitResponse(jobId: string, message: string, options?: {
        metadata?: Record<string, unknown>;
        processingTimeMs?: number;
        apiKey?: string;
    }): Promise<JobResponseResult>;
    /**
     * Convenience wrapper around connect() that calls a handler for each
     * benchmark job received from HAI.ai.
     *
     * Connects to the event stream and dispatches benchmark_job events to
     * the provided callback. Non-benchmark events (heartbeats, etc.) are
     * silently consumed. Runs until disconnect() is called.
     *
     * @param handler - Async function called for each benchmark job.
     *   Receives a BenchmarkJob with runId, scenario, and raw data.
     * @param options - apiKey and transport options
     *
     * @example
     * ```typescript
     * await hai.onBenchmarkJob(async (job) => {
     *   console.log(`Received job ${job.runId}`);
     *   const response = mediator.respond(job.scenario);
     *   await hai.submitResponse(job.runId, response);
     * });
     * ```
     */
    onBenchmarkJob(handler: (job: BenchmarkJob) => Promise<void>, options?: OnBenchmarkJobOptions): Promise<void>;
    /**
     * Connect to HAI.ai event stream via SSE or WebSocket.
     *
     * Returns an async generator that yields HaiEvent objects as they arrive.
     * Supports automatic reconnection with exponential backoff.
     *
     * @param apiKey - API key for authentication (or HAI_API_KEY env var)
     * @param options - Transport and callback options
     * @returns AsyncGenerator of HaiEvent objects
     *
     * @example
     * ```typescript
     * // SSE (default)
     * for await (const event of hai.connect('api-key')) {
     *   console.log(event.eventType, event.data);
     * }
     *
     * // WebSocket
     * for await (const event of hai.connect('api-key', { transport: 'ws' })) {
     *   console.log(event.eventType, event.data);
     * }
     * ```
     */
    connect(apiKey?: string, options?: ConnectOptions): AsyncGenerator<HaiEvent>;
    /**
     * Disconnect from HAI.ai event stream (SSE or WebSocket).
     * Safe to call even if not connected.
     */
    disconnect(): void;
    private _connectSSE;
    private _connectWS;
    /**
     * Open a WebSocket connection. Uses the `ws` package if available,
     * falls back to built-in WebSocket (Node 21+).
     */
    private _openWebSocket;
    /** Receive one message from a WebSocket, parsing JSON if possible. */
    private _wsRecv;
    /** Build a JACS-signed handshake message for WS authentication. */
    private _buildWSHandshake;
}
