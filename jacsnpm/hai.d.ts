/**
 * JACS HAI.ai Integration Module
 *
 * Provides methods for integrating JACS agents with HAI.ai platform:
 * - hello(): Verify connectivity with JACS-signed hello world exchange
 * - verifyHaiMessage(): Verify any HAI-signed message
 * - register(): Register an existing agent with HAI.ai
 * - connect(): Connect to HAI.ai SSE stream
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
    constructor(jacsClient: JacsClient, baseUrl?: string, options?: HaiClientOptions);
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
}
