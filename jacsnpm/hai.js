"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.HaiClient = exports.WebSocketError = exports.HaiConnectionError = exports.AuthenticationError = exports.HaiError = void 0;
// =============================================================================
// Errors
// =============================================================================
class HaiError extends Error {
    constructor(message, statusCode, responseData) {
        super(message);
        this.name = 'HaiError';
        this.statusCode = statusCode;
        this.responseData = responseData;
    }
}
exports.HaiError = HaiError;
class AuthenticationError extends HaiError {
    constructor(message, statusCode) {
        super(message, statusCode);
        this.name = 'AuthenticationError';
    }
}
exports.AuthenticationError = AuthenticationError;
class HaiConnectionError extends HaiError {
    constructor(message) {
        super(message);
        this.name = 'HaiConnectionError';
    }
}
exports.HaiConnectionError = HaiConnectionError;
class WebSocketError extends HaiError {
    constructor(message, statusCode) {
        super(message, statusCode);
        this.name = 'WebSocketError';
    }
}
exports.WebSocketError = WebSocketError;
// =============================================================================
// HaiClient
// =============================================================================
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
class HaiClient {
    constructor(jacsClient, baseUrl = 'https://hai.ai', options) {
        this._shouldDisconnect = false;
        this._connected = false;
        this._wsConnection = null;
        this._lastEventId = null;
        this.jacsClient = jacsClient;
        this.baseUrl = baseUrl.replace(/\/+$/, '');
        this.timeout = options?.timeout ?? 30000;
        this.maxRetries = options?.maxRetries ?? 3;
    }
    /** Whether the client is currently connected to an event stream. */
    get isConnected() {
        return this._connected;
    }
    // ---------------------------------------------------------------------------
    // URL helper
    // ---------------------------------------------------------------------------
    makeUrl(path) {
        const cleanPath = path.startsWith('/') ? path : `/${path}`;
        return `${this.baseUrl}${cleanPath}`;
    }
    // ---------------------------------------------------------------------------
    // hello() -- Step 21
    // ---------------------------------------------------------------------------
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
    async hello(includeTest = false) {
        const agentId = this.jacsClient.agentId;
        if (!agentId) {
            throw new HaiError('No agent loaded on JacsClient. Call quickstart() or load() first.');
        }
        // Build JACS signature auth header
        const timestamp = new Date().toISOString();
        const signPayload = `${agentId}:${timestamp}`;
        let signature = '';
        try {
            const signed = await this.jacsClient.signMessage(signPayload);
            // Extract signature from signed document
            const doc = JSON.parse(signed.raw);
            signature = doc?.jacsSignature?.signature ?? '';
        }
        catch (e) {
            throw new HaiError(`Failed to sign hello request: ${e}`);
        }
        const url = this.makeUrl('/api/v1/agents/hello');
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `JACS ${agentId}:${timestamp}:${signature}`,
        };
        const payload = { agent_id: agentId };
        if (includeTest) {
            payload.include_test = true;
        }
        let response;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            response = await fetch(url, {
                method: 'POST',
                headers,
                body: JSON.stringify(payload),
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
        }
        catch (e) {
            if (e instanceof Error && e.name === 'AbortError') {
                throw new HaiConnectionError(`Request timed out after ${this.timeout}ms`);
            }
            throw new HaiConnectionError(`Connection failed: ${e}`);
        }
        if (response.status === 401) {
            let errorData = {};
            try {
                errorData = await response.json();
            }
            catch { /* empty */ }
            throw new AuthenticationError('JACS signature rejected by HAI', 401);
        }
        if (response.status === 429) {
            throw new HaiError('Rate limited -- too many hello requests', 429);
        }
        if (response.status !== 200 && response.status !== 201) {
            let errorMsg = `Hello failed with status ${response.status}`;
            try {
                const errBody = await response.json();
                if (errBody.error)
                    errorMsg = String(errBody.error);
            }
            catch { /* empty */ }
            throw new HaiError(errorMsg, response.status);
        }
        const data = await response.json();
        // Verify HAI's signature on the ACK
        let haiSigValid = false;
        const haiAckSignature = data.hai_ack_signature;
        if (haiAckSignature) {
            haiSigValid = this.verifyHaiMessage(JSON.stringify(data), haiAckSignature, data.hai_public_key || '');
        }
        return {
            success: true,
            timestamp: data.timestamp || '',
            clientIp: data.client_ip || '',
            haiPublicKeyFingerprint: data.hai_public_key_fingerprint || '',
            message: data.message || '',
            haiSignatureValid: haiSigValid,
            rawResponse: data,
        };
    }
    // ---------------------------------------------------------------------------
    // verifyHaiMessage() -- Step 21
    // ---------------------------------------------------------------------------
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
    verifyHaiMessage(message, signature, haiPublicKey = '') {
        if (!signature || !message) {
            return false;
        }
        // If the message looks like a JACS signed document, verify via JacsClient
        try {
            const parsed = JSON.parse(message);
            if (parsed && typeof parsed === 'object' && 'jacsSignature' in parsed) {
                const result = this.jacsClient.verifySync(message);
                return result.valid;
            }
        }
        catch {
            // Not JSON or parse error -- fall through to raw verification
        }
        // For raw message + signature, we would need the HAI public key
        // and a crypto library. Since Node's built-in crypto can handle
        // Ed25519, attempt verification if we have a key.
        if (haiPublicKey) {
            try {
                const crypto = require('crypto');
                const sigBuffer = Buffer.from(signature, 'base64');
                const msgBuffer = Buffer.from(message, 'utf-8');
                // Try Ed25519 verification
                let keyObject;
                if (haiPublicKey.startsWith('-----')) {
                    keyObject = crypto.createPublicKey(haiPublicKey);
                }
                else {
                    // Assume raw base64 Ed25519 public key
                    const keyBuffer = Buffer.from(haiPublicKey, 'base64');
                    keyObject = crypto.createPublicKey({
                        key: keyBuffer,
                        format: 'der',
                        type: 'spki',
                    });
                }
                return crypto.verify(null, msgBuffer, keyObject, sigBuffer);
            }
            catch {
                // Verification failed or unsupported key format
            }
        }
        return false;
    }
    // ---------------------------------------------------------------------------
    // register()
    // ---------------------------------------------------------------------------
    /**
     * Register a JACS agent with HAI.ai.
     *
     * @param apiKey - API key for authentication (or HAI_API_KEY env var)
     * @returns HaiRegistrationResult with registration details
     */
    async register(apiKey) {
        const resolvedKey = apiKey || process.env.HAI_API_KEY || '';
        let agentJson;
        try {
            const agent = this.jacsClient;
            agentJson = agent.agent.getAgentJsonSync();
        }
        catch {
            throw new HaiError('Failed to export agent document. Ensure agent is loaded.');
        }
        const url = this.makeUrl('/api/v1/agents/register');
        const headers = {
            'Content-Type': 'application/json',
        };
        if (resolvedKey) {
            headers['Authorization'] = `Bearer ${resolvedKey}`;
        }
        let lastError = null;
        for (let attempt = 0; attempt < this.maxRetries; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.timeout);
                const response = await fetch(url, {
                    method: 'POST',
                    headers,
                    body: agentJson,
                    signal: controller.signal,
                });
                clearTimeout(timeoutId);
                if (response.status === 200 || response.status === 201) {
                    const data = await response.json();
                    return {
                        success: true,
                        agentId: data.agent_id || data.agentId || '',
                        haiSignature: data.hai_signature || data.haiSignature || '',
                        registrationId: data.registration_id || data.registrationId || '',
                        registeredAt: data.registered_at || data.registeredAt || '',
                        rawResponse: data,
                    };
                }
                if (response.status === 401) {
                    throw new AuthenticationError('Invalid or missing API key', 401);
                }
                lastError = new HaiError(`Registration failed with status ${response.status}`, response.status);
            }
            catch (e) {
                if (e instanceof HaiError)
                    throw e;
                lastError = e instanceof Error ? e : new Error(String(e));
            }
            // Exponential backoff
            if (attempt < this.maxRetries - 1) {
                await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
            }
        }
        throw lastError || new HaiError('Registration failed after all retries');
    }
    // ---------------------------------------------------------------------------
    // Transcript parsing helper
    // ---------------------------------------------------------------------------
    parseTranscript(raw) {
        return (raw || []).map((msg) => {
            const m = msg;
            return {
                role: m.role || 'system',
                content: m.content || '',
                timestamp: m.timestamp || '',
                annotations: m.annotations || [],
            };
        });
    }
    // ---------------------------------------------------------------------------
    // freeChaoticRun() -- Step 90
    // ---------------------------------------------------------------------------
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
    async freeChaoticRun(options) {
        const agentId = this.jacsClient.agentId;
        if (!agentId) {
            throw new HaiError('No agent loaded. Call quickstart() or load() first.');
        }
        const apiKey = options?.apiKey || process.env.HAI_API_KEY || '';
        // Build JACS signature auth header
        const timestamp = new Date().toISOString();
        const signPayload = `${agentId}:${timestamp}`;
        let signature = '';
        try {
            const signed = await this.jacsClient.signMessage(signPayload);
            const doc = JSON.parse(signed.raw);
            signature = doc?.jacsSignature?.signature ?? '';
        }
        catch (e) {
            throw new HaiError(`Failed to sign request: ${e}`);
        }
        const url = this.makeUrl('/api/benchmark/run');
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `JACS ${agentId}:${timestamp}:${signature}`,
        };
        if (apiKey) {
            headers['X-API-Key'] = apiKey;
        }
        const payload = {
            name: `Free Chaotic Run - ${agentId.slice(0, 8)}`,
            tier: 'free_chaotic',
            transport: options?.transport ?? 'sse',
        };
        let response;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), Math.max(this.timeout, 120000));
            response = await fetch(url, {
                method: 'POST',
                headers,
                body: JSON.stringify(payload),
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
        }
        catch (e) {
            if (e instanceof Error && e.name === 'AbortError') {
                throw new HaiConnectionError('Request timed out');
            }
            throw new HaiConnectionError(`Connection failed: ${e}`);
        }
        if (response.status === 401) {
            throw new AuthenticationError('Authentication failed', 401);
        }
        if (response.status === 429) {
            throw new HaiError('Rate limited -- maximum 3 free chaotic runs per 24 hours', 429);
        }
        if (response.status !== 200 && response.status !== 201) {
            let msg = `Free chaotic run failed with status ${response.status}`;
            try {
                const errBody = await response.json();
                if (errBody.error)
                    msg = String(errBody.error);
            }
            catch { /* empty */ }
            throw new HaiError(msg, response.status);
        }
        const data = await response.json();
        return {
            success: true,
            runId: data.run_id || data.runId || '',
            transcript: this.parseTranscript(data.transcript || []),
            upsellMessage: data.upsell_message || data.upsellMessage || '',
            rawResponse: data,
        };
    }
    // ---------------------------------------------------------------------------
    // baselineRun() -- Step 90
    // ---------------------------------------------------------------------------
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
    async baselineRun(options) {
        const agentId = this.jacsClient.agentId;
        if (!agentId) {
            throw new HaiError('No agent loaded. Call quickstart() or load() first.');
        }
        const apiKey = options?.apiKey || process.env.HAI_API_KEY || '';
        const pollIntervalMs = options?.pollIntervalMs ?? 2000;
        const pollTimeoutMs = options?.pollTimeoutMs ?? 300000;
        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) {
            headers['Authorization'] = `Bearer ${apiKey}`;
        }
        // Step 1: Create Stripe Checkout session
        const purchaseUrl = this.makeUrl('/api/benchmark/purchase');
        const purchasePayload = { tier: 'baseline', agent_id: agentId };
        let checkoutUrl;
        let paymentId;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            const resp = await fetch(purchaseUrl, {
                method: 'POST',
                headers,
                body: JSON.stringify(purchasePayload),
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            if (resp.status === 401) {
                throw new AuthenticationError('Authentication failed', 401);
            }
            if (resp.status !== 200 && resp.status !== 201) {
                throw new HaiError(`Failed to create payment: HTTP ${resp.status}`, resp.status);
            }
            const purchaseData = await resp.json();
            checkoutUrl = purchaseData.checkout_url || '';
            paymentId = purchaseData.payment_id || '';
            if (!checkoutUrl) {
                throw new HaiError('No checkout URL returned from API');
            }
        }
        catch (e) {
            if (e instanceof HaiError)
                throw e;
            throw new HaiConnectionError(`Failed to create payment: ${e}`);
        }
        // Step 2: Notify caller of checkout URL
        if (options?.onCheckoutUrl) {
            options.onCheckoutUrl(checkoutUrl);
        }
        // Step 3: Poll for payment confirmation
        const paymentStatusUrl = this.makeUrl(`/api/benchmark/payments/${paymentId}/status`);
        const startTime = Date.now();
        while ((Date.now() - startTime) < pollTimeoutMs) {
            try {
                const statusResp = await fetch(paymentStatusUrl, { headers });
                if (statusResp.status === 200) {
                    const statusData = await statusResp.json();
                    const paymentStatus = statusData.status || '';
                    if (paymentStatus === 'paid')
                        break;
                    if (['failed', 'expired', 'cancelled'].includes(paymentStatus)) {
                        throw new HaiError(`Payment ${paymentStatus}: ${statusData.message || ''}`);
                    }
                }
            }
            catch (e) {
                if (e instanceof HaiError)
                    throw e;
                // Ignore transient errors during polling
            }
            await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
        }
        if ((Date.now() - startTime) >= pollTimeoutMs) {
            throw new HaiError('Payment not confirmed within timeout. Complete payment and retry.');
        }
        // Step 4: Run the benchmark
        const runTimestamp = new Date().toISOString();
        const runSignPayload = `${agentId}:${runTimestamp}`;
        let runSignature = '';
        try {
            const signed = await this.jacsClient.signMessage(runSignPayload);
            const doc = JSON.parse(signed.raw);
            runSignature = doc?.jacsSignature?.signature ?? '';
        }
        catch (e) {
            throw new HaiError(`Failed to sign run request: ${e}`);
        }
        const runUrl = this.makeUrl('/api/benchmark/run');
        const runHeaders = {
            'Content-Type': 'application/json',
            'Authorization': `JACS ${agentId}:${runTimestamp}:${runSignature}`,
        };
        if (apiKey) {
            runHeaders['X-API-Key'] = apiKey;
        }
        const runPayload = {
            name: `Baseline Run - ${agentId.slice(0, 8)}`,
            tier: 'baseline',
            payment_id: paymentId,
            transport: options?.transport ?? 'sse',
        };
        let runResponse;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), Math.max(this.timeout, 300000));
            runResponse = await fetch(runUrl, {
                method: 'POST',
                headers: runHeaders,
                body: JSON.stringify(runPayload),
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
        }
        catch (e) {
            if (e instanceof Error && e.name === 'AbortError') {
                throw new HaiConnectionError('Benchmark request timed out');
            }
            throw new HaiConnectionError(`Connection failed: ${e}`);
        }
        if (runResponse.status !== 200 && runResponse.status !== 201) {
            let msg = `Baseline run failed with status ${runResponse.status}`;
            try {
                const errBody = await runResponse.json();
                if (errBody.error)
                    msg = String(errBody.error);
            }
            catch { /* empty */ }
            throw new HaiError(msg, runResponse.status);
        }
        const data = await runResponse.json();
        return {
            success: true,
            runId: data.run_id || data.runId || '',
            score: Number(data.score) || 0,
            transcript: this.parseTranscript(data.transcript || []),
            paymentId,
            rawResponse: data,
        };
    }
    // ---------------------------------------------------------------------------
    // submitResponse() -- Step 100
    // ---------------------------------------------------------------------------
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
    async submitResponse(jobId, message, options) {
        const agentId = this.jacsClient.agentId;
        if (!agentId) {
            throw new HaiError('No agent loaded. Call quickstart() or load() first.');
        }
        const apiKey = options?.apiKey || process.env.HAI_API_KEY || '';
        // Build JACS signature auth header
        const timestamp = new Date().toISOString();
        const signPayload = `${agentId}:${timestamp}`;
        let signature = '';
        try {
            const signed = await this.jacsClient.signMessage(signPayload);
            const doc = JSON.parse(signed.raw);
            signature = doc?.jacsSignature?.signature ?? '';
        }
        catch (e) {
            throw new HaiError(`Failed to sign request: ${e}`);
        }
        const url = this.makeUrl(`/api/v1/agents/jobs/${jobId}/response`);
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `JACS ${agentId}:${timestamp}:${signature}`,
        };
        if (apiKey) {
            headers['X-API-Key'] = apiKey;
        }
        // Build ModerationResponse payload (matches Rust JobResponseRequest)
        const responseBody = { message };
        if (options?.metadata !== undefined) {
            responseBody.metadata = options.metadata;
        }
        if (options?.processingTimeMs !== undefined) {
            responseBody.processing_time_ms = options.processingTimeMs;
        }
        const payload = { response: responseBody };
        let response;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            response = await fetch(url, {
                method: 'POST',
                headers,
                body: JSON.stringify(payload),
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
        }
        catch (e) {
            if (e instanceof Error && e.name === 'AbortError') {
                throw new HaiConnectionError('Request timed out');
            }
            throw new HaiConnectionError(`Connection failed: ${e}`);
        }
        if (response.status === 401) {
            throw new AuthenticationError('Authentication failed', 401);
        }
        if (response.status === 404) {
            throw new HaiError(`Job not found: ${jobId}`, 404);
        }
        if (response.status !== 200 && response.status !== 201) {
            let msg = `Job response rejected with status ${response.status}`;
            try {
                const errBody = await response.json();
                if (errBody.error)
                    msg = String(errBody.error);
            }
            catch { /* empty */ }
            throw new HaiError(msg, response.status);
        }
        const data = await response.json();
        return {
            success: data.success ?? true,
            jobId: data.job_id || data.jobId || jobId,
            message: data.message || 'Response accepted',
            rawResponse: data,
        };
    }
    // ---------------------------------------------------------------------------
    // onBenchmarkJob() -- Step 100
    // ---------------------------------------------------------------------------
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
    async onBenchmarkJob(handler, options) {
        const apiKey = options?.apiKey;
        const transport = options?.transport;
        for await (const event of this.connect(apiKey, { transport })) {
            if (event.eventType === 'benchmark_job') {
                const data = (typeof event.data === 'object' && event.data !== null)
                    ? event.data
                    : {};
                const job = {
                    runId: data.run_id || data.runId || '',
                    scenario: data.scenario ?? data.prompt ?? data,
                    data,
                };
                await handler(job);
            }
        }
    }
    // ---------------------------------------------------------------------------
    // connect() -- Steps 59-61: SSE and WebSocket transport
    // ---------------------------------------------------------------------------
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
    async *connect(apiKey, options) {
        const transport = options?.transport ?? 'sse';
        const onEvent = options?.onEvent;
        if (transport !== 'sse' && transport !== 'ws') {
            throw new Error(`transport must be 'sse' or 'ws', got '${transport}'`);
        }
        this._shouldDisconnect = false;
        this._connected = false;
        const resolvedKey = apiKey || process.env.HAI_API_KEY || '';
        const agentId = this.jacsClient.agentId;
        if (!agentId) {
            throw new HaiError('No agent loaded on JacsClient. Call quickstart() or load() first.');
        }
        if (transport === 'ws') {
            yield* this._connectWS(resolvedKey, agentId, onEvent);
        }
        else {
            yield* this._connectSSE(resolvedKey, agentId, onEvent);
        }
    }
    /**
     * Disconnect from HAI.ai event stream (SSE or WebSocket).
     * Safe to call even if not connected.
     */
    disconnect() {
        this._shouldDisconnect = true;
        if (this._wsConnection) {
            try {
                this._wsConnection.close();
            }
            catch { /* ignore */ }
            this._wsConnection = null;
        }
        this._connected = false;
    }
    // ---------------------------------------------------------------------------
    // SSE transport (internal)
    // ---------------------------------------------------------------------------
    async *_connectSSE(apiKey, agentId, onEvent) {
        const url = this.makeUrl(`/api/v1/agents/${agentId}/events`);
        let reconnectDelay = 1000;
        const maxReconnectDelay = 60000;
        while (!this._shouldDisconnect) {
            try {
                const headers = {
                    Authorization: `Bearer ${apiKey}`,
                    Accept: 'text/event-stream',
                };
                if (this._lastEventId) {
                    headers['Last-Event-ID'] = this._lastEventId;
                }
                const response = await fetch(url, { headers, signal: undefined });
                if (response.status === 401) {
                    throw new AuthenticationError('Invalid or missing API key', 401);
                }
                if (response.status !== 200) {
                    throw new HaiConnectionError(`SSE connection failed with status ${response.status}`);
                }
                this._connected = true;
                reconnectDelay = 1000;
                const reader = response.body?.getReader();
                if (!reader)
                    throw new HaiConnectionError('No response body for SSE');
                const decoder = new TextDecoder();
                let buffer = '';
                while (!this._shouldDisconnect) {
                    const { done, value } = await reader.read();
                    if (done)
                        break;
                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || '';
                    let eventType = 'message';
                    let eventData = '';
                    let eventId;
                    for (const line of lines) {
                        if (line.startsWith('event:')) {
                            eventType = line.slice(6).trim();
                        }
                        else if (line.startsWith('data:')) {
                            eventData += (eventData ? '\n' : '') + line.slice(5).trim();
                        }
                        else if (line.startsWith('id:')) {
                            eventId = line.slice(3).trim();
                        }
                        else if (line === '') {
                            if (eventData) {
                                if (eventId)
                                    this._lastEventId = eventId;
                                let parsed;
                                try {
                                    parsed = JSON.parse(eventData);
                                }
                                catch {
                                    parsed = eventData;
                                }
                                const event = {
                                    eventType,
                                    data: parsed,
                                    id: eventId,
                                    raw: eventData,
                                };
                                if (onEvent)
                                    onEvent(event);
                                yield event;
                                eventType = 'message';
                                eventData = '';
                                eventId = undefined;
                            }
                        }
                    }
                }
            }
            catch (e) {
                this._connected = false;
                if (this._shouldDisconnect)
                    break;
                if (e instanceof HaiError)
                    throw e;
                await new Promise(resolve => setTimeout(resolve, reconnectDelay));
                reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay);
            }
        }
        this._connected = false;
    }
    // ---------------------------------------------------------------------------
    // WebSocket transport (internal) -- Step 61
    // ---------------------------------------------------------------------------
    async *_connectWS(apiKey, agentId, onEvent) {
        // Convert HTTP URL to WS URL
        const wsUrl = this.baseUrl
            .replace(/^https:/, 'wss:')
            .replace(/^http:/, 'ws:')
            + `/api/v1/agents/${agentId}/ws`;
        let reconnectDelay = 1000;
        const maxReconnectDelay = 60000;
        while (!this._shouldDisconnect) {
            try {
                const ws = await this._openWebSocket(wsUrl, apiKey);
                this._wsConnection = ws;
                try {
                    // Send JACS-signed handshake as first message
                    const handshake = await this._buildWSHandshake(agentId);
                    ws.send(JSON.stringify(handshake));
                    // Wait for handshake ACK
                    const ackData = await this._wsRecv(ws);
                    if (typeof ackData === 'object' && ackData !== null) {
                        const ack = ackData;
                        if (ack.type === 'error') {
                            const msg = ack.message || 'Handshake rejected';
                            if (ack.code === 401)
                                throw new AuthenticationError(msg, 401);
                            throw new WebSocketError(msg);
                        }
                    }
                    this._connected = true;
                    reconnectDelay = 1000;
                    // Yield connected event
                    const connEvent = {
                        eventType: 'connected',
                        data: ackData,
                        raw: JSON.stringify(ackData),
                    };
                    if (onEvent)
                        onEvent(connEvent);
                    yield connEvent;
                    // Receive loop
                    while (!this._shouldDisconnect) {
                        let msgData;
                        try {
                            msgData = await this._wsRecv(ws);
                        }
                        catch (e) {
                            if (this._shouldDisconnect)
                                break;
                            throw e;
                        }
                        let eventType = 'message';
                        let eventId;
                        if (typeof msgData === 'object' && msgData !== null) {
                            const msg = msgData;
                            eventType = msg.type || msg.event_type || 'message';
                            eventId = msg.id || msg.event_id || undefined;
                        }
                        if (eventId)
                            this._lastEventId = eventId;
                        const event = {
                            eventType,
                            data: msgData,
                            id: eventId,
                            raw: JSON.stringify(msgData),
                        };
                        if (onEvent)
                            onEvent(event);
                        yield event;
                    }
                }
                finally {
                    try {
                        ws.close();
                    }
                    catch { /* ignore */ }
                    this._wsConnection = null;
                }
            }
            catch (e) {
                this._connected = false;
                if (this._shouldDisconnect)
                    break;
                if (e instanceof HaiError)
                    throw e;
                await new Promise(resolve => setTimeout(resolve, reconnectDelay));
                reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay);
            }
        }
        this._connected = false;
    }
    /**
     * Open a WebSocket connection. Uses the `ws` package if available,
     * falls back to built-in WebSocket (Node 21+).
     */
    _openWebSocket(url, apiKey) {
        return new Promise((resolve, reject) => {
            // Try ws package first (works on all Node versions)
            try {
                // eslint-disable-next-line @typescript-eslint/no-var-requires
                const WS = require('ws');
                const ws = new WS(url, {
                    headers: { Authorization: `Bearer ${apiKey}` },
                    handshakeTimeout: this.timeout,
                });
                ws.on('open', () => resolve(ws));
                ws.on('error', (err) => reject(new HaiConnectionError(`WebSocket error: ${err.message}`)));
                return;
            }
            catch { /* ws not installed, fall through */ }
            // Fall back to built-in WebSocket (Node 21+)
            try {
                const ws = new WebSocket(url, { headers: { Authorization: `Bearer ${apiKey}` } });
                ws.addEventListener('open', () => resolve(ws));
                ws.addEventListener('error', (e) => reject(new HaiConnectionError(`WebSocket error: ${e}`)));
            }
            catch {
                reject(new HaiError('WebSocket support requires the "ws" package or Node 21+. Install with: npm install ws'));
            }
        });
    }
    /** Receive one message from a WebSocket, parsing JSON if possible. */
    _wsRecv(ws) {
        return new Promise((resolve, reject) => {
            const handler = (data) => {
                const str = typeof data === 'string' ? data
                    : data instanceof Buffer ? data.toString('utf-8')
                        : String(data);
                try {
                    resolve(JSON.parse(str));
                }
                catch {
                    resolve(str);
                }
            };
            // ws package uses .on()
            if (typeof ws.on === 'function') {
                ws
                    .once('message', handler);
                ws
                    .once('close', () => reject(new HaiConnectionError('WebSocket closed')));
                ws
                    .once('error', (err) => reject(new WebSocketError(err.message)));
                return;
            }
            // Built-in WebSocket uses addEventListener
            const wsBuiltin = ws;
            const onMessage = (e) => {
                wsBuiltin.removeEventListener('message', onMessage);
                handler(e.data);
            };
            wsBuiltin.addEventListener('message', onMessage);
            wsBuiltin.addEventListener('close', () => reject(new HaiConnectionError('WebSocket closed')), { once: true });
            wsBuiltin.addEventListener('error', () => reject(new WebSocketError('WebSocket error')), { once: true });
        });
    }
    /** Build a JACS-signed handshake message for WS authentication. */
    async _buildWSHandshake(agentId) {
        const timestamp = new Date().toISOString();
        const signPayload = `${agentId}:${timestamp}`;
        let signature = '';
        try {
            const signed = await this.jacsClient.signMessage(signPayload);
            const doc = JSON.parse(signed.raw);
            signature = doc?.jacsSignature?.signature ?? '';
        }
        catch (e) {
            throw new WebSocketError(`Failed to sign WS handshake: ${e}`);
        }
        const handshake = {
            type: 'handshake',
            agent_id: agentId,
            timestamp,
            signature,
        };
        if (this._lastEventId) {
            handshake.last_event_id = this._lastEventId;
        }
        return handshake;
    }
}
exports.HaiClient = HaiClient;
//# sourceMappingURL=hai.js.map