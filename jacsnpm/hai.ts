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

// =============================================================================
// Types
// =============================================================================

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

// =============================================================================
// Errors
// =============================================================================

export class HaiError extends Error {
  statusCode?: number;
  responseData?: Record<string, unknown>;

  constructor(message: string, statusCode?: number, responseData?: Record<string, unknown>) {
    super(message);
    this.name = 'HaiError';
    this.statusCode = statusCode;
    this.responseData = responseData;
  }
}

export class AuthenticationError extends HaiError {
  constructor(message: string, statusCode?: number) {
    super(message, statusCode);
    this.name = 'AuthenticationError';
  }
}

export class HaiConnectionError extends HaiError {
  constructor(message: string) {
    super(message);
    this.name = 'HaiConnectionError';
  }
}

export class WebSocketError extends HaiError {
  constructor(message: string, statusCode?: number) {
    super(message, statusCode);
    this.name = 'WebSocketError';
  }
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
export class HaiClient {
  private jacsClient: JacsClient;
  private baseUrl: string;
  private timeout: number;
  private maxRetries: number;
  private _shouldDisconnect = false;
  private _connected = false;
  private _wsConnection: unknown = null;
  private _lastEventId: string | null = null;

  constructor(jacsClient: JacsClient, baseUrl: string = 'https://hai.ai', options?: HaiClientOptions) {
    this.jacsClient = jacsClient;
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.timeout = options?.timeout ?? 30000;
    this.maxRetries = options?.maxRetries ?? 3;
  }

  /** Whether the client is currently connected to an event stream. */
  get isConnected(): boolean {
    return this._connected;
  }

  // ---------------------------------------------------------------------------
  // URL helper
  // ---------------------------------------------------------------------------

  private makeUrl(path: string): string {
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
  async hello(includeTest: boolean = false): Promise<HelloWorldResult> {
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
    } catch (e) {
      throw new HaiError(`Failed to sign hello request: ${e}`);
    }

    const url = this.makeUrl('/api/v1/agents/hello');
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `JACS ${agentId}:${timestamp}:${signature}`,
    };

    const payload: Record<string, unknown> = { agent_id: agentId };
    if (includeTest) {
      payload.include_test = true;
    }

    let response: Response;
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
    } catch (e: unknown) {
      if (e instanceof Error && e.name === 'AbortError') {
        throw new HaiConnectionError(`Request timed out after ${this.timeout}ms`);
      }
      throw new HaiConnectionError(`Connection failed: ${e}`);
    }

    if (response.status === 401) {
      let errorData: Record<string, unknown> = {};
      try { errorData = await response.json() as Record<string, unknown>; } catch { /* empty */ }
      throw new AuthenticationError('JACS signature rejected by HAI', 401);
    }

    if (response.status === 429) {
      throw new HaiError('Rate limited -- too many hello requests', 429);
    }

    if (response.status !== 200 && response.status !== 201) {
      let errorMsg = `Hello failed with status ${response.status}`;
      try {
        const errBody = await response.json() as Record<string, unknown>;
        if (errBody.error) errorMsg = String(errBody.error);
      } catch { /* empty */ }
      throw new HaiError(errorMsg, response.status);
    }

    const data = await response.json() as Record<string, unknown>;

    // Verify HAI's signature on the ACK
    let haiSigValid = false;
    const haiAckSignature = data.hai_ack_signature as string | undefined;
    if (haiAckSignature) {
      haiSigValid = this.verifyHaiMessage(
        JSON.stringify(data),
        haiAckSignature,
        (data.hai_public_key as string) || '',
      );
    }

    return {
      success: true,
      timestamp: (data.timestamp as string) || '',
      clientIp: (data.client_ip as string) || '',
      haiPublicKeyFingerprint: (data.hai_public_key_fingerprint as string) || '',
      message: (data.message as string) || '',
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
  verifyHaiMessage(message: string, signature: string, haiPublicKey: string = ''): boolean {
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
    } catch {
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
        let keyObject: ReturnType<typeof crypto.createPublicKey>;
        if (haiPublicKey.startsWith('-----')) {
          keyObject = crypto.createPublicKey(haiPublicKey);
        } else {
          // Assume raw base64 Ed25519 public key
          const keyBuffer = Buffer.from(haiPublicKey, 'base64');
          keyObject = crypto.createPublicKey({
            key: keyBuffer,
            format: 'der',
            type: 'spki',
          });
        }

        return crypto.verify(null, msgBuffer, keyObject, sigBuffer);
      } catch {
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
  async register(apiKey?: string): Promise<HaiRegistrationResult> {
    const resolvedKey = apiKey || process.env.HAI_API_KEY || '';

    let agentJson: string;
    try {
      const agent = this.jacsClient as unknown as { agent: { getAgentJsonSync(): string } | null };
      agentJson = (agent.agent as { getAgentJsonSync(): string }).getAgentJsonSync();
    } catch {
      throw new HaiError('Failed to export agent document. Ensure agent is loaded.');
    }

    const url = this.makeUrl('/api/v1/agents/register');
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (resolvedKey) {
      headers['Authorization'] = `Bearer ${resolvedKey}`;
    }

    let lastError: Error | null = null;
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
          const data = await response.json() as Record<string, unknown>;
          return {
            success: true,
            agentId: (data.agent_id as string) || (data.agentId as string) || '',
            haiSignature: (data.hai_signature as string) || (data.haiSignature as string) || '',
            registrationId: (data.registration_id as string) || (data.registrationId as string) || '',
            registeredAt: (data.registered_at as string) || (data.registeredAt as string) || '',
            rawResponse: data,
          };
        }

        if (response.status === 401) {
          throw new AuthenticationError('Invalid or missing API key', 401);
        }

        lastError = new HaiError(`Registration failed with status ${response.status}`, response.status);
      } catch (e) {
        if (e instanceof HaiError) throw e;
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

  private parseTranscript(raw: unknown[]): TranscriptMessage[] {
    return (raw || []).map((msg: unknown) => {
      const m = msg as Record<string, unknown>;
      return {
        role: (m.role as string) || 'system',
        content: (m.content as string) || '',
        timestamp: (m.timestamp as string) || '',
        annotations: (m.annotations as string[]) || [],
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
  async freeChaoticRun(options?: {
    apiKey?: string;
    transport?: 'sse' | 'ws';
  }): Promise<FreeChaoticResult> {
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
    } catch (e) {
      throw new HaiError(`Failed to sign request: ${e}`);
    }

    const url = this.makeUrl('/api/benchmark/run');
    const headers: Record<string, string> = {
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

    let response: Response;
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
    } catch (e: unknown) {
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
        const errBody = await response.json() as Record<string, unknown>;
        if (errBody.error) msg = String(errBody.error);
      } catch { /* empty */ }
      throw new HaiError(msg, response.status);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      success: true,
      runId: (data.run_id as string) || (data.runId as string) || '',
      transcript: this.parseTranscript((data.transcript as unknown[]) || []),
      upsellMessage: (data.upsell_message as string) || (data.upsellMessage as string) || '',
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
  async baselineRun(options?: {
    apiKey?: string;
    transport?: 'sse' | 'ws';
    /** Milliseconds between payment status checks. Default: 2000. */
    pollIntervalMs?: number;
    /** Max milliseconds to wait for payment. Default: 300000 (5 min). */
    pollTimeoutMs?: number;
    /** Callback with checkout URL (e.g., to open in browser). */
    onCheckoutUrl?: (url: string) => void;
  }): Promise<BaselineRunResult> {
    const agentId = this.jacsClient.agentId;
    if (!agentId) {
      throw new HaiError('No agent loaded. Call quickstart() or load() first.');
    }

    const apiKey = options?.apiKey || process.env.HAI_API_KEY || '';
    const pollIntervalMs = options?.pollIntervalMs ?? 2000;
    const pollTimeoutMs = options?.pollTimeoutMs ?? 300000;

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    // Step 1: Create Stripe Checkout session
    const purchaseUrl = this.makeUrl('/api/benchmark/purchase');
    const purchasePayload = { tier: 'baseline', agent_id: agentId };

    let checkoutUrl: string;
    let paymentId: string;

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

      const purchaseData = await resp.json() as Record<string, unknown>;
      checkoutUrl = (purchaseData.checkout_url as string) || '';
      paymentId = (purchaseData.payment_id as string) || '';

      if (!checkoutUrl) {
        throw new HaiError('No checkout URL returned from API');
      }
    } catch (e) {
      if (e instanceof HaiError) throw e;
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
          const statusData = await statusResp.json() as Record<string, unknown>;
          const paymentStatus = (statusData.status as string) || '';

          if (paymentStatus === 'paid') break;
          if (['failed', 'expired', 'cancelled'].includes(paymentStatus)) {
            throw new HaiError(`Payment ${paymentStatus}: ${statusData.message || ''}`);
          }
        }
      } catch (e) {
        if (e instanceof HaiError) throw e;
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
    } catch (e) {
      throw new HaiError(`Failed to sign run request: ${e}`);
    }

    const runUrl = this.makeUrl('/api/benchmark/run');
    const runHeaders: Record<string, string> = {
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

    let runResponse: Response;
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
    } catch (e: unknown) {
      if (e instanceof Error && e.name === 'AbortError') {
        throw new HaiConnectionError('Benchmark request timed out');
      }
      throw new HaiConnectionError(`Connection failed: ${e}`);
    }

    if (runResponse.status !== 200 && runResponse.status !== 201) {
      let msg = `Baseline run failed with status ${runResponse.status}`;
      try {
        const errBody = await runResponse.json() as Record<string, unknown>;
        if (errBody.error) msg = String(errBody.error);
      } catch { /* empty */ }
      throw new HaiError(msg, runResponse.status);
    }

    const data = await runResponse.json() as Record<string, unknown>;

    return {
      success: true,
      runId: (data.run_id as string) || (data.runId as string) || '',
      score: Number(data.score) || 0,
      transcript: this.parseTranscript((data.transcript as unknown[]) || []),
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
  async submitResponse(
    jobId: string,
    message: string,
    options?: {
      metadata?: Record<string, unknown>;
      processingTimeMs?: number;
      apiKey?: string;
    },
  ): Promise<JobResponseResult> {
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
    } catch (e) {
      throw new HaiError(`Failed to sign request: ${e}`);
    }

    const url = this.makeUrl(`/api/v1/agents/jobs/${jobId}/response`);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `JACS ${agentId}:${timestamp}:${signature}`,
    };
    if (apiKey) {
      headers['X-API-Key'] = apiKey;
    }

    // Build ModerationResponse payload (matches Rust JobResponseRequest)
    const responseBody: Record<string, unknown> = { message };
    if (options?.metadata !== undefined) {
      responseBody.metadata = options.metadata;
    }
    if (options?.processingTimeMs !== undefined) {
      responseBody.processing_time_ms = options.processingTimeMs;
    }

    const payload = { response: responseBody };

    let response: Response;
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
    } catch (e: unknown) {
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
        const errBody = await response.json() as Record<string, unknown>;
        if (errBody.error) msg = String(errBody.error);
      } catch { /* empty */ }
      throw new HaiError(msg, response.status);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      success: (data.success as boolean) ?? true,
      jobId: (data.job_id as string) || (data.jobId as string) || jobId,
      message: (data.message as string) || 'Response accepted',
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
  async onBenchmarkJob(
    handler: (job: BenchmarkJob) => Promise<void>,
    options?: OnBenchmarkJobOptions,
  ): Promise<void> {
    const apiKey = options?.apiKey;
    const transport = options?.transport;

    for await (const event of this.connect(apiKey, { transport })) {
      if (event.eventType === 'benchmark_job') {
        const data = (typeof event.data === 'object' && event.data !== null)
          ? event.data as Record<string, unknown>
          : {};

        const job: BenchmarkJob = {
          runId: (data.run_id as string) || (data.runId as string) || '',
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
  async *connect(apiKey?: string, options?: ConnectOptions): AsyncGenerator<HaiEvent> {
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
    } else {
      yield* this._connectSSE(resolvedKey, agentId, onEvent);
    }
  }

  /**
   * Disconnect from HAI.ai event stream (SSE or WebSocket).
   * Safe to call even if not connected.
   */
  disconnect(): void {
    this._shouldDisconnect = true;

    if (this._wsConnection) {
      try {
        (this._wsConnection as { close(): void }).close();
      } catch { /* ignore */ }
      this._wsConnection = null;
    }

    this._connected = false;
  }

  // ---------------------------------------------------------------------------
  // SSE transport (internal)
  // ---------------------------------------------------------------------------

  private async *_connectSSE(
    apiKey: string,
    agentId: string,
    onEvent?: (event: HaiEvent) => void,
  ): AsyncGenerator<HaiEvent> {
    const url = this.makeUrl(`/api/v1/agents/${agentId}/events`);
    let reconnectDelay = 1000;
    const maxReconnectDelay = 60000;

    while (!this._shouldDisconnect) {
      try {
        const headers: Record<string, string> = {
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
        if (!reader) throw new HaiConnectionError('No response body for SSE');

        const decoder = new TextDecoder();
        let buffer = '';

        while (!this._shouldDisconnect) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          let eventType = 'message';
          let eventData = '';
          let eventId: string | undefined;

          for (const line of lines) {
            if (line.startsWith('event:')) {
              eventType = line.slice(6).trim();
            } else if (line.startsWith('data:')) {
              eventData += (eventData ? '\n' : '') + line.slice(5).trim();
            } else if (line.startsWith('id:')) {
              eventId = line.slice(3).trim();
            } else if (line === '') {
              if (eventData) {
                if (eventId) this._lastEventId = eventId;

                let parsed: unknown;
                try { parsed = JSON.parse(eventData); } catch { parsed = eventData; }

                const event: HaiEvent = {
                  eventType,
                  data: parsed,
                  id: eventId,
                  raw: eventData,
                };

                if (onEvent) onEvent(event);
                yield event;

                eventType = 'message';
                eventData = '';
                eventId = undefined;
              }
            }
          }
        }
      } catch (e) {
        this._connected = false;
        if (this._shouldDisconnect) break;
        if (e instanceof HaiError) throw e;

        await new Promise(resolve => setTimeout(resolve, reconnectDelay));
        reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay);
      }
    }

    this._connected = false;
  }

  // ---------------------------------------------------------------------------
  // WebSocket transport (internal) -- Step 61
  // ---------------------------------------------------------------------------

  private async *_connectWS(
    apiKey: string,
    agentId: string,
    onEvent?: (event: HaiEvent) => void,
  ): AsyncGenerator<HaiEvent> {
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
          (ws as { send(data: string): void }).send(JSON.stringify(handshake));

          // Wait for handshake ACK
          const ackData = await this._wsRecv(ws);
          if (typeof ackData === 'object' && ackData !== null) {
            const ack = ackData as Record<string, unknown>;
            if (ack.type === 'error') {
              const msg = (ack.message as string) || 'Handshake rejected';
              if (ack.code === 401) throw new AuthenticationError(msg, 401);
              throw new WebSocketError(msg);
            }
          }

          this._connected = true;
          reconnectDelay = 1000;

          // Yield connected event
          const connEvent: HaiEvent = {
            eventType: 'connected',
            data: ackData,
            raw: JSON.stringify(ackData),
          };
          if (onEvent) onEvent(connEvent);
          yield connEvent;

          // Receive loop
          while (!this._shouldDisconnect) {
            let msgData: unknown;
            try {
              msgData = await this._wsRecv(ws);
            } catch (e) {
              if (this._shouldDisconnect) break;
              throw e;
            }

            let eventType = 'message';
            let eventId: string | undefined;
            if (typeof msgData === 'object' && msgData !== null) {
              const msg = msgData as Record<string, unknown>;
              eventType = (msg.type as string) || (msg.event_type as string) || 'message';
              eventId = (msg.id as string) || (msg.event_id as string) || undefined;
            }

            if (eventId) this._lastEventId = eventId;

            const event: HaiEvent = {
              eventType,
              data: msgData,
              id: eventId,
              raw: JSON.stringify(msgData),
            };

            if (onEvent) onEvent(event);
            yield event;
          }
        } finally {
          try { (ws as { close(): void }).close(); } catch { /* ignore */ }
          this._wsConnection = null;
        }
      } catch (e) {
        this._connected = false;
        if (this._shouldDisconnect) break;
        if (e instanceof HaiError) throw e;

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
  private _openWebSocket(url: string, apiKey: string): Promise<unknown> {
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
        ws.on('error', (err: Error) => reject(new HaiConnectionError(`WebSocket error: ${err.message}`)));
        return;
      } catch { /* ws not installed, fall through */ }

      // Fall back to built-in WebSocket (Node 21+)
      try {
        const ws = new WebSocket(url, { headers: { Authorization: `Bearer ${apiKey}` } } as unknown as string);
        ws.addEventListener('open', () => resolve(ws));
        ws.addEventListener('error', (e) => reject(new HaiConnectionError(`WebSocket error: ${e}`)));
      } catch {
        reject(new HaiError(
          'WebSocket support requires the "ws" package or Node 21+. Install with: npm install ws'
        ));
      }
    });
  }

  /** Receive one message from a WebSocket, parsing JSON if possible. */
  private _wsRecv(ws: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const handler = (data: unknown) => {
        const str = typeof data === 'string' ? data
          : data instanceof Buffer ? data.toString('utf-8')
          : String(data);
        try { resolve(JSON.parse(str)); } catch { resolve(str); }
      };

      // ws package uses .on()
      if (typeof (ws as { on?: Function }).on === 'function') {
        (ws as { on(event: string, fn: Function): void; once(event: string, fn: Function): void })
          .once('message', handler);
        (ws as { once(event: string, fn: Function): void })
          .once('close', () => reject(new HaiConnectionError('WebSocket closed')));
        (ws as { once(event: string, fn: Function): void })
          .once('error', (err: Error) => reject(new WebSocketError(err.message)));
        return;
      }

      // Built-in WebSocket uses addEventListener
      const wsBuiltin = ws as WebSocket;
      const onMessage = (e: MessageEvent) => {
        wsBuiltin.removeEventListener('message', onMessage);
        handler(e.data);
      };
      wsBuiltin.addEventListener('message', onMessage);
      wsBuiltin.addEventListener('close', () => reject(new HaiConnectionError('WebSocket closed')), { once: true });
      wsBuiltin.addEventListener('error', () => reject(new WebSocketError('WebSocket error')), { once: true });
    });
  }

  /** Build a JACS-signed handshake message for WS authentication. */
  private async _buildWSHandshake(agentId: string): Promise<Record<string, unknown>> {
    const timestamp = new Date().toISOString();
    const signPayload = `${agentId}:${timestamp}`;

    let signature = '';
    try {
      const signed = await this.jacsClient.signMessage(signPayload);
      const doc = JSON.parse(signed.raw);
      signature = doc?.jacsSignature?.signature ?? '';
    } catch (e) {
      throw new WebSocketError(`Failed to sign WS handshake: ${e}`);
    }

    const handshake: Record<string, unknown> = {
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
