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
