"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.HaiClient = exports.HaiConnectionError = exports.AuthenticationError = exports.HaiError = void 0;
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
        this.jacsClient = jacsClient;
        this.baseUrl = baseUrl.replace(/\/+$/, '');
        this.timeout = options?.timeout ?? 30000;
        this.maxRetries = options?.maxRetries ?? 3;
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
}
exports.HaiClient = HaiClient;
//# sourceMappingURL=hai.js.map