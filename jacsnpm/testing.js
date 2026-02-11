"use strict";
/**
 * JACS Test Helpers
 *
 * Utilities for creating ephemeral clients in tests. Each client gets its own
 * in-memory agent -- no config files, no key files, no env vars needed.
 *
 * @example
 * ```typescript
 * import { createTestClient, createTestClientSync } from '@hai.ai/jacs/testing';
 *
 * // Async (preferred)
 * const client = await createTestClient('ring-Ed25519');
 * const signed = await client.signMessage({ hello: 'test' });
 * const result = await client.verify(signed.raw);
 * assert(result.valid);
 *
 * // Sync
 * const client2 = createTestClientSync('ring-Ed25519');
 * const signed2 = client2.signMessageSync({ hello: 'test' });
 * const result2 = client2.verifySync(signed2.raw);
 * assert(result2.valid);
 * ```
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.JacsClient = void 0;
exports.createTestClient = createTestClient;
exports.createTestClientSync = createTestClientSync;
const client_1 = require("./client");
Object.defineProperty(exports, "JacsClient", { enumerable: true, get: function () { return client_1.JacsClient; } });
/**
 * Create an ephemeral JacsClient for testing (async). No files or env vars needed.
 *
 * @param algorithm - Signing algorithm (default: "ring-Ed25519" for speed)
 * @returns A fully-initialized JacsClient backed by an in-memory agent
 */
async function createTestClient(algorithm) {
    return client_1.JacsClient.ephemeral(algorithm ?? 'ring-Ed25519');
}
/**
 * Create an ephemeral JacsClient for testing (sync). No files or env vars needed.
 *
 * @param algorithm - Signing algorithm (default: "ring-Ed25519" for speed)
 * @returns A fully-initialized JacsClient backed by an in-memory agent
 */
function createTestClientSync(algorithm) {
    return client_1.JacsClient.ephemeralSync(algorithm ?? 'ring-Ed25519');
}
//# sourceMappingURL=testing.js.map