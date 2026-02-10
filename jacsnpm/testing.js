"use strict";
/**
 * JACS Test Helpers
 *
 * Utilities for creating ephemeral clients in tests. Each client gets its own
 * in-memory agent -- no config files, no key files, no env vars needed.
 *
 * @example
 * ```typescript
 * import { createTestClient } from '@hai.ai/jacs/testing';
 *
 * const client = createTestClient('ring-Ed25519');
 * const signed = client.signMessage({ hello: 'test' });
 * const result = client.verify(signed.raw);
 * assert(result.valid);
 * ```
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.JacsClient = void 0;
exports.createTestClient = createTestClient;
const client_1 = require("./client");
Object.defineProperty(exports, "JacsClient", { enumerable: true, get: function () { return client_1.JacsClient; } });
/**
 * Create an ephemeral JacsClient for testing. No files or env vars needed.
 *
 * @param algorithm - Signing algorithm (default: "ring-Ed25519" for speed)
 * @returns A fully-initialized JacsClient backed by an in-memory agent
 */
function createTestClient(algorithm) {
    return client_1.JacsClient.ephemeral(algorithm ?? 'ring-Ed25519');
}
//# sourceMappingURL=testing.js.map