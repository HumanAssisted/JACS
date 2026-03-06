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
 * const client = await createTestClient('pq2025');
 * const signed = await client.signMessage({ hello: 'test' });
 * const result = await client.verify(signed.raw);
 * assert(result.valid);
 *
 * // Sync
 * const client2 = createTestClientSync('pq2025');
 * const signed2 = client2.signMessageSync({ hello: 'test' });
 * const result2 = client2.verifySync(signed2.raw);
 * assert(result2.valid);
 * ```
 */

import { JacsClient } from './client';

export { JacsClient };

/**
 * Create an ephemeral JacsClient for testing (async). No files or env vars needed.
 *
 * @param algorithm - Signing algorithm (default: "pq2025")
 * @returns A fully-initialized JacsClient backed by an in-memory agent
 */
export async function createTestClient(algorithm?: string): Promise<JacsClient> {
  return JacsClient.ephemeral(algorithm ?? 'pq2025');
}

/**
 * Create an ephemeral JacsClient for testing (sync). No files or env vars needed.
 *
 * @param algorithm - Signing algorithm (default: "pq2025")
 * @returns A fully-initialized JacsClient backed by an in-memory agent
 */
export function createTestClientSync(algorithm?: string): JacsClient {
  return JacsClient.ephemeralSync(algorithm ?? 'pq2025');
}
