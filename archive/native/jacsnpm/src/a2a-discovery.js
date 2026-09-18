/**
 * JACS A2A Agent Card Discovery Client
 *
 * Discovers remote A2A agents by fetching their .well-known/agent-card.json
 * and assessing JACS trust level.
 *
 * @example
 * ```js
 * const { discoverAgent, discoverAndAssess } = require('jacs/a2a-discovery');
 *
 * const card = await discoverAgent('https://agent.example.com');
 * console.log(card.name, card.skills);
 *
 * const result = await discoverAndAssess('https://agent.example.com');
 * console.log(result.allowed, result.trustLevel);
 * ```
 */

const { JACS_EXTENSION_URI } = require('./a2a');
const { fetchAgentCardAsync } = require('../index.js');
const VALID_TRUST_POLICIES = ['open', 'verified', 'strict'];

/**
 * Fetch and parse a remote agent's A2A Agent Card.
 *
 * Uses Node.js native HTTP so the request is truly async and doesn't block
 * the event loop (unlike the synchronous Rust FFI fetchAgentCard).
 *
 * @param {string} url - Base URL of the agent (e.g. "https://agent.example.com")
 * @param {Object} [options]
 * @param {number} [options.timeoutMs=10000] - Request timeout in milliseconds
 * @returns {Promise<Object>} Parsed Agent Card JSON
 * @throws {Error} If the agent is unreachable, returns non-JSON, or returns non-200
 */
async function discoverAgent(url, options = {}) {
  const timeoutMs = options.timeoutMs || 10000;

  const trimmed = (url || '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    throw new Error('Agent base URL cannot be empty');
  }
  if (typeof fetchAgentCardAsync !== 'function') {
    throw new Error(
      'Secure native Agent Card fetch is unavailable; refusing the legacy unbounded HTTP path',
    );
  }
  const raw = await fetchAgentCardAsync(trimmed, timeoutMs);
  try {
    return JSON.parse(raw);
  } catch (_error) {
    throw new Error(`Secure native Agent Card fetch returned invalid JSON for ${trimmed}`);
  }
}

/**
 * Check whether an Agent Card declares the JACS extension.
 *
 * Looks for `urn:jacs:provenance-v1` in:
 * - capabilities.extensions[].uri
 *
 * @param {Object} card - Parsed Agent Card
 * @returns {boolean}
 */
function hasJacsExtension(card) {
  const extensions = card && card.capabilities && card.capabilities.extensions;
  if (!Array.isArray(extensions)) return false;
  return extensions.some(
    (ext) => ext && ext.uri === JACS_EXTENSION_URI
  );
}

/**
 * Extract jacsId from Agent Card metadata.
 *
 * @param {Object} card - Parsed Agent Card
 * @returns {string|null}
 */
function extractAgentId(card) {
  const metadata = card && card.metadata;
  if (!metadata || typeof metadata !== 'object') {
    return null;
  }
  const jacsId = metadata.jacsId;
  return jacsId ? String(jacsId) : null;
}

/**
 * Evaluate trust store membership for an agent ID.
 *
 * @param {string|null} agentId
 * @param {Object} options
 * @returns {boolean}
 */
function evaluateTrustStore(agentId, options = {}) {
  if (!agentId) return false;

  // Custom hook takes precedence.
  if (typeof options.trustStoreEvaluator === 'function') {
    try {
      return !!options.trustStoreEvaluator(agentId);
    } catch {
      return false;
    }
  }

  // Lightweight hook for callers that only need trust lookup.
  if (typeof options.isTrusted === 'function') {
    try {
      return !!options.isTrusted(agentId);
    } catch {
      return false;
    }
  }

  // JacsClient-compatible hook.
  if (options.client && typeof options.client.isTrusted === 'function') {
    try {
      return !!options.client.isTrusted(agentId);
    } catch {
      return false;
    }
  }

  return false;
}

/**
 * Resolve trust policy from options and validate it.
 *
 * @param {Object} options
 * @returns {'open'|'verified'|'strict'}
 */
function resolveTrustPolicy(options = {}) {
  const policy = options.policy || options.trustPolicy || 'verified';
  if (!VALID_TRUST_POLICIES.includes(policy)) {
    throw new Error(
      `Invalid trust policy: ${policy}. Must be one of ${VALID_TRUST_POLICIES.join(', ')}`
    );
  }
  return policy;
}

/**
 * Discover a remote agent and assess its JACS trust level.
 *
 * Trust levels:
 * - `trusted`: Agent Card declares JACS extension and is in local trust store
 * - `jacs_registered`: Agent Card declares JACS extension
 * - `untrusted`: Valid A2A card but no JACS extension
 *
 * @param {string} url - Base URL of the agent
 * @param {Object} [options]
 * @param {number} [options.timeoutMs=10000] - Request timeout in milliseconds
 * @param {'open'|'verified'|'strict'} [options.policy='verified'] - Trust policy
 * @param {'open'|'verified'|'strict'} [options.trustPolicy='verified'] - Alias for policy
 * @param {Object} [options.client] - JacsClient with native A2A assessment. Without it, only open can allow.
 * @param {(agentId: string) => boolean} [options.trustStoreEvaluator] - Deprecated; cannot establish identity trust
 * @param {(agentId: string) => boolean} [options.isTrusted] - Deprecated; cannot establish identity trust
 * @returns {Promise<{
 *   card: Object,
 *   jacsRegistered: boolean,
 *   trustLevel: 'trusted'|'jacs_registered'|'untrusted',
 *   allowed: boolean,
 *   inTrustStore: boolean,
 *   policy: 'open'|'verified'|'strict',
 *   agentId: string|null,
 * }>}
 * @throws {Error} If the agent is unreachable or returns invalid data
 */
async function discoverAndAssess(url, options = {}) {
  const policy = resolveTrustPolicy(options);
  const card = await discoverAgent(url, options);
  const jacsRegistered = hasJacsExtension(card);
  const agentId = extractAgentId(card);

  const nativeAssess = options.client?._agent?.assessA2aAgent;
  if (typeof nativeAssess === 'function') {
    try {
      const canonical = JSON.parse(await nativeAssess.call(
        options.client._agent,
        JSON.stringify(card),
        policy,
      ));
      const canonicalLevel = String(canonical.trustLevel || 'Untrusted');
      const trustLevel = canonicalLevel === 'ExplicitlyTrusted'
        ? 'trusted'
        : canonicalLevel === 'JacsVerified'
          ? 'jacs_registered'
          : 'untrusted';
      return {
        card,
        jacsRegistered: canonical.jacsRegistered === true,
        trustLevel,
        allowed: canonical.allowed === true,
        inTrustStore: canonicalLevel === 'ExplicitlyTrusted',
        policy,
        agentId,
        reason: String(canonical.reason || ''),
        firstContact: canonical.firstContact === true,
      };
    } catch (_error) {
      // Continue into the fail-closed result below. A native outage or malformed
      // result must not become a fresh wrapper-only trust opportunity.
    }
  }

  const allowed = policy === 'open';
  const reason = allowed
    ? 'Open policy: agent allowed without native cryptographic assessment; no identity assurance is claimed'
    : `${policy[0].toUpperCase()}${policy.slice(1)} policy: native cryptographic assessment is unavailable; `
      + 'an Agent Card extension or trust-store name alone does not prove identity';

  return {
    card,
    jacsRegistered,
    trustLevel: 'untrusted',
    allowed,
    inTrustStore: false,
    policy,
    agentId,
    reason,
    firstContact: false,
  };
}

module.exports = {
  discoverAgent,
  discoverAndAssess,
  hasJacsExtension,
  extractAgentId,
  VALID_TRUST_POLICIES,
};
