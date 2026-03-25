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

const http = require('http');
const https = require('https');
const { JACS_EXTENSION_URI } = require('./a2a');
const { ensureNetworkAccess } = require('../index.js');
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

  // Enforce Rust-owned network access policy
  ensureNetworkAccess('agent_card_fetch');

  const trimmed = (url || '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    throw new Error('Agent base URL cannot be empty');
  }
  const cardUrl = `${trimmed}/.well-known/agent-card.json`;

  return new Promise((resolve, reject) => {
    const mod = cardUrl.startsWith('https') ? https : http;
    const req = mod.get(cardUrl, { timeout: timeoutMs, headers: { Accept: 'application/json' } }, (res) => {
      if (res.statusCode !== 200) {
        res.resume(); // drain
        reject(new Error(`Agent card fetch failed: ${res.statusCode} for ${cardUrl}`));
        return;
      }
      const contentType = res.headers['content-type'] || '';
      if (!contentType.includes('json')) {
        res.resume();
        reject(new Error(`Agent card response is not JSON (content-type: ${contentType}) for ${cardUrl}`));
        return;
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error(`Agent card response is not valid JSON for ${cardUrl}`));
        }
      });
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Agent discovery timed out: ${cardUrl}`));
    });
    req.on('error', (err) => {
      reject(new Error(`Agent discovery failed: ${err.message}`));
    });
  });
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
 * @param {Object} [options.client] - Optional JacsClient-like object with isTrusted(agentId)
 * @param {(agentId: string) => boolean} [options.trustStoreEvaluator] - Optional trust lookup hook
 * @param {(agentId: string) => boolean} [options.isTrusted] - Optional shorthand trust lookup hook
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
  const inTrustStore = jacsRegistered
    ? evaluateTrustStore(agentId, options)
    : false;
  const trustLevel = inTrustStore
    ? 'trusted'
    : (jacsRegistered ? 'jacs_registered' : 'untrusted');

  let allowed = false;
  switch (policy) {
    case 'open':
      allowed = true;
      break;
    case 'verified':
      allowed = jacsRegistered;
      break;
    case 'strict':
      allowed = inTrustStore;
      break;
    default:
      allowed = false;
      break;
  }

  return {
    card,
    jacsRegistered,
    trustLevel,
    allowed,
    inTrustStore,
    policy,
    agentId,
  };
}

module.exports = {
  discoverAgent,
  discoverAndAssess,
  hasJacsExtension,
  extractAgentId,
  VALID_TRUST_POLICIES,
};
