/**
 * JACS A2A Agent Card Discovery Client
 *
 * Discovers remote A2A agents by fetching their .well-known/agent-card.json
 * and assessing JACS trust level.
 *
 * @example
 * ```js
 * const { discoverAgent, discoverAndAssess } = require('@hai.ai/jacs/a2a-discovery');
 *
 * const card = await discoverAgent('https://agent.example.com');
 * console.log(card.name, card.skills);
 *
 * const result = await discoverAndAssess('https://agent.example.com');
 * console.log(result.jacsRegistered, result.trustLevel);
 * ```
 */

const { JACS_EXTENSION_URI } = require('./a2a');

/**
 * Fetch and parse a remote agent's A2A Agent Card.
 *
 * @param {string} url - Base URL of the agent (e.g. "https://agent.example.com")
 * @param {Object} [options]
 * @param {number} [options.timeoutMs=10000] - Request timeout in milliseconds
 * @returns {Promise<Object>} Parsed Agent Card JSON
 * @throws {Error} If the agent is unreachable, returns non-JSON, or returns non-200
 */
async function discoverAgent(url, options = {}) {
  const timeoutMs = options.timeoutMs || 10000;
  const baseUrl = url.replace(/\/+$/, '');
  const cardUrl = `${baseUrl}/.well-known/agent-card.json`;

  let response;
  try {
    response = await fetch(cardUrl, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { Accept: 'application/json' },
    });
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      throw new Error(`Agent discovery timed out: ${cardUrl}`);
    }
    throw new Error(`Agent unreachable: ${cardUrl} (${err.message})`);
  }

  if (response.status === 404) {
    throw new Error(`Agent card not found (404): ${cardUrl}`);
  }

  if (!response.ok) {
    throw new Error(
      `Agent card request failed (HTTP ${response.status}): ${cardUrl}`
    );
  }

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('json')) {
    throw new Error(
      `Agent card response is not JSON (content-type: ${contentType}): ${cardUrl}`
    );
  }

  let card;
  try {
    card = await response.json();
  } catch (err) {
    throw new Error(`Agent card is not valid JSON: ${cardUrl} (${err.message})`);
  }

  return card;
}

/**
 * Check whether an Agent Card declares the JACS extension.
 *
 * Looks for `urn:hai.ai:jacs-provenance-v1` in:
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
 * Discover a remote agent and assess its JACS trust level.
 *
 * Trust levels:
 * - `jacs_registered`: Agent Card declares the JACS extension
 * - `untrusted`: Valid A2A card but no JACS extension
 *
 * Future: Phase 2.2.4 will add full trust policy assessment
 * (signature verification, trust store lookup, etc.)
 *
 * @param {string} url - Base URL of the agent
 * @param {Object} [options]
 * @param {number} [options.timeoutMs=10000] - Request timeout in milliseconds
 * @returns {Promise<{card: Object, jacsRegistered: boolean, trustLevel: string}>}
 * @throws {Error} If the agent is unreachable or returns invalid data
 */
async function discoverAndAssess(url, options = {}) {
  const card = await discoverAgent(url, options);
  const jacsRegistered = hasJacsExtension(card);

  return {
    card,
    jacsRegistered,
    trustLevel: jacsRegistered ? 'jacs_registered' : 'untrusted',
  };
}

module.exports = {
  discoverAgent,
  discoverAndAssess,
  hasJacsExtension,
};
