/**
 * JACS A2A Express Middleware
 *
 * Middleware factory that serves A2A .well-known discovery endpoints
 * from an existing Express app. All 6 identity-bound endpoints are cached
 * together and refreshed lazily from the signed binding's issuance time.
 *
 * @example
 * ```js
 * const express = require('express');
 * const { JacsClient } = require('jacs/client');
 * const { jacsA2AMiddleware } = require('jacs/a2a-server');
 *
 * const client = await JacsClient.quickstart({
 *   name: 'a2a-agent',
 *   domain: 'a2a.local',
 * });
 * const app = express();
 * app.use(jacsA2AMiddleware(client, {
 *   skills: [{ id: 'search', name: 'Search', description: 'Search the web', tags: ['search'] }],
 * }));
 * app.listen(3000);
 * ```
 */

const {
  JACSA2AIntegration,
  A2AAgentSkill,
} = require('./a2a');

/**
 * CORS headers for cross-origin agent discovery.
 * A2A clients need to fetch agent cards from different origins.
 */
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
  'Access-Control-Max-Age': '86400',
};

/**
 * Build all 6 identity-bound well-known document payloads from a JacsClient.
 *
 * @param {import('../client').JacsClient} client
 * @param {Object} options
 * @returns {Record<string, Object>} path -> JSON payload
 */
function buildWellKnownDocuments(client, options = {}) {
  const integration = new JACSA2AIntegration(client);

  const agentData = {
    jacsId: client.agentId || 'unknown',
    jacsName: client.name || 'JACS A2A Agent',
    jacsDescription: `JACS agent ${client.name || client.agentId}`,
    jacsVersion: '1',
    jacsAgentType: 'ai',
    keyAlgorithm: options.keyAlgorithm || 'pq2025',
  };

  if (options.url) {
    agentData.jacsAgentDomain = options.url;
  }

  // 1. Agent Card
  const card = integration.exportAgentCard(agentData);
  const cardJson = JSON.parse(JSON.stringify(card));

  // Override skills if provided
  if (options.skills && Array.isArray(options.skills)) {
    cardJson.skills = options.skills.map((s) => {
      if (s instanceof A2AAgentSkill) return JSON.parse(JSON.stringify(s));
      return {
        id: s.id || slugify(s.name || 'unnamed'),
        name: s.name || 'unnamed',
        description: s.description || '',
        tags: s.tags || ['jacs'],
      };
    });
  }

  // The compatibility arguments are ignored by the integration when the
  // required native generator is present. They remain here only for API
  // source compatibility with older callers.
  const documents = integration.generateWellKnownDocuments(cardJson, '', '', agentData);

  // Caller-side mutation after signing would invalidate the JWS. Optional
  // server overrides are therefore assertions about already-configured agent
  // data, never rewrites of the native signed card.
  const nativeCard = documents['/.well-known/agent-card.json'];
  if (options.skills && JSON.stringify(nativeCard.skills || []) !== JSON.stringify(cardJson.skills || [])) {
    throw new Error(
      "Cannot override A2A skills after the Agent Card is signed; configure the agent's skills before generation"
    );
  }
  if (options.url) {
    const interfaceUrl = nativeCard.supportedInterfaces?.[0]?.url;
    if (typeof interfaceUrl !== 'string' || !interfaceUrl.includes(options.url)) {
      throw new Error(
        'Cannot override the A2A interface URL after the Agent Card is signed; configure the agent domain before generation'
      );
    }
  }
  if (options.keyAlgorithm) {
    const nativeAlgorithm = documents['/.well-known/jacs-agent.json']?.keyAlgorithm;
    if (nativeAlgorithm !== options.keyAlgorithm) {
      throw new Error(
        'Cannot relabel the native JACS algorithm in signed discovery documents; use the agent configuration value'
      );
    }
  }
  return documents;
}

/**
 * Convert a name to a URL-friendly slug.
 * @param {string} name
 * @returns {string}
 */
function slugify(name) {
  return name
    .toLowerCase()
    .replace(/[\s_]+/g, '-')
    .replace(/[^a-z0-9-]/g, '');
}

// Match compatibility/binding.rs and exports.rs. These are serving deadlines,
// not substitutes for the native signature/key/scope/rollback verification.
const DAY_MS = 24 * 60 * 60 * 1000;
const RETRY_MS = 60 * 1000;
const FUTURE_SKEW_MS = 5 * 60 * 1000;

function bindingTime(value, ceiling = false) {
  // Date.parse alone accepts missing zones and normalizes impossible dates.
  const parts = typeof value === 'string' && value.match(
    /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})$/
  );
  if (!parts) throw new Error('Invalid discovery binding timestamp');
  const [, year, month, day, hour, minute, second, fraction = '', zone] = parts;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (+month < 1 || +month > 12 || +day < 1 || +day > days[month - 1]
      || +hour > 23 || +minute > 59 || +second > 59
      || (zone.length > 1 && (+zone.slice(1, 3) > 23 || +zone.slice(4) > 59))) {
    throw new Error('Invalid discovery binding timestamp');
  }
  const instant = Date.parse(value);
  if (!Number.isFinite(instant)) throw new Error('Invalid discovery binding timestamp');
  // Native RFC3339 can carry nanoseconds. Round deadlines down, but future
  // skew checks up, so Date's millisecond precision never extends acceptance.
  return instant + (ceiling && /[1-9]/.test(fraction.slice(3)) ? 1 : 0);
}

function discoverySnapshot(documents, now) {
  const binding = documents['/.well-known/jacs-compat-binding.json']?.compatibilityKeyBinding;
  const issued = bindingTime(binding?.issuedAt);
  const issuedLatest = bindingTime(binding?.issuedAt, true);
  const expires = binding?.expiresAt == null ? Infinity : bindingTime(binding.expiresAt);
  const snapshot = { documents, issued, issuedLatest, expires, until: Math.min(issued + 7 * DAY_MS, expires) };
  if (!snapshotValid(snapshot, now)) throw new Error('Discovery binding is outside its lifetime');
  return snapshot;
}

function snapshotValid(snapshot, now) {
  return now < snapshot.until && snapshot.issuedLatest <= now + FUTURE_SKEW_MS;
}

/**
 * Create Express middleware that serves A2A .well-known discovery endpoints.
 *
 * Registers routes for:
 * - `/.well-known/agent-card.json`
 * - `/.well-known/jwks.json`
 * - `/.well-known/jacs-compat-binding.json`
 * - `/.well-known/jacs-agent.json`
 * - `/.well-known/jacs-pubkey.json`
 * - `/.well-known/jacs-extension.json`
 *
 * All responses include CORS headers for cross-origin discovery.
 * Documents refresh together on a request at six days after binding issuance.
 * Failed refreshes retry at most once per minute; valid cached data may be
 * served until seven days or explicit expiry, then requests receive 503.
 * HTTP freshness ends at the six-day renewal boundary; still-valid snapshots
 * awaiting renewal are served with no-store.
 * Explicit expiry requires renewed authorization and remounting, not automatic
 * extension. Separate resource requests can straddle a snapshot replacement;
 * this is not a transactional client bundle. Consumers must verify the binding.
 *
 * @param {import('../client').JacsClient} client - An initialized JacsClient
 * @param {Object} [options]
 * @param {Array<{id: string, name: string, description: string, tags: string[]}>} [options.skills] - Custom A2A skills
 * @param {string} [options.url] - Base URL / domain for the agent card
 * @param {string} [options.keyAlgorithm] - Key algorithm label (default: 'pq2025')
 * @returns {Function} Express middleware (Router)
 */
function jacsA2AMiddleware(client, options = {}) {
  let express;
  try {
    express = require('express');
  } catch {
    throw new Error(
      'jacsA2AMiddleware requires express. Install it with: npm install express'
    );
  }

  const router = express.Router();

  let snapshot = discoverySnapshot(buildWellKnownDocuments(client, options), Date.now());
  let retryAt = 0;
  let expiryLogged = false;

  function currentSnapshot() {
    let now = Date.now();
    if (now >= snapshot.expires) {
      // Native reissue preserves finite expiry. Do not sign on every request
      // for a grant which cannot be renewed by this cache.
      if (!expiryLogged) console.warn('a2a_discovery_expired: explicit authorization expiry');
      expiryLogged = true;
      return null;
    }
    if ((now >= snapshot.issued + 6 * DAY_MS || !snapshotValid(snapshot, now)) && now >= retryAt) {
      try {
        const replacement = discoverySnapshot(buildWellKnownDocuments(client, options), Date.now());
        if (replacement.expires > snapshot.expires) throw new Error('Discovery expiry cannot be extended');
        // The existing builder validates the complete native card/JWKS/binding
        // set and override assertions before one synchronous publication.
        snapshot = replacement;
      } catch {
        console.warn('a2a_discovery_refresh_failed: retry deferred for 60 seconds');
      } finally {
        retryAt = Date.now() + RETRY_MS;
      }
      now = Date.now();
    }
    return snapshotValid(snapshot, now) ? snapshot : null;
  }

  // Helper: set CORS headers and send cached JSON
  function serveDocument(path) {
    return (_req, res) => {
      for (const [key, value] of Object.entries(CORS_HEADERS)) {
        res.set(key, value);
      }
      const current = currentSnapshot();
      const now = Date.now();
      const remaining = current ? current.until - now : 0;
      if (remaining <= 0) {
        res.set('Cache-Control', 'no-store');
        return res.status(503).json({ error: 'A2A discovery unavailable' });
      }
      // HTTP caches must revalidate when another resource can trigger renewal.
      const cacheRemaining = Math.min(remaining, current.issued + 6 * DAY_MS - now);
      const maxAge = Math.max(0, Math.min(3600, Math.floor(cacheRemaining / 1000)));
      res.set('Cache-Control', maxAge ? `public, max-age=${maxAge}, must-revalidate` : 'no-store');
      res.json(current.documents[path]);
    };
  }

  // CORS preflight handler
  function preflightHandler(_req, res) {
    for (const [key, value] of Object.entries(CORS_HEADERS)) {
      res.set(key, value);
    }
    res.status(204).end();
  }

  // Register GET + OPTIONS for each well-known endpoint
  for (const path of Object.keys(snapshot.documents)) {
    router.get(path, serveDocument(path));
    router.options(path, preflightHandler);
  }

  return router;
}

module.exports = {
  jacsA2AMiddleware,
  buildWellKnownDocuments,
  CORS_HEADERS,
};
