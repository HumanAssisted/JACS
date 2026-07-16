/**
 * JACS A2A Express Middleware
 *
 * Middleware factory that serves A2A .well-known discovery endpoints
 * from an existing Express app. All 6 identity-bound endpoints are cached
 * after first generation.
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
 * Documents are generated once and cached (not regenerated per request).
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

  // Build and cache all documents once
  const documents = buildWellKnownDocuments(client, options);

  // Helper: set CORS headers and send cached JSON
  function serveDocument(path) {
    return (_req, res) => {
      for (const [key, value] of Object.entries(CORS_HEADERS)) {
        res.set(key, value);
      }
      res.json(documents[path]);
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
  for (const path of Object.keys(documents)) {
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
