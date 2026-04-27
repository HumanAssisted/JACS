/**
 * PRD §4.2.6 / Issue 022 — Node parameterised drift test for MCP path policy.
 *
 * Consumes the same JSON fixture as the Rust + Python tests so the three
 * languages enforce identical policy. The fixture is shared at
 * jacs-mcp/tests/fixtures/mcp_path_policy_cases.json.
 *
 * The Rust delegate (jacsMcpResolveInputPath, exposed via NAPI) is what
 * we're exercising; Node is a thin shell.
 */

const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { jacsMcpResolveInputPath } = require('../index.js');

function fixturePath() {
  // jacsnpm/test/ -> jacsnpm/ -> JACS/ -> jacs-mcp/tests/fixtures/...
  return path.resolve(__dirname, '..', '..', 'jacs-mcp', 'tests', 'fixtures', 'mcp_path_policy_cases.json');
}

function loadFixture() {
  const text = fs.readFileSync(fixturePath(), 'utf8');
  const parsed = JSON.parse(text);
  if (parsed.schema_version !== 1) {
    throw new Error('fixture schema_version must be 1');
  }
  return parsed.cases;
}

/** Decode `\\uXXXX` escapes for cases that need to carry control chars. */
function decodeUnicodeEscapes(s) {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_m, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function resolvedRawPath(c) {
  if (c.raw_path !== undefined) return c.raw_path;
  if (c.raw_path_escaped !== undefined) return decodeUnicodeEscapes(c.raw_path_escaped);
  throw new Error(`[case ${c.id}] requires raw_path or raw_path_escaped`);
}

function withEnv(envOverrides, body) {
  const saved = {};
  for (const k of Object.keys(envOverrides)) {
    saved[k] = process.env[k];
    if (envOverrides[k] === '') {
      delete process.env[k];
    } else {
      process.env[k] = envOverrides[k];
    }
  }
  try {
    body();
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = saved[k];
      }
    }
  }
}

describe('MCP path policy — shared fixture (Node)', function () {
  const cases = loadFixture();

  it('runs every fixture case', function () {
    expect(cases.length).to.be.greaterThan(0);

    for (const c of cases) {
      const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-mcp-policy-'));
      try {
        // Materialise setup (file or symlink) when requested.
        if (c.setup) {
          if (c.setup.kind === 'file') {
            const target = path.join(baseDir, c.setup.name);
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, c.setup.contents || '');
          } else if (c.setup.kind === 'symlink') {
            if (process.platform === 'win32') continue; // unix-only matrix entry
            const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-mcp-policy-outside-'));
            const target = c.setup.target_outside_base !== false
              ? path.join(outsideDir, 'attacker_target')
              : path.join(baseDir, 'inside_target');
            fs.writeFileSync(target, 'sensitive');
            fs.symlinkSync(target, path.join(baseDir, c.setup.name));
            // outsideDir is leaked intentionally — test process exits soon.
          } else {
            throw new Error(`[case ${c.id}] unknown setup kind: ${c.setup.kind}`);
          }
        }

        const env = Object.assign({ JACS_MCP_BASE_DIR: baseDir }, c.env || {});
        // Default-clear gating env vars not in the case.
        if (env.JACS_MCP_OVERWRITE_OK === undefined) env.JACS_MCP_OVERWRITE_OK = '';
        if (env.JACS_MCP_FOLLOW_SYMLINKS === undefined) env.JACS_MCP_FOLLOW_SYMLINKS = '';

        withEnv(env, () => {
          const raw = resolvedRawPath(c);
          const kind = c.kind;

          if (c.expect === 'accept') {
            expect(() => jacsMcpResolveInputPath(raw, kind))
              .to.not.throw(`[case ${c.id}] expected accept, threw`);
          } else if (c.expect === 'reject') {
            let caught;
            try {
              jacsMcpResolveInputPath(raw, kind);
            } catch (e) {
              caught = e;
            }
            expect(caught, `[case ${c.id}] expected reject, did not throw`).to.exist;
            if (c.reason_substring_lowercase) {
              expect(String(caught).toLowerCase()).to.include(c.reason_substring_lowercase,
                `[case ${c.id}] error did not contain expected substring`);
            }
          } else {
            throw new Error(`[case ${c.id}] unknown expect: ${c.expect}`);
          }
        });
      } finally {
        try {
          fs.rmSync(baseDir, { recursive: true, force: true });
        } catch (_) { /* noop */ }
      }
    }
  });
});
