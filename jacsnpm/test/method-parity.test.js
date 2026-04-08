/**
 * Method enumeration parity test for the Node.js binding.
 *
 * Validates that all methods listed in
 * binding-core/tests/fixtures/method_parity.json are exposed on the
 * JacsSimpleAgent class, with documented exclusions and camelCase name mappings.
 *
 * This is a *structural* test (method names), not a *behavioral* test.
 * It complements, not duplicates, test_parity.js.
 */

const fs = require('fs');
const path = require('path');
const { expect } = require('chai');

const FIXTURE_PATH = path.resolve(
  __dirname,
  '../../binding-core/tests/fixtures/method_parity.json'
);

// Methods that are intentionally Rust-only and not exposed in Node.
const EXCLUDED_FROM_NODE = new Set([
  // inner_ref returns a raw Rust reference; not meaningful across FFI
  'inner_ref',
  // from_agent wraps a Rust SimpleAgent; not callable from JS
  'from_agent',
  // load_with_info is an internal Rust helper; Node uses load() directly
  'load_with_info',
]);

// Rust snake_case method name -> Node camelCase method name mapping.
const NODE_NAME_MAP = {
  'create': 'create',               // static
  'load': 'load',                   // static
  'ephemeral': 'ephemeral',         // static
  'create_with_params': 'createWithParams', // static
  'get_agent_id': 'getAgentId',
  'key_id': 'keyId',
  'is_strict': 'isStrict',
  'config_path': 'configPath',
  'export_agent': 'exportAgent',
  'get_public_key_pem': 'getPublicKeyPem',
  'get_public_key_base64': 'getPublicKeyBase64',
  'diagnostics': 'diagnostics',
  'verify_self': 'verifySelf',
  'verify_json': 'verify',
  'verify_with_key_json': 'verifyWithKey',
  'verify_by_id_json': 'verifyById',
  'sign_message_json': 'signMessage',
  'sign_raw_bytes_base64': 'signRawBytes',
  'sign_file_json': 'signFile',
  'to_yaml': 'toYaml',
  'from_yaml': 'fromYaml',
  'to_html': 'toHtml',
  'from_html': 'fromHtml',
  'rotate_keys': 'rotateKeys',
};

// Static methods (on the class itself, not on instances)
const STATIC_METHODS = new Set(['create', 'load', 'ephemeral', 'createWithParams']);

describe('Node.js method enumeration parity', function () {
  let fixture;
  let JacsSimpleAgent;
  let agent;

  before(function () {
    if (!fs.existsSync(FIXTURE_PATH)) {
      console.log('  Skipping method parity tests - fixture not found');
      this.skip();
      return;
    }
    fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));

    try {
      const bindings = require('../index.js');
      JacsSimpleAgent = bindings.JacsSimpleAgent;
      if (!JacsSimpleAgent) {
        this.skip();
        return;
      }
      agent = JacsSimpleAgent.ephemeral('ed25519');
    } catch (e) {
      console.log('  Skipping method parity tests - native binding not available');
      this.skip();
    }
  });

  it('all non-excluded methods from fixture exist on JacsSimpleAgent', function () {
    const allMethods = fixture.all_methods_flat;
    const missing = [];

    for (const rustName of allMethods) {
      if (EXCLUDED_FROM_NODE.has(rustName)) continue;

      const nodeName = NODE_NAME_MAP[rustName];
      if (!nodeName) {
        missing.push(`${rustName} (no NODE_NAME_MAP entry)`);
        continue;
      }

      if (STATIC_METHODS.has(nodeName)) {
        // Check on the class itself
        if (typeof JacsSimpleAgent[nodeName] !== 'function') {
          missing.push(`${rustName} -> static ${nodeName}`);
        }
      } else {
        // Check on the instance
        if (typeof agent[nodeName] !== 'function') {
          missing.push(`${rustName} -> ${nodeName}`);
        }
      }
    }

    expect(missing, `Missing methods:\n${missing.join('\n')}`).to.be.empty;
  });

  it('exclusions are all valid fixture methods', function () {
    const allMethods = new Set(fixture.all_methods_flat);
    const invalid = [];
    for (const excluded of EXCLUDED_FROM_NODE) {
      if (!allMethods.has(excluded)) {
        invalid.push(excluded);
      }
    }
    expect(invalid, `EXCLUDED_FROM_NODE contains methods not in fixture: ${invalid}`).to.be.empty;
  });

  it('NODE_NAME_MAP covers all non-excluded methods', function () {
    const allMethods = fixture.all_methods_flat;
    const unmapped = [];
    for (const rustName of allMethods) {
      if (EXCLUDED_FROM_NODE.has(rustName)) continue;
      if (!(rustName in NODE_NAME_MAP)) {
        unmapped.push(rustName);
      }
    }
    expect(unmapped, `Methods without NODE_NAME_MAP entry: ${unmapped}`).to.be.empty;
  });

  it('NODE_NAME_MAP has no stale entries', function () {
    const allMethods = new Set(fixture.all_methods_flat);
    const stale = [];
    for (const rustName of Object.keys(NODE_NAME_MAP)) {
      if (!allMethods.has(rustName)) {
        stale.push(rustName);
      }
    }
    expect(stale, `Stale NODE_NAME_MAP entries: ${stale}`).to.be.empty;
  });

  it('method count matches fixture minus exclusions', function () {
    const expected = fixture.all_methods_flat.length - EXCLUDED_FROM_NODE.size;
    const nodeNameCount = Object.keys(NODE_NAME_MAP).length;
    expect(nodeNameCount).to.equal(expected,
      `NODE_NAME_MAP has ${nodeNameCount} entries but expected ${expected} (fixture has ${fixture.all_methods_flat.length}, ${EXCLUDED_FROM_NODE.size} excluded)`
    );
  });
});
