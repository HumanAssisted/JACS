/**
 * Tests for the ES256 compatibility key exports (P2 Tasks 002 / 004 / 004b).
 *
 * A persistent agent minted via createWithParams gets the ES256
 * `ecosystem_signing` compatibility key eagerly. Identity exports
 * (JWKS, key binding) auto-issue the default identity binding; content
 * exports (AP2 mandate) require an explicit binding scope and must be
 * denied on a fresh agent.
 */

const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');

let bindings;
try {
  bindings = require('../index.js');
} catch (e) {
  bindings = null;
}

const TEST_PASSWORD = 'TestP@ss123!#';

describe('ES256 compatibility exports', function () {
  let tmpDir;
  let agent;

  before(function () {
    if (!bindings || !bindings.JacsSimpleAgent) {
      console.log('  Skipping compat export tests - native binding not available');
      this.skip();
      return;
    }
    process.env.JACS_PRIVATE_KEY_PASSWORD = TEST_PASSWORD;
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-compat-')));
    const params = {
      name: 'compat-export-node',
      password: TEST_PASSWORD,
      data_directory: path.join(tmpDir, 'jacs_data'),
      key_directory: path.join(tmpDir, 'jacs_keys'),
      config_path: path.join(tmpDir, 'jacs.config.json'),
    };
    agent = bindings.JacsSimpleAgent.createWithParams(JSON.stringify(params));
  });

  after(function () {
    if (tmpDir) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('exportCompatibilityJwks returns an EC P-256 JWKS', function () {
    const jwks = JSON.parse(agent.exportCompatibilityJwks());
    expect(jwks.keys).to.be.an('array').with.lengthOf(1);
    const key = jwks.keys[0];
    expect(key.kty).to.equal('EC');
    expect(key.crv).to.equal('P-256');
    expect(key.kid).to.be.a('string').and.not.empty;
    // Public key only — PQ / private material is never published here.
    expect(key).to.not.have.property('d');
  });

  it('exportCompatibilityKeyBinding is signed by the pq2025 root', function () {
    const binding = JSON.parse(agent.exportCompatibilityKeyBinding());
    expect(binding.jacsSignature).to.be.an('object');
    expect(binding.jacsSignature.signingAlgorithm).to.equal('pq2025');
    const details = binding.compatibilityKeyBinding;
    expect(details.compatibilityKey.algorithm).to.equal('ES256');
    expect(details.scope).to.be.an('array').that.includes('jwks');
  });

  it('exportAp2Mandate without the ap2-mandate scope is rejected', function () {
    // Content exports never auto-issue a binding scope; a fresh agent's
    // binding only carries identity scopes, so this must be denied.
    const checkout = {
      id: 'c1',
      currency: 'USD',
      line_items: [{ id: 'li1' }],
      totals: [{ type: 'total', amount: 100 }],
    };
    expect(() => agent.exportAp2Mandate(JSON.stringify(checkout)))
      .to.throw(/binding|scope/);
  });
});
