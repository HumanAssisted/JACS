const { expect } = require('chai');
const sinon = require('sinon');
const { JACSA2AIntegration } = require('../src/a2a');
const { buildWellKnownDocuments } = require('../src/a2a-server');

function boundPairs() {
  const documents = {
    '/.well-known/agent-card.json': {
      name: 'native-bound',
      metadata: {
        jacsCompatKid: 'compat-kid',
        jacsCompatBindingHash: 'binding-hash',
        jacsCompatBindingPath: '/.well-known/jacs-compat-binding.json',
      },
      signatures: [{ keyId: 'compat-kid', jws: 'native-es256-jws' }],
    },
    '/.well-known/jwks.json': {
      keys: [{ kid: 'compat-kid', alg: 'ES256', use: 'sig' }],
    },
    '/.well-known/jacs-compat-binding.json': { jacsSha256: 'binding-hash' },
    '/.well-known/jacs-agent.json': { agentId: 'native-id' },
    '/.well-known/jacs-pubkey.json': { agentId: 'native-id' },
    '/.well-known/jacs-extension.json': { uri: 'urn:jacs:provenance-v1' },
  };
  return Object.entries(documents).map(([path, document]) => ({ path, document }));
}

function integrationWith(generator) {
  return new JACSA2AIntegration({
    _agent: { generateWellKnownDocumentsSync: generator },
    agentId: 'local-id',
    name: 'local',
  });
}

describe('identity-bound A2A public wrappers', () => {
  it('does not overwrite the native signed card with caller data or JWS', () => {
    const generator = sinon.stub().returns(JSON.stringify(boundPairs()));
    const integration = integrationWith(generator);

    const documents = integration.generateWellKnownDocuments(
      { name: 'caller-controlled', signatures: [{ jws: 'caller-card-jws' }] },
      'attacker-jws',
      'attacker-key',
      { jacsId: 'copied-id' },
    );

    expect(Object.keys(documents)).to.have.length(6);
    expect(documents['/.well-known/agent-card.json']).to.deep.equal({
      name: 'native-bound',
      metadata: {
        jacsCompatKid: 'compat-kid',
        jacsCompatBindingHash: 'binding-hash',
        jacsCompatBindingPath: '/.well-known/jacs-compat-binding.json',
      },
      signatures: [{ keyId: 'compat-kid', jws: 'native-es256-jws' }],
    });
  });

  it('never falls back to unbound documents after a native error', () => {
    const integration = integrationWith(sinon.stub().throws(new Error('native failed')));
    expect(() => integration.generateWellKnownDocuments({}, 'jws', 'key', {}))
      .to.throw(/Identity-bound A2A discovery generation failed/);
  });

  it('fails closed when the native generator is unavailable', () => {
    const integration = new JACSA2AIntegration({ _agent: {}, agentId: 'id', name: 'name' });
    expect(() => integration.generateWellKnownDocuments({}, 'jws', 'key', {}))
      .to.throw(/requires the native JACS generator/);
  });

  it('the Express document builder serves the native signed card unchanged', () => {
    const generator = sinon.stub().returns(JSON.stringify(boundPairs()));
    const documents = buildWellKnownDocuments({
      _agent: { generateWellKnownDocumentsSync: generator },
      agentId: 'wrapper-id',
      name: 'wrapper-name',
    });

    expect(documents['/.well-known/agent-card.json'].name).to.equal('native-bound');
    expect(documents['/.well-known/agent-card.json'].signatures).to.deep.equal([
      { keyId: 'compat-kid', jws: 'native-es256-jws' },
    ]);
    expect(documents).to.have.property('/.well-known/jacs-compat-binding.json');
  });
});

// Synthetic native-output fixture: cryptographic verification is exercised in
// Rust; these tests cover the wrapper boundary and never assert identity trust.
function directPairs() {
  const pub = Buffer.alloc(2592, 7).toString('base64url');
  const kid = require('crypto').createHash('sha256')
    .update(JSON.stringify({ alg: 'ML-DSA-87', kty: 'AKP', pub })).digest('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'ML-DSA-87', kid, typ: 'JOSE' })).toString('base64url');
  const documents = {
    '/.well-known/agent-card.json': {
      name: 'native-root', version: '1',
      metadata: { jacsId: 'root-id', jacsVersion: '1', jacsRootKid: kid },
      signatures: [{ keyId: kid, jws: `${header}.e30.c2ln` }],
    },
    '/.well-known/jwks.json': { keys: [{ kid, kty: 'AKP', alg: 'ML-DSA-87', pub, use: 'sig' }] },
    '/.well-known/jacs-agent.json': { agentId: 'root-id', agentVersion: '1', keyAlgorithm: 'pq2025' },
    '/.well-known/jacs-pubkey.json': {
      agentId: 'root-id', agentVersion: '1', algorithm: 'pq2025',
      publicKey: Buffer.from(pub, 'base64url').toString('base64'),
    },
    '/.well-known/jacs-extension.json': { uri: 'urn:jacs:provenance-v1' },
  };
  return Object.entries(documents).map(([path, document]) => ({ path, document }));
}

describe('direct ML-DSA-87 A2A wrapper output', () => {
  it('accepts the five native root documents without manufacturing a compatibility binding', () => {
    const integration = integrationWith(() => JSON.stringify(directPairs()));
    const documents = integration.generateWellKnownDocuments({}, 'attacker-jws', 'attacker-key', {});
    expect(Object.keys(documents)).to.have.length(5);
    expect(documents['/.well-known/agent-card.json'].name).to.equal('native-root');
    expect(documents).not.to.have.property('/.well-known/jacs-compat-binding.json');
  });

  for (const [label, change] of [
    ['mismatched root key', (docs) => { docs[3].document.publicKey = Buffer.alloc(2592, 8).toString('base64'); }],
    ['mismatched key id', (docs) => { docs[1].document.keys[0].kid = 'other'; }],
    ['unsupported algorithm', (docs) => { docs[1].document.keys[0].alg = 'ML-DSA-65'; }],
    ['truncated key', (docs) => { docs[1].document.keys[0].pub = 'AA'; }],
    ['private key material', (docs) => { docs[1].document.keys[0].priv = 'secret'; }],
    ['mismatched identity', (docs) => { docs[2].document.agentId = 'other'; }],
    ['mismatched protected header', (docs) => { docs[0].document.signatures[0].jws = 'e30.e30.c2ln'; }],
    ['missing root marker', (docs) => { delete docs[0].document.metadata.jacsRootKid; }],
    ['mixed compatibility metadata', (docs) => { docs[0].document.metadata.jacsCompatKid = 'other'; }],
  ]) {
    it(`rejects ${label}`, () => {
      const pairs = directPairs();
      change(pairs);
      expect(() => integrationWith(() => JSON.stringify(pairs)).generateWellKnownDocuments({}, '', '', {})).to.throw();
    });
  }

  it('passes explicit ES256 compatibility selection to the native generator', () => {
    const generator = sinon.stub().returns(JSON.stringify(boundPairs()));
    const documents = buildWellKnownDocuments({ _agent: { generateWellKnownDocumentsSync: generator } }, { a2aAlgorithm: 'es256' });
    expect(generator.calledOnceWithExactly('es256')).to.equal(true);
    expect(documents).to.have.property('/.well-known/jacs-compat-binding.json');
  });

  it('does not infer remote identity trust from a direct root card', () => {
    const card = directPairs()[0].document;
    card.capabilities = { extensions: [{ uri: 'urn:jacs:provenance-v1' }] };
    for (const policy of ['verified', 'strict']) {
      const integration = new JACSA2AIntegration({ _agent: {}, isTrusted: () => true }, policy);
      expect(integration.assessRemoteAgent(card).allowed).to.equal(false);
    }
  });

  it('serves and refreshes direct snapshots without reading a compatibility binding', () => {
    const { jacsA2AMiddleware } = require('../src/a2a-server');
    const clock = sinon.useFakeTimers({ now: Date.UTC(2026, 0, 1), toFake: ['Date'] });
    try {
      const generator = sinon.stub().callsFake(() => JSON.stringify(directPairs()));
      const router = jacsA2AMiddleware({ _agent: { generateWellKnownDocumentsSync: generator } });
      expect(router.stack.filter((layer) => layer.route?.methods.get)).to.have.length(5);
      const route = router.stack.find((layer) => layer.route?.path === '/.well-known/agent-card.json');
      const response = { set: sinon.stub(), json: sinon.stub(), status: sinon.stub() };
      response.set.returns(response); response.status.returns(response);
      route.route.stack[0].handle({}, response);
      expect(response.json.firstCall.args[0].name).to.equal('native-root');
      clock.tick(6 * 24 * 60 * 60 * 1000);
      route.route.stack[0].handle({}, response);
      expect(generator.callCount).to.equal(2);
      generator.throws(new Error('native generation failed'));
      clock.tick(7 * 24 * 60 * 60 * 1000);
      route.route.stack[0].handle({}, response);
      expect(response.status.calledWith(503)).to.equal(true);
    } finally { clock.restore(); }
  });
});
