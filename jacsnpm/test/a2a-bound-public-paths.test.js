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
