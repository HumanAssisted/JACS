const { expect } = require('chai');
const sinon = require('sinon');

const CARD = {
  name: 'Remote',
  capabilities: { extensions: [{ uri: 'urn:jacs:provenance-v1' }] },
  metadata: { jacsId: 'remote-id', jacsVersion: 'v1' },
};

function loadDiscoveryWithCard(card = CARD) {
  const index = require('../index.js');
  const original = index.fetchAgentCardAsync;
  index.fetchAgentCardAsync = sinon.stub().resolves(JSON.stringify(card));
  delete require.cache[require.resolve('../src/a2a-discovery')];
  const discovery = require('../src/a2a-discovery');
  return {
    discovery,
    restore() {
      index.fetchAgentCardAsync = original;
      delete require.cache[require.resolve('../src/a2a-discovery')];
    },
  };
}

describe('A2A discovery trust boundary', () => {
  it('does not treat a self-advertised extension as verified identity', async () => {
    const loaded = loadDiscoveryWithCard();
    try {
      const result = await loaded.discovery.discoverAndAssess('https://agent.example.com');
      expect(result.jacsRegistered).to.equal(true);
      expect(result.allowed).to.equal(false);
      expect(result.trustLevel).to.equal('untrusted');
      expect(result.reason).to.include('native cryptographic assessment');
    } finally {
      loaded.restore();
    }
  });

  it('uses native assessment and exposes first-contact TOFU state', async () => {
    const loaded = loadDiscoveryWithCard();
    try {
      const client = {
        _agent: {
          assessA2aAgent: sinon.stub().resolves(JSON.stringify({
            allowed: true,
            trustLevel: 'JacsVerified',
            jacsRegistered: true,
            reason: 'origin key pinned',
            firstContact: true,
          })),
        },
      };
      const result = await loaded.discovery.discoverAndAssess(
        'https://agent.example.com',
        { client },
      );
      expect(result.allowed).to.equal(true);
      expect(result.trustLevel).to.equal('jacs_registered');
      expect(result.firstContact).to.equal(true);
    } finally {
      loaded.restore();
    }
  });
});
