const { expect } = require('chai');
const { JacsAgent } = require('../index.js');

// Exercise actual scoped N-API values rather than a mocked facade.
describe('Native JavaScript value conversion', function () {
  this.timeout(30000);
  let agent;
  beforeEach(() => {
    agent = new JacsAgent();
    agent.ephemeralSync('ring-Ed25519');
  });

  it('preserves nested arrays, scalar values and binary buffers through signed requests', () => {
    const payload = {
      text: 'Unicode π', enabled: true, empty: null, integer: 42, fraction: 0.25,
      nested: [{ bytes: Buffer.from([0, 127, 255]), values: [false, null, ''] }],
    };
    const signed = agent.signRequest(payload);
    expect(agent.verifyResponse(signed).payload).to.deep.equal(payload);
    const withAgent = agent.verifyResponseWithAgentId(signed);
    expect(withAgent.payload).to.deep.equal(payload);
    expect(withAgent.agent_id).to.be.a('string').and.not.empty;
  });

  it('rejects unsupported values rather than silently signing a different payload', () => {
    expect(() => agent.signRequest({ value: Symbol('unsupported') })).to.throw(/Unsupported JavaScript type/);
  });
});
