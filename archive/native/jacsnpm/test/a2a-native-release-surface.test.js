const { expect } = require('chai');
const { JacsAgent, fetchAgentCardAsync } = require('../index.js');

describe('Node release native A2A surface', () => {
  it('includes identity-bound generation and native trust assessment by default', () => {
    expect(JacsAgent).to.be.a('function');
    expect(JacsAgent.prototype.generateWellKnownDocumentsSync).to.be.a('function');
    expect(JacsAgent.prototype.assessA2aAgentSync).to.be.a('function');
    expect(fetchAgentCardAsync).to.be.a('function');
  });
});
