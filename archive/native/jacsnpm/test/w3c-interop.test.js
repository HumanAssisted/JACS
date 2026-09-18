const assert = require('assert');

const ORIGIN = 'https://agent.example.com';
const REQUEST_URL = 'https://api.example.com/tasks?priority=high';
const REQUEST_BODY = '{"task":"review proposal","ok":true}';
const CREATED = '2026-01-01T00:00:00Z';
const MAX_AGE_SECONDS = 4_000_000_000;

describe('Node.js W3C DID interop smoke', function () {
  let JacsSimpleAgent;

  before(function () {
    try {
      const bindings = require('../index.js');
      JacsSimpleAgent = bindings.JacsSimpleAgent;
      if (!JacsSimpleAgent) this.skip();
    } catch (e) {
      this.skip();
    }
  });

  it('exports discovery artifacts and verifies request-bound DID proof', function () {
    const agent = JacsSimpleAgent.ephemeral('ed25519');

    const did = agent.exportW3cDid(ORIGIN);
    assert.match(did, /^did:wba:agent\.example\.com:agent:/);

    const didDocument = JSON.parse(agent.exportW3cDidDocument(ORIGIN));
    assert.equal(didDocument.id, did);
    assert.equal(typeof didDocument.jacs.jacsId, 'string');
    assert.notEqual(didDocument.jacs.jacsId, '');

    const agentDescription = JSON.parse(agent.exportW3cAgentDescription(ORIGIN));
    assert.equal(agentDescription.did, did);
    assert.equal(agentDescription.jacs.jacsId, didDocument.jacs.jacsId);

    const wellKnown = JSON.parse(agent.generateW3cWellKnown(ORIGIN));
    assert.ok(wellKnown['/.well-known/agent-descriptions']);

    const proof = JSON.parse(agent.signW3cRequest(JSON.stringify({
      method: 'POST',
      url: REQUEST_URL,
      body: REQUEST_BODY,
      nonce: 'node-w3c-smoke-nonce',
      created: CREATED,
      origin: ORIGIN,
    })));
    assert.equal(proof.did, did);
    assert.match(proof.contentDigest, /^sha-256=:/);

    assert.throws(() => agent.verifyW3cRequest(
      JSON.stringify(proof),
      JSON.stringify(didDocument),
      REQUEST_BODY,
      MAX_AGE_SECONDS,
      'POST',
      'https://api.example.com/other'
    ), /target URI/);

    const verification = JSON.parse(agent.verifyW3cRequest(
      JSON.stringify(proof),
      JSON.stringify(didDocument),
      REQUEST_BODY,
      MAX_AGE_SECONDS,
      'POST',
      REQUEST_URL
    ));
    assert.equal(verification.valid, true);
    assert.equal(verification.expectedRequestChecked, true);
  });
});
