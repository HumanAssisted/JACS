// Copied into a fresh consumer so resolution cannot use source-tree fallbacks.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const entry = require.resolve('@hai.ai/jacs');
  assert.ok(entry.startsWith(path.join(process.cwd(), 'node_modules') + path.sep));
  const metadata = JSON.parse(fs.readFileSync(path.join(path.dirname(entry), 'package.json'), 'utf8'));
  assert.equal(metadata.version, process.argv[2]);
  for (const name of ['.', './signing-input', './simple', './client', './a2a', './mcp', './http',
                      './express', './koa', './vercel-ai', './testing', './langchain',
                      './a2a-server', './a2a-discovery']) {
    assert.ok(metadata.exports[name], `missing public export ${name}`);
    for (const file of Object.values(metadata.exports[name])) {
      assert.ok(fs.existsSync(path.join(path.dirname(entry), file)), `missing packed file ${file}`);
    }
  }
  const {JacsAgent, JacsSimpleAgent} = require('@hai.ai/jacs');
  assert.equal(typeof JacsAgent, 'function');
  assert.equal(typeof require('@hai.ai/jacs/client').JacsClient, 'function');
  require('@hai.ai/jacs/simple');
  require('@hai.ai/jacs/a2a');
  const signing = await import('@hai.ai/jacs/signing-input');
  for (const name of ['buildDocumentChecksumInputV1', 'buildHaiSignatureInputDigestPreimageV1',
                     'buildHumanApprovalDocumentSignatureInputDigestPreimageV1',
                     'buildSignedDocumentSignatureInputV2', 'canonicalizeJson', 'encodeUtf8']) {
    assert.equal(typeof signing[name], 'function', `missing HAI signing-input export ${name}`);
  }
  assert.equal(signing.canonicalizeJson({z: 1, a: 2}), '{"a":2,"z":1}');
  const agent = JacsSimpleAgent.ephemeral();
  const signed = agent.signMessage(JSON.stringify({message: 'binding-smoke-original'}));
  assert.equal(JSON.parse(agent.verify(signed)).valid, true);
  assert.equal(JSON.parse(signed).jacsSignature.signingAlgorithm, 'pq2025');
  const tampered = signed.replace('binding-smoke-original', 'binding-smoke-tampered');
  assert.notEqual(tampered, signed);
  let accepted = false;
  try { accepted = JSON.parse(agent.verify(tampered)).valid; } catch (_) {}
  assert.equal(accepted, false, 'tampered document accepted');
  const esm = await import('@hai.ai/jacs');
  const second = esm.JacsSimpleAgent.ephemeral();
  assert.equal(JSON.parse(second.verify(second.signMessage('{"esm":true}'))).valid, true);
  console.log('NPM-CANDIDATE-OK: full exports, CJS/ESM PQ signing, tamper rejection, signing-input');
})().catch((error) => { console.error(error); process.exitCode = 1; });
