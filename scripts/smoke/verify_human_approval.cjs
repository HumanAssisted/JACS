// Check the exact installed package, not a source-tree fallback. No test deps.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { JacsSimpleAgent } = require(path.resolve(process.argv[2]));
const fixture = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
function verify(value) {
  return JSON.parse(JacsSimpleAgent.verifyHumanApprovedDocument(
    ...['bundle', 'expected', 'authority', 'provenance'].map((name) => JSON.stringify(value[name])),
  ));
}
assert.deepEqual(verify(fixture), fixture.report, 'incomplete or incorrect public proof report');
assert.equal(fixture.report.current, 'not_evaluated');
assert.equal(fixture.report.approval.current, 'not_evaluated');
const wrong = JSON.parse(JSON.stringify(fixture));
wrong.expected.humanId += '-other';
assert.throws(() => verify(wrong), /VerificationFailed:/);
console.log('PUBLIC-HUMAN-PROOF-OK (archival evidence; current status not evaluated)');
