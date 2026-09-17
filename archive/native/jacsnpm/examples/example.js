import assert from 'assert';
import * as jacs from '../simple.js';

async function main() {
  const info = await jacs.quickstart({
    name: 'example-agent',
    domain: 'example.local',
  });

  const payload = { hello: 'world' };
  const signed = await jacs.signMessage(payload);
  const verification = await jacs.verify(signed.raw);

  assert.strictEqual(verification.valid, true, `verification failed: ${verification.errors}`);
  console.log('Agent ID:', info.agentId);
  console.log('Signed document ID:', signed.documentId);
  console.log('Verification valid:', verification.valid);
}

main().catch((error) => {
  console.error('Error:', error);
  process.exit(1);
});
