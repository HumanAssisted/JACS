/**
 * JACS Quickstart Example
 *
 * Sign it. Prove it. Three lines to sign and verify.
 *
 * Usage:
 *   node quickstart.js
 *   node quickstart.js --advanced   # Load from config file instead
 */

const jacs = require('../simple');

async function main() {
  console.log('='.repeat(60));
  console.log('JACS Quickstart');
  console.log('='.repeat(60));

  // Step 1: One call creates an ephemeral agent -- no config file needed
  console.log('\n1. Creating ephemeral agent...');
  const info = jacs.quickstart();
  console.log(`   Agent ID: ${info.agentId}`);
  console.log(`   Algorithm: ${info.algorithm}`);

  // Step 2: Sign a message
  console.log('\n2. Signing a message...');
  const signed = jacs.signMessage({ hello: 'world', action: 'approve' });
  console.log(`   Document ID: ${signed.documentId}`);
  console.log(`   Signed by: ${signed.agentId}`);
  console.log(`   Timestamp: ${signed.timestamp}`);

  // Step 3: Verify it
  console.log('\n3. Verifying the signed message...');
  const result = jacs.verify(signed.raw);
  console.log(`   Valid: ${result.valid}`);
  console.log(`   Signer: ${result.signerId}`);

  console.log('\n' + '='.repeat(60));
  console.log('Done. Three lines to sign and verify.');
  console.log('='.repeat(60));
}

async function advanced() {
  console.log('='.repeat(60));
  console.log('JACS Advanced Example (config file)');
  console.log('='.repeat(60));

  // Load existing agent from config
  try {
    const agent = jacs.load('./jacs.config.json');
    console.log(`\nLoaded agent: ${agent.agentId}`);
  } catch (e) {
    console.error('No agent found. Run: jacs create --name "my-agent"');
    process.exit(1);
  }

  // Sign a message
  const signed = jacs.signMessage({
    action: 'approve',
    amount: 100,
    currency: 'USD',
    timestamp: new Date().toISOString(),
  });
  console.log(`Signed document ID: ${signed.documentId}`);
  console.log(`Signed by: ${signed.agentId}`);

  // Verify the signed document
  const result = jacs.verify(signed.raw);
  console.log(`\nVerification:`);
  console.log(`  Valid: ${result.valid}`);
  console.log(`  Signer: ${result.signerId}`);

  // Verify agent's own integrity
  const selfVerify = jacs.verifySelf();
  console.log(`\nSelf verification: ${selfVerify.valid ? 'PASSED' : 'FAILED'}`);
}

const useAdvanced = process.argv.includes('--advanced');

if (useAdvanced) {
  advanced().catch(console.error);
} else {
  main().catch(console.error);
}
