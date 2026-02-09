/**
 * JACS Quickstart Example
 *
 * Demonstrates the simplified API for signing and verifying messages.
 *
 * Usage:
 *   node quickstart.js
 */

const jacs = require('@hai.ai/jacs/simple');

async function main() {
  // Load existing agent (requires jacs.config.json)
  // Run `jacs create --name "my-agent"` first if you don't have one
  try {
    const agent = jacs.load('./jacs.config.json');
    console.log(`Loaded agent: ${agent.agentId}`);
  } catch (e) {
    console.error('No agent found. Run: jacs create --name "my-agent"');
    process.exit(1);
  }

  // Sign a message
  const data = {
    action: 'approve',
    amount: 100,
    currency: 'USD',
    timestamp: new Date().toISOString(),
  };

  const signed = jacs.signMessage(data);
  console.log(`Signed document ID: ${signed.documentId}`);
  console.log(`Signed by: ${signed.agentId}`);
  console.log(`Timestamp: ${signed.timestamp}`);

  // Verify the signed document
  const result = jacs.verify(signed.raw);
  console.log(`\nVerification result:`);
  console.log(`  Valid: ${result.valid}`);
  console.log(`  Signer: ${result.signerId}`);
  console.log(`  Data: ${JSON.stringify(result.data)}`);

  // Verify agent's own integrity
  const selfVerify = jacs.verifySelf();
  console.log(`\nSelf verification: ${selfVerify.valid ? 'PASSED' : 'FAILED'}`);
}

main().catch(console.error);
