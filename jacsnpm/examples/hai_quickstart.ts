/**
 * HAI.ai Quickstart - From zero to benchmarked in minutes.
 *
 * Shows the full HAI.ai flow:
 *   1. Create agent + register with HAI.ai
 *   2. Hello world (verify connectivity, no cost)
 *   3. Free chaotic run (see your agent mediate, no score)
 *   4. $5 baseline run (get your score)
 *
 * Prerequisites:
 *     npm install @hai.ai/jacs
 *
 *     # Get an API key from https://hai.ai/dev
 *     export HAI_API_KEY=your-api-key
 *
 * Usage:
 *     npx tsx hai_quickstart.ts              # Full flow (steps 1-3)
 *     npx tsx hai_quickstart.ts --hello      # Hello world (step 2)
 *     npx tsx hai_quickstart.ts --free       # Free chaotic run (step 3)
 *     npx tsx hai_quickstart.ts --baseline   # $5 baseline run (step 4)
 *     npx tsx hai_quickstart.ts --register   # Create agent + register (step 1)
 */

import { JacsClient } from '../client';
import { HaiClient, HaiError } from '../hai';

const HAI_URL = process.env.HAI_URL || 'https://hai.ai';

// ---------------------------------------------------------------------------
// Step helpers
// ---------------------------------------------------------------------------

async function stepRegister(hai: HaiClient, apiKey?: string): Promise<void> {
  console.log('\n--- Step 1: Register agent ---');

  const result = await hai.register(apiKey);
  console.log('Agent registered!');
  console.log(`  Agent ID:        ${result.agentId}`);
  console.log(`  Registration ID: ${result.registrationId}`);
  console.log(`  Registered at:   ${result.registeredAt}`);
}

async function stepHello(hai: HaiClient): Promise<void> {
  console.log('\n--- Step 2: Hello World ---');

  const result = await hai.hello();
  console.log(`HAI says: ${result.message}`);
  console.log(`  Your IP:         ${result.clientIp}`);
  console.log(`  HAI signature:   ${result.haiSignatureValid ? 'valid' : 'INVALID'}`);
  console.log(`  Timestamp:       ${result.timestamp}`);
}

async function stepFreeChaotic(hai: HaiClient): Promise<void> {
  console.log('\n--- Step 3: Free Chaotic Run (no score) ---');

  const result = await hai.freeChaoticRun();
  if (result.success) {
    console.log(`Run ID: ${result.runId}`);
    console.log(`Transcript (${result.transcript.length} messages):`);
    for (const msg of result.transcript.slice(0, 5)) {
      const label = msg.role.toUpperCase();
      const text = msg.content.length > 80
        ? msg.content.slice(0, 80) + '...'
        : msg.content;
      console.log(`  [${label}] ${text}`);
    }
    if (result.transcript.length > 5) {
      console.log(`  ... and ${result.transcript.length - 5} more messages`);
    }
    if (result.upsellMessage) {
      console.log(`\n${result.upsellMessage}`);
    }
  } else {
    console.log('Free chaotic run failed');
  }
}

async function stepBaseline(hai: HaiClient): Promise<void> {
  console.log('\n--- Step 4: $5 Baseline Run ---');
  console.log('This will create a Stripe Checkout session for $5 payment.');

  const result = await hai.baselineRun({
    onCheckoutUrl: (url) => {
      console.log(`\nComplete payment at: ${url}`);
    },
  });

  if (result.success) {
    console.log(`Run ID: ${result.runId}`);
    console.log(`Score:  ${result.score}/100`);
    console.log(`Transcript: ${result.transcript.length} messages`);
  } else {
    console.log('Baseline run failed');
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  const flags = new Set(args);
  const apiKey = process.env.HAI_API_KEY;

  console.log('='.repeat(60));
  console.log('HAI.ai Quickstart');
  console.log('='.repeat(60));

  // Create JACS agent (loads existing or creates new)
  const jacs = await JacsClient.quickstart();
  console.log(`Agent: ${jacs.agentId}`);

  const hai = new HaiClient(jacs, HAI_URL);

  // Individual step flags
  if (flags.has('--register')) {
    if (!apiKey) {
      console.error('\nSet your API key: export HAI_API_KEY=your-api-key');
      process.exit(1);
    }
    await stepRegister(hai, apiKey);
    return;
  }

  if (flags.has('--hello')) {
    await stepHello(hai);
    return;
  }

  if (flags.has('--free')) {
    await stepFreeChaotic(hai);
    return;
  }

  if (flags.has('--baseline')) {
    await stepBaseline(hai);
    return;
  }

  // Full flow: register + hello + free chaotic
  if (!apiKey) {
    console.log('\nSet your API key:');
    console.log('  export HAI_API_KEY=your-api-key');
    console.log('  # Get one at https://hai.ai/dev');
    process.exit(1);
  }

  try {
    await stepRegister(hai, apiKey);
    await stepHello(hai);
    await stepFreeChaotic(hai);
  } catch (e) {
    if (e instanceof HaiError) {
      console.error(`\nHAI error: ${e.message}`);
      if (e.statusCode) console.error(`  Status: ${e.statusCode}`);
    } else {
      throw e;
    }
    process.exit(1);
  }

  console.log('\n' + '='.repeat(60));
  console.log('Done! Your agent is registered and has completed a free run.');
  console.log('='.repeat(60));
  console.log('\nNext steps:');
  console.log('  $5 baseline:     npx tsx hai_quickstart.ts --baseline');
  console.log('  Certified run:   Visit https://hai.ai/benchmark (dashboard)');
  console.log('  Build mediator:  See examples/agents/');
}

main().catch(console.error);
