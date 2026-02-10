#!/usr/bin/env npx ts-node
/**
 * Multi-agent agreement with cryptographic proof -- zero setup.
 *
 * Three agents negotiate and co-sign a deployment proposal using JACS.
 * Demonstrates quorum (2-of-3), timeout, independent verification,
 * and a full crypto proof chain.
 *
 * Run:
 *   npx ts-node --compiler-options '{"module":"commonjs","moduleResolution":"node","esModuleInterop":true}' examples/multi_agent_agreement.ts
 */

import { JacsClient } from '../jacsnpm/client';

function main(): void {
  // -- Step 1: Create three ephemeral agents ----------------------------------
  console.log('Step 1 -- Create agents');
  const alice = JacsClient.ephemeral('ring-Ed25519');
  const bob = JacsClient.ephemeral('ring-Ed25519');
  const mediator = JacsClient.ephemeral('ring-Ed25519');

  console.log(`  Alice    : ${alice.agentId}`);
  console.log(`  Bob      : ${bob.agentId}`);
  console.log(`  Mediator : ${mediator.agentId}`);

  // -- Step 2: Alice proposes an agreement ------------------------------------
  console.log('\nStep 2 -- Alice proposes an agreement');
  const proposal = {
    proposal: 'Deploy model v2 to production',
    conditions: ['passes safety audit', 'approved by 2 of 3 signers'],
  };

  const deadline = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const agentIds = [alice.agentId, bob.agentId, mediator.agentId];

  let agreement = alice.createAgreement(proposal, agentIds, {
    question: 'Do you approve deployment of model v2?',
    context: 'Production rollout pending safety audit sign-off.',
    quorum: 2,
    timeout: deadline,
  });
  console.log(`  Agreement ID : ${agreement.documentId}`);
  console.log(`  Quorum       : 2 of 3`);
  console.log(`  Deadline     : ${deadline}`);

  // -- Step 3: Alice signs ----------------------------------------------------
  console.log('\nStep 3 -- Alice signs');
  agreement = alice.signAgreement(agreement);
  console.log(`  Signed by Alice    (${alice.agentId.substring(0, 12)}...)`);

  // -- Step 4: Bob co-signs ---------------------------------------------------
  console.log('\nStep 4 -- Bob co-signs');
  agreement = bob.signAgreement(agreement);
  console.log(`  Signed by Bob      (${bob.agentId.substring(0, 12)}...)`);

  // -- Step 5: Mediator countersigns ------------------------------------------
  console.log('\nStep 5 -- Mediator countersigns');
  agreement = mediator.signAgreement(agreement);
  console.log(`  Signed by Mediator (${mediator.agentId.substring(0, 12)}...)`);

  // -- Step 6: Inspect agreement status ---------------------------------------
  console.log('\nStep 6 -- Agreement status');
  const doc = JSON.parse(agreement.raw);
  const ag = doc.jacsAgreement;
  const sigCount = ag.signatures?.length ?? 0;
  const quorum = ag.quorum ?? ag.agentIDs.length;
  const complete = sigCount >= quorum;

  console.log(`  Signatures : ${sigCount} of ${ag.agentIDs.length}`);
  console.log(`  Quorum met : ${complete}`);
  for (const sig of ag.signatures ?? []) {
    console.log(
      `    ${sig.agentID.substring(0, 12)}... signed at ${sig.date}  (${sig.signingAlgorithm})`,
    );
  }

  // -- Step 7: Independent self-verification ----------------------------------
  console.log('\nStep 7 -- Independent self-verification');
  for (const [name, client] of [
    ['Alice', alice],
    ['Bob', bob],
    ['Mediator', mediator],
  ] as const) {
    const result = client.verifySelf();
    console.log(`  ${name} verifies self: valid=${result.valid}`);
  }

  // -- Cleanup ----------------------------------------------------------------
  alice.dispose();
  bob.dispose();
  mediator.dispose();
  console.log('\nDone.');
}

main();
