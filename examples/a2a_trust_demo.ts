#!/usr/bin/env npx ts-node
/**
 * Multi-agent A2A trust verification demo -- zero setup.
 *
 * Three agents interact via the A2A protocol:
 *   Agent A (JACS) -- Signs a task artifact and sends it
 *   Agent B (JACS) -- Receives, verifies, and countersigns with chain of custody
 *   Agent C (plain) -- Attempts to participate but is blocked by trust policy
 *
 * Demonstrates:
 *   - A2A artifact signing with JACS provenance
 *   - Cross-agent verification and trust assessment
 *   - Chain of custody across multiple signers
 *   - Trust policy enforcement (verified rejects non-JACS, strict requires trust store)
 *   - Agent Card export and JACS extension detection
 *
 * Run:
 *   npx ts-node --compiler-options '{"module":"commonjs","moduleResolution":"node","esModuleInterop":true}' examples/a2a_trust_demo.ts
 */

import { JacsClient } from '../jacsnpm/client';
import { JACSA2AIntegration, TRUST_POLICIES } from '../jacsnpm/a2a';

async function main(): Promise<void> {
  // -- Step 1: Create JACS agents (A and B) -----------------------------------
  console.log('Step 1 -- Create agents');
  const agentA = await JacsClient.ephemeral('ring-Ed25519');
  const agentB = await JacsClient.ephemeral('ring-Ed25519');

  console.log(`  Agent A (JACS) : ${agentA.agentId}`);
  console.log(`  Agent B (JACS) : ${agentB.agentId}`);
  console.log('  Agent C (plain): no JACS identity -- standard A2A only');

  // -- Step 2: Agent A signs a task artifact ----------------------------------
  console.log('\nStep 2 -- Agent A signs a task artifact');
  const taskPayload = {
    action: 'classify',
    input: 'Analyze quarterly revenue data',
    priority: 'high',
  };

  const signedTask = await agentA.signArtifact(taskPayload, 'task');
  console.log(`  Artifact ID : ${signedTask.jacsId}`);
  console.log(`  Type        : ${signedTask.jacsType}`);
  console.log(`  Signer      : ${(signedTask.jacsSignature as any)?.agentID?.substring(0, 12)}...`);

  // -- Step 3: Agent B verifies the artifact ----------------------------------
  console.log('\nStep 3 -- Agent B verifies the artifact from Agent A');
  const a2aB = new JACSA2AIntegration(agentB, TRUST_POLICIES.VERIFIED);
  const verifyResult = await a2aB.verifyWrappedArtifact(signedTask);

  console.log(`  Valid       : ${verifyResult.valid}`);
  console.log(`  Signer ID   : ${verifyResult.signerId?.substring(0, 12)}...`);
  console.log(`  Trust level : ${verifyResult.trustAssessment?.trustLevel}`);
  console.log(`  Allowed     : ${verifyResult.trustAssessment?.allowed}`);

  // -- Step 4: Agent B countersigns with chain of custody ---------------------
  console.log('\nStep 4 -- Agent B countersigns (chain of custody)');
  const resultPayload = {
    action: 'classify_result',
    output: { category: 'financial', confidence: 0.97 },
    parentTaskId: signedTask.jacsId,
  };

  const signedResult = await agentB.signArtifact(resultPayload, 'result', [signedTask]);
  console.log(`  Result ID   : ${signedResult.jacsId}`);
  console.log(`  Parents     : ${(signedResult.jacsParentSignatures as any[])?.length ?? 0}`);
  console.log(`  Signer      : ${(signedResult.jacsSignature as any)?.agentID?.substring(0, 12)}...`);

  // -- Step 5: Verify the full chain ------------------------------------------
  console.log('\nStep 5 -- Verify the full chain of custody');
  const a2aA = new JACSA2AIntegration(agentA, TRUST_POLICIES.VERIFIED);
  const chainResult = await a2aA.verifyWrappedArtifact(signedResult);

  console.log(`  Chain valid            : ${chainResult.valid}`);
  console.log(`  Parent sigs valid      : ${chainResult.parentSignaturesValid}`);
  console.log(`  Parent sigs count      : ${chainResult.parentSignaturesCount}`);

  // -- Step 6: Agent C (non-JACS) is blocked by trust policy ------------------
  console.log('\nStep 6 -- Agent C (plain A2A, no JACS) tries to join');

  // Simulate Agent C's agent card -- a standard A2A card with no JACS extension
  const agentCCard = {
    name: 'Agent C',
    description: 'A plain A2A agent without JACS',
    version: '1.0',
    protocolVersions: ['0.4.0'],
    skills: [{ id: 'chat', name: 'Chat', description: 'General chat', tags: ['chat'] }],
    capabilities: { streaming: true },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
  };

  // Agent B assesses Agent C under "verified" policy (default)
  const assessVerified = a2aB.assessRemoteAgent(agentCCard);
  console.log(`  Verified policy:`);
  console.log(`    JACS registered : ${assessVerified.jacsRegistered}`);
  console.log(`    Allowed         : ${assessVerified.allowed}`);
  console.log(`    Reason          : ${assessVerified.reason}`);

  // Under "strict" policy, even Agent A would be rejected without trust store entry
  const a2aStrict = new JACSA2AIntegration(agentB, TRUST_POLICIES.STRICT);
  const cardA = agentA.exportAgentCard();
  const assessStrict = a2aStrict.assessRemoteAgent(JSON.stringify(cardA));
  console.log(`  Strict policy (Agent A):`);
  console.log(`    JACS registered : ${assessStrict.jacsRegistered}`);
  console.log(`    In trust store  : ${assessStrict.inTrustStore}`);
  console.log(`    Allowed         : ${assessStrict.allowed}`);
  console.log(`    Reason          : ${assessStrict.reason}`);

  // -- Step 7: Export Agent Cards for A2A discovery ---------------------------
  console.log('\nStep 7 -- Export Agent Cards');
  const cardAgentA = agentA.exportAgentCard();
  const cardAgentB = agentB.exportAgentCard();

  console.log(`  Agent A card: name="${cardAgentA.name}", skills=${cardAgentA.skills?.length ?? 0}`);
  console.log(`  Agent B card: name="${cardAgentB.name}", skills=${cardAgentB.skills?.length ?? 0}`);
  console.log(`  Both declare JACS extension: ${
    cardAgentA.capabilities?.extensions?.some((e: any) => e.uri?.includes('jacs')) &&
    cardAgentB.capabilities?.extensions?.some((e: any) => e.uri?.includes('jacs'))
  }`);

  // -- Cleanup ----------------------------------------------------------------
  agentA.dispose();
  agentB.dispose();
  console.log('\nDone.');
}

main().catch(console.error);
