#!/usr/bin/env node
/**
 * Attestation hello world -- create and verify your first attestation.
 *
 * Demonstrates the core attestation flow: sign a document, attest WHY it is
 * trustworthy, then verify the attestation. Uses an ephemeral agent (in-memory
 * keys, no files on disk) for the simplest possible setup.
 *
 * Run:
 *     npm install @hai.ai/jacs
 *     node examples/attestation_hello_world.js
 */

const { JacsClient } = require('@hai.ai/jacs/client');

async function main() {
  // 1. Create an ephemeral agent (in-memory keys, no files)
  const client = await JacsClient.ephemeral('ring-Ed25519');

  // 2. Sign a document
  const signed = await client.signMessage({ action: 'approve', amount: 100 });
  console.log(`Signed document: ${signed.documentId}`);

  // 3. Attest WHY this document is trustworthy
  const attestation = await client.createAttestation({
    subject: {
      type: 'artifact',
      id: signed.documentId,
      digests: { sha256: 'from-signed-doc' },
    },
    claims: [{ name: 'reviewed_by', value: 'human', confidence: 0.95 }],
  });
  console.log(`Attestation created: ${attestation.documentId}`);

  // 4. Verify the attestation
  const result = await client.verifyAttestation(attestation.raw);
  console.log(`Valid: ${result.valid}`);
  console.log(`Signature OK: ${result.crypto.signature_valid}`);
  console.log(`Hash OK: ${result.crypto.hash_valid}`);

  // 5. Full verification (includes evidence checks)
  const fullResult = await client.verifyAttestation(attestation.raw, { full: true });
  console.log(`Full verify valid: ${fullResult.valid}`);
  console.log(`Evidence items: ${(fullResult.evidence || []).length}`);
}

main().catch(console.error);
