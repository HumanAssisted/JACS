/**
 * JACS File Signing Example
 *
 * Demonstrates signing files with optional embedding.
 *
 * Usage:
 *   node sign-file.js <file-path> [--embed]
 */

import * as jacs from '@hai.ai/jacs/simple';
import fs from 'fs';

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: node sign-file.js <file-path> [--embed]');
    console.log('');
    console.log('Options:');
    console.log('  --embed    Embed file content in the signed document');
    process.exit(1);
  }

  const filePath = args[0];
  const embed = args.includes('--embed');

  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
  }

  // Load agent
  try {
    await jacs.load('./jacs.config.json');
  } catch (e) {
    console.error('No agent found. Run: jacs create --name "my-agent"');
    process.exit(1);
  }

  // Sign the file
  const signed = await jacs.signFile(filePath, embed);

  console.log('File signed successfully!');
  console.log(`  Document ID: ${signed.documentId}`);
  console.log(`  Agent ID: ${signed.agentId}`);
  console.log(`  Timestamp: ${signed.timestamp}`);
  console.log(`  Embedded: ${embed}`);

  // Save the signed document
  const outputPath = `${filePath}.jacs.json`;
  fs.writeFileSync(outputPath, signed.raw);
  console.log(`\nSaved to: ${outputPath}`);

  // Verify it
  const result = await jacs.verify(signed.raw);
  console.log(`\nVerification: ${result.valid ? 'VALID' : 'INVALID'}`);
}

main().catch(console.error);
