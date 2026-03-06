#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function binaryPath() {
  const binaryName = os.platform() === 'win32' ? 'jacs-cli.exe' : 'jacs-cli';
  return path.join(__dirname, binaryName);
}

function runBinary(target, forwardedArgs) {
  if (!fs.existsSync(target)) {
    return false;
  }

  const result = spawnSync(target, forwardedArgs, { stdio: 'inherit' });
  if (result.error) {
    if (result.error.code === 'ENOENT') {
      return false;
    }
    console.error(`[jacs] Failed to launch CLI binary: ${result.error.message}`);
    process.exit(1);
  }

  if (typeof result.status === 'number') {
    process.exit(result.status);
  }

  process.exit(1);
}

function runInstaller() {
  const installer = path.join(__dirname, '..', 'scripts', 'install-cli.js');
  spawnSync(process.execPath, [installer], { stdio: 'inherit' });
}

function main() {
  const args = process.argv.slice(2);
  const target = binaryPath();

  if (runBinary(target, args)) {
    return;
  }

  runInstaller();

  if (runBinary(target, args)) {
    return;
  }

  console.error('[jacs] CLI binary is not available for this platform/environment.');
  console.error('[jacs] The @hai.ai/jacs library APIs are still available.');
  process.exit(1);
}

main();
