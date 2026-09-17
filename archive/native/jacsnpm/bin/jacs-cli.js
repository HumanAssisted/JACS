#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const installer = require('../scripts/install-cli.js');

function binaryPath() {
  return installer.getBinPath();
}

function runBinary(target, forwardedArgs) {
  if (!target || !installer.isSafeCachedBinary(target)) {
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

  if (args[0] === '--diagnose') {
    if (!target || !installer.isSafeCachedBinary(target)) {
      console.error('[jacs] CLI diagnostic failed: binary is absent or unsafe for this exact version/platform.');
      console.error('[jacs] Reinstall the package or run: cargo install jacs-cli');
      process.exit(1);
    }
    const probe = spawnSync(target, ['--version'], { encoding: 'utf8' });
    if (probe.error || probe.status !== 0) {
      console.error(`[jacs] CLI diagnostic failed: ${probe.error?.message || probe.stderr || `exit ${probe.status}`}`);
      process.exit(1);
    }
    process.stdout.write(`[jacs] CLI diagnostic OK: ${String(probe.stdout).trim()}\n`);
    process.exit(0);
  }

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
