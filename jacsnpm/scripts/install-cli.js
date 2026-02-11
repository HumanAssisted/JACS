#!/usr/bin/env node
/**
 * Optional CLI binary installer for @hai.ai/jacs.
 *
 * Downloads a prebuilt `jacs` CLI binary from GitHub Releases on postinstall.
 * If the download fails (network, unsupported platform, etc.) the library still
 * works -- the CLI is a convenience, not a requirement.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const VERSION = require('../package.json').version;
const REPO = 'HumanAssisted/JACS';

function getPlatformKey() {
  const platform = os.platform();
  const arch = os.arch();

  const map = {
    'darwin-arm64': 'darwin-arm64',
    'darwin-x64': 'darwin-x64',
    'linux-x64': 'linux-x64',
    'linux-arm64': 'linux-arm64',
    'win32-x64': 'windows-x64',
  };

  return map[`${platform}-${arch}`] || null;
}

function getBinDir() {
  return path.join(__dirname, '..', 'bin');
}

function getBinName() {
  return os.platform() === 'win32' ? 'jacs-cli.exe' : 'jacs-cli';
}

function follow(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, { headers: { 'User-Agent': `@hai.ai/jacs/${VERSION}` } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return follow(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      resolve(res);
    }).on('error', reject);
  });
}

async function download(url, dest) {
  const res = await follow(url);
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    res.pipe(file);
    file.on('finish', () => file.close(resolve));
    file.on('error', reject);
  });
}

async function main() {
  const key = getPlatformKey();
  if (!key) {
    console.log(`[jacs] No prebuilt CLI binary for ${os.platform()}-${os.arch()}. Library works without the CLI.`);
    return;
  }

  const isWindows = os.platform() === 'win32';
  const ext = isWindows ? 'zip' : 'tar.gz';
  const assetName = `jacs-cli-${VERSION}-${key}.${ext}`;
  const url = `https://github.com/${REPO}/releases/download/cli/v${VERSION}/${assetName}`;

  const binDir = getBinDir();
  const binPath = path.join(binDir, getBinName());

  // Skip if already installed
  if (fs.existsSync(binPath)) {
    console.log(`[jacs] CLI binary already installed at ${binPath}`);
    return;
  }

  console.log(`[jacs] Downloading CLI binary from ${url}`);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-cli-'));
  const archivePath = path.join(tmpDir, assetName);

  try {
    await download(url, archivePath);

    fs.mkdirSync(binDir, { recursive: true });

    if (isWindows) {
      // Use PowerShell to extract zip
      execSync(
        `powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${tmpDir}'"`,
        { stdio: 'pipe' }
      );
      fs.copyFileSync(path.join(tmpDir, 'jacs-cli.exe'), binPath);
    } else {
      execSync(`tar xzf "${archivePath}" -C "${tmpDir}"`, { stdio: 'pipe' });
      fs.copyFileSync(path.join(tmpDir, 'jacs-cli'), binPath);
      fs.chmodSync(binPath, 0o755);
    }

    console.log(`[jacs] CLI binary installed to ${binPath}`);
  } catch (err) {
    console.log(`[jacs] Could not install CLI binary: ${err.message}`);
    console.log('[jacs] The library works without the CLI. To install the CLI manually:');
    console.log(`[jacs]   cargo install jacs --features cli`);
    console.log(`[jacs]   OR download from https://github.com/${REPO}/releases`);
    // Clean up partial install
    try { fs.rmSync(binDir, { recursive: true, force: true }); } catch (_) {}
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
  }
}

main();
