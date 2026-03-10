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
const crypto = require('crypto');
const { execFileSync } = require('child_process');

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

function sha256File(filePath) {
  const hasher = crypto.createHash('sha256');
  hasher.update(fs.readFileSync(filePath));
  return hasher.digest('hex');
}

function readExpectedSha256(checksumPath, assetName) {
  const checksumText = fs.readFileSync(checksumPath, 'utf8').trim();
  if (!checksumText) {
    throw new Error(`Checksum file was empty: ${checksumPath}`);
  }

  const lines = checksumText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    // Format: "<sha256>  <filename>" (or optional "*" marker)
    let match = line.match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (match) {
      const digest = match[1].toLowerCase();
      const fileName = path.basename(match[2].trim());
      if (fileName === assetName) {
        return digest;
      }
    }

    // Format: "SHA256(<filename>)=<sha256>"
    match = line.match(/^SHA256\s*\((.+)\)\s*=\s*([a-fA-F0-9]{64})$/i);
    if (match) {
      const fileName = path.basename(match[1].trim());
      const digest = match[2].toLowerCase();
      if (fileName === assetName) {
        return digest;
      }
    }

    // Format: "<sha256>" (single-line digest file)
    match = line.match(/^([a-fA-F0-9]{64})$/);
    if (match && lines.length === 1) {
      return match[1].toLowerCase();
    }
  }

  throw new Error(`Checksum for ${assetName} not found in ${checksumPath}`);
}

function verifyArchiveChecksum(archivePath, checksumPath, assetName) {
  const expectedSha256 = readExpectedSha256(checksumPath, assetName);
  const actualSha256 = sha256File(archivePath);
  if (expectedSha256 !== actualSha256) {
    throw new Error(
      `Checksum mismatch for ${assetName}: expected ${expectedSha256}, got ${actualSha256}`
    );
  }
}

function validateArchiveEntry(entryName) {
  if (!entryName || !entryName.trim()) {
    return;
  }
  const normalized = entryName.replace(/\\/g, '/');
  if (normalized.startsWith('/')) {
    throw new Error(`Unsafe archive entry: ${entryName}`);
  }
  const segments = normalized.split('/').filter(Boolean);
  if (segments.includes('..')) {
    throw new Error(`Unsafe archive entry: ${entryName}`);
  }
}

function selectArchiveEntry(entries, binaryName) {
  for (const entry of entries) {
    validateArchiveEntry(entry);
  }

  const candidate = entries.find((entry) => path.posix.basename(entry) === binaryName);
  if (!candidate) {
    throw new Error(`Binary ${binaryName} not found in archive.`);
  }
  return candidate;
}

function extractTarBinary(archivePath, destPath, binaryName) {
  const listing = execFileSync('tar', ['-tzf', archivePath], { encoding: 'utf8' });
  const entries = listing.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const entry = selectArchiveEntry(entries, binaryName);
  const bytes = execFileSync('tar', ['-xzf', archivePath, '-O', entry], { encoding: 'buffer' });
  fs.writeFileSync(destPath, bytes);
}

function extractZipBinary(archivePath, destPath, binaryName) {
  const ps = (value) => String(value).replace(/'/g, "''");
  const script = [
    'Add-Type -AssemblyName System.IO.Compression.FileSystem',
    `$zip=[System.IO.Compression.ZipFile]::OpenRead('${ps(archivePath)}')`,
    'try {',
    '  foreach ($entry in $zip.Entries) {',
    '    $full = $entry.FullName',
    '    if ([string]::IsNullOrWhiteSpace($full)) { continue }',
    "    if ([System.IO.Path]::IsPathRooted($full) -or $full.Contains('../') -or $full.Contains('..\\\\')) {",
    '      throw \"Unsafe archive entry: $full\"',
    '    }',
    '  }',
    `  $entry = $zip.Entries | Where-Object { [System.IO.Path]::GetFileName($_.FullName) -eq '${ps(binaryName)}' } | Select-Object -First 1`,
    `  if ($null -eq $entry) { throw 'Binary ${ps(binaryName)} not found in archive.' }`,
    `  $out=[System.IO.File]::Open('${ps(destPath)}',[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write)`,
    '  try {',
    '    $in=$entry.Open()',
    '    try { $in.CopyTo($out) } finally { $in.Dispose() }',
    '  } finally { $out.Dispose() }',
    '} finally {',
    '  $zip.Dispose()',
    '}',
  ].join('\n');

  execFileSync('powershell', ['-NoProfile', '-Command', script], { stdio: 'pipe' });
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
  const checksumUrl = `${url}.sha256`;

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
  const checksumPath = path.join(tmpDir, `${assetName}.sha256`);

  try {
    console.log(`[jacs] Downloading checksum for pinned version ${VERSION} from ${checksumUrl}`);
    await download(checksumUrl, checksumPath);
    await download(url, archivePath);
    verifyArchiveChecksum(archivePath, checksumPath, assetName);

    fs.mkdirSync(binDir, { recursive: true });

    if (isWindows) {
      extractZipBinary(archivePath, binPath, 'jacs-cli.exe');
    } else {
      extractTarBinary(archivePath, binPath, 'jacs-cli');
      fs.chmodSync(binPath, 0o755);
    }

    console.log(`[jacs] CLI binary installed to ${binPath}`);
  } catch (err) {
    console.log(`[jacs] Could not install CLI binary: ${err.message}`);
    console.log('[jacs] The library works without the CLI. To install the CLI manually:');
    console.log(`[jacs]   cargo install jacs-cli`);
    console.log(`[jacs]   OR download from https://github.com/${REPO}/releases`);
    // Clean up partial install
    try { fs.rmSync(binPath, { force: true }); } catch (_) {}
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
  }
}

module.exports = {
  download,
  follow,
  getBinDir,
  getBinName,
  getPlatformKey,
  main,
  readExpectedSha256,
  selectArchiveEntry,
  sha256File,
  validateArchiveEntry,
  verifyArchiveChecksum,
};

if (process.env.JACS_INSTALL_CLI_AUTORUN !== '0') {
  main();
}
