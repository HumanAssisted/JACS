#!/usr/bin/env node
/**
 * Optional, fail-closed CLI binary installer for @hai.ai/jacs.
 *
 * The native library does not depend on this download.  The installer accepts
 * only the exact release asset for this package version and platform, verifies
 * its pinned checksum, parses the archive with bounded Node built-ins, and
 * publishes the executable without following or replacing an existing path.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');
const { TextDecoder } = require('util');
const zlib = require('zlib');

const VERSION = require('../package.json').version;
const REPO = 'HumanAssisted/JACS';
const MAX_REDIRECTS = 5;
const CONNECT_TIMEOUT_MS = 15_000;
const TOTAL_TIMEOUT_MS = 60_000;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_CHECKSUM_BYTES = 1024 * 1024;
const MAX_EXTRACTED_BYTES = 256 * 1024 * 1024;
const MAX_BINARY_BYTES = 128 * 1024 * 1024;
const MAX_ARCHIVE_MEMBERS = 1024;
const MAX_TAR_METADATA_BYTES = 2 * 1024 * 1024;
const MAX_PAX_RECORDS = 64;
const MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_PATH_BYTES = 4096;
const MAX_REDIRECT_URL_BYTES = 4096;
const DOWNLOAD_CHUNK_BYTES = 64 * 1024;
const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_SIGNATURE = 0x02014b50;
const ZIP_LOCAL_SIGNATURE = 0x04034b50;
const ZIP_EOCD_BYTES = 22;
const ZIP_MAX_COMMENT_BYTES = 65535;
const ZIP_CENTRAL_HEADER_BYTES = 46;
const ZIP_LOCAL_HEADER_BYTES = 30;
const HTTPS_DOWNLOAD_HOSTS = Object.freeze(['github.com', '.githubusercontent.com']);
const HTTP_LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

class ConflictingChecksumError extends Error {}

function normalizedHostname(parsed) {
  return parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
}

function isSafeVersion(value) {
  return typeof value === 'string'
    && /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(value)
    && value.length <= 128;
}

function detectLinuxLibc() {
  if (process.platform !== 'linux') return null;
  try {
    if (fs.existsSync('/etc/alpine-release')) return 'musl';
  } catch (_) {
    // Continue with process-report and loader inspection.
  }
  try {
    const report = process.report && typeof process.report.getReport === 'function'
      ? process.report.getReport()
      : null;
    if (report && report.header && report.header.glibcVersionRuntime) return 'glibc';
    const sharedObjects = report && Array.isArray(report.sharedObjects) ? report.sharedObjects : [];
    if (sharedObjects.some((entry) => /(?:^|[/\\])(?:ld-)?musl[^/\\]*\.so/i.test(entry))) {
      return 'musl';
    }
  } catch (_) {
    // Process reports can be disabled by an embedding runtime.
  }
  try {
    const ldd = fs.readFileSync('/usr/bin/ldd', { encoding: 'utf8', flag: 'r' }).slice(0, 64 * 1024);
    if (/musl/i.test(ldd)) return 'musl';
    if (/glibc|gnu libc/i.test(ldd)) return 'glibc';
  } catch (_) {
    // Unknown fails closed on the real Linux host below.
  }
  return 'unknown';
}

function getPlatformKey(platform = os.platform(), arch = os.arch(), libcFamily = null) {
  if (platform === 'linux') {
    const detectedLibc = libcFamily
      || (platform === os.platform() ? detectLinuxLibc() : 'glibc');
    // There is no musl CLI release. Unknown libc is also rejected on the real
    // host so it can never silently receive the glibc executable.
    if (detectedLibc !== 'glibc') return null;
  }
  const map = {
    'darwin-arm64': 'darwin-arm64',
    'darwin-x64': 'darwin-x64',
    'linux-x64': 'linux-x64',
    'linux-arm64': 'linux-arm64',
    'win32-x64': 'windows-x64',
  };
  return map[`${platform}-${arch}`] || null;
}

function unsupportedPlatformMessage(platform = os.platform(), arch = os.arch()) {
  if (platform === 'linux') {
    const libc = detectLinuxLibc();
    if (libc === 'musl') {
      return 'No prebuilt CLI binary is published for Linux musl; use cargo install jacs-cli.';
    }
    if (libc !== 'glibc') {
      return 'Could not prove this Linux host uses glibc; refusing the glibc CLI asset. Use cargo install jacs-cli.';
    }
  }
  return `No prebuilt CLI binary for ${platform}-${arch}. Library works without the CLI.`;
}

function getCacheBase(platform = os.platform()) {
  if (process.env.XDG_CACHE_HOME) return path.resolve(process.env.XDG_CACHE_HOME);
  if (platform === 'darwin') return path.join(os.homedir(), 'Library', 'Caches');
  if (platform === 'win32') {
    return path.resolve(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'));
  }
  return path.join(os.homedir(), '.cache');
}

function getBinDir(
  platform = os.platform(),
  arch = os.arch(),
  libcFamily = null,
  version = VERSION
) {
  const key = getPlatformKey(platform, arch, libcFamily);
  if (!key || !isSafeVersion(version)) return null;
  return path.join(getCacheBase(platform), 'jacs', 'bin', version, key);
}

function getBinName(platform = os.platform()) {
  return platform === 'win32' ? 'jacs-cli.exe' : 'jacs-cli';
}

function getBinPath(
  platform = os.platform(),
  arch = os.arch(),
  libcFamily = null,
  version = VERSION
) {
  const directory = getBinDir(platform, arch, libcFamily, version);
  return directory ? path.join(directory, getBinName(platform)) : null;
}

function parseAllowedUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || Buffer.byteLength(rawUrl, 'utf8') > MAX_REDIRECT_URL_BYTES) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_) {
    return null;
  }
  if (parsed.username || parsed.password || parsed.hash || !parsed.hostname) return null;
  const host = normalizedHostname(parsed);
  if (parsed.protocol === 'https:') {
    if (parsed.port && parsed.port !== '443') return null;
    if (host === HTTPS_DOWNLOAD_HOSTS[0] || host.endsWith(HTTPS_DOWNLOAD_HOSTS[1])) return parsed;
    return null;
  }
  if (parsed.protocol === 'http:' && HTTP_LOOPBACK_HOSTS.has(host)) return parsed;
  return null;
}

function isAllowedDownloadUrl(rawUrl) {
  return parseAllowedUrl(rawUrl) !== null;
}

function getReleaseBase(version = VERSION, env = process.env) {
  const canonical = `https://github.com/${REPO}/releases/download/cli/v${version}`;
  const configured = env.JACS_CLI_RELEASE_BASE_URL;
  if (configured === undefined || configured === '') return canonical;
  const candidate = configured.replace(/\/+$/, '');
  if (!candidate || !isAllowedDownloadUrl(candidate)) {
    throw new Error('Refusing unsafe CLI release base override');
  }
  return candidate;
}

function normalizedOrigin(parsed) {
  const defaultPort = parsed.protocol === 'https:' ? '443' : '80';
  const host = normalizedHostname(parsed);
  const authorityHost = host.includes(':') ? `[${host}]` : host;
  return `${parsed.protocol}//${authorityHost}:${parsed.port || defaultPort}`;
}

function isAllowedRedirect(initialUrl, redirectUrl) {
  const initial = parseAllowedUrl(initialUrl);
  const redirected = parseAllowedUrl(redirectUrl);
  if (!initial || !redirected) return false;
  const initialLoopback = initial.protocol === 'http:'
    && HTTP_LOOPBACK_HOSTS.has(normalizedHostname(initial));
  if (initialLoopback) return normalizedOrigin(initial) === normalizedOrigin(redirected);
  return redirected.protocol === 'https:';
}

function remainingMs(deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new Error('CLI download timed out: total deadline exceeded');
  return remaining;
}

function requestOnce(rawUrl, deadline) {
  return new Promise((resolve, reject) => {
    const parsed = parseAllowedUrl(rawUrl);
    if (!parsed) {
      reject(new Error('Refusing unsafe CLI download URL'));
      return;
    }
    let timeout;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      reject(error);
    };
    let request;
    try {
      const transport = parsed.protocol === 'https:' ? https : http;
      request = transport.get(parsed, {
        agent: false,
        headers: {
          'Accept-Encoding': 'identity',
          'User-Agent': `@hai.ai/jacs/${VERSION}`,
        },
      }, (response) => {
        if (settled) {
          response.destroy();
          return;
        }
        settled = true;
        if (timeout) clearTimeout(timeout);
        resolve(response);
      });
      const remaining = remainingMs(deadline);
      timeout = setTimeout(() => {
        request.destroy(new Error('CLI download timed out: total deadline exceeded'));
      }, remaining);
      request.setTimeout(Math.min(CONNECT_TIMEOUT_MS, remaining), () => {
        request.destroy(new Error('CLI download connection timed out'));
      });
      request.on('error', fail);
    } catch (error) {
      if (request) request.destroy();
      fail(error);
    }
  });
}

async function followInternal(currentUrl, initialUrl, redirectCount, deadline) {
  if (!parseAllowedUrl(currentUrl)) throw new Error('Refusing unsafe CLI download URL');
  const response = await requestOnce(currentUrl, deadline);
  const status = response.statusCode || 0;
  if (status >= 300 && status < 400) {
    const location = response.headers.location;
    response.destroy();
    if (!location) throw new Error('CLI download redirect omitted Location');
    if (redirectCount >= MAX_REDIRECTS) {
      throw new Error(`CLI download exceeded ${MAX_REDIRECTS} redirects`);
    }
    let redirected;
    try {
      redirected = new URL(location, currentUrl).toString();
    } catch (_) {
      throw new Error('Invalid CLI download redirect');
    }
    if (!isAllowedRedirect(initialUrl, redirected)) {
      throw new Error('Refusing unsafe CLI download URL: redirect context change');
    }
    remainingMs(deadline);
    return followInternal(redirected, initialUrl, redirectCount + 1, deadline);
  }
  if (status !== 200) {
    response.destroy();
    throw new Error(`CLI download returned HTTP ${status}`);
  }
  return response;
}

function follow(url, redirectCount = 0, timeoutMs = TOTAL_TIMEOUT_MS) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return Promise.reject(new Error('CLI download timeout must be positive'));
  }
  return followInternal(url, url, redirectCount, Date.now() + timeoutMs);
}

function headerValues(response, name) {
  const values = [];
  const raw = Array.isArray(response.rawHeaders) ? response.rawHeaders : [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    if (String(raw[index]).toLowerCase() === name.toLowerCase()) values.push(String(raw[index + 1]));
  }
  if (values.length) return values;
  const value = response.headers ? response.headers[name.toLowerCase()] : undefined;
  if (Array.isArray(value)) return value.map(String);
  return value === undefined ? [] : [String(value)];
}

function declaredContentLength(response) {
  const parts = headerValues(response, 'content-length')
    .flatMap((value) => value.split(','))
    .map((value) => value.trim());
  if (!parts.length) return null;
  const lengths = parts.map((value) => {
    if (!/^[0-9]+$/.test(value) || value.length > 16) {
      throw new Error('Invalid Content-Length on CLI download');
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) throw new Error('Invalid Content-Length on CLI download');
    return parsed;
  });
  if (new Set(lengths).size !== 1) {
    throw new Error('Conflicting Content-Length values on CLI download');
  }
  return lengths[0];
}

function validateResponseHeaders(response) {
  const declared = declaredContentLength(response);
  const transferEncoding = headerValues(response, 'transfer-encoding');
  if (declared !== null && transferEncoding.length) {
    throw new Error('CLI download supplied both Content-Length and Transfer-Encoding');
  }
  const transferCodings = transferEncoding
    .flatMap((value) => value.split(','))
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  if (transferCodings.length
      && (transferCodings.length !== 1 || transferCodings[0] !== 'chunked')) {
    throw new Error('CLI download used an unsupported Transfer-Encoding');
  }
  const encodings = headerValues(response, 'content-encoding')
    .flatMap((value) => value.split(','))
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  if (encodings.some((encoding) => encoding !== 'identity')) {
    throw new Error('CLI download used an unsupported Content-Encoding');
  }
  return declared;
}

async function download(url, destination, maxBytes = MAX_ARCHIVE_BYTES, timeoutMs = TOTAL_TIMEOUT_MS) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0
      || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error('CLI download limits must be positive');
  }
  const deadline = Date.now() + timeoutMs;
  const response = await followInternal(url, url, 0, deadline);
  let fd = null;
  let received = 0;
  let settled = false;
  let timer;
  try {
    const declared = validateResponseHeaders(response);
    if (declared !== null && declared > maxBytes) {
      throw new Error(`CLI download exceeded ${maxBytes} byte limit`);
    }
    fd = fs.openSync(destination, fs.constants.O_CREAT | fs.constants.O_EXCL
      | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
    await new Promise((resolve, reject) => {
      const fail = (error) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        response.destroy();
        reject(error);
      };
      timer = setTimeout(() => fail(new Error('CLI download timed out: total deadline exceeded')), remainingMs(deadline));
      response.on('data', (chunk) => {
        if (settled) return;
        received += chunk.length;
        if (received > maxBytes || (declared !== null && received > declared)) {
          fail(new Error(`CLI download exceeded ${maxBytes} byte limit`));
          return;
        }
        try {
          let offset = 0;
          while (offset < chunk.length) offset += fs.writeSync(fd, chunk, offset, chunk.length - offset);
        } catch (error) {
          fail(error);
        }
      });
      response.once('aborted', () => fail(new Error('CLI download response was aborted')));
      response.once('error', fail);
      response.once('end', () => {
        if (settled) return;
        if (declared !== null && received !== declared) {
          fail(new Error('CLI download length did not match declared Content-Length'));
          return;
        }
        settled = true;
        if (timer) clearTimeout(timer);
        resolve();
      });
    });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = null;
  } catch (error) {
    response.destroy();
    if (fd !== null) {
      try { fs.closeSync(fd); } catch (_) {}
      fd = null;
    }
    try { fs.unlinkSync(destination); } catch (_) {}
    throw error;
  }
}

async function downloadChecksum(releaseBase, assetUrl, destination, downloadFn = download) {
  let assetName;
  try {
    assetName = path.posix.basename(new URL(assetUrl).pathname);
  } catch (_) {
    throw new Error('CLI asset URL did not contain a valid filename');
  }
  if (!assetName || !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(assetName)) {
    throw new Error('CLI asset URL did not contain a valid filename');
  }
  const candidates = [
    { url: `${releaseBase}/sha256sums.txt`, allowBareDigest: false },
    { url: `${assetUrl}.sha256`, allowBareDigest: true },
  ];
  const failures = [];
  for (const candidate of candidates) {
    try {
      await downloadFn(candidate.url, destination, MAX_CHECKSUM_BYTES, TOTAL_TIMEOUT_MS);
      readExpectedSha256(destination, assetName, candidate.allowBareDigest);
      return candidate.url;
    } catch (error) {
      try { fs.unlinkSync(destination); } catch (_) {}
      if (error instanceof ConflictingChecksumError) throw error;
      failures.push(error && error.message ? error.message : 'checksum validation failed');
    }
  }
  throw new Error(`Could not download a valid checksum manifest: ${failures.join('; ')}`);
}

function regularFileStat(filePath, maxBytes, description) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile()) throw new Error(`${description} must be a regular file`);
  if (stat.size < 0 || stat.size > maxBytes) throw new Error(`${description} exceeded ${maxBytes} byte limit`);
  return stat;
}

function sha256File(filePath) {
  regularFileStat(filePath, MAX_ARCHIVE_BYTES, 'CLI archive');
  const hasher = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  const buffer = Buffer.allocUnsafe(DOWNLOAD_CHUNK_BYTES);
  try {
    while (true) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!count) break;
      hasher.update(buffer.subarray(0, count));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hasher.digest('hex');
}

function readExpectedSha256(checksumPath, assetName, allowBareDigest = true) {
  const stat = regularFileStat(checksumPath, MAX_CHECKSUM_BYTES, 'CLI checksum file');
  if (stat.size === 0) throw new Error('Checksum file was empty');
  const checksumText = fs.readFileSync(checksumPath, 'utf8').trim();
  const lines = checksumText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const matching = [];
  for (const line of lines) {
    let match = line.match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (match && match[2].trim() === assetName) matching.push(match[1].toLowerCase());
    match = line.match(/^SHA256\s*\((.+)\)\s*=\s*([a-fA-F0-9]{64})$/i);
    if (match && match[1].trim() === assetName) matching.push(match[2].toLowerCase());
  }
  const unique = new Set(matching);
  if (unique.size > 1) throw new ConflictingChecksumError(`Conflicting checksums for ${assetName}`);
  if (unique.size === 1) return [...unique][0];
  if (allowBareDigest && lines.length === 1 && /^[a-fA-F0-9]{64}$/.test(lines[0])) {
    return lines[0].toLowerCase();
  }
  throw new Error(`Checksum for ${assetName} was not present in the manifest`);
}

function verifyArchiveChecksum(archivePath, checksumPath, assetName) {
  const expected = readExpectedSha256(checksumPath, assetName);
  const actual = sha256File(archivePath);
  if (expected !== actual) {
    throw new Error(`Checksum mismatch for ${assetName}: expected ${expected}, got ${actual}`);
  }
}

function safeArchiveName(value) {
  return JSON.stringify(String(value).replace(/[\x00-\x1f\x7f]/g, '?').slice(0, 160));
}

function validateArchiveEntry(entryName) {
  if (typeof entryName !== 'string' || !entryName || entryName.includes('\0')
      || Buffer.byteLength(entryName, 'utf8') > MAX_ARCHIVE_PATH_BYTES) {
    throw new Error('Unsafe archive entry path');
  }
  let normalized = entryName.replace(/\\/g, '/');
  if (normalized.startsWith('/') || normalized.startsWith('//') || /^[A-Za-z]:/.test(normalized)) {
    throw new Error(`Unsafe archive entry: ${safeArchiveName(entryName)}`);
  }
  const rawParts = normalized.split('/');
  if (rawParts.includes('..')) throw new Error(`Unsafe archive entry: ${safeArchiveName(entryName)}`);
  normalized = path.posix.normalize(normalized);
  if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../')) {
    throw new Error(`Unsafe archive entry: ${safeArchiveName(entryName)}`);
  }
  return normalized;
}

function selectArchiveEntry(entries, binaryName) {
  let selected = null;
  const seen = new Set();
  for (const entry of entries) {
    const normalized = validateArchiveEntry(entry);
    if (seen.has(normalized)) throw new Error(`Duplicate archive entry: ${safeArchiveName(normalized)}`);
    seen.add(normalized);
    if (path.posix.basename(normalized) === binaryName) {
      if (selected !== null) throw new Error(`Archive contained multiple ${binaryName} entries`);
      selected = entry;
    }
  }
  if (selected === null) throw new Error(`Binary ${binaryName} not found in archive`);
  return selected;
}

function exclusiveOutputFd(destination, mode = 0o600) {
  return fs.openSync(destination, fs.constants.O_CREAT | fs.constants.O_EXCL
    | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), mode);
}

function copyFileRange(sourcePath, destination, offset, size, mode = 0o600) {
  if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_BINARY_BYTES) {
    throw new Error(`CLI binary exceeded ${MAX_BINARY_BYTES} byte limit`);
  }
  const sourceFd = fs.openSync(sourcePath, 'r');
  let destinationFd;
  const buffer = Buffer.allocUnsafe(DOWNLOAD_CHUNK_BYTES);
  let copied = 0;
  try {
    destinationFd = exclusiveOutputFd(destination, mode);
    while (copied < size) {
      const wanted = Math.min(buffer.length, size - copied);
      const count = fs.readSync(sourceFd, buffer, 0, wanted, offset + copied);
      if (!count) throw new Error('CLI binary was truncated in archive');
      let written = 0;
      while (written < count) {
        written += fs.writeSync(destinationFd, buffer, written, count - written);
      }
      copied += count;
    }
    fs.fsyncSync(destinationFd);
  } catch (error) {
    try { fs.unlinkSync(destination); } catch (_) {}
    throw error;
  } finally {
    fs.closeSync(sourceFd);
    if (destinationFd !== undefined) fs.closeSync(destinationFd);
  }
}

async function decompressGzipBounded(archivePath, tarPath) {
  regularFileStat(archivePath, MAX_ARCHIVE_BYTES, 'CLI archive');
  const input = fs.createReadStream(archivePath, { highWaterMark: DOWNLOAD_CHUNK_BYTES });
  const gunzip = zlib.createGunzip();
  let expanded = 0;
  const limiter = new Transform({
    transform(chunk, _encoding, callback) {
      expanded += chunk.length;
      if (expanded > MAX_EXTRACTED_BYTES + MAX_TAR_METADATA_BYTES) {
        callback(new Error(`Archive exceeded ${MAX_EXTRACTED_BYTES} byte expansion limit`));
        return;
      }
      callback(null, chunk);
    },
  });
  const output = fs.createWriteStream(tarPath, { flags: 'wx', mode: 0o600 });
  try {
    await pipeline(input, gunzip, limiter, output);
  } catch (error) {
    try { fs.unlinkSync(tarPath); } catch (_) {}
    throw error;
  }
}

function decodeUtf8Field(buffer) {
  const nul = buffer.indexOf(0);
  const bytes = nul === -1 ? buffer : buffer.subarray(0, nul);
  try {
    return UTF8_DECODER.decode(bytes);
  } catch (_) {
    throw new Error('Archive entry path was not valid UTF-8');
  }
}

function parseTarOctal(buffer, fieldName) {
  if (buffer[0] & 0x80) throw new Error(`Unsupported base-256 TAR ${fieldName}`);
  const value = buffer.toString('ascii').replace(/\0.*$/, '').trim();
  if (!value) return 0;
  if (!/^[0-7]+$/.test(value)) throw new Error(`Invalid TAR ${fieldName}`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`Invalid TAR ${fieldName}`);
  return parsed;
}

function verifyTarHeaderChecksum(header) {
  const expected = parseTarOctal(header.subarray(148, 156), 'checksum');
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (actual !== expected) throw new Error('TAR header checksum mismatch');
}

function bufferIsZero(buffer) {
  for (const byte of buffer) if (byte !== 0) return false;
  return true;
}

function parseLocalPaxMetadata(payload) {
  if (!payload.length) throw new Error('Local PAX metadata was empty');
  const seen = new Set();
  let cursor = 0;
  let records = 0;
  while (cursor < payload.length) {
    records += 1;
    if (records > MAX_PAX_RECORDS) {
      throw new Error(`Local PAX metadata exceeded ${MAX_PAX_RECORDS} record limit`);
    }
    const space = payload.indexOf(0x20, cursor);
    if (space < 0 || space === cursor || space - cursor > 10) {
      throw new Error('Local PAX record length was malformed');
    }
    const lengthText = payload.subarray(cursor, space).toString('ascii');
    if (!/^[1-9][0-9]*$/.test(lengthText)) {
      throw new Error('Local PAX record length was malformed');
    }
    const length = Number(lengthText);
    const recordEnd = cursor + length;
    if (!Number.isSafeInteger(length) || length <= space - cursor + 3
        || recordEnd > payload.length || payload[recordEnd - 1] !== 0x0a) {
      throw new Error('Local PAX record exceeded its metadata bounds');
    }
    const valueStart = payload.indexOf(0x3d, space + 1);
    if (valueStart < 0 || valueStart >= recordEnd - 1) {
      throw new Error('Local PAX record omitted its key/value separator');
    }
    const keyBytes = payload.subarray(space + 1, valueStart);
    if (!keyBytes.length || [...keyBytes].some((byte) => byte > 0x7f)) {
      throw new Error('Local PAX metadata key was not ASCII');
    }
    const key = keyBytes.toString('ascii');
    if (!/^[A-Za-z0-9_.-]+$/.test(key)) throw new Error('Local PAX metadata key was invalid');
    if (seen.has(key)) throw new Error(`Duplicate local PAX metadata key: ${key}`);
    seen.add(key);

    const value = payload.subarray(valueStart + 1, recordEnd - 1);
    if (key === 'path' || key === 'linkpath' || key === 'size') {
      throw new Error(`Local PAX ${key} override is not allowed`);
    }
    if (key === 'mtime') {
      if (!value.length || [...value].some((byte) => byte > 0x7f)
          || !/^-?[0-9]+(?:\.[0-9]+)?$/.test(value.toString('ascii'))) {
        throw new Error('Local PAX mtime metadata was invalid');
      }
    } else if (!/^(?:LIBARCHIVE|SCHILY)\.xattr\.[A-Za-z0-9_.-]+$/.test(key)) {
      throw new Error(`Unsupported local PAX metadata key: ${key}`);
    }
    cursor = recordEnd;
  }
}

function scanTarArchive(tarPath, binaryName) {
  const stat = regularFileStat(
    tarPath,
    MAX_EXTRACTED_BYTES + MAX_TAR_METADATA_BYTES,
    'Expanded CLI archive'
  );
  const fd = fs.openSync(tarPath, 'r');
  const header = Buffer.alloc(512);
  const seen = new Set();
  let offset = 0;
  let members = 0;
  let totalPayload = 0;
  let metadataBytes = 0;
  let candidate = null;
  let terminated = false;
  let pendingLocalPax = false;
  try {
    while (offset + 512 <= stat.size) {
      const count = fs.readSync(fd, header, 0, 512, offset);
      if (count !== 512) throw new Error('TAR header was truncated');
      if (bufferIsZero(header)) {
        terminated = true;
        offset += 512;
        break;
      }
      verifyTarHeaderChecksum(header);
      members += 1;
      if (members > MAX_ARCHIVE_MEMBERS) {
        throw new Error(`Archive exceeded ${MAX_ARCHIVE_MEMBERS} member limit`);
      }
      const name = decodeUtf8Field(header.subarray(0, 100));
      const prefix = decodeUtf8Field(header.subarray(345, 500));
      const normalized = validateArchiveEntry(prefix ? `${prefix}/${name}` : name);
      metadataBytes += 512 + Buffer.byteLength(normalized, 'utf8');
      if (metadataBytes > MAX_TAR_METADATA_BYTES) {
        throw new Error(`Archive metadata exceeded ${MAX_TAR_METADATA_BYTES} byte limit`);
      }
      if (seen.has(normalized)) throw new Error(`Duplicate archive entry: ${safeArchiveName(normalized)}`);
      seen.add(normalized);
      const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
      const size = parseTarOctal(header.subarray(124, 136), 'member size');
      if (type !== '0' && type !== '5' && type !== 'x') {
        throw new Error(`Unsupported TAR member type for ${safeArchiveName(normalized)}`);
      }
      if (type === '5' && size !== 0) throw new Error('TAR directory member had payload bytes');
      const dataOffset = offset + 512;
      const paddedSize = Math.ceil(size / 512) * 512;
      const nextOffset = dataOffset + paddedSize;
      if (!Number.isSafeInteger(nextOffset) || nextOffset > stat.size) {
        throw new Error('TAR member exceeded archive bounds');
      }
      if (type === 'x') {
        if (pendingLocalPax) throw new Error('Consecutive local PAX metadata records are not supported');
        metadataBytes += size;
        if (metadataBytes > MAX_TAR_METADATA_BYTES) {
          throw new Error(`Archive metadata exceeded ${MAX_TAR_METADATA_BYTES} byte limit`);
        }
        parseLocalPaxMetadata(readExactly(fd, size, dataOffset, 'Local PAX metadata'));
        pendingLocalPax = true;
      } else {
        if (pendingLocalPax && type !== '0') {
          throw new Error('Local PAX metadata may only describe a regular file');
        }
        pendingLocalPax = false;
      }
      if (type === '0') {
        totalPayload += size;
        if (totalPayload > MAX_EXTRACTED_BYTES) {
          throw new Error(`Archive exceeded ${MAX_EXTRACTED_BYTES} byte expansion limit`);
        }
        if (path.posix.basename(normalized) === binaryName) {
          if (candidate !== null) throw new Error(`Archive contained multiple ${binaryName} entries`);
          if (size <= 0 || size > MAX_BINARY_BYTES) {
            throw new Error(`CLI binary exceeded ${MAX_BINARY_BYTES} byte limit`);
          }
          candidate = { offset: dataOffset, size };
        }
      }
      offset = nextOffset;
    }
    if (!terminated) throw new Error('TAR archive omitted its end marker');
    if (pendingLocalPax) throw new Error('Local PAX metadata did not precede a regular file');
    const tail = Buffer.alloc(DOWNLOAD_CHUNK_BYTES);
    while (offset < stat.size) {
      const count = fs.readSync(fd, tail, 0, Math.min(tail.length, stat.size - offset), offset);
      if (!count) break;
      if (!bufferIsZero(tail.subarray(0, count))) throw new Error('TAR archive contained data after its end marker');
      offset += count;
    }
  } finally {
    fs.closeSync(fd);
  }
  if (candidate === null) throw new Error(`Binary ${binaryName} not found in archive`);
  return candidate;
}

async function extractTarBinary(archivePath, destination, binaryName) {
  const tarPath = `${destination}.expanded-${process.pid}-${crypto.randomBytes(8).toString('hex')}`;
  try {
    await decompressGzipBounded(archivePath, tarPath);
    const candidate = scanTarArchive(tarPath, binaryName);
    copyFileRange(tarPath, destination, candidate.offset, candidate.size);
    return destination;
  } catch (error) {
    try { fs.unlinkSync(destination); } catch (_) {}
    throw error;
  } finally {
    try { fs.unlinkSync(tarPath); } catch (_) {}
  }
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let value = n;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    }
    table[n] = value >>> 0;
  }
  return table;
})();

function crc32Update(crc, buffer) {
  let value = crc;
  for (const byte of buffer) value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return value >>> 0;
}

function readExactly(fd, length, position, description) {
  const buffer = Buffer.alloc(length);
  let read = 0;
  while (read < length) {
    const count = fs.readSync(fd, buffer, read, length - read, position + read);
    if (!count) throw new Error(`${description} was truncated`);
    read += count;
  }
  return buffer;
}

function decodeZipName(bytes, utf8) {
  if (!utf8) {
    for (const byte of bytes) if (byte > 0x7f) throw new Error('Non-UTF-8 ZIP paths must be ASCII');
    return bytes.toString('ascii');
  }
  try {
    return UTF8_DECODER.decode(bytes);
  } catch (_) {
    throw new Error('ZIP entry path was not valid UTF-8');
  }
}

function findZipEocd(fd, archiveSize) {
  const tailSize = Math.min(archiveSize, ZIP_EOCD_BYTES + ZIP_MAX_COMMENT_BYTES);
  const tail = readExactly(fd, tailSize, archiveSize - tailSize, 'ZIP end record');
  for (let index = tail.length - ZIP_EOCD_BYTES; index >= 0; index -= 1) {
    if (tail.readUInt32LE(index) !== ZIP_EOCD_SIGNATURE) continue;
    const commentLength = tail.readUInt16LE(index + 20);
    if (index + ZIP_EOCD_BYTES + commentLength === tail.length) {
      return { offset: archiveSize - tailSize + index, bytes: tail.subarray(index, index + ZIP_EOCD_BYTES) };
    }
  }
  throw new Error('ZIP archive omitted a valid end-of-central-directory record');
}

function validateZipLocalEntry(fd, entry, centralDirectoryOffset) {
  const header = readExactly(fd, ZIP_LOCAL_HEADER_BYTES, entry.localOffset, 'ZIP local header');
  if (header.readUInt32LE(0) !== ZIP_LOCAL_SIGNATURE) throw new Error('ZIP local header signature was invalid');
  const flags = header.readUInt16LE(6);
  const compression = header.readUInt16LE(8);
  if (flags !== entry.flags || compression !== entry.compression) {
    throw new Error('ZIP local and central metadata disagreed');
  }
  const nameLength = header.readUInt16LE(26);
  const extraLength = header.readUInt16LE(28);
  const nameBytes = readExactly(fd, nameLength, entry.localOffset + ZIP_LOCAL_HEADER_BYTES, 'ZIP local name');
  const localName = validateArchiveEntry(decodeZipName(nameBytes, Boolean(flags & 0x0800)));
  if (localName !== entry.name) throw new Error('ZIP local and central filenames disagreed');
  if (!(flags & 0x0008)) {
    if (header.readUInt32LE(14) !== entry.crc
        || header.readUInt32LE(18) !== entry.compressedSize
        || header.readUInt32LE(22) !== entry.uncompressedSize) {
      throw new Error('ZIP local and central sizes disagreed');
    }
  }
  const dataOffset = entry.localOffset + ZIP_LOCAL_HEADER_BYTES + nameLength + extraLength;
  const dataEnd = dataOffset + entry.compressedSize;
  if (!Number.isSafeInteger(dataEnd) || dataEnd > centralDirectoryOffset) {
    throw new Error('ZIP member exceeded archive bounds');
  }
  entry.dataOffset = dataOffset;
  entry.dataEnd = dataEnd;
}

function scanZipArchive(archivePath, binaryName) {
  const stat = regularFileStat(archivePath, MAX_ARCHIVE_BYTES, 'CLI archive');
  const fd = fs.openSync(archivePath, 'r');
  let candidate = null;
  try {
    const eocd = findZipEocd(fd, stat.size);
    const record = eocd.bytes;
    const diskNumber = record.readUInt16LE(4);
    const centralDisk = record.readUInt16LE(6);
    const diskEntries = record.readUInt16LE(8);
    const totalEntries = record.readUInt16LE(10);
    const centralSize = record.readUInt32LE(12);
    const centralOffset = record.readUInt32LE(16);
    if (diskNumber !== 0 || centralDisk !== 0 || diskEntries !== totalEntries) {
      throw new Error('Multi-disk ZIP archives are not supported');
    }
    if (totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
      throw new Error('ZIP64 CLI archives are not supported');
    }
    if (totalEntries > MAX_ARCHIVE_MEMBERS) {
      throw new Error(`Archive exceeded ${MAX_ARCHIVE_MEMBERS} member limit`);
    }
    if (centralSize > MAX_ZIP_CENTRAL_DIRECTORY_BYTES) {
      throw new Error(`ZIP central directory exceeded ${MAX_ZIP_CENTRAL_DIRECTORY_BYTES} byte limit`);
    }
    if (centralOffset + centralSize !== eocd.offset) throw new Error('ZIP central directory bounds were inconsistent');
    const central = readExactly(fd, centralSize, centralOffset, 'ZIP central directory');
    const entries = [];
    const seen = new Set();
    let cursor = 0;
    let totalUncompressed = 0;
    while (cursor < central.length) {
      if (central.length - cursor < ZIP_CENTRAL_HEADER_BYTES
          || central.readUInt32LE(cursor) !== ZIP_CENTRAL_SIGNATURE) {
        throw new Error('ZIP central directory record was invalid');
      }
      const versionMadeBy = central.readUInt16LE(cursor + 4);
      const flags = central.readUInt16LE(cursor + 8);
      const compression = central.readUInt16LE(cursor + 10);
      const crc = central.readUInt32LE(cursor + 16);
      const compressedSize = central.readUInt32LE(cursor + 20);
      const uncompressedSize = central.readUInt32LE(cursor + 24);
      const nameLength = central.readUInt16LE(cursor + 28);
      const extraLength = central.readUInt16LE(cursor + 30);
      const commentLength = central.readUInt16LE(cursor + 32);
      const diskStart = central.readUInt16LE(cursor + 34);
      const externalAttributes = central.readUInt32LE(cursor + 38);
      const localOffset = central.readUInt32LE(cursor + 42);
      const recordLength = ZIP_CENTRAL_HEADER_BYTES + nameLength + extraLength + commentLength;
      if (recordLength > central.length - cursor) throw new Error('ZIP central directory record exceeded its bounds');
      if (diskStart !== 0) throw new Error('Multi-disk ZIP archives are not supported');
      if (flags & ~0x080e) throw new Error('ZIP member used unsupported or encrypted flags');
      if (compression !== 0 && compression !== 8) throw new Error('ZIP member used unsupported compression');
      if (compression === 0 && compressedSize !== uncompressedSize) {
        throw new Error('Stored ZIP member had inconsistent sizes');
      }
      const nameBytes = central.subarray(cursor + ZIP_CENTRAL_HEADER_BYTES,
        cursor + ZIP_CENTRAL_HEADER_BYTES + nameLength);
      const name = validateArchiveEntry(decodeZipName(nameBytes, Boolean(flags & 0x0800)));
      if (seen.has(name)) throw new Error(`Duplicate archive entry: ${safeArchiveName(name)}`);
      seen.add(name);
      const creator = versionMadeBy >>> 8;
      const unixMode = externalAttributes >>> 16;
      const unixType = unixMode & 0o170000;
      const isDirectory = name.endsWith('/') || Boolean(externalAttributes & 0x10);
      if (creator === 3) {
        if (unixType === 0o120000) throw new Error(`ZIP symlink is not allowed: ${safeArchiveName(name)}`);
        const expectedType = isDirectory ? 0o040000 : 0o100000;
        if (unixType !== 0 && unixType !== expectedType) {
          throw new Error(`Unsupported ZIP member type: ${safeArchiveName(name)}`);
        }
      } else if (externalAttributes & 0x08) {
        throw new Error(`Unsupported ZIP member type: ${safeArchiveName(name)}`);
      }
      if (isDirectory && (compressedSize !== 0 || uncompressedSize !== 0)) {
        throw new Error('ZIP directory member had payload bytes');
      }
      if (!isDirectory && uncompressedSize > 0 && compressedSize === 0) {
        throw new Error('ZIP member had inconsistent compressed size');
      }
      if (!isDirectory) {
        totalUncompressed += uncompressedSize;
        if (totalUncompressed > MAX_EXTRACTED_BYTES) {
          throw new Error(`Archive exceeded ${MAX_EXTRACTED_BYTES} byte expansion limit`);
        }
      }
      const entry = {
        name,
        flags,
        compression,
        crc,
        compressedSize,
        uncompressedSize,
        localOffset,
        isDirectory,
      };
      validateZipLocalEntry(fd, entry, centralOffset);
      entries.push(entry);
      if (!isDirectory && path.posix.basename(name) === binaryName) {
        if (candidate !== null) throw new Error(`Archive contained multiple ${binaryName} entries`);
        if (uncompressedSize <= 0 || uncompressedSize > MAX_BINARY_BYTES) {
          throw new Error(`CLI binary exceeded ${MAX_BINARY_BYTES} byte limit`);
        }
        candidate = entry;
      }
      cursor += recordLength;
    }
    if (entries.length !== totalEntries) throw new Error('ZIP member count did not match its directory');
    const intervals = entries.map((entry) => [entry.localOffset, entry.dataEnd]).sort((a, b) => a[0] - b[0]);
    for (let index = 1; index < intervals.length; index += 1) {
      if (intervals[index][0] < intervals[index - 1][1]) throw new Error('ZIP local members overlapped');
    }
  } finally {
    fs.closeSync(fd);
  }
  if (candidate === null) throw new Error(`Binary ${binaryName} not found in archive`);
  return candidate;
}

async function extractZipBinary(archivePath, destination, binaryName) {
  const candidate = scanZipArchive(archivePath, binaryName);
  let count = 0;
  let crc = 0xffffffff;
  const verifier = new Transform({
    transform(chunk, _encoding, callback) {
      count += chunk.length;
      if (count > candidate.uncompressedSize || count > MAX_BINARY_BYTES) {
        callback(new Error(`CLI binary exceeded ${MAX_BINARY_BYTES} byte limit`));
        return;
      }
      crc = crc32Update(crc, chunk);
      callback(null, chunk);
    },
  });
  const input = fs.createReadStream(archivePath, {
    start: candidate.dataOffset,
    end: candidate.dataEnd - 1,
    highWaterMark: DOWNLOAD_CHUNK_BYTES,
  });
  const output = fs.createWriteStream(destination, { flags: 'wx', mode: 0o600 });
  const inflater = candidate.compression === 8 ? zlib.createInflateRaw() : null;
  try {
    if (inflater) await pipeline(input, inflater, verifier, output);
    else await pipeline(input, verifier, output);
    if (count !== candidate.uncompressedSize) throw new Error('CLI binary size did not match ZIP metadata');
    if (((crc ^ 0xffffffff) >>> 0) !== candidate.crc) throw new Error('CLI binary CRC did not match ZIP metadata');
    if (inflater && inflater.bytesWritten !== candidate.compressedSize) {
      throw new Error('CLI ZIP member contained trailing compressed data');
    }
    return destination;
  } catch (error) {
    try { fs.unlinkSync(destination); } catch (_) {}
    throw error;
  }
}

function lstatOrNull(filePath) {
  try {
    return fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
}

function ownedByCurrentUser(stat) {
  return typeof process.geteuid !== 'function' || stat.uid === process.geteuid();
}

function isSafeInstallDirectory(directory) {
  const stat = lstatOrNull(directory);
  if (!stat || !stat.isDirectory() || !ownedByCurrentUser(stat)) return false;
  if (process.platform === 'win32') return true;
  return (stat.mode & 0o022) === 0;
}

function walkSafeCacheDirectory(directory, createMissing) {
  const absolute = path.resolve(directory);
  const parsed = path.parse(absolute);
  const components = absolute.slice(parsed.root.length).split(path.sep).filter(Boolean);
  const base = path.resolve(getCacheBase());
  const relativeToBase = path.relative(base, absolute);
  if (relativeToBase === '..' || relativeToBase.startsWith(`..${path.sep}`)
      || path.isAbsolute(relativeToBase)) {
    throw new Error('Refusing CLI cache path outside the configured cache root');
  }
  const baseParent = path.dirname(base);
  let current = parsed.root;
  let baseReached = current === base;
  for (const component of components) {
    current = path.join(current, component);
    let stat = lstatOrNull(current);
    if (!stat) {
      if (!createMissing) throw new Error('CLI cache directory does not exist');
      const parentStat = fs.lstatSync(path.dirname(current));
      if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
        throw new Error('Refusing unsafe CLI cache parent');
      }
      if (current === base && process.platform !== 'win32' && (parentStat.mode & 0o022)) {
        throw new Error('Refusing CLI cache under a group/world-writable parent');
      }
      fs.mkdirSync(current, { mode: 0o700 });
      stat = fs.lstatSync(current);
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error('Refusing symlink or non-directory in CLI cache path');
    }
    if (current === base) baseReached = true;
    if (baseReached && (!ownedByCurrentUser(stat)
        || (process.platform !== 'win32' && (stat.mode & 0o022)))) {
      throw new Error('Refusing unsafe CLI cache directory');
    }
    if (!baseReached && current === baseParent && process.platform !== 'win32'
        && (stat.mode & 0o022)) {
      throw new Error('Refusing CLI cache under a group/world-writable parent');
    }
  }
  if (!isSafeInstallDirectory(absolute)) throw new Error('Refusing unsafe CLI cache directory');
}

function ensureSafeCacheDirectory(directory) {
  walkSafeCacheDirectory(directory, true);
}

function validateExistingCacheDirectory(directory) {
  walkSafeCacheDirectory(directory, false);
}

function isSafeInstalledBinary(filePath, isWindows = os.platform() === 'win32') {
  const stat = lstatOrNull(filePath);
  if (!stat || !stat.isFile() || !ownedByCurrentUser(stat)
      || stat.size <= 0 || stat.size > MAX_BINARY_BYTES) return false;
  if (isWindows) return true;
  return (stat.mode & 0o022) === 0 && Boolean(stat.mode & 0o100);
}

function isSafeCachedBinary(filePath = getBinPath(), isWindows = os.platform() === 'win32') {
  if (!filePath || path.resolve(filePath) !== path.resolve(getBinPath() || '')) return false;
  try {
    validateExistingCacheDirectory(path.dirname(filePath));
  } catch (_) {
    return false;
  }
  return isSafeInstalledBinary(filePath, isWindows);
}

function installBinaryAtomically(source, destination, isWindows) {
  const sourceStat = regularFileStat(source, MAX_BINARY_BYTES, 'Extracted CLI binary');
  if (sourceStat.size <= 0) throw new Error('Extracted CLI binary was empty');
  const directory = path.dirname(destination);
  if (!isSafeInstallDirectory(directory)) throw new Error('Refusing unsafe CLI install directory');
  if (lstatOrNull(destination)) throw new Error('Refusing to replace an existing CLI install path');
  const temporary = path.join(directory,
    `.${path.basename(destination)}.install-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
  const sourceFd = fs.openSync(source, 'r');
  let destinationFd;
  const buffer = Buffer.allocUnsafe(DOWNLOAD_CHUNK_BYTES);
  let copied = 0;
  try {
    destinationFd = exclusiveOutputFd(temporary, isWindows ? 0o600 : 0o700);
    while (copied < sourceStat.size) {
      const count = fs.readSync(sourceFd, buffer, 0,
        Math.min(buffer.length, sourceStat.size - copied), copied);
      if (!count) throw new Error('Extracted CLI binary was truncated');
      let written = 0;
      while (written < count) written += fs.writeSync(destinationFd, buffer, written, count - written);
      copied += count;
    }
    fs.fsyncSync(destinationFd);
    fs.closeSync(destinationFd);
    destinationFd = undefined;
    if (!isWindows) fs.chmodSync(temporary, 0o700);
    // link(2) provides the no-replace atomic publication that rename(2) lacks.
    // The temporary and destination are in the same package directory.
    fs.linkSync(temporary, destination);
    try {
      const directoryFd = fs.openSync(directory, 'r');
      try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
    } catch (_) {
      // Directory fsync is unavailable on some supported Windows/filesystems.
    }
  } finally {
    fs.closeSync(sourceFd);
    if (destinationFd !== undefined) {
      try { fs.closeSync(destinationFd); } catch (_) {}
    }
    try { fs.unlinkSync(temporary); } catch (_) {}
  }
}

async function main() {
  if (!isSafeVersion(VERSION)) {
    console.warn('[jacs] WARNING: Refusing unsafe package version metadata.');
    return;
  }
  const platform = os.platform();
  const key = getPlatformKey(platform, os.arch());
  if (!key) {
    console.log(`[jacs] ${unsupportedPlatformMessage(platform, os.arch())}`);
    return;
  }
  const isWindows = platform === 'win32';
  const extension = isWindows ? 'zip' : 'tar.gz';
  const assetName = `jacs-cli-${VERSION}-${key}.${extension}`;
  let releaseBase;
  try {
    releaseBase = getReleaseBase(VERSION);
  } catch (error) {
    console.warn(`[jacs] WARNING: ${error.message}`);
    return;
  }
  const assetUrl = `${releaseBase}/${assetName}`;
  const binDir = getBinDir(platform, os.arch());
  const binPath = getBinPath(platform, os.arch());
  const existing = lstatOrNull(binPath);
  if (existing) {
    if (isSafeCachedBinary(binPath, isWindows)) {
      console.log(`[jacs] CLI binary already installed at ${binPath}`);
    } else {
      console.warn('[jacs] WARNING: Refusing unsafe pre-existing CLI install path.');
    }
    return;
  }
  try {
    ensureSafeCacheDirectory(binDir);
  } catch (error) {
    console.warn(`[jacs] WARNING: Could not create a safe CLI cache: ${error.message}`);
    return;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-cli-'));
  try { fs.chmodSync(tmpDir, 0o700); } catch (_) {}
  const archivePath = path.join(tmpDir, assetName);
  const checksumPath = path.join(tmpDir, `${assetName}.sha256`);
  const extractedPath = path.join(tmpDir, getBinName(platform));
  try {
    const checksumUrl = await downloadChecksum(releaseBase, assetUrl, checksumPath);
    console.log(`[jacs] Downloaded and validated checksum for pinned version ${VERSION} from ${checksumUrl}`);
    console.log(`[jacs] Downloading CLI binary from ${assetUrl}`);
    await download(assetUrl, archivePath, MAX_ARCHIVE_BYTES, TOTAL_TIMEOUT_MS);
    verifyArchiveChecksum(archivePath, checksumPath, assetName);
    if (isWindows) await extractZipBinary(archivePath, extractedPath, 'jacs-cli.exe');
    else await extractTarBinary(archivePath, extractedPath, 'jacs-cli');
    installBinaryAtomically(extractedPath, binPath, isWindows);
    console.log(`[jacs] CLI binary installed to ${binPath}`);
  } catch (error) {
    console.warn(`[jacs] WARNING: Could not install CLI binary: ${error.message}`);
    console.warn('[jacs] The library works without the CLI. Diagnose with: jacs-cli --diagnose');
    console.warn('[jacs] To install the CLI manually:');
    console.warn('[jacs]   cargo install jacs-cli');
    console.warn(`[jacs]   OR download from https://github.com/${REPO}/releases`);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
  }
}

module.exports = {
  ConflictingChecksumError,
  declaredContentLength,
  detectLinuxLibc,
  download,
  downloadChecksum,
  extractTarBinary,
  extractZipBinary,
  follow,
  getBinDir,
  getBinName,
  getBinPath,
  getPlatformKey,
  getReleaseBase,
  installBinaryAtomically,
  isAllowedDownloadUrl,
  isAllowedRedirect,
  isSafeInstallDirectory,
  isSafeCachedBinary,
  isSafeInstalledBinary,
  isSafeVersion,
  ensureSafeCacheDirectory,
  validateExistingCacheDirectory,
  main,
  readExpectedSha256,
  scanTarArchive,
  scanZipArchive,
  selectArchiveEntry,
  sha256File,
  validateArchiveEntry,
  validateResponseHeaders,
  verifyArchiveChecksum,
};

if (require.main === module && process.env.JACS_INSTALL_CLI_AUTORUN !== '0') {
  main().catch((error) => {
    console.warn(`[jacs] WARNING: Could not install CLI binary: ${error.message}`);
  });
}
