/**
 * Tests for npm CLI install helpers.
 */

const { expect } = require('chai');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const zlib = require('zlib');

const ROOT = path.join(__dirname, '..');

function runNodeInline(jsCode) {
  return spawnSync(process.execPath, ['-e', jsCode], {
    cwd: ROOT,
    encoding: 'utf8',
  });
}

function loadInstallerHelpers() {
  const previousAutorun = process.env.JACS_INSTALL_CLI_AUTORUN;
  const modulePath = path.join(ROOT, 'scripts', 'install-cli.js');
  delete require.cache[require.resolve(modulePath)];
  process.env.JACS_INSTALL_CLI_AUTORUN = '0';
  try {
    return require(modulePath);
  } finally {
    if (previousAutorun === undefined) {
      delete process.env.JACS_INSTALL_CLI_AUTORUN;
    } else {
      process.env.JACS_INSTALL_CLI_AUTORUN = previousAutorun;
    }
  }
}

describe('CLI release base', () => {
  it('accepts exact loopback staging and strips trailing slashes', () => {
    const installer = loadInstallerHelpers();
    expect(installer.getReleaseBase('0.11.4', {
      JACS_CLI_RELEASE_BASE_URL: 'http://127.0.0.1:43123/staged/',
    })).to.equal('http://127.0.0.1:43123/staged');
  });

  it('rejects an untrusted release base override', () => {
    const installer = loadInstallerHelpers();
    expect(() => installer.getReleaseBase('0.11.4', {
      JACS_CLI_RELEASE_BASE_URL: 'https://example.com/staged',
    })).to.throw(/release base/i);
  });
});

async function expectRejects(promise, pattern) {
  let error;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  expect(error).to.be.instanceOf(Error);
  expect(error.message).to.match(pattern);
}

function writeTarString(header, offset, length, value) {
  Buffer.from(value, 'utf8').copy(header, offset, 0, Math.min(length, Buffer.byteLength(value)));
}

function writeTarOctal(header, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, '0') + '\0';
  writeTarString(header, offset, length, encoded);
}

function tarMember(name, bytes = Buffer.alloc(0), type = '0', linkName = '') {
  const payload = Buffer.from(bytes);
  const header = Buffer.alloc(512);
  writeTarString(header, 0, 100, name);
  writeTarOctal(header, 100, 8, type === '5' ? 0o755 : 0o755);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, payload.length);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeTarString(header, 157, 100, linkName);
  writeTarString(header, 257, 6, 'ustar\0');
  writeTarString(header, 263, 2, '00');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  const checksumText = checksum.toString(8).padStart(6, '0');
  writeTarString(header, 148, 8, `${checksumText}\0 `);
  const padding = Buffer.alloc((512 - (payload.length % 512)) % 512);
  return Buffer.concat([header, payload, padding]);
}

function writeTarGz(filePath, members) {
  const tar = Buffer.concat([...members, Buffer.alloc(1024)]);
  fs.writeFileSync(filePath, zlib.gzipSync(tar));
}

function paxRecord(key, value) {
  const body = Buffer.concat([
    Buffer.from(`${key}=`),
    Buffer.isBuffer(value) ? value : Buffer.from(String(value)),
    Buffer.from('\n'),
  ]);
  let length = body.length + 2;
  while (true) {
    const prefix = Buffer.from(`${length} `);
    const next = prefix.length + body.length;
    if (next === length) return Buffer.concat([prefix, body]);
    length = next;
  }
}

function paxPayload(records) {
  return Buffer.concat(records.map(([key, value]) => paxRecord(key, value)));
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

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZip(entries) {
  const locals = [];
  const centrals = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const payload = Buffer.from(entry.bytes || Buffer.alloc(0));
    const declaredSize = entry.declaredSize === undefined ? payload.length : entry.declaredSize;
    const compressed = entry.directory ? Buffer.alloc(0) : zlib.deflateRawSync(payload);
    const checksum = entry.checksum === undefined ? crc32(payload) : entry.checksum;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(declaredSize, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(declaredSize, 24);
    central.writeUInt16LE(name.length, 28);
    const unixMode = entry.symlink ? 0o120777 : (entry.directory ? 0o040755 : 0o100755);
    central.writeUInt32LE((unixMode << 16) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centrals.push(central, name);
    localOffset += local.length + name.length + compressed.length;
  }
  const centralDirectory = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...locals, centralDirectory, eocd]);
}

describe('CLI installer scripts', function () {
  this.timeout(15000);

  it('packages the canonical Apache-2.0 license', () => {
    const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    const packagedLicense = path.join(ROOT, 'LICENSE');
    const canonicalLicense = path.join(ROOT, '..', 'LICENSE-APACHE');

    expect(packageJson.files).to.include('LICENSE');
    expect(fs.readFileSync(packagedLicense, 'utf8')).to.equal(
      fs.readFileSync(canonicalLicense, 'utf8'),
    );
  });

  it('package inventory cannot include a host-specific downloaded CLI', () => {
    const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    expect(packageJson.files).to.include('bin/jacs-cli.js');
    expect(packageJson.files).to.include('verification.js');
    expect(packageJson.files).to.include('verification.d.ts');
    expect(packageJson.files).to.include('verification.js.map');
    expect(packageJson.files).to.include('output-policy.js');
    expect(packageJson.files).to.include('output-policy.d.ts');
    expect(packageJson.files).to.include('output-policy.js.map');
    expect(packageJson.files).to.include('client.js.map');
    expect(packageJson.files).to.include('simple.js.map');
    expect(packageJson.files).not.to.include('bin/');
    expect(packageJson.files).not.to.include('bin/jacs-cli');
    expect(packageJson.files).not.to.include('bin/jacs-cli.exe');
  });

  it('packages every source map referenced by published JavaScript', () => {
    const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    const included = new Set(packageJson.files);

    for (const relativePath of packageJson.files.filter((entry) => entry.endsWith('.js'))) {
      const absolutePath = path.join(ROOT, relativePath);
      if (!fs.existsSync(absolutePath)) continue;
      const source = fs.readFileSync(absolutePath, 'utf8');
      const match = source.match(/sourceMappingURL=([^\s]+)/);
      if (!match) continue;

      const mapPath = path.normalize(path.join(path.dirname(relativePath), match[1]));
      expect(
        included.has(mapPath),
        `${relativePath} references ${mapPath}, but the map is absent from package.json files`,
      ).to.equal(true);
      expect(fs.existsSync(path.join(ROOT, mapPath))).to.equal(true);
    }
  });

  it('install-cli exits successfully on unsupported platforms', () => {
    const result = runNodeInline(
      "const os=require('os'); os.platform=()=> 'freebsd'; os.arch=()=> 'x64'; require('./scripts/install-cli.js').main();"
    );

    expect(result.status).to.equal(0);
    expect(result.stdout).to.include('No prebuilt CLI binary for freebsd-x64');
  });

  it('install-cli exits successfully when download fails', () => {
    const result = runNodeInline(
      "const os=require('os'); os.platform=()=> 'darwin'; os.arch=()=> 'arm64'; const https=require('https'); const {EventEmitter}=require('events'); https.get=()=>{const req=new EventEmitter(); req.setTimeout=()=>{}; req.destroy=()=>{}; process.nextTick(()=>req.emit('error', new Error('simulated-download-failure'))); return req;}; require('./scripts/install-cli.js').main();"
    );

    expect(result.status).to.equal(0);
    expect(result.stderr).to.include('WARNING: Could not install CLI binary');
    expect(result.stderr).to.include('simulated-download-failure');
  });

  it('install-cli helper rejects checksum mismatch', () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-install-cli-checksum-'));
    const assetName = 'jacs-cli-0.9.3-darwin-arm64.tar.gz';
    const archivePath = path.join(tmpDir, assetName);
    const checksumPath = path.join(tmpDir, `${assetName}.sha256`);

    try {
      fs.writeFileSync(archivePath, 'archive-bytes');
      const wrongDigest = crypto.createHash('sha256').update('different-bytes').digest('hex');
      fs.writeFileSync(checksumPath, `${wrongDigest}  ${assetName}\n`);

      expect(() => installer.verifyArchiveChecksum(archivePath, checksumPath, assetName))
        .to.throw(/Checksum mismatch/);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('install-cli helper rejects unsafe archive members', () => {
    const installer = loadInstallerHelpers();
    expect(() => installer.selectArchiveEntry(['../escape', 'nested/jacs-cli'], 'jacs-cli'))
      .to.throw(/Unsafe archive entry/);
    expect(() => installer.selectArchiveEntry(['/absolute/jacs-cli'], 'jacs-cli'))
      .to.throw(/Unsafe archive entry/);
  });

  it('install-cli helper rejects unsafe redirect targets', () => {
    const installer = loadInstallerHelpers();
    expect(installer.isAllowedDownloadUrl('https://github.com/HumanAssisted/JACS')).to.equal(true);
    expect(installer.isAllowedDownloadUrl('http://127.0.0.1:8123/test')).to.equal(true);
    expect(installer.isAllowedDownloadUrl('http://169.254.169.254/latest/meta-data')).to.equal(false);
    expect(installer.isAllowedDownloadUrl('https://127.0.0.1/private')).to.equal(false);
    expect(installer.isAllowedDownloadUrl('https://example.com/untrusted')).to.equal(false);
    expect(installer.isAllowedDownloadUrl('https://release-assets.githubusercontent.com/file')).to.equal(true);
    expect(installer.isAllowedDownloadUrl('file:///etc/passwd')).to.equal(false);
    expect(installer.isAllowedDownloadUrl('https://user:secret@example.com/file')).to.equal(false);
    expect(installer.isAllowedRedirect(
      'https://github.com/HumanAssisted/JACS/releases/file',
      'http://127.0.0.1:8123/private'
    )).to.equal(false);
    expect(installer.isAllowedRedirect(
      'http://127.0.0.1:8123/one',
      'http://127.0.0.1:8124/two'
    )).to.equal(false);
    expect(installer.isAllowedRedirect(
      'http://127.0.0.1:8123/one',
      'http://127.0.0.1:8123/two'
    )).to.equal(true);
  });

  it('accepts only same-origin IPv6 loopback redirects in local test mode', () => {
    const installer = loadInstallerHelpers();
    const origin = 'http://[::1]:43123/checksum';

    expect(installer.isAllowedDownloadUrl(origin)).to.equal(true);
    expect(installer.isAllowedRedirect(origin, 'http://[::1]:43123/archive')).to.equal(true);
    expect(installer.isAllowedRedirect(origin, 'http://[::1]:43124/archive')).to.equal(false);
    expect(installer.isAllowedRedirect(
      'https://github.com/HumanAssisted/JACS/releases',
      'http://[::1]:43123/archive'
    )).to.equal(false);
  });

  it('never includes URL credentials in unsafe-download diagnostics', async () => {
    const installer = loadInstallerHelpers();
    let error;
    try {
      await installer.follow('https://user:super-secret@github.com/archive');
    } catch (caught) {
      error = caught;
    }
    expect(error).to.be.instanceOf(Error);
    expect(error.message).not.to.include('user');
    expect(error.message).not.to.include('super-secret');
  });

  it('maps every advertised CLI platform to its release asset suffix', () => {
    const installer = loadInstallerHelpers();
    expect(installer.getPlatformKey('darwin', 'arm64')).to.equal('darwin-arm64');
    expect(installer.getPlatformKey('darwin', 'x64')).to.equal('darwin-x64');
    expect(installer.getPlatformKey('linux', 'x64')).to.equal('linux-x64');
    expect(installer.getPlatformKey('linux', 'arm64')).to.equal('linux-arm64');
    expect(installer.getPlatformKey('linux', 'x64', 'musl')).to.equal(null);
    expect(installer.getPlatformKey('win32', 'x64')).to.equal('windows-x64');
    expect(installer.getPlatformKey('win32', 'arm64')).to.equal(null);
  });

  it('isolates cached binaries by exact package version and platform', () => {
    const installer = loadInstallerHelpers();
    const linux = installer.getBinPath('linux', 'x64', 'glibc', '0.11.4');
    const darwin = installer.getBinPath('darwin', 'arm64', null, '0.11.4');
    const older = installer.getBinPath('linux', 'x64', 'glibc', '0.11.3');
    expect(linux).not.to.equal(darwin);
    expect(linux).not.to.equal(older);
    expect(linux).to.include(path.join('0.11.4', 'linux-x64'));
    expect(darwin).to.include(path.join('0.11.4', 'darwin-arm64'));
  });

  it('download enforces the streaming body limit', async () => {
    const installer = loadInstallerHelpers();
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      res.end(Buffer.alloc(4096, 7));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const dest = path.join(os.tmpdir(), `jacs-download-limit-${process.pid}-${Date.now()}`);
    try {
      let error;
      try {
        await installer.download(`http://127.0.0.1:${address.port}/archive`, dest, 1024, 1000);
      } catch (err) {
        error = err;
      }
      expect(error).to.be.instanceOf(Error);
      expect(error.message).to.include('byte limit');
      expect(fs.existsSync(dest)).to.equal(false);
    } finally {
      server.close();
      try { fs.rmSync(dest, { force: true }); } catch (_) {}
    }
  });

  it('rejects invalid, conflicting, and ambiguous response length headers', () => {
    const installer = loadInstallerHelpers();
    expect(() => installer.declaredContentLength({
      rawHeaders: ['Content-Length', '10x'],
      headers: {},
    })).to.throw(/Invalid Content-Length/);
    expect(() => installer.declaredContentLength({
      rawHeaders: ['Content-Length', '10', 'Content-Length', '11'],
      headers: {},
    })).to.throw(/Conflicting Content-Length/);
    expect(installer.declaredContentLength({
      rawHeaders: ['Content-Length', '10', 'Content-Length', '10'],
      headers: {},
    })).to.equal(10);
    expect(() => installer.validateResponseHeaders({
      rawHeaders: ['Transfer-Encoding', 'gzip, chunked'],
      headers: {},
    })).to.throw(/unsupported Transfer-Encoding/);
    expect(() => installer.validateResponseHeaders({
      rawHeaders: ['Content-Length', '10', 'Transfer-Encoding', 'chunked'],
      headers: {},
    })).to.throw(/both Content-Length and Transfer-Encoding/);
  });

  it('enforces one total deadline while a response body keeps trickling', async () => {
    const installer = loadInstallerHelpers();
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      const interval = setInterval(() => res.write(Buffer.from([1])), 10);
      res.once('close', () => clearInterval(interval));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const dest = path.join(os.tmpdir(), `jacs-download-deadline-${process.pid}-${Date.now()}`);
    try {
      await expectRejects(
        installer.download(`http://127.0.0.1:${address.port}/slow`, dest, 1024, 60),
        /timed out|deadline/i
      );
      expect(fs.existsSync(dest)).to.equal(false);
    } finally {
      server.close();
      try { fs.rmSync(dest, { force: true }); } catch (_) {}
    }
  });

  it('follow bounds redirect loops and request stalls', async () => {
    const installer = loadInstallerHelpers();
    const server = http.createServer((req, res) => {
      if (req.url === '/stall') return;
      res.writeHead(302, { Location: '/loop' });
      res.end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const base = `http://127.0.0.1:${address.port}`;
    try {
      let redirectError;
      try {
        await installer.follow(`${base}/loop`, 0, 1000);
      } catch (err) {
        redirectError = err;
      }
      expect(redirectError.message).to.include('redirects');

      let timeoutError;
      try {
        await installer.follow(`${base}/stall`, 0, 30);
      } catch (err) {
        timeoutError = err;
      }
      expect(timeoutError.message).to.include('timed out');
    } finally {
      server.close();
    }
  });

  it('install-cli helper selects the packaged binary entry', () => {
    const installer = loadInstallerHelpers();
    expect(installer.selectArchiveEntry(['release/jacs-cli'], 'jacs-cli'))
      .to.equal('release/jacs-cli');
  });

  it('validates an aggregate checksum before falling back to a per-asset digest', async () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-checksum-fallback-'));
    const dest = path.join(tmpDir, 'checksum');
    const asset = 'jacs-cli-0.11.4-linux-x64.tar.gz';
    const digest = crypto.createHash('sha256').update('asset').digest('hex');
    const calls = [];
    const fakeDownload = async (url, destination) => {
      calls.push(url);
      fs.writeFileSync(destination, calls.length === 1 ? `${digest}  another-asset\n` : `${digest}\n`);
    };
    try {
      const selected = await installer.downloadChecksum(
        'https://github.com/HumanAssisted/JACS/releases/download/cli/v0.11.4',
        `https://github.com/HumanAssisted/JACS/releases/download/cli/v0.11.4/${asset}`,
        dest,
        fakeDownload
      );
      expect(selected.endsWith('.sha256')).to.equal(true);
      expect(calls).to.have.length(2);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('rejects conflicting checksums without downloading an archive or fallback', async () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-checksum-conflict-'));
    const dest = path.join(tmpDir, 'checksum');
    const asset = 'jacs-cli-0.11.4-linux-x64.tar.gz';
    const one = '1'.repeat(64);
    const two = '2'.repeat(64);
    let calls = 0;
    const fakeDownload = async (_url, destination) => {
      calls += 1;
      fs.writeFileSync(destination, `${one}  ${asset}\n${two}  ${asset}\n`);
    };
    try {
      let error;
      try {
        await installer.downloadChecksum('https://github.com/release', `https://github.com/${asset}`, dest, fakeDownload);
      } catch (caught) {
        error = caught;
      }
      expect(error.message).to.include('Conflicting checksums');
      expect(calls).to.equal(1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('extracts a large tar binary without shelling out or buffering it as command output', async () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-tar-extract-'));
    const archive = path.join(tmpDir, 'cli.tar.gz');
    const destination = path.join(tmpDir, 'jacs-cli.out');
    const bytes = Buffer.alloc(2 * 1024 * 1024, 0x5a);
    writeTarGz(archive, [tarMember('release/jacs-cli', bytes)]);
    try {
      await installer.extractTarBinary(archive, destination, 'jacs-cli');
      expect(fs.readFileSync(destination)).to.deep.equal(bytes);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('extracts the bounded local PAX metadata emitted by macOS bsdtar', async () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-tar-pax-'));
    const archive = path.join(tmpDir, 'cli.tar.gz');
    const destination = path.join(tmpDir, 'jacs-cli.out');
    const binary = Buffer.from('macos-cli');
    const metadata = paxPayload([
      ['mtime', '1783684159.057300482'],
      ['LIBARCHIVE.xattr.com.apple.provenance', 'AQIAlc2VFQ5lCho'],
      ['SCHILY.xattr.com.apple.provenance', Buffer.from([1, 2, 0, 0xff, 0x0a, 0x1a])],
    ]);
    writeTarGz(archive, [
      tarMember('PaxHeader/jacs-cli', metadata, 'x'),
      tarMember('jacs-cli', binary),
    ]);
    try {
      await installer.extractTarBinary(archive, destination, 'jacs-cli');
      expect(fs.readFileSync(destination)).to.deep.equal(binary);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('rejects PAX path, link, size, malformed, global, and GNU overrides', async () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-tar-pax-reject-'));
    const cases = [
      ['path', [tarMember('PaxHeader/jacs-cli', paxPayload([['path', 'jacs-cli']]), 'x'), tarMember('safe', 'x')]],
      ['linkpath', [tarMember('PaxHeader/jacs-cli', paxPayload([['linkpath', '/bin/sh']]), 'x'), tarMember('jacs-cli', 'x')]],
      ['size', [tarMember('PaxHeader/jacs-cli', paxPayload([['size', '1']]), 'x'), tarMember('jacs-cli', 'x')]],
      ['malformed', [tarMember('PaxHeader/jacs-cli', Buffer.from('99 mtime=1\n'), 'x'), tarMember('jacs-cli', 'x')]],
      ['record-count', [
        tarMember('PaxHeader/jacs-cli', paxPayload(Array.from(
          { length: 65 },
          (_, index) => [`SCHILY.xattr.review${index}`, 'x']
        )), 'x'),
        tarMember('jacs-cli', 'x'),
      ]],
      ['global', [tarMember('GlobalHead', paxPayload([['mtime', '1']]), 'g'), tarMember('jacs-cli', 'x')]],
      ['gnu-longname', [tarMember('././@LongLink', Buffer.from('jacs-cli\0'), 'L'), tarMember('safe', 'x')]],
    ];
    try {
      for (const [label, members] of cases) {
        const archive = path.join(tmpDir, `${label}.tar.gz`);
        writeTarGz(archive, members);
        await expectRejects(
          installer.extractTarBinary(archive, path.join(tmpDir, `${label}.out`), 'jacs-cli'),
          /PAX|TAR member type|override|metadata/i
        );
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('rejects tar links, duplicate binary members, and excessive member counts', async () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-tar-reject-'));
    try {
      const linkArchive = path.join(tmpDir, 'link.tar.gz');
      writeTarGz(linkArchive, [tarMember('jacs-cli', Buffer.alloc(0), '2', '/bin/sh')]);
      await expectRejects(
        installer.extractTarBinary(linkArchive, path.join(tmpDir, 'link-out'), 'jacs-cli'),
        /type|link/i
      );

      const duplicateArchive = path.join(tmpDir, 'duplicate.tar.gz');
      writeTarGz(duplicateArchive, [tarMember('one/jacs-cli', 'one'), tarMember('two/jacs-cli', 'two')]);
      await expectRejects(
        installer.extractTarBinary(duplicateArchive, path.join(tmpDir, 'dup-out'), 'jacs-cli'),
        /multiple|duplicate/i
      );

      const membersArchive = path.join(tmpDir, 'members.tar.gz');
      writeTarGz(membersArchive, Array.from({ length: 1025 }, (_, index) => tarMember(`entry-${index}`, 'x')));
      await expectRejects(
        installer.extractTarBinary(membersArchive, path.join(tmpDir, 'member-out'), 'jacs-cli'),
        /member limit/i
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('extracts a bounded ZIP and rejects symlinks and duplicate binary entries', async () => {
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-zip-extract-'));
    try {
      const safe = path.join(tmpDir, 'safe.zip');
      const safeOut = path.join(tmpDir, 'safe.exe');
      fs.writeFileSync(safe, makeZip([{ name: 'release/jacs-cli.exe', bytes: Buffer.from('exe') }]));
      await installer.extractZipBinary(safe, safeOut, 'jacs-cli.exe');
      expect(fs.readFileSync(safeOut, 'utf8')).to.equal('exe');

      const corrupt = path.join(tmpDir, 'corrupt.zip');
      const corruptOut = path.join(tmpDir, 'corrupt.exe');
      fs.writeFileSync(corrupt, makeZip([{
        name: 'jacs-cli.exe',
        bytes: Buffer.from('exe'),
        checksum: 0,
      }]));
      await expectRejects(installer.extractZipBinary(corrupt, corruptOut, 'jacs-cli.exe'), /CRC/i);
      expect(fs.existsSync(corruptOut)).to.equal(false);

      const link = path.join(tmpDir, 'link.zip');
      fs.writeFileSync(link, makeZip([{ name: 'jacs-cli.exe', bytes: Buffer.from('target'), symlink: true }]));
      await expectRejects(
        installer.extractZipBinary(link, path.join(tmpDir, 'link.exe'), 'jacs-cli.exe'),
        /symlink|type/i
      );

      const duplicate = path.join(tmpDir, 'duplicate.zip');
      fs.writeFileSync(duplicate, makeZip([
        { name: 'one/jacs-cli.exe', bytes: Buffer.from('one') },
        { name: 'two/jacs-cli.exe', bytes: Buffer.from('two') },
      ]));
      await expectRejects(
        installer.extractZipBinary(duplicate, path.join(tmpDir, 'duplicate.exe'), 'jacs-cli.exe'),
        /multiple|duplicate/i
      );

      const expansion = path.join(tmpDir, 'expansion.zip');
      fs.writeFileSync(expansion, makeZip([{
        name: 'jacs-cli.exe',
        bytes: Buffer.from('tiny'),
        declaredSize: 300 * 1024 * 1024,
      }]));
      await expectRejects(
        installer.extractZipBinary(expansion, path.join(tmpDir, 'expansion.exe'), 'jacs-cli.exe'),
        /expansion limit/i
      );

      const excessiveMembers = path.join(tmpDir, 'members.zip');
      fs.writeFileSync(excessiveMembers, makeZip(Array.from(
        { length: 1025 },
        (_, index) => ({ name: `entry-${index}`, bytes: Buffer.from('x') })
      )));
      await expectRejects(
        installer.extractZipBinary(excessiveMembers, path.join(tmpDir, 'members.exe'), 'jacs-cli.exe'),
        /member limit/i
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('atomically refuses to replace an unsafe pre-existing install path', () => {
    if (process.platform === 'win32') this.skip();
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-install-no-replace-'));
    const source = path.join(tmpDir, 'source');
    const victim = path.join(tmpDir, 'victim');
    const destination = path.join(tmpDir, 'jacs-cli');
    fs.writeFileSync(source, 'safe-cli');
    fs.writeFileSync(victim, 'do-not-touch');
    fs.symlinkSync(victim, destination);
    try {
      expect(() => installer.installBinaryAtomically(source, destination, false))
        .to.throw(/already exists|existing|unsafe/i);
      expect(fs.readFileSync(victim, 'utf8')).to.equal('do-not-touch');
      expect(fs.lstatSync(destination).isSymbolicLink()).to.equal(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('installs an owner-only regular executable and refuses cache symlinks', () => {
    if (process.platform === 'win32') this.skip();
    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-safe-cache-'));
    const source = path.join(tmpDir, 'source');
    const destination = path.join(tmpDir, 'installed');
    fs.writeFileSync(source, 'safe-cli');
    try {
      installer.installBinaryAtomically(source, destination, false);
      const installed = fs.lstatSync(destination);
      expect(installed.isFile()).to.equal(true);
      expect(installed.mode & 0o777).to.equal(0o700);

      const cacheBase = path.join(fs.realpathSync(tmpDir), 'cache');
      const victim = path.join(tmpDir, 'victim-cache');
      fs.mkdirSync(cacheBase, { mode: 0o700 });
      fs.mkdirSync(victim, { mode: 0o700 });
      fs.symlinkSync(victim, path.join(cacheBase, 'jacs'));
      const previousCache = process.env.XDG_CACHE_HOME;
      process.env.XDG_CACHE_HOME = cacheBase;
      try {
        expect(() => installer.ensureSafeCacheDirectory(installer.getBinDir()))
          .to.throw(/symlink|unsafe/i);
      } finally {
        if (previousCache === undefined) delete process.env.XDG_CACHE_HOME;
        else process.env.XDG_CACHE_HOME = previousCache;
      }
      expect(fs.lstatSync(path.join(cacheBase, 'jacs')).isSymbolicLink()).to.equal(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('uses only Node built-ins for archive extraction', () => {
    const source = fs.readFileSync(path.join(ROOT, 'scripts', 'install-cli.js'), 'utf8');
    expect(source).not.to.match(/execFileSync|powershell|tar',\s*\[/i);
  });

  it('bin shim forwards arguments to a local binary when present', () => {
    if (process.platform === 'win32') {
      this.skip();
    }

    const installer = loadInstallerHelpers();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-shim-cache-'));
    const cacheBase = path.join(fs.realpathSync(tmpDir), 'cache');
    const previousCache = process.env.XDG_CACHE_HOME;
    process.env.XDG_CACHE_HOME = cacheBase;
    const binPath = installer.getBinPath();
    if (previousCache === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousCache;
    fs.mkdirSync(path.dirname(binPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(binPath, '#!/usr/bin/env bash\necho shim-ok \"$@\"\n', { mode: 0o755 });

    try {
      const result = spawnSync(process.execPath, ['bin/jacs-cli.js', 'hello', 'world'], {
        cwd: ROOT,
        encoding: 'utf8',
        env: { ...process.env, XDG_CACHE_HOME: cacheBase },
      });

      expect(result.status).to.equal(0);
      expect(result.stdout).to.include('shim-ok hello world');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('bin shim diagnostic fails clearly when the optional binary is absent', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-shim-diagnose-'));
    const cacheBase = path.join(fs.realpathSync(tmpDir), 'cache');

    const result = spawnSync(process.execPath, ['bin/jacs-cli.js', '--diagnose'], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, XDG_CACHE_HOME: cacheBase },
    });

    expect(result.status).to.equal(1);
    expect(result.stderr).to.include('CLI diagnostic failed: binary is absent or unsafe');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
