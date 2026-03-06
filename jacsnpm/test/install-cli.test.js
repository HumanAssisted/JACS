/**
 * Tests for npm CLI install helpers.
 */

const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

function runNodeInline(jsCode) {
  return spawnSync(process.execPath, ['-e', jsCode], {
    cwd: ROOT,
    encoding: 'utf8',
  });
}

describe('CLI installer scripts', function () {
  this.timeout(15000);

  it('install-cli exits successfully on unsupported platforms', () => {
    const result = runNodeInline(
      "const os=require('os'); os.platform=()=> 'freebsd'; os.arch=()=> 'x64'; require('./scripts/install-cli.js');"
    );

    expect(result.status).to.equal(0);
    expect(result.stdout).to.include('No prebuilt CLI binary for freebsd-x64');
  });

  it('install-cli exits successfully when download fails', () => {
    const result = runNodeInline(
      "const os=require('os'); os.platform=()=> 'darwin'; os.arch=()=> 'arm64'; const https=require('https'); const {EventEmitter}=require('events'); https.get=()=>{const req=new EventEmitter(); process.nextTick(()=>req.emit('error', new Error('simulated-download-failure'))); return req;}; require('./scripts/install-cli.js');"
    );

    expect(result.status).to.equal(0);
    expect(result.stdout).to.include('Could not install CLI binary: simulated-download-failure');
  });

  it('bin shim forwards arguments to a local binary when present', () => {
    if (process.platform === 'win32') {
      this.skip();
    }

    const binName = process.platform === 'win32' ? 'jacs-cli.exe' : 'jacs-cli';
    const binPath = path.join(ROOT, 'bin', binName);

    fs.mkdirSync(path.dirname(binPath), { recursive: true });
    fs.writeFileSync(binPath, '#!/usr/bin/env bash\necho shim-ok \"$@\"\n', { mode: 0o755 });

    try {
      const result = spawnSync(process.execPath, ['bin/jacs-cli.js', 'hello', 'world'], {
        cwd: ROOT,
        encoding: 'utf8',
      });

      expect(result.status).to.equal(0);
      expect(result.stdout).to.include('shim-ok hello world');
    } finally {
      try {
        fs.unlinkSync(binPath);
      } catch (_) {
        // no-op cleanup
      }
    }
  });
});
