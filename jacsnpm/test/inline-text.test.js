/**
 * Inline text sign/verify tests (Task 11 — PRD §3.1, §4.1, C1, C2).
 *
 * Mocha + Chai style (matches the rest of jacsnpm/test/).
 *
 * Covers:
 *   - JacsSimpleAgent.signText / verifyText round trip (C2 byte preservation)
 *   - signature block YAML body shape (C3)
 *   - permissive (default) vs strict ({ strict: true }) missing-signature (C1)
 *   - sync variants
 *   - pq2025 algorithm coverage
 *   - duplicate-signer no-op
 */

const { expect } = require('chai');
const path = require('path');
const fs = require('fs');
const os = require('os');

let JacsSimpleAgent;
try {
  const bindings = require('../index.js');
  JacsSimpleAgent = bindings.JacsSimpleAgent;
} catch (_) {
  JacsSimpleAgent = null;
}

const SIG_BEGIN = '-----BEGIN JACS SIGNATURE-----';
const PGP_WRAPPER = '-----BEGIN JACS SIGNED MESSAGE-----';

describe('inline text signatures (JacsSimpleAgent)', function () {
  this.timeout(15000);

  before(function () {
    if (!JacsSimpleAgent) {
      console.log('  Skipping inline text tests - native binding not available');
      this.skip();
    }
  });

  let tmp;
  let agent;

  beforeEach(async function () {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-inline-'));
    agent = await JacsSimpleAgent.ephemeral('ed25519');
  });

  afterEach(function () {
    if (tmp && fs.existsSync(tmp)) {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('signText then verifyText returns status=signed', async function () {
    const p = path.join(tmp, 'r.md');
    fs.writeFileSync(p, 'hello\n');
    await agent.signText(p);
    const r = await agent.verifyText(p);
    expect(r.status).to.equal('signed');
    expect(r.signatures).to.have.lengthOf(1);
  });

  it('C2: signed file content is preserved (no PGP wrapper, prefix unchanged)', async function () {
    const p = path.join(tmp, 'c2.md');
    const original = '# Title\n\nHello\n';
    fs.writeFileSync(p, original);
    await agent.signText(p);

    const content = fs.readFileSync(p, 'utf8');
    expect(content.includes(PGP_WRAPPER)).to.equal(false);
    const prefixEnd = content.indexOf(SIG_BEGIN);
    expect(prefixEnd).to.be.greaterThan(0);
    const prefix = content.slice(0, prefixEnd).replace(/\n+$/, '\n');
    expect(prefix).to.equal(original);
  });

  it('C3: signature block body has the required YAML-ish keys', async function () {
    const p = path.join(tmp, 'c3.md');
    fs.writeFileSync(p, 'hi\n');
    await agent.signText(p);

    const content = fs.readFileSync(p, 'utf8');
    const start = content.indexOf(`${SIG_BEGIN}\n`) + `${SIG_BEGIN}\n`.length;
    const end = content.indexOf('\n-----END JACS SIGNATURE-----');
    expect(end).to.be.greaterThan(start);
    const body = content.slice(start, end);
    // Verify the four required fields are present without depending on a YAML parser
    // (we don't add js-yaml as a devDep; the same fields are checked in the Rust + Python
    // tests with a real YAML parser, this is a lightweight binding-side smoke check).
    for (const key of ['signer:', 'algorithm:', 'signedContentHash:', 'signature:']) {
      expect(body).to.contain(key);
    }
  });

  it('C1 permissive: verifyText on unsigned file returns status=missing_signature', async function () {
    const p = path.join(tmp, 'plain.md');
    fs.writeFileSync(p, 'hi\n');
    const r = await agent.verifyText(p);
    expect(r.status).to.equal('missing_signature');
  });

  it('C1 strict: verifyText on unsigned file rejects with /no JACS signature found/', async function () {
    const p = path.join(tmp, 'plain2.md');
    fs.writeFileSync(p, 'hi\n');
    let caught;
    try {
      await agent.verifyText(p, { strict: true });
    } catch (e) {
      caught = e;
    }
    expect(caught, 'expected strict verifyText to reject').to.exist;
    expect(caught.message).to.match(/no JACS signature found/);
  });

  it('C1 strict: verifyText on signed file still resolves with status=signed', async function () {
    const p = path.join(tmp, 'ok.md');
    fs.writeFileSync(p, 'ok\n');
    await agent.signText(p);
    const r = await agent.verifyText(p, { strict: true });
    expect(r.status).to.equal('signed');
  });

  it('signTextSync + verifyTextSync round trip (sync variants exist)', function () {
    const p = path.join(tmp, 's.md');
    fs.writeFileSync(p, 'z\n');
    agent.signTextSync(p);
    const r = agent.verifyTextSync(p);
    expect(r.status).to.equal('signed');
  });

  it('signTextFile / verifyTextFile parity-name aliases work the same as signText / verifyText', async function () {
    const p = path.join(tmp, 'parity.md');
    fs.writeFileSync(p, 'hi\n');
    await agent.signTextFile(p);
    const r = await agent.verifyTextFile(p);
    expect(r.status).to.equal('signed');
  });

  it('pq2025: signText + verifyText round trip', async function () {
    const pqAgent = await JacsSimpleAgent.ephemeral('pq2025');
    const p = path.join(tmp, 'pq.md');
    fs.writeFileSync(p, 'z\n');
    await pqAgent.signText(p);
    const r = await pqAgent.verifyText(p);
    expect(r.status).to.equal('signed');
    expect(r.signatures[0].algorithm).to.equal('pq2025');
  });

  it('signText duplicate signer is a byte-identical no-op', async function () {
    const p = path.join(tmp, 'dup.md');
    fs.writeFileSync(p, 'same\n');
    await agent.signText(p);
    const first = fs.readFileSync(p);
    await agent.signText(p);
    const second = fs.readFileSync(p);
    expect(second.equals(first)).to.equal(true);
    const matches = (second.toString().match(new RegExp(SIG_BEGIN, 'g')) || []).length;
    expect(matches).to.equal(1);
  });
});
