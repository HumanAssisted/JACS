/**
 * Image sign / verify / extract tests (Task 11 — PRD §3.2, §4.2, C1).
 *
 * Mocha + Chai style. Uses tiny committed unsigned PNG/JPEG/WebP fixtures
 * under jacsnpm/test/fixtures/images/. Each test copies one into a temp dir
 * to keep the originals untouched.
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

const FIXTURES_DIR = path.resolve(__dirname, 'fixtures/images');
const FIXTURES = {
  png: path.join(FIXTURES_DIR, 'unsigned_16x16.png'),
  jpeg: path.join(FIXTURES_DIR, 'unsigned_16x16.jpg'),
  webp: path.join(FIXTURES_DIR, 'unsigned_16x16.webp'),
};

const FORMAT_PAIRS = [
  ['png', '.png', 'png'],
  ['jpeg', '.jpg', 'jpeg'],
  ['webp', '.webp', 'webp'],
];

describe('image signatures (JacsSimpleAgent)', function () {
  this.timeout(30000);

  before(function () {
    if (!JacsSimpleAgent) {
      console.log('  Skipping image signature tests - native binding not available');
      this.skip();
    }
    for (const [fmt, , ] of FORMAT_PAIRS) {
      if (!fs.existsSync(FIXTURES[fmt])) {
        console.log(`  Missing fixture for ${fmt}: ${FIXTURES[fmt]}`);
        this.skip();
        return;
      }
    }
  });

  let tmp;
  let agent;

  beforeEach(async function () {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-img-'));
    agent = await JacsSimpleAgent.ephemeral('ed25519');
  });

  afterEach(function () {
    if (tmp && fs.existsSync(tmp)) {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  function copyFixture(fmt, basename) {
    const dest = path.join(tmp, basename);
    fs.copyFileSync(FIXTURES[fmt], dest);
    return dest;
  }

  // ---------------------------------------------------------------------
  // Round trips per format.
  // ---------------------------------------------------------------------

  for (const [fmt, ext, expectedFmt] of FORMAT_PAIRS) {
    it(`signImage + verifyImage round trip (${fmt})`, async function () {
      const src = copyFixture(fmt, `in${ext}`);
      const dst = path.join(tmp, `out${ext}`);
      const result = await agent.signImage(src, dst);
      expect(result).to.have.property('format', expectedFmt);

      const verify = await agent.verifyImage(dst);
      expect(verify.status).to.equal('valid');
    });
  }

  // ---------------------------------------------------------------------
  // C1 permissive vs strict per format.
  // ---------------------------------------------------------------------

  for (const [fmt, ext] of FORMAT_PAIRS) {
    it(`C1 permissive: verifyImage on unsigned ${fmt} returns missing_signature status`, async function () {
      const src = copyFixture(fmt, `plain${ext}`);
      const r = await agent.verifyImage(src);
      expect(r.status).to.equal('missing_signature');
    });

    it(`C1 strict: verifyImage on unsigned ${fmt} rejects /no JACS signature found/`, async function () {
      const src = copyFixture(fmt, `plain_strict${ext}`);
      let caught;
      try {
        await agent.verifyImage(src, { strict: true });
      } catch (e) {
        caught = e;
      }
      expect(caught, 'expected strict verifyImage to reject').to.exist;
      expect(caught.message).to.match(/no JACS signature found/);
    });
  }

  // ---------------------------------------------------------------------
  // extract_media_signature (PRD §3.2).
  // ---------------------------------------------------------------------

  it('extractMediaSignature on signed PNG returns a JSON-shaped string by default', async function () {
    const src = copyFixture('png', 'in.png');
    const dst = path.join(tmp, 'out.png');
    await agent.signImage(src, dst);

    const payload = await agent.extractMediaSignature(dst);
    expect(payload).to.be.a('string');
    expect(payload.trim().startsWith('{')).to.equal(true, 'default extract should be decoded JSON');
  });

  it('extractMediaSignature on unsigned input returns null (default mode)', async function () {
    const src = copyFixture('png', 'plain.png');
    const payload = await agent.extractMediaSignature(src);
    expect(payload).to.equal(null);
  });

  it('extractMediaSignature on unsigned input returns null (rawPayload: true)', async function () {
    const src = copyFixture('png', 'plain.png');
    const payload = await agent.extractMediaSignature(src, { rawPayload: true });
    expect(payload).to.equal(null);
  });

  it('extractMediaSignature with { rawPayload: true } returns base64url-style (not JSON braces)', async function () {
    const src = copyFixture('png', 'in.png');
    const dst = path.join(tmp, 'out.png');
    await agent.signImage(src, dst);

    const decoded = await agent.extractMediaSignature(dst);
    const raw = await agent.extractMediaSignature(dst, { rawPayload: true });
    expect(decoded).to.be.a('string');
    expect(raw).to.be.a('string');
    expect(decoded).to.not.equal(raw, 'raw and decoded payloads should differ');
    expect(raw.trim().startsWith('{')).to.equal(false, 'rawPayload should not be JSON');
  });

  // ---------------------------------------------------------------------
  // Sync variants.
  // ---------------------------------------------------------------------

  it('signImageSync + verifyImageSync round trip', function () {
    const src = copyFixture('png', 'in.png');
    const dst = path.join(tmp, 'out.png');
    agent.signImageSync(src, dst);
    const r = agent.verifyImageSync(dst);
    expect(r.status).to.equal('valid');
  });

  it('extractMediaSignatureSync returns null on unsigned input', function () {
    const src = copyFixture('png', 'plain.png');
    const r = agent.extractMediaSignatureSync(src);
    expect(r).to.equal(null);
  });

  // ---------------------------------------------------------------------
  // refuseOverwrite single-signer guard (PRD §4.2.2).
  // ---------------------------------------------------------------------

  it('signImage with { refuseOverwrite: true } on already-signed input rejects', async function () {
    const src = copyFixture('png', 'first.png');
    const dst = path.join(tmp, 'signed.png');
    await agent.signImage(src, dst);

    let caught;
    try {
      await agent.signImage(dst, dst, { refuseOverwrite: true });
    } catch (e) {
      caught = e;
    }
    expect(caught, 'expected refuseOverwrite to reject on already-signed input').to.exist;
  });

  // ---------------------------------------------------------------------
  // Issue 010 / PRD §10 eighth-pass — robust mode contract.
  // ---------------------------------------------------------------------

  it('signImage with { robust: true } on WebP rejects with "deferred" message', async function () {
    const src = copyFixture('webp', 'in.webp');
    const dst = path.join(tmp, 'out.webp');
    let caught;
    try {
      await agent.signImage(src, dst, { robust: true });
    } catch (e) {
      caught = e;
    }
    expect(caught, 'expected robust:true on WebP to reject').to.exist;
    expect(caught.message).to.match(/webp robust mode deferred/);
  });

  it('robust mode is off by default (PRD Q4)', async function () {
    const src = copyFixture('png', 'default-robust.png');
    const dst = path.join(tmp, 'out-default.png');
    const result = await agent.signImage(src, dst);
    expect(result.robust).to.equal(false, 'default signImage must not enable robust');
  });
});
