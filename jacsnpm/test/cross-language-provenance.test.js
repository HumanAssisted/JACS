/**
 * Cross-language provenance tests (Task 13, PRD §5.1 / §5.2).
 *
 * Verifies that text + image fixtures signed by Rust under
 * `jacs/tests/fixtures/provenance/` are accepted by the Node binding,
 * and that a Node-signed file round-trips through the Rust `jacs verify-text`
 * CLI.
 *
 * Fixtures are committed; regenerate with:
 *
 *   UPDATE_PROVENANCE_FIXTURES=1 cargo test -p jacs --test \
 *     provenance_cross_language_tests -- --ignored regenerate_provenance_fixtures
 *
 * The test suite is skipped when fixtures are absent.
 */

const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

let yaml;
try {
  yaml = require('js-yaml');
} catch (_) {
  yaml = null;
}

let JacsSimpleAgent;
try {
  ({ JacsSimpleAgent } = require('../index.js'));
} catch (_) {
  JacsSimpleAgent = null;
}

const FIXTURES_DIR = path.resolve(
  __dirname,
  '..',
  '..',
  'jacs',
  'tests',
  'fixtures',
  'provenance'
);
const KEYS_DIR = path.join(FIXTURES_DIR, 'keys');
const METADATA_PATH = path.join(FIXTURES_DIR, 'metadata.json');

function fixturesPresent() {
  return fs.existsSync(METADATA_PATH) && fs.existsSync(KEYS_DIR);
}

function readMetadata() {
  return JSON.parse(fs.readFileSync(METADATA_PATH, 'utf8'));
}

describe('cross-language provenance fixtures (Node verifies Rust-signed)', function () {
  this.timeout(60000);

  let agent;
  let metadata;

  before(async function () {
    if (!JacsSimpleAgent) {
      console.log('  Skipping: native binding not built');
      this.skip();
    }
    if (!fixturesPresent()) {
      console.log('  Skipping: provenance fixtures missing — run UPDATE_PROVENANCE_FIXTURES=1 cargo test ... --ignored regenerate_provenance_fixtures');
      this.skip();
    }
    metadata = readMetadata();
  });

  beforeEach(async function () {
    agent = await JacsSimpleAgent.ephemeral('ed25519');
  });

  // -------------------------------------------------------------------
  // Acceptance #2 — Node verifies all four Rust-signed media types.
  // -------------------------------------------------------------------

  it('verifies rust_signed_ed25519.md', async function () {
    const target = path.join(FIXTURES_DIR, 'rust_signed_ed25519.md');
    const result = await agent.verifyText(target, { keyDir: KEYS_DIR });
    expect(result.status).to.equal('signed');
    expect(result.signatures).to.have.lengthOf(1);
    const sig = result.signatures[0];
    expect(sig.status).to.equal('valid');
    expect(sig.algorithm).to.equal('ed25519');
    expect(sig.signer_id || sig.signerId).to.equal(metadata.agent_ed25519.agent_id);
  });

  it('verifies rust_signed_pq2025.md', async function () {
    const target = path.join(FIXTURES_DIR, 'rust_signed_pq2025.md');
    const result = await agent.verifyText(target, { keyDir: KEYS_DIR });
    expect(result.status).to.equal('signed');
    expect(result.signatures).to.have.lengthOf(1);
    const sig = result.signatures[0];
    expect(sig.status).to.equal('valid');
    expect(sig.algorithm).to.equal('pq2025');
    expect(sig.signer_id || sig.signerId).to.equal(metadata.agent_pq2025.agent_id);
  });

  it('verifies rust_signed_multi_algo.md (mixed-algorithm, unordered)', async function () {
    const target = path.join(FIXTURES_DIR, 'rust_signed_multi_algo.md');
    const result = await agent.verifyText(target, { keyDir: KEYS_DIR });
    expect(result.status).to.equal('signed');
    expect(result.signatures).to.have.lengthOf(2);

    const statuses = new Set(result.signatures.map((s) => s.status));
    expect([...statuses]).to.deep.equal(['valid']);

    const algos = result.signatures.map((s) => s.algorithm).sort();
    expect(algos).to.deep.equal(['ed25519', 'pq2025']);
  });

  it('verifies rust_signed_ed25519.png', async function () {
    const target = path.join(FIXTURES_DIR, 'rust_signed_ed25519.png');
    const result = await agent.verifyImage(target, { keyDir: KEYS_DIR });
    expect(result.status).to.equal('valid');
    expect(result.format).to.equal('png');
  });

  it('verifies rust_signed_ed25519.jpg', async function () {
    const target = path.join(FIXTURES_DIR, 'rust_signed_ed25519.jpg');
    const result = await agent.verifyImage(target, { keyDir: KEYS_DIR });
    expect(result.status).to.equal('valid');
    expect(result.format).to.equal('jpeg');
  });

  it('verifies rust_signed_ed25519.webp', async function () {
    const target = path.join(FIXTURES_DIR, 'rust_signed_ed25519.webp');
    const result = await agent.verifyImage(target, { keyDir: KEYS_DIR });
    expect(result.status).to.equal('valid');
    expect(result.format).to.equal('webp');
  });

  // -------------------------------------------------------------------
  // C3 — js-yaml parses the Rust-signed markdown signature block body
  // as a full JACS YAML document footer.
  // -------------------------------------------------------------------

  it('C3: js-yaml parses Rust-signed markdown block body as full JACS footer', function () {
    if (!yaml) this.skip();
    const content = fs.readFileSync(
      path.join(FIXTURES_DIR, 'rust_signed_ed25519.md'),
      'utf8'
    );
    const begin = '-----BEGIN JACS SIGNATURE-----\n';
    const endMarker = '\n-----END JACS SIGNATURE-----';
    const start = content.indexOf(begin) + begin.length;
    const end = content.indexOf(endMarker);
    expect(end).to.be.greaterThan(start);
    const body = content.slice(start, end);
    const parsed = yaml.load(body);

    expect(parsed).to.have.property('jacsType', 'inline-md');
    expect(parsed).to.have.property('jacsId').that.is.a('string');
    expect(parsed).to.have.property('jacsVersion').that.is.a('string');
    expect(parsed).to.have.nested.property('jacsSignature.agentID').that.is.a('string');
    expect(parsed).to.have.nested.property('jacsSignature.publicKeyHash').that.is.a('string');
    expect(parsed).to.have.nested.property('jacsSignature.signature').that.is.a('string');
    expect(parsed).to.have.nested.property('content.inlineSignatureVersion', 1);
    expect(parsed).to.have.nested.property('content.signedContentHash').that.is.a('string');
  });

  // -------------------------------------------------------------------
  // C1 — strict + permissive parity for unsigned fixtures.
  // -------------------------------------------------------------------

  it('C1 permissive: unsigned.md returns missing_signature', async function () {
    const target = path.join(FIXTURES_DIR, 'unsigned.md');
    const result = await agent.verifyText(target);
    expect(result.status).to.equal('missing_signature');
    // The binding omits `signatures` for the missing case (matches the wire
    // shape produced by binding-core::serialize_verify_text_result). Either
    // unset or [] is acceptable for downstream consumers.
    expect(result.signatures || []).to.deep.equal([]);
  });

  it('C1 strict: unsigned.md rejects /no JACS signature found/', async function () {
    const target = path.join(FIXTURES_DIR, 'unsigned.md');
    let caught;
    try {
      await agent.verifyText(target, { strict: true });
    } catch (e) {
      caught = e;
    }
    expect(caught, 'expected strict verifyText to reject').to.exist;
    expect(caught.message).to.match(/no JACS signature found/);
  });

  for (const [fixture, expectedFmt] of [
    ['unsigned.png', 'png'],
    ['unsigned.jpg', 'jpeg'],
    ['unsigned.webp', 'webp'],
  ]) {
    it(`C1 permissive: ${fixture} returns missing_signature`, async function () {
      const target = path.join(FIXTURES_DIR, fixture);
      const result = await agent.verifyImage(target);
      expect(result.status).to.equal('missing_signature');
      // format detection still happens before the signature check.
      expect(result.format).to.equal(expectedFmt);
    });

    it(`C1 strict: ${fixture} rejects /no JACS signature found/`, async function () {
      const target = path.join(FIXTURES_DIR, fixture);
      let caught;
      try {
        await agent.verifyImage(target, { strict: true });
      } catch (e) {
        caught = e;
      }
      expect(caught, `expected strict verifyImage to reject ${fixture}`).to.exist;
      expect(caught.message).to.match(/no JACS signature found/);
    });
  }

  it('strict on rust_signed_ed25519.md still resolves with status=signed', async function () {
    const target = path.join(FIXTURES_DIR, 'rust_signed_ed25519.md');
    const result = await agent.verifyText(target, {
      strict: true,
      keyDir: KEYS_DIR,
    });
    expect(result.status).to.equal('signed');
  });

  // -------------------------------------------------------------------
  // Acceptance #2 — Node signs locally, Rust CLI verifies (round trip).
  // -------------------------------------------------------------------

  it('node-signs then Rust CLI verifies (round trip)', async function () {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-xlang-'));
    try {
      const target = path.join(tmp, 'node_signed.md');
      fs.writeFileSync(target, '# Node-signed\n\nVerify me from Rust.\n');

      await agent.signText(target);

      const keyDir = path.join(tmp, 'keys');
      fs.mkdirSync(keyDir);
      const signerId = await agent.getAgentId();
      const pem = await agent.getPublicKeyPem();
      const encoded = signerId.replace(/\.\./g, '%2E%2E').replace(/:/g, '%3A');
      fs.writeFileSync(path.join(keyDir, `${encoded}.public.pem`), pem);

      const workspaceRoot = path.resolve(__dirname, '..', '..');
      // Prefer cargo run from a developer checkout (matches the Python test
      // path); the CI image always has cargo available.
      const result = spawnSync(
        'cargo',
        [
          'run',
          '-q',
          '--bin',
          'jacs',
          '--',
          'verify-text',
          target,
          '--key-dir',
          keyDir,
          '--json',
        ],
        {
          cwd: workspaceRoot,
          encoding: 'utf8',
          env: { ...process.env, JACS_MAX_IAT_SKEW_SECONDS: '0' },
        }
      );
      expect(
        result.status,
        `cargo verify-text exited ${result.status}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`
      ).to.equal(0);

      const parsed = JSON.parse(result.stdout);
      expect(parsed.status).to.equal('signed');
      expect(parsed.signatures).to.have.lengthOf(1);
      expect(parsed.signatures[0].status).to.equal('valid');
      expect(parsed.signatures[0].signer_id).to.equal(signerId);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
