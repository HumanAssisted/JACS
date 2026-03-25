/**
 * Tests for JACS format conversion (YAML/HTML).
 *
 * Covers:
 * - JacsSimpleAgent: sync conversion methods (toYaml, fromYaml, etc.)
 * - JacsAgent: sync conversion methods (toYamlSync, fromYamlSync, etc.)
 * - JacsAgent: async conversion methods (toYaml, fromYaml, etc.)
 * - Error cases for invalid input
 */

const { expect } = require('chai');
const path = require('path');
const fs = require('fs');

let bindings;
try {
  bindings = require('../index.js');
} catch (e) {
  bindings = null;
}

const FIXTURES_DIR = path.resolve(__dirname, '../../jacs/tests/scratch');
const TEST_CONFIG = path.join(FIXTURES_DIR, 'jacs.config.json');
const fixturesExist = fs.existsSync(TEST_CONFIG);

// =============================================================================
// JacsSimpleAgent conversion tests (existing)
// =============================================================================

describe('Format Conversion (JacsSimpleAgent)', function () {
  if (!bindings || !bindings.JacsSimpleAgent) {
    it.skip('JacsSimpleAgent not available');
    return;
  }

  let agent;

  before(function () {
    agent = bindings.JacsSimpleAgent.ephemeral('ed25519');
  });

  describe('YAML conversion', function () {
    it('toYaml returns valid YAML', function () {
      const signed = agent.signMessage(JSON.stringify({ hello: 'world' }));
      const yaml = agent.toYaml(signed);
      expect(yaml).to.be.a('string');
      expect(yaml).to.include('hello');
    });

    it('fromYaml returns valid JSON', function () {
      const yaml = 'hello: world\ncount: 42\n';
      const json = agent.fromYaml(yaml);
      const parsed = JSON.parse(json);
      expect(parsed.hello).to.equal('world');
      expect(parsed.count).to.equal(42);
    });

    it('YAML round-trip preserves content', function () {
      const signed = agent.signMessage(JSON.stringify({ data: 'test', num: 42 }));
      const yaml = agent.toYaml(signed);
      const jsonBack = agent.fromYaml(yaml);
      const original = JSON.parse(signed);
      const reconstituted = JSON.parse(jsonBack);
      expect(reconstituted.content).to.exist;
      expect(reconstituted.content.data).to.equal('test');
    });

    it('verifyYaml succeeds on valid document', function () {
      const signed = agent.signMessage(JSON.stringify({ data: 'verify me' }));
      const yaml = agent.toYaml(signed);
      const resultJson = agent.verifyYaml(yaml);
      const result = JSON.parse(resultJson);
      expect(result.valid).to.be.true;
    });

    it('toYaml rejects invalid JSON', function () {
      expect(() => agent.toYaml('{not valid json}')).to.throw();
    });

    it('fromYaml rejects invalid YAML', function () {
      expect(() => agent.fromYaml('{{{{ not yaml ::::')).to.throw();
    });
  });

  describe('HTML conversion', function () {
    it('toHtml returns valid HTML', function () {
      const signed = agent.signMessage(JSON.stringify({ content: 'test' }));
      const html = agent.toHtml(signed);
      expect(html).to.include('<!DOCTYPE html>');
      expect(html).to.include('<script type="application/json" id="jacs-data">');
    });

    it('fromHtml returns valid JSON', function () {
      const signed = agent.signMessage(JSON.stringify({ content: 'extract me' }));
      const html = agent.toHtml(signed);
      const jsonBack = agent.fromHtml(html);
      const parsed = JSON.parse(jsonBack);
      expect(parsed).to.be.an('object');
    });

    it('HTML round-trip preserves content', function () {
      const signed = agent.signMessage(JSON.stringify({ data: 'html test' }));
      const html = agent.toHtml(signed);
      const jsonBack = agent.fromHtml(html);
      const resultJson = agent.verify(jsonBack);
      const result = JSON.parse(resultJson);
      expect(result.valid).to.be.true;
    });
  });
});

// =============================================================================
// JacsAgent conversion tests (sync variants)
// =============================================================================

describe('Format Conversion (JacsAgent sync)', function () {
  if (!bindings || !bindings.JacsAgent || !fixturesExist) {
    it.skip('JacsAgent or fixtures not available');
    return;
  }

  this.timeout(10000);

  let agent;

  before(function () {
    const originalCwd = process.cwd();
    process.chdir(FIXTURES_DIR);
    try {
      agent = new bindings.JacsAgent();
      agent.loadSync(TEST_CONFIG);
    } finally {
      process.chdir(originalCwd);
    }
  });

  describe('YAML sync', function () {
    it('toYamlSync converts JSON to YAML', function () {
      const json = JSON.stringify({ hello: 'world', count: 42 });
      const yaml = agent.toYamlSync(json);
      expect(yaml).to.be.a('string');
      expect(yaml).to.include('hello');
      expect(yaml).to.include('42');
    });

    it('fromYamlSync converts YAML to JSON', function () {
      const yaml = 'greeting: hello\nnum: 7\n';
      const json = agent.fromYamlSync(yaml);
      const parsed = JSON.parse(json);
      expect(parsed.greeting).to.equal('hello');
      expect(parsed.num).to.equal(7);
    });

    it('YAML sync round-trip preserves content', function () {
      const original = { data: 'sync-test', value: 123 };
      const json = JSON.stringify(original);
      const yaml = agent.toYamlSync(json);
      const jsonBack = agent.fromYamlSync(yaml);
      const reconstituted = JSON.parse(jsonBack);
      expect(reconstituted.data).to.equal('sync-test');
      expect(reconstituted.value).to.equal(123);
    });

    it('toYamlSync rejects invalid JSON', function () {
      expect(() => agent.toYamlSync('{not valid}')).to.throw();
    });

    it('fromYamlSync rejects invalid YAML', function () {
      expect(() => agent.fromYamlSync('{{{{ broken ::::')).to.throw();
    });
  });

  describe('HTML sync', function () {
    it('toHtmlSync returns valid HTML', function () {
      const json = JSON.stringify({ content: 'sync html' });
      const html = agent.toHtmlSync(json);
      expect(html).to.include('<!DOCTYPE html>');
      expect(html).to.include('jacs-data');
    });

    it('fromHtmlSync extracts JSON', function () {
      const json = JSON.stringify({ content: 'extract sync' });
      const html = agent.toHtmlSync(json);
      const jsonBack = agent.fromHtmlSync(html);
      const parsed = JSON.parse(jsonBack);
      expect(parsed.content).to.equal('extract sync');
    });

    it('HTML sync round-trip preserves content', function () {
      const original = { data: 'html-sync', count: 99 };
      const json = JSON.stringify(original);
      const html = agent.toHtmlSync(json);
      const jsonBack = agent.fromHtmlSync(html);
      const reconstituted = JSON.parse(jsonBack);
      expect(reconstituted.data).to.equal('html-sync');
      expect(reconstituted.count).to.equal(99);
    });
  });

  describe('verifyYaml sync', function () {
    it('verifyYamlSync verifies a signed document via YAML', function () {
      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const signed = agent.createDocumentSync(
          JSON.stringify({ jacsDocument: { type: 'message', content: { test: 'verify-yaml-sync' } } }),
          null, null, true, null, null,
        );
        const yaml = agent.toYamlSync(signed);
        const isValid = agent.verifyYamlSync(yaml);
        expect(isValid).to.be.true;
      } finally {
        process.chdir(originalCwd);
      }
    });
  });
});

// =============================================================================
// JacsAgent conversion tests (async variants)
// =============================================================================

describe('Format Conversion (JacsAgent async)', function () {
  if (!bindings || !bindings.JacsAgent || !fixturesExist) {
    it.skip('JacsAgent or fixtures not available');
    return;
  }

  this.timeout(15000);

  let agent;

  before(function () {
    const originalCwd = process.cwd();
    process.chdir(FIXTURES_DIR);
    try {
      agent = new bindings.JacsAgent();
      agent.loadSync(TEST_CONFIG);
    } finally {
      process.chdir(originalCwd);
    }
  });

  describe('YAML async', function () {
    it('toYaml returns a Promise that resolves to YAML', async function () {
      const json = JSON.stringify({ hello: 'async', num: 10 });
      const yaml = await agent.toYaml(json);
      expect(yaml).to.be.a('string');
      expect(yaml).to.include('hello');
    });

    it('fromYaml returns a Promise that resolves to JSON', async function () {
      const yaml = 'key: async_value\ncount: 5\n';
      const json = await agent.fromYaml(yaml);
      const parsed = JSON.parse(json);
      expect(parsed.key).to.equal('async_value');
      expect(parsed.count).to.equal(5);
    });

    it('async YAML round-trip preserves content', async function () {
      const original = { data: 'async-test', value: 456 };
      const json = JSON.stringify(original);
      const yaml = await agent.toYaml(json);
      const jsonBack = await agent.fromYaml(yaml);
      const reconstituted = JSON.parse(jsonBack);
      expect(reconstituted.data).to.equal('async-test');
      expect(reconstituted.value).to.equal(456);
    });

    it('toYaml rejects on invalid JSON', async function () {
      try {
        await agent.toYaml('{broken}');
        expect.fail('should have thrown');
      } catch (e) {
        expect(e.message).to.be.a('string');
      }
    });
  });

  describe('HTML async', function () {
    it('toHtml returns a Promise that resolves to HTML', async function () {
      const json = JSON.stringify({ content: 'async html' });
      const html = await agent.toHtml(json);
      expect(html).to.include('<!DOCTYPE html>');
    });

    it('fromHtml returns a Promise that resolves to JSON', async function () {
      const json = JSON.stringify({ content: 'extract async' });
      const html = await agent.toHtml(json);
      const jsonBack = await agent.fromHtml(html);
      const parsed = JSON.parse(jsonBack);
      expect(parsed.content).to.equal('extract async');
    });

    it('async HTML round-trip preserves content', async function () {
      const original = { data: 'html-async', count: 77 };
      const json = JSON.stringify(original);
      const html = await agent.toHtml(json);
      const jsonBack = await agent.fromHtml(html);
      const reconstituted = JSON.parse(jsonBack);
      expect(reconstituted.data).to.equal('html-async');
      expect(reconstituted.count).to.equal(77);
    });
  });

  describe('verifyYaml async', function () {
    it('verifyYaml returns a Promise that resolves to true', async function () {
      const originalCwd = process.cwd();
      process.chdir(FIXTURES_DIR);
      try {
        const signed = agent.createDocumentSync(
          JSON.stringify({ jacsDocument: { type: 'message', content: { test: 'verify-yaml-async' } } }),
          null, null, true, null, null,
        );
        const yaml = agent.toYamlSync(signed);
        const isValid = await agent.verifyYaml(yaml);
        expect(isValid).to.be.true;
      } finally {
        process.chdir(originalCwd);
      }
    });
  });
});
