/**
 * Tests for JACS format conversion (YAML/HTML) via JacsSimpleAgent.
 */

const { expect } = require('chai');

let bindings;
try {
  bindings = require('../index.js');
} catch (e) {
  bindings = null;
}

describe('Format Conversion', function () {
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
