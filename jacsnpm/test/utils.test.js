/**
 * Tests for JACS utility functions
 */

const { expect } = require('chai');
const { hashString, createConfig } = require('../index');

describe('JACS Utility Functions', () => {
  describe('hashString', () => {
    it('should hash a simple string', () => {
      const hash = hashString('hello world');
      expect(hash).to.be.a('string');
      expect(hash).to.have.length(64); // SHA-256 produces 64 hex characters
    });

    it('should produce consistent hashes for the same input', () => {
      const hash1 = hashString('test data');
      const hash2 = hashString('test data');
      expect(hash1).to.equal(hash2);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = hashString('input1');
      const hash2 = hashString('input2');
      expect(hash1).to.not.equal(hash2);
    });

    it('should handle empty string', () => {
      const hash = hashString('');
      expect(hash).to.be.a('string');
      expect(hash).to.have.length(64);
    });

    it('should handle unicode characters', () => {
      const hash = hashString('Hello \u4e16\u754c \ud83c\udf0d');
      expect(hash).to.be.a('string');
      expect(hash).to.have.length(64);
    });

    it('should handle JSON strings', () => {
      const jsonData = JSON.stringify({ action: 'approve', amount: 100 });
      const hash = hashString(jsonData);
      expect(hash).to.be.a('string');
      expect(hash).to.have.length(64);
    });

    it('should handle large strings', () => {
      const largeString = 'a'.repeat(100000);
      const hash = hashString(largeString);
      expect(hash).to.be.a('string');
      expect(hash).to.have.length(64);
    });
  });

  describe('createConfig', () => {
    it('should create a config with default values', () => {
      const configJson = createConfig();
      const config = JSON.parse(configJson);

      expect(config).to.be.an('object');
      expect(config).to.have.property('$schema');
    });

    it('should create a config with custom data directory', () => {
      const configJson = createConfig(
        null, // jacs_use_security
        './custom_data', // jacs_data_directory
        null, // jacs_key_directory
        null, // jacs_agent_private_key_filename
        null, // jacs_agent_public_key_filename
        null, // jacs_agent_key_algorithm
        null, // jacs_private_key_password
        null, // jacs_agent_id_and_version
        null  // jacs_default_storage
      );
      const config = JSON.parse(configJson);

      expect(config.jacs_data_directory).to.equal('./custom_data');
    });

    it('should create a config with custom key algorithm', () => {
      const configJson = createConfig(
        null, // jacs_use_security
        null, // jacs_data_directory
        null, // jacs_key_directory
        null, // jacs_agent_private_key_filename
        null, // jacs_agent_public_key_filename
        'ring-Ed25519', // jacs_agent_key_algorithm
        null, // jacs_private_key_password
        null, // jacs_agent_id_and_version
        null  // jacs_default_storage
      );
      const config = JSON.parse(configJson);

      expect(config.jacs_agent_key_algorithm).to.equal('ring-Ed25519');
    });

    it('should create a config with all custom values', () => {
      const configJson = createConfig(
        'true', // jacs_use_security
        './my_data', // jacs_data_directory
        './my_keys', // jacs_key_directory
        'my-private.pem', // jacs_agent_private_key_filename
        'my-public.pem', // jacs_agent_public_key_filename
        'RSA-PSS', // jacs_agent_key_algorithm
        'secret123', // jacs_private_key_password
        'agent-123:v1', // jacs_agent_id_and_version
        'fs' // jacs_default_storage
      );
      const config = JSON.parse(configJson);

      expect(config.jacs_use_security).to.equal('true');
      expect(config.jacs_data_directory).to.equal('./my_data');
      expect(config.jacs_key_directory).to.equal('./my_keys');
      expect(config.jacs_agent_private_key_filename).to.equal('my-private.pem');
      expect(config.jacs_agent_public_key_filename).to.equal('my-public.pem');
      expect(config.jacs_agent_key_algorithm).to.equal('RSA-PSS');
      expect(config.jacs_agent_id_and_version).to.equal('agent-123:v1');
      expect(config.jacs_default_storage).to.equal('fs');
    });
  });
});
