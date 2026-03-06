const fs = require('fs');
const path = require('path');
const { expect } = require('chai');

let mcpModule;
try {
  mcpModule = require('../mcp.js');
} catch (e) {
  mcpModule = null;
}

const CONTRACT_PATH = path.resolve(__dirname, '../../jacs-mcp/contract/jacs-mcp-contract.json');

const EXPECTED_CANONICAL_TOOL_NAMES = new Set([
  'jacs_sign_document',
  'jacs_verify_document',
  'jacs_create_agreement',
  'jacs_sign_agreement',
  'jacs_check_agreement',
  'jacs_audit',
  'jacs_export_agent',
  'jacs_export_agent_card',
  'jacs_wrap_a2a_artifact',
  'jacs_verify_a2a_artifact',
  'jacs_assess_a2a_agent',
  'jacs_trust_agent',
  'jacs_list_trusted_agents',
  'jacs_get_trusted_agent',
  'jacs_untrust_agent',
  'jacs_is_trusted',
  'jacs_reencrypt_key',
]);

const EXPECTED_COMPATIBILITY_TOOL_NAMES = new Set([
  'jacs_verify_by_id',
  'jacs_sign_file',
  'jacs_verify_self',
  'jacs_agent_info',
  'jacs_share_public_key',
  'jacs_share_agent',
  'fetch_agent_key',
  'jacs_register',
  'jacs_setup_instructions',
  'jacs_trust_agent_with_key',
  'jacs_list_trusted',
]);

function sorted(values) {
  return Array.from(values).sort();
}

function canonicalShape(tool) {
  const schema = tool.input_schema || {};
  return {
    properties: sorted(Object.keys(schema.properties || {})),
    required: sorted(schema.required || []),
  };
}

function nodeShape(tool) {
  const schema = tool.inputSchema || {};
  return {
    properties: sorted(Object.keys(schema.properties || {})),
    required: sorted(schema.required || []),
  };
}

describe('jacsnpm MCP contract drift', function () {
  const available = mcpModule !== null;

  before(function () {
    if (!available) {
      console.log('  Skipping MCP contract drift tests - mcp.js not compiled');
      this.skip();
    }
  });

  it('only advertises canonical Rust tools or explicit compatibility tools', () => {
    const contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8'));
    const canonicalNames = new Set(contract.tools.map(tool => tool.name));
    const published = mcpModule.getJacsMcpToolDefinitions();
    const publishedNames = new Set(published.map(tool => tool.name));

    const matchingCanonical = new Set(sorted([...publishedNames].filter(name => canonicalNames.has(name))));
    const compatibilityOnly = new Set(sorted([...publishedNames].filter(name => !canonicalNames.has(name))));

    expect(sorted(matchingCanonical)).to.deep.equal(sorted(EXPECTED_CANONICAL_TOOL_NAMES));
    expect(sorted(compatibilityOnly)).to.deep.equal(sorted(EXPECTED_COMPATIBILITY_TOOL_NAMES));
  });

  it('keeps canonical tool parameter names aligned with the Rust contract', () => {
    const contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8'));
    const canonical = new Map(contract.tools.map(tool => [tool.name, tool]));
    const published = mcpModule.getJacsMcpToolDefinitions();

    for (const tool of published) {
      if (!EXPECTED_CANONICAL_TOOL_NAMES.has(tool.name)) {
        continue;
      }

      expect(nodeShape(tool)).to.deep.equal(canonicalShape(canonical.get(tool.name)));
    }
  });
});
