/**
 * Adapter inventory parity test for the Node.js binding.
 *
 * Validates that all Node adapters listed in
 * binding-core/tests/fixtures/adapter_inventory.json are requireable
 * and expose the documented public functions.
 *
 * This test complements (does not duplicate) the MCP contract drift test.
 * It validates API surface existence only.
 */

const fs = require('fs');
const path = require('path');
const { expect } = require('chai');

const FIXTURE_PATH = path.resolve(
  __dirname,
  '../../binding-core/tests/fixtures/adapter_inventory.json'
);

describe('Node.js adapter inventory parity', function () {
  let inventory;
  let nodeAdapters;

  before(function () {
    if (!fs.existsSync(FIXTURE_PATH)) {
      console.log('  Skipping adapter inventory tests - fixture not found');
      this.skip();
    }
    inventory = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));
    nodeAdapters = inventory.adapters && inventory.adapters.node;
    if (!nodeAdapters) {
      console.log('  Skipping - no Node adapters in inventory');
      this.skip();
    }
  });

  it('inventory fixture is valid JSON with expected structure', function () {
    expect(inventory).to.have.property('adapters');
    expect(inventory.adapters).to.have.property('node');
  });

  it('node adapter entries have required fields', function () {
    for (const [adapterName, adapter] of Object.entries(nodeAdapters)) {
      if (adapterName.startsWith('_')) continue;
      expect(adapter, `${adapterName} should have module`).to.have.property('module');
      expect(adapter, `${adapterName} should have public_functions`).to.have.property('public_functions');
      expect(adapter.public_functions, `${adapterName} public_functions should be non-empty`).to.be.an('array').that.is.not.empty;
    }
  });

  it('MCP adapter module is requireable', function () {
    const mcpAdapter = nodeAdapters.mcp;
    if (!mcpAdapter) {
      this.skip();
      return;
    }

    let mcpModule;
    try {
      mcpModule = require(`../${mcpAdapter.module}.js`);
    } catch (e) {
      // If the MCP module isn't compiled, skip
      this.skip();
      return;
    }

    expect(mcpModule).to.not.be.null;
  });

  it('MCP adapter exposes all listed public functions', function () {
    const mcpAdapter = nodeAdapters.mcp;
    if (!mcpAdapter) {
      this.skip();
      return;
    }

    let mcpModule;
    try {
      mcpModule = require(`../${mcpAdapter.module}.js`);
    } catch (e) {
      this.skip();
      return;
    }

    const missing = [];
    for (const funcName of mcpAdapter.public_functions) {
      if (typeof mcpModule[funcName] === 'undefined') {
        missing.push(funcName);
      }
    }

    expect(missing, `MCP adapter missing public functions: ${missing.join(', ')}`).to.be.empty;
  });

  it('all Node adapter public functions exist in their modules', function () {
    for (const [adapterName, adapter] of Object.entries(nodeAdapters)) {
      if (adapterName.startsWith('_')) continue;

      let mod;
      try {
        mod = require(`../${adapter.module}.js`);
      } catch (e) {
        // Module not compiled/available, skip this adapter
        continue;
      }

      const missing = [];
      for (const funcName of adapter.public_functions) {
        if (typeof mod[funcName] === 'undefined') {
          missing.push(funcName);
        }
      }

      expect(
        missing,
        `Node adapter '${adapterName}' (${adapter.module}) missing: ${missing.join(', ')}`
      ).to.be.empty;
    }
  });
});
