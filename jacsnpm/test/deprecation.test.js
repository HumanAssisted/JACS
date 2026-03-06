const { expect } = require('chai');

function loadDeprecationModule() {
  delete require.cache[require.resolve('../deprecation.js')];
  return require('../deprecation.js');
}

describe('JACS deprecation warnings', () => {
  const envVar = 'JACS_SHOW_DEPRECATIONS';
  let originalWarn;
  let originalEnv;

  beforeEach(() => {
    originalWarn = console.warn;
    originalEnv = process.env[envVar];
  });

  afterEach(() => {
    console.warn = originalWarn;
    if (originalEnv === undefined) {
      delete process.env[envVar];
    } else {
      process.env[envVar] = originalEnv;
    }
    delete require.cache[require.resolve('../deprecation.js')];
  });

  it('does not warn when deprecations are disabled', () => {
    delete process.env[envVar];
    const calls = [];
    console.warn = (message) => calls.push(message);

    const { warnDeprecated } = loadDeprecationModule();
    warnDeprecated('oldThing', 'newThing');

    expect(calls).to.deep.equal([]);
  });

  it('warns once per deprecated alias when enabled', () => {
    process.env[envVar] = '1';
    const calls = [];
    console.warn = (message) => calls.push(message);

    const { warnDeprecated } = loadDeprecationModule();
    warnDeprecated('oldThing', 'newThing');
    warnDeprecated('oldThing', 'newThing');

    expect(calls).to.have.lengthOf(1);
    expect(calls[0]).to.include('oldThing() is deprecated, use newThing() instead');
  });

  it('warns separately for distinct deprecated aliases', () => {
    process.env[envVar] = '1';
    const calls = [];
    console.warn = (message) => calls.push(message);

    const { warnDeprecated } = loadDeprecationModule();
    warnDeprecated('oldThing', 'newThing');
    warnDeprecated('oldOtherThing', 'newOtherThing');

    expect(calls).to.have.lengthOf(2);
    expect(calls[0]).to.include('oldThing() is deprecated, use newThing() instead');
    expect(calls[1]).to.include('oldOtherThing() is deprecated, use newOtherThing() instead');
  });
});
