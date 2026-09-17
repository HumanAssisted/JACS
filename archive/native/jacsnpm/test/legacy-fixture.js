'use strict';

const LEGACY_SIGNATURE_ENV = 'JACS_ALLOW_LEGACY_SIGNATURE_CONTENT';

/**
 * Enable legacy-v1 verification only for tests that load the committed
 * pre-v2 agent fixture. Returns an idempotent restore function so the secure
 * process default is reinstated before other suites run.
 */
function enableLegacyFixtureCompatibility() {
  const hadPrevious = Object.prototype.hasOwnProperty.call(
    process.env,
    LEGACY_SIGNATURE_ENV,
  );
  const previous = process.env[LEGACY_SIGNATURE_ENV];
  let restored = false;

  process.env[LEGACY_SIGNATURE_ENV] = 'true';
  return () => {
    if (restored) return;
    restored = true;
    if (hadPrevious) {
      process.env[LEGACY_SIGNATURE_ENV] = previous;
    } else {
      delete process.env[LEGACY_SIGNATURE_ENV];
    }
  };
}

function withLegacyFixtureCompatibility(body) {
  const restore = enableLegacyFixtureCompatibility();
  try {
    const result = body();
    if (result && typeof result.then === 'function') {
      return Promise.resolve(result).finally(restore);
    }
    restore();
    return result;
  } catch (error) {
    restore();
    throw error;
  }
}

module.exports = {
  LEGACY_SIGNATURE_ENV,
  enableLegacyFixtureCompatibility,
  withLegacyFixtureCompatibility,
};
