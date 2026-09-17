const { expect } = require('chai');

let replay;
try {
  replay = require('../auth-replay.js');
} catch (e) {
  replay = null;
}

describe('Auth Replay Helpers', () => {
  if (!replay) {
    it('skips because auth-replay.js is not compiled', () => {});
    return;
  }

  it('normalizes default auth replay options', () => {
    const opts = replay.normalizeAuthReplayOptions(undefined);
    expect(opts).to.deep.equal({
      enabled: false,
      maxAgeSeconds: 30,
      clockSkewSeconds: 5,
      cacheTtlSeconds: 35,
    });
  });

  it('normalizes enabled shorthand auth replay options', () => {
    const opts = replay.normalizeAuthReplayOptions(true);
    expect(opts).to.deep.equal({
      enabled: true,
      maxAgeSeconds: 30,
      clockSkewSeconds: 5,
      cacheTtlSeconds: 35,
    });
  });

  it('normalizes invalid numeric options and enforces minimum cache TTL', () => {
    const normalized = replay.normalizeAuthReplayOptions({
      enabled: true,
      maxAgeSeconds: -10,
      clockSkewSeconds: Number.NaN,
      cacheTtlSeconds: -1,
    });
    expect(normalized).to.deep.equal({
      enabled: true,
      maxAgeSeconds: 30,
      clockSkewSeconds: 5,
      cacheTtlSeconds: 35,
    });

    const minimumTtl = replay.normalizeAuthReplayOptions({
      enabled: true,
      maxAgeSeconds: 0,
      clockSkewSeconds: 0,
      cacheTtlSeconds: 0,
    });
    expect(minimumTtl.cacheTtlSeconds).to.equal(1);
  });

  it('uses verifier fields when envelope signer/timestamp are absent', () => {
    const cache = new replay.InMemoryReplayCache();
    const now = new Date().toISOString();
    const raw = JSON.stringify({
      jacsSignature: { signature: 'sig-verifier-fields' },
      jacsDocument: { action: 'auth' },
    });
    const opts = replay.normalizeAuthReplayOptions({
      enabled: true,
      maxAgeSeconds: 60,
      clockSkewSeconds: 5,
    });

    const err = replay.checkAuthReplay(
      raw,
      { signerId: 'agent-from-verifier', timestamp: now },
      cache,
      opts
    );

    expect(err).to.equal(null);
  });

  it('rejects malformed JSON envelopes', () => {
    const cache = new replay.InMemoryReplayCache();
    const opts = replay.normalizeAuthReplayOptions(true);
    const err = replay.checkAuthReplay('not-json', {}, cache, opts);
    expect(err).to.include('valid JSON');
  });

  it('rejects envelopes missing signerId', () => {
    const cache = new replay.InMemoryReplayCache();
    const opts = replay.normalizeAuthReplayOptions(true);
    const raw = JSON.stringify({
      jacsSignature: {
        date: new Date().toISOString(),
        signature: 'sig-no-signer',
      },
    });
    const err = replay.checkAuthReplay(raw, {}, cache, opts);
    expect(err).to.include('signerId');
  });

  it('rejects envelopes with invalid timestamps', () => {
    const cache = new replay.InMemoryReplayCache();
    const opts = replay.normalizeAuthReplayOptions(true);
    const raw = JSON.stringify({
      jacsSignature: {
        agentID: 'agent-invalid-ts',
        date: 'not-a-timestamp',
        signature: 'sig-invalid-ts',
      },
    });
    const err = replay.checkAuthReplay(raw, {}, cache, opts);
    expect(err).to.include('invalid timestamp');
  });

  it('rejects envelopes with future timestamps outside skew window', () => {
    const cache = new replay.InMemoryReplayCache();
    const opts = replay.normalizeAuthReplayOptions({
      enabled: true,
      maxAgeSeconds: 60,
      clockSkewSeconds: 0,
    });
    const raw = JSON.stringify({
      jacsSignature: {
        agentID: 'agent-future-ts',
        date: new Date(Date.now() + 60_000).toISOString(),
        signature: 'sig-future-ts',
      },
    });
    const err = replay.checkAuthReplay(raw, {}, cache, opts);
    expect(err).to.include('future timestamp');
  });

  it('expires replay cache entries based on TTL', () => {
    const cache = new replay.InMemoryReplayCache();
    expect(cache.checkAndRemember('k', 1000, 1000)).to.equal(false);
    expect(cache.checkAndRemember('k', 1500, 1000)).to.equal(true);
    expect(cache.checkAndRemember('k', 2501, 1000)).to.equal(false);
  });

  it('keeps replay state per cache instance', () => {
    const cacheA = new replay.InMemoryReplayCache();
    const cacheB = new replay.InMemoryReplayCache();

    expect(cacheA.checkAndRemember('shared-key', 1000, 60_000)).to.equal(false);
    expect(cacheA.checkAndRemember('shared-key', 1001, 60_000)).to.equal(true);

    // Separate cache instance should not inherit prior replay state.
    expect(cacheB.checkAndRemember('shared-key', 1001, 60_000)).to.equal(false);
  });
});
