const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const diagnosticsChannel = require('node:diagnostics_channel');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const native = require('../index.js');
const simple = require('../simple.js');

const CONTRACT_PATH = path.resolve(
  __dirname,
  '../../binding-core/tests/fixtures/external_replay_contract.json',
);
const contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8'));
const requiredErrorCodes = new Set(contract.sharedStore.requiredErrors);

function eventSha256(eventJson) {
  return crypto.createHash('sha256').update(eventJson, 'utf8').digest('hex');
}

function fakePreparation(eventJson, options = {}) {
  const maxAgeSeconds = options.maxAgeSeconds ?? 300;
  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const issuedAtSeconds = options.issuedAtSeconds ?? nowSeconds - 1;
  const expiresAtUnixSeconds = issuedAtSeconds + maxAgeSeconds;
  const signerId = 'server-agent:version-1';
  const documentId = 'event-document-1';
  const replayScope = `signed-event:${signerId}`;
  return {
    contractVersion: 1,
    status: 'crypto_verified_replay_pending',
    cryptographicallyVerified: true,
    freshnessVerified: true,
    replayConsumed: false,
    signerId,
    timestamp: new Date(issuedAtSeconds * 1000).toISOString(),
    algorithm: 'pq2025',
    documentId,
    eventSha256: eventSha256(eventJson),
    replayKey: `jacs-replay-v1:${Buffer.byteLength(replayScope, 'utf8')}:${replayScope}:${documentId}`,
    replayTtlSeconds: Math.max(1, expiresAtUnixSeconds - nowSeconds + 1),
    expiresAtUnixSeconds,
    ...options.overrides,
  };
}

function fakeAgentFor(eventJson, options = {}) {
  let calls = 0;
  const preparation = fakePreparation(eventJson, options);
  const agent = new native.JacsAgent();
  Object.defineProperties(agent, {
    calls: { get: () => calls },
    preparation: { value: preparation },
  });
  agent.prepareSignedEventReplay = async function prepareSignedEventReplay(
    receivedEvent,
    receivedKeys,
    receivedMaxAge,
  ) {
    calls += 1;
    assert.equal(receivedEvent, eventJson);
    assert.equal(receivedKeys, '{"server":"key"}');
    assert.equal(receivedMaxAge, options.maxAgeSeconds ?? 300);
    if (options.error) {
      throw options.error;
    }
    return options.rawPreparation ?? JSON.stringify(preparation);
  };
  return agent;
}

async function expectReplayError(promise, code) {
  assert.ok(requiredErrorCodes.has(code), `${code} must come from the shared contract`);
  try {
    await promise;
    assert.fail(`expected ${code}`);
  } catch (error) {
    assert.equal(error && error.code, code, String(error));
    return error;
  }
}

describe('external shared signed-event replay', function () {
  this.timeout(60_000);

  const eventData = Object.freeze({ secret: 'release only after replay consumption' });
  const fakeEventJson = JSON.stringify({
    version: '2.0.0',
    data: eventData,
    metadata: { document_id: 'event-document-1' },
    jacsSignature: { agentID: 'server-agent:version-1' },
  });

  it('matches the canonical condition-to-error contract', function () {
    assert.deepEqual(contract.sharedStore.errorSemantics, {
      wrongScope: 'replay_store_not_shared',
      invalidName: 'replay_store_invalid_result',
      metadataUnavailable: 'replay_store_unavailable',
      backendUnavailable: 'replay_store_unavailable',
      backendTimeout: 'replay_store_timeout',
      duplicate: 'replay_duplicate',
      invalidBackendResult: 'replay_store_invalid_result',
      invalidPreparation: 'replay_store_invalid_result',
      expired: 'signed_event_expired',
    });
  });

  it('exports the async native preparation surface on both classes', function () {
    const simpleAgent = native.JacsSimpleAgent.ephemeral('pq2025');
    const agent = new native.JacsAgent();

    assert.equal(typeof simpleAgent.prepareSignedEventReplay, 'function');
    assert.equal(typeof simpleAgent.prepareSignedEventReplaySync, 'undefined');
    assert.equal(typeof agent.prepareSignedEventReplay, 'function');
    assert.equal(typeof agent.prepareSignedEventReplaySync, 'function');
  });

  it('does not parse or release event data until shared consumption returns literal true', async function () {
    const agent = fakeAgentFor(fakeEventJson);
    let parsedEvent = false;
    let consumeCalls = 0;
    const originalParse = JSON.parse;
    JSON.parse = function monitoredParse(input, ...rest) {
      if (input === fakeEventJson) {
        parsedEvent = true;
      }
      return originalParse.call(JSON, input, ...rest);
    };

    try {
      const result = await simple.unwrapSignedEventWithReplayStore(
        agent,
        fakeEventJson,
        '{"server":"key"}',
        {
          scope: 'shared',
          name: 'test-shared',
          async consume(key, ttl, signal) {
            consumeCalls += 1;
            assert.equal(parsedEvent, false, 'event payload was parsed before replay consumption');
            assert.equal(key, agent.preparation.replayKey);
            assert.equal(ttl, agent.preparation.replayTtlSeconds);
            assert.equal(signal instanceof AbortSignal, true);
            return true;
          },
        },
      );

      assert.equal(consumeCalls, 1);
      assert.equal(parsedEvent, true);
      assert.deepEqual(result, {
        status: 'verified',
        verified: true,
        replayConsumed: true,
        data: eventData,
        signerId: 'server-agent:version-1',
        timestamp: agent.preparation.timestamp,
        algorithm: 'pq2025',
        documentId: 'event-document-1',
      });
    } finally {
      JSON.parse = originalParse;
    }
  });

  it('validates preparation schema and the exact UTF-8 SHA-256 before touching the store', async function () {
    for (const overrides of [
      { data: { leaked: true } },
      { contractVersion: '1' },
      { status: 'verified' },
      { cryptographicallyVerified: false },
      { freshnessVerified: 1 },
      { replayConsumed: 0 },
      { eventSha256: '0'.repeat(64) },
      { replayTtlSeconds: 0 },
      { expiresAtUnixSeconds: 'soon' },
    ]) {
      let storeCalls = 0;
      const agent = fakeAgentFor(fakeEventJson, { overrides });
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          agent,
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
        ),
        'replay_store_invalid_result',
      );
      assert.equal(storeCalls, 0);
    }
  });

  it('fails closed for local, duplicate, unavailable, timeout, and non-boolean stores', async function () {
    const localAgent = fakeAgentFor(fakeEventJson);
    await expectReplayError(
      simple.unwrapSignedEventWithReplayStore(
        localAgent,
        fakeEventJson,
        '{"server":"key"}',
        { scope: 'local', name: 'test-local', async consume() { return true; } },
      ),
      'replay_store_not_shared',
    );
    assert.equal(localAgent.calls, 0, 'local stores must fail before cryptographic work');

    await expectReplayError(
      simple.unwrapSignedEventWithReplayStore(
        fakeAgentFor(fakeEventJson),
        fakeEventJson,
        '{"server":"key"}',
        { scope: 'shared', name: 'test-shared', async consume() { return false; } },
      ),
      'replay_duplicate',
    );

    await expectReplayError(
      simple.unwrapSignedEventWithReplayStore(
        fakeAgentFor(fakeEventJson),
        fakeEventJson,
        '{"server":"key"}',
        {
          scope: 'shared',
          name: 'test-shared',
          async consume() {
            throw new Error('redis unavailable');
          },
        },
      ),
      'replay_store_unavailable',
    );

    let timeoutSignalAborted = false;
    await expectReplayError(
      simple.unwrapSignedEventWithReplayStore(
        fakeAgentFor(fakeEventJson),
        fakeEventJson,
        '{"server":"key"}',
        {
          scope: 'shared',
          name: 'test-shared',
          async consume(_key, _ttl, signal) {
            signal.addEventListener('abort', () => {
              timeoutSignalAborted = true;
            }, { once: true });
            await new Promise(() => {});
          },
        },
        { timeoutMs: 10 },
      ),
      'replay_store_timeout',
    );
    assert.equal(timeoutSignalAborted, true);

    for (const invalid of [undefined, null, 1, 'true', new Boolean(true)]) {
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          fakeAgentFor(fakeEventJson),
          fakeEventJson,
          '{"server":"key"}',
          { scope: 'shared', name: 'test-shared', async consume() { return invalid; } },
        ),
        'replay_store_invalid_result',
      );
    }
  });

  it('rechecks absolute expiry after successful shared consumption', async function () {
    const realDateNow = Date.now;
    const maxAgeSeconds = 2;
    let fakeNowSeconds = 1_800_000_000;
    const issuedAtSeconds = fakeNowSeconds - 1;
    const expiresAtUnixSeconds = issuedAtSeconds + maxAgeSeconds;
    Date.now = () => fakeNowSeconds * 1000;

    try {
      const agent = fakeAgentFor(fakeEventJson, {
        maxAgeSeconds,
        nowSeconds: fakeNowSeconds,
        issuedAtSeconds,
      });
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          agent,
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              fakeNowSeconds = expiresAtUnixSeconds + 1;
              return true;
            },
          },
          { maxAgeSeconds },
        ),
        'signed_event_expired',
      );
    } finally {
      Date.now = realDateNow;
    }
  });

  it('rejects an already expired preparation before calling the store', async function () {
    const realDateNow = Date.now;
    const fakeNowSeconds = 1_800_000_100;
    Date.now = () => fakeNowSeconds * 1000;
    let storeCalls = 0;

    try {
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          fakeAgentFor(fakeEventJson, {
            maxAgeSeconds: 2,
            nowSeconds: fakeNowSeconds,
            issuedAtSeconds: fakeNowSeconds - 10,
          }),
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
          { maxAgeSeconds: 2 },
        ),
        'signed_event_expired',
      );
      assert.equal(storeCalls, 0);
    } finally {
      Date.now = realDateNow;
    }
  });

  it('rejects lone UTF-16 surrogates in event and key JSON before native or store calls', async function () {
    for (const [label, eventJson, serverKeysJson] of [
      ['event high surrogate', `${fakeEventJson}\ud800`, '{"server":"key"}'],
      ['event low surrogate', `${fakeEventJson}\udc00`, '{"server":"key"}'],
      ['keys high surrogate', fakeEventJson, '{"server":"\ud800"}'],
      ['keys low surrogate', fakeEventJson, '{"server":"\udc00"}'],
    ]) {
      const agent = fakeAgentFor(fakeEventJson);
      let storeCalls = 0;
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          agent,
          eventJson,
          serverKeysJson,
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
        ),
        'replay_store_invalid_result',
      );
      assert.equal(agent.calls, 0, `${label} reached native preparation`);
      assert.equal(storeCalls, 0, `${label} reached the replay store`);
    }
  });

  it('rejects duck-typed preparers before native or store work', async function () {
    let prepareCalls = 0;
    const duckTypedAgent = {
      async prepareSignedEventReplay() {
        prepareCalls += 1;
        return JSON.stringify(fakePreparation(fakeEventJson));
      },
    };
    const prototypeSpoof = Object.create(native.JacsAgent.prototype);
    prototypeSpoof.prepareSignedEventReplay = duckTypedAgent.prepareSignedEventReplay;

    for (const invalidAgent of [duckTypedAgent, prototypeSpoof]) {
      let storeCalls = 0;
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          invalidAgent,
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
        ),
        'replay_store_invalid_result',
      );
      assert.equal(storeCalls, 0);
    }
    assert.equal(prepareCalls, 0);
  });

  it('requires a nonblank shared-store name before native preparation', async function () {
    for (const name of [undefined, null, '', '   ', 42]) {
      const agent = fakeAgentFor(fakeEventJson);
      let storeCalls = 0;
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          agent,
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name,
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
        ),
        'replay_store_invalid_result',
      );
      assert.equal(agent.calls, 0);
      assert.equal(storeCalls, 0);
    }
  });

  it('maps throwing store metadata access to a redacted unavailable error', async function () {
    const secret = 'redis://operator:super-secret@replay.internal';
    const agent = fakeAgentFor(fakeEventJson);
    let storeCalls = 0;
    const store = {
      get scope() {
        throw new Error(secret);
      },
      name: 'unreachable-name',
      async consume() {
        storeCalls += 1;
        return true;
      },
    };

    const error = await expectReplayError(
      simple.unwrapSignedEventWithReplayStore(
        agent,
        fakeEventJson,
        '{"server":"key"}',
        store,
      ),
      'replay_store_unavailable',
    );
    assert.equal(String(error).includes(secret), false);
    assert.equal(String(error.stack).includes(secret), false);
    assert.equal(agent.calls, 0);
    assert.equal(storeCalls, 0);
  });

  it('rejects a synchronous busy store without invoking it', async function () {
    const agent = fakeAgentFor(fakeEventJson);
    let storeCalls = 0;
    function busyConsume() {
      storeCalls += 1;
      const until = Date.now() + 250;
      while (Date.now() < until) {
        // This must never execute on the event loop.
      }
      return true;
    }
    Object.defineProperty(busyConsume, Symbol.toStringTag, { value: 'AsyncFunction' });
    await expectReplayError(
      simple.unwrapSignedEventWithReplayStore(
        agent,
        fakeEventJson,
        '{"server":"key"}',
        {
          scope: 'shared',
          name: 'sync-busy-store',
          consume: busyConsume,
        },
      ),
      'replay_store_invalid_result',
    );
    assert.equal(agent.calls, 0);
    assert.equal(storeCalls, 0);
  });

  it('rejects extra and duplicate preparation keys before store consumption', async function () {
    const missingPreparationValue = fakePreparation(fakeEventJson);
    delete missingPreparationValue.algorithm;
    const missingPreparation = JSON.stringify(missingPreparationValue);
    const extraPreparation = JSON.stringify(fakePreparation(fakeEventJson, {
      overrides: { futureField: true },
    }));
    const normalPreparation = JSON.stringify(fakePreparation(fakeEventJson));
    const duplicatePreparation = normalPreparation.replace(
      '"status":"crypto_verified_replay_pending"',
      '"status":"verified","st\\u0061tus":"crypto_verified_replay_pending"',
    );

    for (const rawPreparation of [missingPreparation, extraPreparation, duplicatePreparation]) {
      const agent = fakeAgentFor(fakeEventJson, { rawPreparation });
      let storeCalls = 0;
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          agent,
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
        ),
        'replay_store_invalid_result',
      );
      assert.equal(storeCalls, 0);
    }
  });

  it('validates timestamp, exact replay key, expiry math, and bounded TTL semantics', async function () {
    const maxAgeSeconds = 300;
    const nowSeconds = Math.floor(Date.now() / 1000);
    const cases = [
      { timestamp: '2026-07-11' },
      { timestamp: '2026-02-30T12:00:00Z' },
      { replayKey: 'jacs-replay-v1:wrong' },
      { signerId: 'other-signer' },
      { expiresAtUnixSeconds: nowSeconds + maxAgeSeconds + 10 },
      { replayTtlSeconds: 1 },
      { replayTtlSeconds: maxAgeSeconds + 302 },
    ];

    for (const overrides of cases) {
      const agent = fakeAgentFor(fakeEventJson, { maxAgeSeconds, nowSeconds, overrides });
      let storeCalls = 0;
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          agent,
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
          { maxAgeSeconds },
        ),
        'replay_store_invalid_result',
      );
      assert.equal(storeCalls, 0, `store called for ${JSON.stringify(overrides)}`);
    }
  });

  it('accepts an event through the expiry second and expires it only when now is greater', async function () {
    const realDateNow = Date.now;
    const nowSeconds = 1_800_000_000;
    const maxAgeSeconds = 300;
    Date.now = () => nowSeconds * 1000;
    try {
      const agent = fakeAgentFor(fakeEventJson, {
        maxAgeSeconds,
        nowSeconds,
        issuedAtSeconds: nowSeconds - maxAgeSeconds,
      });
      const result = await simple.unwrapSignedEventWithReplayStore(
        agent,
        fakeEventJson,
        '{"server":"key"}',
        {
          scope: 'shared',
          name: 'test-shared',
          async consume() {
            return true;
          },
        },
        { maxAgeSeconds },
      );
      assert.equal(result.verified, true);
    } finally {
      Date.now = realDateNow;
    }
  });

  it('redacts replay backend exceptions and exposes no raw cause', async function () {
    const secret = 'redis://admin:correct-horse-battery-staple@internal/replay';
    const error = await expectReplayError(
      simple.unwrapSignedEventWithReplayStore(
        fakeAgentFor(fakeEventJson),
        fakeEventJson,
        '{"server":"key"}',
        {
          scope: 'shared',
          name: 'test-shared',
          async consume() {
            throw new Error(secret);
          },
        },
      ),
      'replay_store_unavailable',
    );
    assert.equal(String(error).includes(secret), false);
    assert.equal(String(error.stack).includes(secret), false);
    assert.equal(Object.hasOwn(error, 'cause'), false);
    assert.equal(error.cause, undefined);
  });

  it('publishes one structured redacted WARN security event for replay failure', async function () {
    const secret = 'redis://admin:do-not-log@internal/replay/private-key';
    const events = [];
    const securityChannel = diagnosticsChannel.channel(
      simple.JACS_SECURITY_DIAGNOSTICS_CHANNEL,
    );
    const subscriber = (event) => events.push(event);
    securityChannel.subscribe(subscriber);
    try {
      await expectReplayError(
        simple.unwrapSignedEventWithReplayStore(
          fakeAgentFor(fakeEventJson),
          fakeEventJson,
          '{"server":"key"}',
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              throw new Error(secret);
            },
          },
        ),
        'replay_store_unavailable',
      );
    } finally {
      securityChannel.unsubscribe(subscriber);
    }

    const expected = contract.observability;
    assert.deepEqual(events, [{
      level: expected.level,
      event: expected.event,
      operation: expected.operation,
      outcome: expected.outcome,
      [expected.errorCodeField]: 'replay_store_unavailable',
    }]);
    assert.equal(JSON.stringify(events).includes(secret), false);
  });

  describe('native PQ integration', function () {
    let signer;
    let verifier;
    let legacyAgentVerifier;
    let eventJson;
    let serverKeysJson;

    before(function () {
      signer = native.JacsSimpleAgent.ephemeral('pq2025');
      verifier = native.JacsSimpleAgent.ephemeral('pq2025');
      legacyAgentVerifier = new native.JacsAgent();
      eventJson = signer.signResponse(JSON.stringify({ command: 'send-email', id: 42 }));
      const event = JSON.parse(eventJson);
      serverKeysJson = JSON.stringify({
        [event.jacsSignature.agentID]: signer.getPublicKeyPem(),
      });
    });

    it('prepares on the worker pool with the contract schema and exact hash', async function () {
      const simplePending = signer.prepareSignedEventReplay(eventJson, serverKeysJson, 300);
      const agentPending = legacyAgentVerifier.prepareSignedEventReplay(
        eventJson,
        serverKeysJson,
        300,
      );
      assert.equal(typeof simplePending.then, 'function');
      assert.equal(typeof agentPending.then, 'function');
      const preparations = [
        JSON.parse(await simplePending),
        JSON.parse(await agentPending),
        JSON.parse(legacyAgentVerifier.prepareSignedEventReplaySync(
          eventJson,
          serverKeysJson,
          300,
        )),
      ];

      for (const preparation of preparations) {
        for (const field of contract.preparation.requiredFields) {
          assert.ok(Object.hasOwn(preparation, field), `missing preparation field ${field}`);
        }
        for (const field of contract.preparation.forbiddenFields) {
          assert.equal(Object.hasOwn(preparation, field), false, `preparation leaked ${field}`);
        }
        assert.equal(preparation.eventSha256, eventSha256(eventJson));
        assert.equal(preparation.status, contract.preparation.status);
        assert.equal(preparation.replayConsumed, false);
      }
    });

    it('rejects invalid cryptography without calling the application store', async function () {
      const tampered = JSON.parse(eventJson);
      tampered.data.command = 'delete-everything';
      let storeCalls = 0;

      await assert.rejects(
        simple.unwrapSignedEventWithReplayStore(
          verifier,
          JSON.stringify(tampered),
          serverKeysJson,
          {
            scope: 'shared',
            name: 'test-shared',
            async consume() {
              storeCalls += 1;
              return true;
            },
          },
        ),
      );
      assert.equal(storeCalls, 0);
    });

    it('rejects U+FFFD-to-surrogate substitutions before native verification or store use', async function () {
      const replacementEvent = signer.signResponse(JSON.stringify({ value: '\ufffd' }));
      assert.equal(replacementEvent.includes('\ufffd'), true);

      for (const surrogate of ['\ud800', '\udc00']) {
        const substituted = replacementEvent.replace('\ufffd', surrogate);
        assert.equal(
          eventSha256(substituted),
          eventSha256(replacementEvent),
          'Node UTF-8 encoding should demonstrate the replacement collision',
        );
        let storeCalls = 0;
        await expectReplayError(
          simple.unwrapSignedEventWithReplayStore(
            verifier,
            substituted,
            serverKeysJson,
            {
              scope: 'shared',
              name: 'test-shared',
              async consume() {
                storeCalls += 1;
                return true;
              },
            },
          ),
          'replay_store_invalid_result',
        );
        assert.equal(storeCalls, 0);
      }
    });

    it('allows exactly one of 64 concurrent deliveries across two verifier agents', async function () {
      const consumed = new Set();
      const store = {
        scope: 'shared',
        name: 'test-shared',
        async consume(key) {
          if (consumed.has(key)) {
            return false;
          }
          consumed.add(key);
          return true;
        },
      };
      let heartbeat = 0;
      const timer = setInterval(() => {
        heartbeat += 1;
      }, 1);

      const deliveries = Array.from({ length: 64 }, (_, index) =>
        simple.unwrapSignedEventWithReplayStore(
          index % 2 === 0 ? signer : verifier,
          eventJson,
          serverKeysJson,
          store,
        ));
      const settled = await Promise.allSettled(deliveries);
      clearInterval(timer);

      const accepted = settled.filter((item) => item.status === 'fulfilled');
      const rejected = settled.filter((item) => item.status === 'rejected');
      assert.equal(accepted.length, 1);
      assert.equal(rejected.length, 63);
      for (const item of rejected) {
        assert.equal(item.reason.code, 'replay_duplicate');
      }
      assert.deepEqual(accepted[0].value.data, { command: 'send-email', id: 42 });
      assert.equal(heartbeat > 0, true, 'concurrent PQ verification blocked the event loop');
    });
  });

  it('exports the high-level helper through CJS, ESM, and declarations', async function () {
    assert.equal(typeof simple.unwrapSignedEventWithReplayStore, 'function');

    const esm = await import(pathToFileURL(path.resolve(__dirname, '../simple.js')).href);
    assert.equal(typeof esm.unwrapSignedEventWithReplayStore, 'function');

    const simpleDeclarations = fs.readFileSync(path.resolve(__dirname, '../simple.d.ts'), 'utf8');
    const nativeDeclarations = fs.readFileSync(path.resolve(__dirname, '../index.d.ts'), 'utf8');
    assert.match(simpleDeclarations, /unwrapSignedEventWithReplayStore/);
    assert.match(simpleDeclarations, /SharedReplayStore/);
    assert.match(
      simpleDeclarations,
      /SignedEventReplayPreparer = JacsAgent \| JacsSimpleAgent/,
    );
    assert.match(simpleDeclarations, /readonly name: string/);
    assert.match(
      simpleDeclarations,
      /consume\(key: string, ttlSeconds: number, signal: AbortSignal\): Promise<boolean>/,
    );
    assert.doesNotMatch(simpleDeclarations, /readonly cause/);
    assert.equal((nativeDeclarations.match(/prepareSignedEventReplay\(/g) || []).length, 2);
    assert.equal((nativeDeclarations.match(/prepareSignedEventReplaySync\(/g) || []).length, 1);
  });
});
