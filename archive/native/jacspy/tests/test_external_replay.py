from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import jacs
import jacs.replay as replay_module
from jacs import JacsAgent, SimpleAgent
from jacs.replay import (
    REPLAY_ERROR_CODES,
    ReplayError,
    unwrap_signed_event_with_replay_store,
)


CONTRACT_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "binding-core"
    / "tests"
    / "fixtures"
    / "external_replay_contract.json"
)
_REMOVE_FIELD = object()


@pytest.fixture
def signed_event() -> tuple[SimpleAgent, str, str]:
    signer, _ = SimpleAgent.ephemeral("ed25519")
    event_json = signer.sign_response('{"command":"run","sequence":7}')
    envelope = json.loads(event_json)
    signer_id = envelope["jacsSignature"]["agentID"]
    keys_json = json.dumps({signer_id: signer.get_public_key_pem()})
    return signer, event_json, keys_json


class CountingStore:
    scope = "shared"
    name = "counting-store"

    def __init__(
        self,
        result: Any = True,
        *,
        error: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.result = result
        self.error = error
        self.delay = delay
        self.calls = 0

    async def consume(self, key: str, ttl_seconds: int) -> Any:
        self.calls += 1
        assert key
        assert ttl_seconds > 0
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.result


class AtomicStore:
    scope = "shared"
    name = "atomic-store"

    def __init__(self) -> None:
        self.calls = 0
        self._seen: set[str] = set()
        self._lock = asyncio.Lock()

    async def consume(self, key: str, ttl_seconds: int) -> bool:
        assert ttl_seconds > 0
        async with self._lock:
            self.calls += 1
            if key in self._seen:
                return False
            self._seen.add(key)
            return True


class SyncStore:
    scope = "shared"
    name = "sync-store"

    def __init__(self) -> None:
        self.calls = 0

    def consume(self, key: str, ttl_seconds: int) -> bool:
        assert key
        assert ttl_seconds > 0
        time.sleep(0.05)
        self.calls += 1
        return True


class NonCooperativeSyncStore:
    scope = "shared"
    name = "noncooperative-sync-store"

    def __init__(self) -> None:
        self.calls = 0

    def consume(self, key: str, ttl_seconds: int) -> bool:
        assert key
        assert ttl_seconds > 0
        self.calls += 1
        time.sleep(0.25)
        return True


class MissingNameStore:
    scope = "shared"

    def __init__(self) -> None:
        self.calls = 0

    async def consume(self, key: str, ttl_seconds: int) -> bool:
        del key, ttl_seconds
        self.calls += 1
        return True


class RaisingNameStore(CountingStore):
    @property
    def name(self) -> str:
        raise RuntimeError("redis://operator:super-secret@replay.internal")


class PreparedAgent:
    def __init__(self, preparation: dict[str, Any], delay: float = 0.0) -> None:
        self.preparation = preparation
        self.delay = delay

    def prepare_signed_event_replay(
        self, event_json: str, server_keys_json: str, max_age_seconds: int
    ) -> str:
        del event_json, server_keys_json, max_age_seconds
        if self.delay:
            time.sleep(self.delay)
        return json.dumps(self.preparation, separators=(",", ":"))


def preparation_for(
    event_json: str,
    *,
    expires_in: int = 30,
    max_age_seconds: int = 300,
    now_seconds: int | None = None,
) -> dict[str, Any]:
    now_seconds = int(time.time()) if now_seconds is None else now_seconds
    issued_at = now_seconds + expires_in - max_age_seconds
    expires_at = issued_at + max_age_seconds
    signer_id = "test-signer:1"
    document_id = "test-document:1"
    replay_scope = f"signed-event:{signer_id}"
    return {
        "contractVersion": 1,
        "status": "crypto_verified_replay_pending",
        "cryptographicallyVerified": True,
        "freshnessVerified": True,
        "replayConsumed": False,
        "signerId": signer_id,
        "timestamp": datetime.fromtimestamp(issued_at, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "algorithm": "ring-Ed25519",
        "documentId": document_id,
        "eventSha256": hashlib.sha256(event_json.encode("utf-8")).hexdigest(),
        "replayKey": (
            f"jacs-replay-v1:{len(replay_scope.encode('utf-8'))}:"
            f"{replay_scope}:{document_id}"
        ),
        "replayTtlSeconds": max(expires_at - now_seconds + 1, 1),
        "expiresAtUnixSeconds": expires_at,
    }


def assert_replay_error(error: pytest.ExceptionInfo[ReplayError], code: str) -> None:
    assert error.value.code == code
    assert str(error.value).startswith(f"{code}:")


def test_external_replay_error_codes_match_contract() -> None:
    contract = json.loads(CONTRACT_PATH.read_text())
    assert set(REPLAY_ERROR_CODES) == set(contract["sharedStore"]["requiredErrors"])
    assert contract["sharedStore"]["errorSemantics"] == {
        "wrongScope": "replay_store_not_shared",
        "invalidName": "replay_store_invalid_result",
        "metadataUnavailable": "replay_store_unavailable",
        "backendUnavailable": "replay_store_unavailable",
        "backendTimeout": "replay_store_timeout",
        "duplicate": "replay_duplicate",
        "invalidBackendResult": "replay_store_invalid_result",
        "invalidPreparation": "replay_store_invalid_result",
        "expired": "signed_event_expired",
    }


@pytest.mark.parametrize(
    "timestamp",
    ["2026-07-11t00:00:00Z", "2026-07-11T00:00:00z"],
)
def test_timestamp_parser_rejects_non_contract_case(timestamp: str) -> None:
    with pytest.raises(ReplayError) as error:
        replay_module._parse_rfc3339_unix_seconds(timestamp)
    assert_replay_error(error, "replay_store_invalid_result")


def test_native_preparation_is_payload_free_on_both_agent_classes(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event
    advanced = JacsAgent()

    contract = json.loads(CONTRACT_PATH.read_text())
    required = set(contract["preparation"]["requiredFields"])
    forbidden = set(contract["preparation"]["forbiddenFields"])

    for agent in (signer, advanced):
        prepared = json.loads(
            agent.prepare_signed_event_replay(event_json, keys_json, 300)
        )
        assert set(prepared) == required
        assert forbidden.isdisjoint(prepared)
        assert (
            prepared["eventSha256"]
            == hashlib.sha256(event_json.encode("utf-8")).hexdigest()
        )
        assert prepared["replayConsumed"] is False


@pytest.mark.asyncio
async def test_high_level_helper_accepts_both_native_agent_classes(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event

    for verifier in (signer, JacsAgent()):
        verified = await unwrap_signed_event_with_replay_store(
            verifier, event_json, keys_json, CountingStore(True)
        )
        assert verified["data"] == {"command": "run", "sequence": 7}


@pytest.mark.asyncio
async def test_payload_is_not_parsed_until_store_accepts(
    signed_event: tuple[SimpleAgent, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, event_json, keys_json = signed_event
    store = CountingStore(True)
    original_loads = replay_module._strict_json_loads

    def guarded_loads(raw: str) -> Any:
        if raw == event_json and store.calls == 0:
            raise AssertionError("payload parsed before replay consume")
        return original_loads(raw)

    monkeypatch.setattr(replay_module, "_strict_json_loads", guarded_loads)
    verified = await unwrap_signed_event_with_replay_store(
        signer, event_json, keys_json, store
    )
    assert verified["data"] == {"command": "run", "sequence": 7}
    assert verified["verified"] is True
    assert verified["replayConsumed"] is True


@pytest.mark.asyncio
async def test_invalid_crypto_never_calls_store(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event
    tampered = json.loads(event_json)
    tampered["data"]["command"] = "tampered"
    store = CountingStore(True)

    with pytest.raises(Exception) as error:
        await unwrap_signed_event_with_replay_store(
            signer, json.dumps(tampered), keys_json, store
        )
    assert not isinstance(error.value, ReplayError)
    assert store.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("result", "expected_code"),
    [
        (False, "replay_duplicate"),
        (1, "replay_store_invalid_result"),
        (None, "replay_store_invalid_result"),
    ],
)
async def test_store_false_and_non_bool_results_fail_closed(
    signed_event: tuple[SimpleAgent, str, str], result: Any, expected_code: str
) -> None:
    signer, event_json, keys_json = signed_event
    store = CountingStore(result)
    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )
    assert_replay_error(error, expected_code)


@pytest.mark.asyncio
async def test_store_error_and_timeout_fail_closed(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event

    unavailable = CountingStore(error=RuntimeError("redis unavailable"))
    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, unavailable
        )
    assert_replay_error(error, "replay_store_unavailable")

    slow = CountingStore(True, delay=0.2)
    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer,
            event_json,
            keys_json,
            slow,
            store_timeout_seconds=0.01,
        )
    assert_replay_error(error, "replay_store_timeout")
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.asyncio
async def test_process_local_store_is_rejected_before_preparation(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event
    store = CountingStore(True)
    store.scope = "process-local"
    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )
    assert_replay_error(error, "replay_store_not_shared")
    assert store.calls == 0


@pytest.mark.asyncio
async def test_invalid_preparation_digest_or_schema_never_calls_store(
    signed_event: tuple[SimpleAgent, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, event_json, keys_json = signed_event
    store = CountingStore(True)

    wrong_digest = preparation_for(event_json)
    wrong_digest["eventSha256"] = "0" * 64

    def return_wrong_digest(
        self: SimpleAgent, event: str, keys: str, max_age: int
    ) -> str:
        del self, event, keys, max_age
        return json.dumps(wrong_digest, separators=(",", ":"))

    monkeypatch.setattr(SimpleAgent, "prepare_signed_event_replay", return_wrong_digest)
    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )
    assert_replay_error(error, "replay_store_invalid_result")

    payload_leak = preparation_for(event_json)
    payload_leak["data"] = {"command": "run"}

    def return_payload_leak(
        self: SimpleAgent, event: str, keys: str, max_age: int
    ) -> str:
        del self, event, keys, max_age
        return json.dumps(payload_leak, separators=(",", ":"))

    monkeypatch.setattr(SimpleAgent, "prepare_signed_event_replay", return_payload_leak)
    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )
    assert_replay_error(error, "replay_store_invalid_result")
    assert store.calls == 0


@pytest.mark.asyncio
async def test_two_agents_and_64_concurrent_calls_release_one_payload(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    _, event_json, keys_json = signed_event
    verifier_a, _ = SimpleAgent.ephemeral("ed25519")
    verifier_b, _ = SimpleAgent.ephemeral("ed25519")
    store = AtomicStore()

    async def verify(index: int) -> tuple[str, Any]:
        verifier = verifier_a if index % 2 == 0 else verifier_b
        try:
            result = await unwrap_signed_event_with_replay_store(
                verifier, event_json, keys_json, store
            )
            return "accepted", result
        except ReplayError as error:
            return "rejected", error.code

    results = await asyncio.gather(*(verify(index) for index in range(64)))
    accepted = [value for status, value in results if status == "accepted"]
    rejected = [value for status, value in results if status == "rejected"]
    assert len(accepted) == 1
    assert accepted[0]["data"] == {"command": "run", "sequence": 7}
    assert rejected == ["replay_duplicate"] * 63
    assert store.calls == 64


@pytest.mark.asyncio
async def test_expiry_crossing_during_store_consume_releases_no_payload(
    signed_event: tuple[SimpleAgent, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, event_json, keys_json = signed_event
    now = [1_800_000_000]
    preparation = preparation_for(event_json, expires_in=1, now_seconds=now[0])

    def boundary_preparation(
        self: SimpleAgent, event: str, keys: str, max_age: int
    ) -> str:
        del self, event, keys, max_age
        return json.dumps(preparation, separators=(",", ":"))

    class ExpiryCrossingStore(CountingStore):
        async def consume(self, key: str, ttl_seconds: int) -> bool:
            self.calls += 1
            assert key
            assert ttl_seconds > 0
            now[0] += 2
            return True

    monkeypatch.setattr(
        SimpleAgent, "prepare_signed_event_replay", boundary_preparation
    )
    monkeypatch.setattr(replay_module.time, "time", lambda: float(now[0]))
    store = ExpiryCrossingStore(True)

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer,
            event_json,
            keys_json,
            store,
        )
    assert_replay_error(error, "signed_event_expired")
    assert store.calls == 1


@pytest.mark.asyncio
async def test_native_preparation_runs_off_event_loop(
    signed_event: tuple[SimpleAgent, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, event_json, keys_json = signed_event
    preparation = preparation_for(event_json)
    ticked = False

    def slow_native_preparation(
        self: SimpleAgent, event: str, keys: str, max_age: int
    ) -> str:
        del self, event, keys, max_age
        time.sleep(0.1)
        return json.dumps(preparation, separators=(",", ":"))

    async def ticker() -> None:
        nonlocal ticked
        await asyncio.sleep(0.01)
        ticked = True

    monkeypatch.setattr(
        SimpleAgent, "prepare_signed_event_replay", slow_native_preparation
    )
    ticker_task = asyncio.create_task(ticker())
    verified = await unwrap_signed_event_with_replay_store(
        signer,
        event_json,
        keys_json,
        CountingStore(True),
    )
    await ticker_task
    assert ticked is True
    assert verified["data"] == {"command": "run", "sequence": 7}


@pytest.mark.asyncio
async def test_synchronous_store_runs_off_event_loop(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event
    store = SyncStore()
    ticked = False

    async def ticker() -> None:
        nonlocal ticked
        await asyncio.sleep(0.01)
        ticked = True

    ticker_task = asyncio.create_task(ticker())
    verified = await unwrap_signed_event_with_replay_store(
        signer, event_json, keys_json, store
    )
    await ticker_task
    assert ticked is True
    assert store.calls == 1
    assert verified["data"] == {"command": "run", "sequence": 7}


@pytest.mark.asyncio
async def test_noncooperative_synchronous_store_timeout_is_bounded(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event
    store = NonCooperativeSyncStore()
    started = time.monotonic()

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer,
            event_json,
            keys_json,
            store,
            store_timeout_seconds=0.01,
        )

    assert_replay_error(error, "replay_store_timeout")
    assert time.monotonic() - started < 0.1
    assert store.calls == 1


def test_replay_helper_is_exported_from_top_level_package() -> None:
    assert (
        jacs.unwrap_signed_event_with_replay_store
        is unwrap_signed_event_with_replay_store
    )
    assert jacs.ReplayError is ReplayError


@pytest.mark.asyncio
async def test_fake_agent_cannot_forge_verified_data() -> None:
    event_json = '{"data":{"command":"delete-everything"}}'
    store = CountingStore(True)

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            PreparedAgent(preparation_for(event_json)), event_json, "{}", store
        )

    assert_replay_error(error, "replay_store_invalid_result")
    assert store.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_name", [None, "", "   ", 7])
async def test_store_requires_nonblank_string_name(
    signed_event: tuple[SimpleAgent, str, str], bad_name: Any
) -> None:
    signer, event_json, keys_json = signed_event
    store = MissingNameStore()
    if bad_name is not None:
        store.name = bad_name

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )

    assert_replay_error(error, "replay_store_invalid_result")
    assert store.calls == 0


@pytest.mark.asyncio
async def test_store_name_error_is_redacted_and_has_no_raw_cause(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event
    store = RaisingNameStore()

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )

    assert_replay_error(error, "replay_store_unavailable")
    assert "super-secret" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert store.calls == 0


@pytest.mark.asyncio
async def test_store_failure_is_redacted_and_has_no_raw_cause(
    signed_event: tuple[SimpleAgent, str, str],
) -> None:
    signer, event_json, keys_json = signed_event
    store = CountingStore(
        error=RuntimeError("redis://operator:super-secret@replay.internal")
    )

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )

    assert_replay_error(error, "replay_store_unavailable")
    assert "super-secret" not in str(error.value)
    assert "super-secret" not in repr(error.value)
    assert error.value.__cause__ is None


@pytest.mark.asyncio
async def test_replay_failure_emits_one_structured_redacted_warning(
    signed_event: tuple[SimpleAgent, str, str], caplog: pytest.LogCaptureFixture
) -> None:
    signer, event_json, keys_json = signed_event
    secret = "redis://operator:do-not-log@replay.internal/private-key"
    caplog.set_level("WARNING", logger="jacs.security")

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer,
            event_json,
            keys_json,
            CountingStore(error=RuntimeError(secret)),
        )

    assert_replay_error(error, "replay_store_unavailable")
    records = [
        record
        for record in caplog.records
        if getattr(record, "operation", None) == "signed_event_replay"
    ]
    assert len(records) == 1
    record = records[0]
    observability = json.loads(CONTRACT_PATH.read_text())["observability"]
    assert record.levelname.lower().startswith(observability["level"])
    assert record.event == observability["event"]
    assert record.operation == observability["operation"]
    assert record.outcome == observability["outcome"]
    assert (
        getattr(record, observability["errorCodeField"]) == "replay_store_unavailable"
    )
    assert secret not in record.getMessage()
    assert secret not in repr(record.__dict__)
    assert error.value.__context__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("timestamp", "2026-07-11 00:00:00Z"),
        ("timestamp", "2026-07-11t00:00:00Z"),
        ("timestamp", "2026-07-11T00:00:00z"),
        ("replayKey", "jacs-replay-v1:wrong"),
        ("expiresAtUnixSeconds", lambda claim: claim["expiresAtUnixSeconds"] + 1),
        ("replayTtlSeconds", 1),
        ("replayTtlSeconds", 1 << 64),
        ("cryptographicallyVerified", 1),
        ("freshnessVerified", 1),
        ("replayConsumed", 0),
        ("algorithm", _REMOVE_FIELD),
        ("unexpected", "field"),
    ],
)
async def test_malformed_preparation_claim_never_calls_store(
    signed_event: tuple[SimpleAgent, str, str],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    bad_value: Any,
) -> None:
    signer, event_json, keys_json = signed_event
    claim = preparation_for(event_json, expires_in=30)
    if bad_value is _REMOVE_FIELD:
        claim.pop(field)
    else:
        claim[field] = bad_value(claim) if callable(bad_value) else bad_value

    def forged_native_preparation(
        self: SimpleAgent,
        received_event: str,
        received_keys: str,
        received_max_age: int,
    ) -> str:
        del self
        assert received_event == event_json
        assert received_keys == keys_json
        assert received_max_age == 300
        return json.dumps(claim, separators=(",", ":"))

    monkeypatch.setattr(
        SimpleAgent, "prepare_signed_event_replay", forged_native_preparation
    )
    store = CountingStore(True)

    with pytest.raises(ReplayError) as error:
        await unwrap_signed_event_with_replay_store(
            signer, event_json, keys_json, store
        )

    assert_replay_error(error, "replay_store_invalid_result")
    assert store.calls == 0


@pytest.mark.asyncio
async def test_expiry_second_is_still_accepted(
    signed_event: tuple[SimpleAgent, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer, event_json, keys_json = signed_event
    expiry = 1_800_000_000
    claim = preparation_for(
        event_json,
        expires_in=0,
        max_age_seconds=300,
        now_seconds=expiry,
    )

    def boundary_preparation(
        self: SimpleAgent,
        received_event: str,
        received_keys: str,
        received_max_age: int,
    ) -> str:
        del self, received_event, received_keys, received_max_age
        return json.dumps(claim, separators=(",", ":"))

    monkeypatch.setattr(
        SimpleAgent, "prepare_signed_event_replay", boundary_preparation
    )
    monkeypatch.setattr(replay_module.time, "time", lambda: float(expiry))
    store = CountingStore(True)

    verified = await unwrap_signed_event_with_replay_store(
        signer, event_json, keys_json, store
    )

    assert verified["data"] == {"command": "run", "sequence": 7}
    assert store.calls == 1
