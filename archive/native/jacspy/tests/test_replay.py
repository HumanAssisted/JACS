"""Tests for shared replay-protection helpers used by auth middleware."""

import json
from datetime import datetime, timezone

from jacs._replay import (
    InMemoryReplayCache,
    build_auth_replay_options,
    check_auth_replay,
)


def _signed_envelope(
    *,
    signer_id: str,
    timestamp: str,
    signature: str,
) -> str:
    return json.dumps(
        {
            "jacsSignature": {
                "agentID": signer_id,
                "date": timestamp,
                "signature": signature,
            },
            "jacsDocument": {"action": "auth"},
        }
    )


def test_check_auth_replay_rejects_duplicate_signature():
    options = build_auth_replay_options(enabled=True, max_age_seconds=60)
    cache = InMemoryReplayCache()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    raw = _signed_envelope(
        signer_id="agent-replay",
        timestamp=now,
        signature="sig-replay",
    )

    first = check_auth_replay(raw, {}, cache, options)
    second = check_auth_replay(raw, {}, cache, options)

    assert first is None
    assert second is not None
    assert "replay" in second


def test_check_auth_replay_rejects_expired_timestamp():
    options = build_auth_replay_options(
        enabled=True, max_age_seconds=30, clock_skew_seconds=0
    )
    cache = InMemoryReplayCache()
    raw = _signed_envelope(
        signer_id="agent-expired",
        timestamp="2020-01-01T00:00:00Z",
        signature="sig-old",
    )

    error = check_auth_replay(raw, {}, cache, options)

    assert error is not None
    assert "expired" in error


def test_check_auth_replay_rejects_future_timestamp():
    options = build_auth_replay_options(
        enabled=True, max_age_seconds=60, clock_skew_seconds=0
    )
    cache = InMemoryReplayCache()
    raw = _signed_envelope(
        signer_id="agent-future",
        timestamp="2999-01-01T00:00:00Z",
        signature="sig-future",
    )

    error = check_auth_replay(raw, {}, cache, options)

    assert error is not None
    assert "future" in error


def test_check_auth_replay_uses_verifier_fields_when_envelope_missing_fields():
    options = build_auth_replay_options(enabled=True, max_age_seconds=60)
    cache = InMemoryReplayCache()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    raw = json.dumps(
        {
            "jacsSignature": {
                "signature": "sig-verifier-fields",
            },
            "jacsDocument": {"action": "auth"},
        }
    )

    error = check_auth_replay(
        raw,
        {"signer_id": "agent-from-verifier", "timestamp": now},
        cache,
        options,
    )

    assert error is None


def test_check_auth_replay_rejects_invalid_json_envelope():
    options = build_auth_replay_options(enabled=True, max_age_seconds=60)
    cache = InMemoryReplayCache()

    error = check_auth_replay("not-json", {}, cache, options)

    assert error is not None
    assert "valid JSON" in error


def test_check_auth_replay_rejects_missing_signature_value():
    options = build_auth_replay_options(enabled=True, max_age_seconds=60)
    cache = InMemoryReplayCache()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    raw = json.dumps(
        {
            "jacsSignature": {
                "agentID": "agent-no-signature",
                "date": now,
            }
        }
    )

    error = check_auth_replay(raw, {}, cache, options)

    assert error is not None
    assert "signature value" in error


def test_build_auth_replay_options_normalizes_invalid_values_and_min_ttl():
    normalized = build_auth_replay_options(
        enabled=True,
        max_age_seconds=-10,
        clock_skew_seconds=-5,
        cache_ttl_seconds=-1,
    )
    assert normalized.enabled is True
    assert normalized.max_age_seconds == 30
    assert normalized.clock_skew_seconds == 5
    assert normalized.cache_ttl_seconds == 35

    minimum_ttl = build_auth_replay_options(
        enabled=True,
        max_age_seconds=0,
        clock_skew_seconds=0,
        cache_ttl_seconds=0,
    )
    assert minimum_ttl.cache_ttl_seconds == 1


def test_check_auth_replay_rejects_invalid_timestamp_format():
    options = build_auth_replay_options(enabled=True, max_age_seconds=60)
    cache = InMemoryReplayCache()
    raw = _signed_envelope(
        signer_id="agent-invalid-ts",
        timestamp="not-a-timestamp",
        signature="sig-invalid-ts",
    )

    error = check_auth_replay(raw, {}, cache, options)

    assert error is not None
    assert "invalid timestamp" in error


def test_check_auth_replay_rejects_missing_signer_id():
    options = build_auth_replay_options(enabled=True, max_age_seconds=60)
    cache = InMemoryReplayCache()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    raw = json.dumps(
        {
            "jacsSignature": {
                "date": now,
                "signature": "sig-no-signer",
            }
        }
    )

    error = check_auth_replay(raw, {}, cache, options)

    assert error is not None
    assert "signerId" in error


def test_check_auth_replay_rejects_non_object_json_envelope():
    options = build_auth_replay_options(enabled=True, max_age_seconds=60)
    cache = InMemoryReplayCache()

    error = check_auth_replay("[]", {}, cache, options)

    assert error is not None
    assert "valid JSON" in error


def test_in_memory_replay_cache_isolation_across_instances():
    cache_a = InMemoryReplayCache()
    cache_b = InMemoryReplayCache()

    assert cache_a.check_and_remember("shared-key", now_seconds=1000, ttl_seconds=60) is False
    assert cache_a.check_and_remember("shared-key", now_seconds=1001, ttl_seconds=60) is True

    # Separate cache instance should not inherit replay state.
    assert cache_b.check_and_remember("shared-key", now_seconds=1001, ttl_seconds=60) is False
