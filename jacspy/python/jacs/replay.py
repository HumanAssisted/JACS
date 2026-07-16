"""Fail-closed signed-event delivery through an application-owned replay store.

The native binding verifies the complete signed envelope and freshness first,
but intentionally returns no payload. This module releases the payload only
after a caller-provided shared store atomically accepts the native replay key.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import json
import logging
import math
import re
import time
from datetime import datetime
from typing import (
    Any,
    Awaitable,
    Callable,
    Literal,
    ParamSpec,
    Protocol,
    TypeVar,
    TypedDict,
)

from . import JacsAgent, SimpleAgent
from .types import VerificationError

LOGGER = logging.getLogger("jacs.security")
_P = ParamSpec("_P")
_T = TypeVar("_T")

ReplayErrorCode = Literal[
    "replay_duplicate",
    "replay_store_unavailable",
    "replay_store_timeout",
    "replay_store_invalid_result",
    "replay_store_not_shared",
    "signed_event_expired",
]

REPLAY_ERROR_CODES: tuple[ReplayErrorCode, ...] = (
    "replay_duplicate",
    "replay_store_unavailable",
    "replay_store_timeout",
    "replay_store_invalid_result",
    "replay_store_not_shared",
    "signed_event_expired",
)

_PREPARATION_FIELDS = frozenset(
    {
        "contractVersion",
        "status",
        "cryptographicallyVerified",
        "freshnessVerified",
        "replayConsumed",
        "signerId",
        "timestamp",
        "algorithm",
        "documentId",
        "eventSha256",
        "replayKey",
        "replayTtlSeconds",
        "expiresAtUnixSeconds",
    }
)
_MAX_U64 = (1 << 64) - 1
_MAX_FUTURE_TIMESTAMP_SECONDS = 300
_RFC3339_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


class ReplayError(VerificationError):
    """Stable external replay-contract failure.

    ``code`` is one of the values in ``REPLAY_ERROR_CODES`` and is suitable for
    application error mapping without parsing the human-readable message.
    Backend exceptions are deliberately not chained onto this public error.
    """

    def __init__(self, code: ReplayErrorCode, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class SharedReplayStore(Protocol):
    """Atomic replay store shared by every replica serving the trust boundary.

    ``scope`` must be exactly ``"shared"`` and ``name`` must be a nonblank
    operational identifier. The name is validated but never copied into errors.
    Async implementations must yield during backend I/O; synchronous methods
    run in a worker thread and should honor their own network deadline.
    """

    scope: Literal["shared"]
    name: str

    def consume(self, key: str, ttl_seconds: int) -> bool | Awaitable[bool]:
        """Return literal ``True`` once; return ``False`` for a duplicate."""


class VerifiedSignedEvent(TypedDict):
    status: Literal["verified"]
    verified: Literal[True]
    replayConsumed: Literal[True]
    data: Any
    signerId: str
    timestamp: str
    algorithm: str
    documentId: str


def _warn_on_replay_rejection(
    function: Callable[_P, Awaitable[_T]],
) -> Callable[_P, Awaitable[_T]]:
    @functools.wraps(function)
    async def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return await function(*args, **kwargs)
        except ReplayError as error:
            LOGGER.warning(
                "JACS signed-event replay delivery rejected",
                extra={
                    "event": "jacs_security_outcome",
                    "operation": "signed_event_replay",
                    "outcome": "rejected",
                    "error_code": error.code,
                },
            )
            raise

    return wrapped


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> None:
    raise ValueError(f"non-JSON numeric value: {value}")


def _strict_json_loads(raw: str) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_duplicate_rejecting_object,
        parse_constant=_reject_non_json_number,
    )


def _invalid_result(message: str) -> ReplayError:
    return ReplayError("replay_store_invalid_result", message)


def _require_non_empty_string(claim: dict[str, Any], field: str) -> str:
    value = claim.get(field)
    if not isinstance(value, str) or not value:
        raise _invalid_result(
            f"native replay preparation field {field!r} must be a non-empty string"
        )
    return value


def _require_positive_integer(
    claim: dict[str, Any], field: str, *, maximum: int = _MAX_U64
) -> int:
    value = claim.get(field)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > maximum
    ):
        raise _invalid_result(
            f"native replay preparation field {field!r} must be a positive "
            f"integer no greater than {maximum}"
        )
    return value


def _parse_rfc3339_unix_seconds(value: str) -> int:
    if _RFC3339_PATTERN.fullmatch(value) is None:
        raise _invalid_result(
            "native replay preparation returned an invalid RFC 3339 timestamp"
        )
    normalized = value
    if value[-1] == "Z":
        normalized = f"{value[:-1]}+00:00"
    try:
        timestamp = datetime.fromisoformat(normalized)
        unix_seconds = math.floor(timestamp.timestamp())
    except (OverflowError, ValueError):
        timestamp = None
        unix_seconds = -1
    if timestamp is None or timestamp.tzinfo is None or unix_seconds < 0:
        raise _invalid_result(
            "native replay preparation returned an invalid RFC 3339 timestamp"
        )
    return unix_seconds


def _expected_replay_key(signer_id: str, document_id: str) -> str:
    replay_scope = f"signed-event:{signer_id}"
    try:
        scope_length = len(replay_scope.encode("utf-8"))
    except UnicodeEncodeError:
        raise _invalid_result(
            "native replay preparation signer ID is not valid UTF-8"
        ) from None
    return f"jacs-replay-v1:{scope_length}:{replay_scope}:{document_id}"


def _validate_preparation(
    prepared: Any,
    event_json: str,
    max_age_seconds: int,
    now_unix_seconds: int,
) -> dict[str, Any]:
    if not isinstance(prepared, dict):
        raise _invalid_result("native replay preparation must be a JSON object")
    if set(prepared) != _PREPARATION_FIELDS:
        missing = sorted(_PREPARATION_FIELDS - set(prepared))
        unexpected = sorted(set(prepared) - _PREPARATION_FIELDS)
        raise _invalid_result(
            "native replay preparation fields do not match contract v1 "
            f"(missing={missing}, unexpected={unexpected})"
        )
    contract_version = prepared.get("contractVersion")
    if (
        isinstance(contract_version, bool)
        or not isinstance(contract_version, int)
        or contract_version != 1
    ):
        raise _invalid_result("unsupported native replay preparation contractVersion")
    if prepared.get("status") != "crypto_verified_replay_pending":
        raise _invalid_result("native replay preparation status is not pending")
    if prepared.get("cryptographicallyVerified") is not True:
        raise _invalid_result(
            "native replay preparation is not cryptographically verified"
        )
    if prepared.get("freshnessVerified") is not True:
        raise _invalid_result("native replay preparation is not freshness verified")
    if prepared.get("replayConsumed") is not False:
        raise _invalid_result(
            "native replay preparation already claims replay consumption"
        )

    for field in ("signerId", "timestamp", "algorithm", "documentId", "replayKey"):
        _require_non_empty_string(prepared, field)
    replay_ttl_seconds = _require_positive_integer(prepared, "replayTtlSeconds")
    expires_at_unix_seconds = _require_positive_integer(
        prepared, "expiresAtUnixSeconds"
    )

    digest = _require_non_empty_string(prepared, "eventSha256")
    expected_digest = hashlib.sha256(event_json.encode("utf-8")).hexdigest()
    if digest != expected_digest:
        raise _invalid_result(
            "native replay preparation digest does not match the exact event input"
        )
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise _invalid_result(
            "native replay preparation digest is not lowercase SHA-256"
        )

    expected_replay_key = _expected_replay_key(
        prepared["signerId"], prepared["documentId"]
    )
    if prepared["replayKey"] != expected_replay_key:
        raise _invalid_result(
            "native replay preparation replay key does not match signer and document"
        )

    issued_at_unix_seconds = _parse_rfc3339_unix_seconds(prepared["timestamp"])
    expected_expiry = issued_at_unix_seconds + max_age_seconds
    if expected_expiry > _MAX_U64 or expires_at_unix_seconds != expected_expiry:
        raise _invalid_result(
            "native replay preparation expiry does not match timestamp plus max_age_seconds"
        )
    if now_unix_seconds < 0:
        raise _invalid_result("system clock predates the Unix epoch")
    if issued_at_unix_seconds > now_unix_seconds + _MAX_FUTURE_TIMESTAMP_SECONDS:
        raise _invalid_result(
            "native replay preparation timestamp exceeds the allowed future skew"
        )
    if now_unix_seconds > expires_at_unix_seconds:
        raise ReplayError(
            "signed_event_expired",
            "signed event expired before replay consumption",
        )

    minimum_safe_ttl = expires_at_unix_seconds - now_unix_seconds + 1
    maximum_native_ttl = min(
        _MAX_U64,
        max_age_seconds + _MAX_FUTURE_TIMESTAMP_SECONDS + 1,
    )
    if replay_ttl_seconds < minimum_safe_ttl:
        raise _invalid_result(
            "native replay preparation TTL ends before the signed event absolute expiry"
        )
    if replay_ttl_seconds > maximum_native_ttl:
        raise _invalid_result(
            "native replay preparation TTL exceeds the bounded freshness window"
        )

    return prepared


def _ensure_not_expired(expires_at_unix_seconds: int) -> None:
    if math.floor(time.time()) > expires_at_unix_seconds:
        raise ReplayError(
            "signed_event_expired",
            "signed event expired before verified payload release",
        )


async def _consume_shared_store(
    store: SharedReplayStore,
    key: str,
    ttl_seconds: int,
    timeout_seconds: float,
) -> bool:
    consume_lookup_failed = False
    try:
        consume = getattr(store, "consume")
    except Exception:
        consume_lookup_failed = True
        consume = None
    if consume_lookup_failed:
        raise ReplayError(
            "replay_store_unavailable",
            "shared replay store has no usable consume method",
        )
    if not callable(consume):
        raise ReplayError(
            "replay_store_unavailable", "shared replay store consume is not callable"
        )

    async def call_consume() -> Any:
        if inspect.iscoroutinefunction(consume):
            return await consume(key, ttl_seconds)
        result = await asyncio.to_thread(consume, key, ttl_seconds)
        if inspect.isawaitable(result):
            return await result
        return result

    failure: ReplayError | None = None
    try:
        result = await asyncio.wait_for(call_consume(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        result = None
        failure = ReplayError(
            "replay_store_timeout",
            f"shared replay store did not respond within {timeout_seconds:g} seconds",
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        result = None
        failure = ReplayError(
            "replay_store_unavailable", "shared replay store consume failed"
        )

    if failure is not None:
        raise failure

    if result is False:
        raise ReplayError(
            "replay_duplicate", "signed event replay key was already consumed"
        )
    if result is not True:
        raise ReplayError(
            "replay_store_invalid_result",
            "shared replay store consume must return literal True or False",
        )
    return True


@_warn_on_replay_rejection
async def unwrap_signed_event_with_replay_store(
    agent: JacsAgent | SimpleAgent,
    event_json: str,
    server_keys_json: str,
    replay_store: SharedReplayStore,
    *,
    max_age_seconds: int = 300,
    store_timeout_seconds: float = 5.0,
) -> VerifiedSignedEvent:
    """Verify and release one signed event through a shared atomic store.

    ``agent`` must be an actual native :class:`JacsAgent` or
    :class:`SimpleAgent`; objects that merely provide a similarly named method
    are rejected before preparation.

    The exact event string is retained unchanged. Native code verifies its
    signature, trusted signer key, complete envelope metadata, and freshness on
    a worker thread. Python validates the payload-free preparation claim, then
    atomically consumes its native replay key. Payload parsing happens only
    after a literal ``True`` result and a second expiry check.
    """

    if not isinstance(event_json, str) or not isinstance(server_keys_json, str):
        raise TypeError("event_json and server_keys_json must be strings")
    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or max_age_seconds <= 0
        or max_age_seconds > _MAX_U64
    ):
        raise ValueError(
            f"max_age_seconds must be a positive integer no greater than {_MAX_U64}"
        )
    if (
        isinstance(store_timeout_seconds, bool)
        or not isinstance(store_timeout_seconds, (int, float))
        or not math.isfinite(store_timeout_seconds)
        or store_timeout_seconds <= 0
    ):
        raise ValueError("store_timeout_seconds must be a positive finite number")

    store_identity_lookup_failed = False
    try:
        scope = getattr(replay_store, "scope", None)
        store_name = getattr(replay_store, "name", None)
    except Exception:
        store_identity_lookup_failed = True
        scope = None
        store_name = None
    if store_identity_lookup_failed:
        raise ReplayError(
            "replay_store_unavailable",
            "shared replay store metadata could not be read",
        )
    if scope != "shared":
        raise ReplayError(
            "replay_store_not_shared",
            "replay store must declare scope == 'shared'",
        )
    if not isinstance(store_name, str) or not store_name.strip():
        raise ReplayError(
            "replay_store_invalid_result",
            "shared replay store must provide a nonblank string name",
        )

    if not isinstance(agent, (JacsAgent, SimpleAgent)):
        raise _invalid_result(
            "agent must be a native JacsAgent or SimpleAgent instance"
        )
    prepare = agent.prepare_signed_event_replay

    exact_event_json = event_json
    prepared_json = await asyncio.to_thread(
        prepare,
        exact_event_json,
        server_keys_json,
        max_age_seconds,
    )
    if not isinstance(prepared_json, str):
        raise _invalid_result("native replay preparation must return a JSON string")
    try:
        prepared_value = _strict_json_loads(prepared_json)
    except ReplayError:
        raise
    except Exception:
        prepared_value = None
    if prepared_value is None:
        raise _invalid_result("native replay preparation returned invalid JSON")
    prepared = _validate_preparation(
        prepared_value,
        exact_event_json,
        max_age_seconds,
        math.floor(time.time()),
    )

    expires_at = prepared["expiresAtUnixSeconds"]
    _ensure_not_expired(expires_at)
    await _consume_shared_store(
        replay_store,
        prepared["replayKey"],
        prepared["replayTtlSeconds"],
        float(store_timeout_seconds),
    )
    _ensure_not_expired(expires_at)

    try:
        envelope = _strict_json_loads(exact_event_json)
    except Exception:
        envelope = None
    if envelope is None:
        raise _invalid_result("verified signed event could not be parsed after consume")
    if not isinstance(envelope, dict) or "data" not in envelope:
        raise _invalid_result("verified signed event has no data field after consume")

    return {
        "status": "verified",
        "verified": True,
        "replayConsumed": True,
        "data": envelope["data"],
        "signerId": prepared["signerId"],
        "timestamp": prepared["timestamp"],
        "algorithm": prepared["algorithm"],
        "documentId": prepared["documentId"],
    }


__all__ = [
    "REPLAY_ERROR_CODES",
    "ReplayError",
    "ReplayErrorCode",
    "SharedReplayStore",
    "VerifiedSignedEvent",
    "unwrap_signed_event_with_replay_store",
]
