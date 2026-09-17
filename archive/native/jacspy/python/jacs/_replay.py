"""Shared replay-protection helpers for JACS auth middleware."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

DEFAULT_MAX_AGE_SECONDS = 30
DEFAULT_CLOCK_SKEW_SECONDS = 5


def _normalize_non_negative_int(value: Any, fallback: int) -> int:
    if not isinstance(value, int) or value < 0:
        return fallback
    return int(value)


def _verification_field(verification: Any, *names: str) -> str:
    if verification is None:
        return ""

    for name in names:
        if isinstance(verification, dict):
            value = verification.get(name)
        else:
            value = getattr(verification, name, None)
        if isinstance(value, str) and value:
            return value
    return ""


def _parse_timestamp(timestamp: str) -> Optional[datetime]:
    if not timestamp:
        return None

    value = timestamp.strip()
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class AuthReplayOptions:
    enabled: bool
    max_age_seconds: int
    clock_skew_seconds: int
    cache_ttl_seconds: int


def build_auth_replay_options(
    enabled: bool = False,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    cache_ttl_seconds: Optional[int] = None,
) -> AuthReplayOptions:
    max_age = _normalize_non_negative_int(max_age_seconds, DEFAULT_MAX_AGE_SECONDS)
    skew = _normalize_non_negative_int(
        clock_skew_seconds, DEFAULT_CLOCK_SKEW_SECONDS
    )
    default_ttl = max_age + skew
    ttl_fallback = default_ttl if default_ttl > 0 else 1
    ttl = _normalize_non_negative_int(cache_ttl_seconds, ttl_fallback)
    if ttl <= 0:
        ttl = 1

    return AuthReplayOptions(
        enabled=enabled,
        max_age_seconds=max_age,
        clock_skew_seconds=skew,
        cache_ttl_seconds=ttl,
    )


class InMemoryReplayCache:
    """Simple in-memory replay cache with lazy TTL pruning."""

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune(self, now_seconds: float) -> None:
        expired = [key for key, exp in self._seen.items() if exp <= now_seconds]
        for key in expired:
            self._seen.pop(key, None)

    def check_and_remember(
        self,
        key: str,
        now_seconds: float,
        ttl_seconds: float,
    ) -> bool:
        with self._lock:
            self._prune(now_seconds)

            existing_expiry = self._seen.get(key)
            if existing_expiry is not None and existing_expiry > now_seconds:
                return True

            self._seen[key] = now_seconds + max(float(ttl_seconds), 1.0)
            return False


def check_auth_replay(
    raw_body: str,
    verification: Any,
    replay_cache: InMemoryReplayCache,
    options: AuthReplayOptions,
) -> Optional[str]:
    try:
        envelope = json.loads(raw_body)
    except json.JSONDecodeError:
        return "replay protection requires a valid JSON JACS document"

    if not isinstance(envelope, dict):
        return "replay protection requires a valid JSON JACS document"

    sig = envelope.get("jacsSignature")
    if not isinstance(sig, dict):
        sig = {}

    signer_id = (
        _verification_field(verification, "signer_id", "signerId")
        or sig.get("agentID")
        or sig.get("agentId")
        or ""
    )
    timestamp = (
        _verification_field(verification, "timestamp")
        or sig.get("date")
        or ""
    )
    signature = sig.get("signature") or ""

    if not signer_id:
        return "replay protection requires signerId"
    if not timestamp:
        return "replay protection requires signature timestamp"
    if not signature:
        return "replay protection requires signature value"

    timestamp_utc = _parse_timestamp(timestamp)
    if timestamp_utc is None:
        return f"replay protection found invalid timestamp '{timestamp}'"

    now_utc = datetime.now(timezone.utc)
    age_seconds = (now_utc - timestamp_utc).total_seconds()

    if age_seconds < -options.clock_skew_seconds:
        return "replay protection rejected request with future timestamp"
    if age_seconds > options.max_age_seconds:
        return "replay protection rejected expired request timestamp"

    replay_key = f"{signer_id}:{signature}"
    if replay_cache.check_and_remember(
        replay_key,
        now_seconds=now_utc.timestamp(),
        ttl_seconds=options.cache_ttl_seconds,
    ):
        return "replay protection detected replayed signature"

    return None


__all__ = [
    "AuthReplayOptions",
    "InMemoryReplayCache",
    "build_auth_replay_options",
    "check_auth_replay",
]
