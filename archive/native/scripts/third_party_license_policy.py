#!/usr/bin/env python3
"""Shared source-hash contract for cargo-deny clarifications and notices."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def _rotate_left_32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def xxhash32(data: bytes) -> int:
    """Return cargo-deny's seed-zero XXH32 digest."""

    prime_1 = 0x9E3779B1
    prime_2 = 0x85EBCA77
    prime_3 = 0xC2B2AE3D
    prime_4 = 0x27D4EB2F
    prime_5 = 0x165667B1

    def round_value(accumulator: int, lane: int) -> int:
        accumulator = (accumulator + lane * prime_2) & 0xFFFFFFFF
        accumulator = _rotate_left_32(accumulator, 13)
        return (accumulator * prime_1) & 0xFFFFFFFF

    offset = 0
    if len(data) >= 16:
        accumulator_1 = (prime_1 + prime_2) & 0xFFFFFFFF
        accumulator_2 = prime_2
        accumulator_3 = 0
        accumulator_4 = (-prime_1) & 0xFFFFFFFF
        while offset <= len(data) - 16:
            accumulator_1 = round_value(
                accumulator_1, int.from_bytes(data[offset : offset + 4], "little")
            )
            accumulator_2 = round_value(
                accumulator_2, int.from_bytes(data[offset + 4 : offset + 8], "little")
            )
            accumulator_3 = round_value(
                accumulator_3, int.from_bytes(data[offset + 8 : offset + 12], "little")
            )
            accumulator_4 = round_value(
                accumulator_4, int.from_bytes(data[offset + 12 : offset + 16], "little")
            )
            offset += 16
        digest = (
            _rotate_left_32(accumulator_1, 1)
            + _rotate_left_32(accumulator_2, 7)
            + _rotate_left_32(accumulator_3, 12)
            + _rotate_left_32(accumulator_4, 18)
        ) & 0xFFFFFFFF
    else:
        digest = prime_5

    digest = (digest + len(data)) & 0xFFFFFFFF
    while offset <= len(data) - 4:
        lane = int.from_bytes(data[offset : offset + 4], "little")
        digest = (digest + lane * prime_3) & 0xFFFFFFFF
        digest = (_rotate_left_32(digest, 17) * prime_4) & 0xFFFFFFFF
        offset += 4
    while offset < len(data):
        digest = (digest + data[offset] * prime_5) & 0xFFFFFFFF
        digest = (_rotate_left_32(digest, 11) * prime_1) & 0xFFFFFFFF
        offset += 1

    digest ^= digest >> 15
    digest = (digest * prime_2) & 0xFFFFFFFF
    digest ^= digest >> 13
    digest = (digest * prime_3) & 0xFFFFFFFF
    digest ^= digest >> 16
    return digest & 0xFFFFFFFF


def cargo_deny_license_hash(raw: bytes) -> int:
    """Match cargo-deny 0.19's newline normalization before XXH32."""

    text = raw.decode("utf-8")
    lines = text.split("\n")
    normalized = "".join(f"{line.rstrip(chr(13))}\n" for line in lines[:-1])
    if lines[-1]:
        normalized += f"{lines[-1].rstrip(chr(13))}\n"
    return xxhash32(normalized.encode("utf-8"))


def license_source_hashes(raw: bytes) -> tuple[int, str]:
    """Return cargo-deny's compatibility hash and a strong exact-byte digest."""

    return cargo_deny_license_hash(raw), hashlib.sha256(raw).hexdigest()


def load_reviewed_license_clarifications(
    path: Path,
) -> dict[str, dict[str, object]]:
    """Load and validate the reviewed clarification source contract."""

    with path.open("rb") as handle:
        document = tomllib.load(handle)
    entries = document.get("reviewed")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path} must contain at least one [[reviewed]] entry")

    reviewed: dict[str, dict[str, object]] = {}
    required_keys = {
        "names",
        "expression",
        "path",
        "cargo-deny-hash",
        "sha256",
    }
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != required_keys:
            raise ValueError(
                f"{path} reviewed entry {index} must contain exactly "
                + ", ".join(sorted(required_keys))
            )
        names = entry["names"]
        expression = entry["expression"]
        source_path = entry["path"]
        cargo_deny_hash = entry["cargo-deny-hash"]
        sha256 = entry["sha256"]
        if (
            not isinstance(names, list)
            or not names
            or any(not isinstance(name, str) or not name for name in names)
            or len(set(names)) != len(names)
        ):
            raise ValueError(f"{path} reviewed entry {index} has invalid names")
        if not isinstance(expression, str) or not expression:
            raise ValueError(f"{path} reviewed entry {index} has invalid expression")
        relative_path = Path(source_path) if isinstance(source_path, str) else Path()
        if (
            not isinstance(source_path, str)
            or not source_path
            or relative_path.is_absolute()
            or ".." in relative_path.parts
        ):
            raise ValueError(f"{path} reviewed entry {index} has invalid source path")
        if (
            isinstance(cargo_deny_hash, bool)
            or not isinstance(cargo_deny_hash, int)
            or not 0 <= cargo_deny_hash <= 0xFFFFFFFF
        ):
            raise ValueError(
                f"{path} reviewed entry {index} has invalid cargo-deny hash"
            )
        if not isinstance(sha256, str) or SHA256_PATTERN.fullmatch(sha256) is None:
            raise ValueError(f"{path} reviewed entry {index} has invalid SHA-256")

        value = {
            "expression": expression,
            "sources": {(source_path, cargo_deny_hash, sha256)},
        }
        for name in names:
            if name in reviewed:
                raise ValueError(f"{path} repeats reviewed package {name!r}")
            reviewed[name] = value
    return reviewed
