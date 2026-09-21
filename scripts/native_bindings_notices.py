#!/usr/bin/env python3
"""Regenerate/check native notices and the restored Go distribution copies."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "archive/native"
GO_COPIES = (NATIVE / "jacsgo/lib/THIRD-PARTY-NOTICES",
             ROOT / "jacsgo/THIRD-PARTY-NOTICES")


def sync_copies(canonical: Path, copies: tuple[Path, ...], *, write: bool) -> bool:
    expected = canonical.read_bytes()
    current = True
    for path in copies:
        if path.is_file() and path.read_bytes() == expected:
            continue
        if write:
            path.write_bytes(expected)
            print(f"updated {path}")
        else:
            current = False
            print(f"ERROR: {path} is stale; run make third-party-notices", file=sys.stderr)
    return current


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = subprocess.run([sys.executable, str(NATIVE / "scripts/third_party_notices.py"),
                             "--write" if args.write else "--check"], cwd=NATIVE)
    if result.returncode:
        return result.returncode
    return 0 if sync_copies(NATIVE / "THIRD-PARTY-NOTICES", GO_COPIES, write=args.write) else 1


if __name__ == "__main__":
    raise SystemExit(main())
