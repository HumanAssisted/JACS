#!/usr/bin/env python3
"""Preserve the public Go module path while native Rust stays isolated.

The retained compatibility Go implementation is mirrored into jacsgo for Go's
subdirectory tags. No native Cargo manifest or build output is copied there.
"""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "archive/native/jacsgo"
DESTINATION = ROOT / "jacsgo"


def files():
    selected = {path.relative_to(SOURCE): path for path in SOURCE.glob("*.go")
                if not path.name.endswith("_test.go")}
    for path in (SOURCE / "cmd").rglob("*.go"):
        selected[path.relative_to(SOURCE)] = path
    for name in ("go.mod", "go.sum", "jacs_cgo.h"):
        selected[Path(name)] = SOURCE / name
    for name in ("LICENSE-APACHE", "THIRD-PARTY-NOTICES"):
        selected[Path(name)] = ROOT / "archive/native" / name
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for relative, source in files().items():
        destination = DESTINATION / relative
        data = source.read_bytes()
        if destination.exists() and destination.read_bytes() == data:
            continue
        if args.check:
            stale.append(str(relative))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    if stale:
        print("Go public module is stale: " + ", ".join(stale), file=sys.stderr)
        print("Run python3 scripts/native_bindings_sync_go.py", file=sys.stderr)
        return 1
    print("OK: public jacsgo module matches the native compatibility API")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
