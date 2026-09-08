#!/usr/bin/env python3
"""Allow reduced-workspace lock pruning without accepting new dependency bytes."""

import argparse
from pathlib import Path
import tomllib


def check_subset(packaged, resolved):
    def identities(lock):
        return {(item["name"], item["version"], item.get("source"), item.get("checksum"))
                for item in lock["package"]}

    before, after = identities(packaged), identities(resolved)
    if not after:
        raise ValueError("resolved source-distribution lock contains no packages")
    added = after - before
    if added:
        raise ValueError(f"source-distribution resolution changed package identities/checksums: {sorted(added, key=repr)}")
    return len(before - after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packaged", type=Path)
    parser.add_argument("resolved", type=Path)
    args = parser.parse_args()
    removed = check_subset(tomllib.loads(args.packaged.read_text()), tomllib.loads(args.resolved.read_text()))
    print(f"CARGO-LOCK-SUBSET-OK ({removed} unused package identities pruned; no added or changed dependency bytes)")


if __name__ == "__main__":
    main()
