#!/usr/bin/env python3
"""Enforce the portable product boundary from Cargo's resolved graph."""
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ACTIVE = {"jacs-core", "jacs-wasm", "jacs-mobile", "jacs-mcp", "jacs-cli"}
FORBIDDEN = {
    "jacs", "jacs-binding-core", "jacs-media", "jacs-duckdb", "jacs-redb",
    "jacs-postgresql", "jacs-surrealdb", "object_store", "reqwest", "mail-parser",
    "hickory-resolver", "sqlx", "duckdb", "surrealdb", "keyring",
    "opentelemetry-otlp",
}

def validate(metadata):
    packages = {p["id"]: p for p in metadata["packages"]}
    members = {packages[i]["name"] for i in metadata["workspace_members"]}
    if members != ACTIVE:
        raise ValueError(f"active workspace must be {sorted(ACTIVE)}, got {sorted(members)}")
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    todo = list(metadata["workspace_members"])
    seen = set()
    while todo:
        key = todo.pop()
        if key in seen:
            continue
        seen.add(key)
        package = packages[key]
        if package["name"] in FORBIDDEN or "archive/native" in package["manifest_path"]:
            raise ValueError(f"archived integration reached from active graph: {package['name']}")
        todo.extend(nodes[key]["dependencies"])
    archive = ROOT / "archive/native/Cargo.toml"
    manifest = tomllib.loads(archive.read_text())
    for relative in manifest["workspace"]["members"] + manifest["workspace"].get("exclude", []):
        package = tomllib.loads((archive.parent / relative / "Cargo.toml").read_text())["package"]
        if package.get("publish") is not False:
            raise ValueError(f"archived package must be publish=false: {relative}")
    return len(seen)

def main():
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        count = validate(json.loads(result.stdout))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        return 1
    print(f"OK: five active crates, {count} resolved packages, no archived integrations")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
