#!/usr/bin/env python3
"""Build the Python source candidate with only the workspaces it contains."""

from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

try:
    from check_python_package_inventory import inventory_errors
    from native_bindings import pinned_rust_environment
except ModuleNotFoundError:
    from scripts.check_python_package_inventory import inventory_errors
    from scripts.native_bindings import pinned_rust_environment

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "archive/native"


def trim_workspace(source: str, available: set[str]) -> str:
    """Prune absent workspace members without changing package/dependency data."""
    document = tomllib.loads(source)
    workspace = document["workspace"]
    section = re.search(r"(?ms)^\[workspace\]\s*\n.*?(?=^\[|\Z)", source)
    if section is None:
        raise ValueError("source distribution has no workspace section")
    edited = section.group()
    for key in ("members", "default-members"):
        if key not in workspace:
            continue
        retained = [member for member in workspace[key] if member in available]
        if not retained:
            raise ValueError(f"source distribution would have empty {key}")
        if retained == workspace[key]:
            continue
        replacement = f"{key} = [{', '.join(repr(member) for member in retained)}]"
        edited, count = re.subn(rf"(?ms)^{key}\s*=\s*\[.*?\]", replacement, edited)
        if count != 1:
            raise ValueError(f"expected one workspace {key} declaration")
    return source[:section.start()] + edited + source[section.end():]


def normalize_sdist(source: Path, destination: Path, version: str) -> None:
    prefix = f"jacs-{version}"
    license_bytes = (NATIVE / "LICENSE-APACHE").read_bytes()
    notices_bytes = (NATIVE / "THIRD-PARTY-NOTICES").read_bytes()
    # Both notice sets are canonical for their own dependency graphs. Permit
    # portable notices at this one exact path; native notices stay mandatory
    # everywhere else, including the installed Python package.
    overrides = {f"{prefix}/jacs-core/THIRD-PARTY-NOTICES":
                 (ROOT / "jacs-core/THIRD-PARTY-NOTICES").read_bytes()}
    errors = inventory_errors(source, license_bytes, notices_bytes, overrides)
    if errors:
        raise ValueError("; ".join(errors))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(source, "r:gz") as original:
        names = set(original.getnames())
        manifests = {f"{prefix}/Cargo.toml", f"{prefix}/archive/native/Cargo.toml"}
        if not manifests.issubset(names):
            raise ValueError("source distribution is missing a required workspace")
        with destination.open("wb") as stream, gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as output:
                for member in original:
                    body = original.extractfile(member) if member.isfile() else None
                    if member.name in manifests:
                        text = body.read().decode("utf-8")
                        parent = member.name.rsplit("/", 1)[0]
                        candidates = tomllib.loads(text)["workspace"]
                        available = {value for key in ("members", "default-members")
                                     for value in candidates.get(key, [])
                                     if f"{parent}/{value}/Cargo.toml" in names}
                        data = trim_workspace(text, available).encode("utf-8")
                        body = io.BytesIO(data)
                        member.size = len(data)
                    output.addfile(member, body)
                    if body is not None:
                        body.close()
    errors = inventory_errors(destination, license_bytes, notices_bytes, overrides)
    if errors:
        destination.unlink()
        raise ValueError("; ".join(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    version = tomllib.loads((NATIVE / "jacspy/pyproject.toml").read_text())["project"]["version"]
    env = pinned_rust_environment(dict(os.environ))
    with tempfile.TemporaryDirectory(prefix="jacs-sdist-") as directory:
        subprocess.run(["maturin", "sdist", "--out", directory], cwd=NATIVE / "jacspy", env=env, check=True)
        source = Path(directory) / f"jacs-{version}.tar.gz"
        destination = args.out.resolve() / source.name
        normalize_sdist(source, destination, version)
        print(f"OK: Python source candidate: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
