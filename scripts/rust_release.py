#!/usr/bin/env python3
"""Prepare all Rust candidates together, then publish their exact verified bytes.

The disposable release workspace combines the two source workspaces only for
packaging. The checked-in portable dependency boundary remains unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib

try:
    from crates_release_gate import fetch_exact_version_checksum, verify_archive_checksum, wait_for_version
    from release_catalog import CRATES, CRATE_MANIFESTS
    from release_tag import validate_semver
except ModuleNotFoundError:
    from scripts.crates_release_gate import fetch_exact_version_checksum, verify_archive_checksum, wait_for_version
    from scripts.release_catalog import CRATES, CRATE_MANIFESTS
    from scripts.release_tag import validate_semver

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCKS = ("Cargo.lock", "archive/native/Cargo.lock", "archive/native/jacs-surrealdb/Cargo.lock")


def run(command, *, cwd=ROOT, capture=False):
    result = subprocess.run(command, cwd=cwd, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else None


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_sources(root, version):
    validate_semver(version)
    seen = set()
    for name, relative in CRATE_MANIFESTS.items():
        data = tomllib.loads((root / relative).read_text())
        package = data["package"]
        if package["name"] != name or package["version"] != version or package.get("publish") is False:
            raise ValueError(f"{relative}: expected publishable {name}@{version}")
        sections = [data.get("dependencies", {}), data.get("build-dependencies", {})]
        for target in data.get("target", {}).values():
            sections.extend([target.get("dependencies", {}), target.get("build-dependencies", {})])
        for section in sections:
            for alias, dependency in section.items():
                if not isinstance(dependency, dict) or "path" not in dependency:
                    continue
                actual = dependency.get("package", alias)
                if actual not in seen:
                    raise ValueError(f"{name}: local dependency {actual} must be published earlier")
                if dependency.get("version", "").lstrip("=^") != version:
                    raise ValueError(f"{name}: {actual} needs a registry version as well as its path")
                expected_path = (root / CRATE_MANIFESTS[actual]).parent.resolve()
                if ((root / relative).parent / dependency["path"]).resolve() != expected_path:
                    raise ValueError(f"{name}: {actual} local dependency path mismatch")
        seen.add(name)


def third_party(lock):
    return {(p["name"], p["version"], p["source"], p.get("checksum"))
            for p in lock.get("package", []) if "source" in p}


def vendor_reviewed_dependencies(source, output):
    """Resolve only versions/checksums already reviewed in a source workspace.

    Separate workspaces can lock different compatible versions of the same
    dependency. Combining their lockfile edges is invalid. A directory source
    containing their exact union lets Cargo select a coherent graph without
    admitting a newly released or merely cached third-party version.
    """
    allowed = set()
    for relative in SOURCE_LOCKS:
        lock = tomllib.loads((source / relative).read_text())
        allowed.update(third_party(lock))
    identities = {}
    for name, version, registry, checksum in allowed:
        key = (name, version, registry)
        if key in identities and identities[key] != checksum:
            raise ValueError(f"inconsistent source checksums for {key}")
        identities[key] = checksum
    # Fetching is deliberately allowed here: a fresh CI cache must work. Cargo's
    # --locked gate and archive checksums bind downloads to the reviewed locks.
    standalone_manifests = {}
    try:
        # An excluded package without its own [workspace] can discover the
        # outer checkout when this source copy lives below its target directory.
        # Give each separately locked package an explicit boundary for vendoring
        # only. Restore exact bytes before assembling the combined candidate.
        for relative in SOURCE_LOCKS:
            manifest = (source / relative).with_name("Cargo.toml")
            original = manifest.read_bytes()
            if "workspace" not in tomllib.loads(original.decode()):
                standalone_manifests[manifest] = original
                manifest.write_bytes(original + b"\n[workspace]\n")
        configuration = run([
            "cargo", "vendor", "--locked", "--versioned-dirs",
            "--sync", "archive/native/Cargo.toml",
            "--sync", "archive/native/jacs-surrealdb/Cargo.toml", str(output / "vendor"),
        ], cwd=source, capture=True)
    finally:
        for manifest, original in standalone_manifests.items():
            manifest.write_bytes(original)
    config_path = output / "vendor-config.toml"
    config_path.write_text(configuration)
    return allowed, config_path


def supplement_native_notices(source):
    """Cover portable versions selected by the combined release graph.

    The two source workspaces retain their own locked inventories. Their union
    can select a compatible portable version for a native dependency, so native
    Rust release candidates carry both reviewed inventories and license texts.
    Only the disposable candidate is changed; source and binding notices remain
    tied to the workspaces that build those artifacts.
    """
    marker = "===== PORTABLE WORKSPACE NOTICES FOR COMBINED RUST RELEASE ====="
    portable = (source / "THIRD-PARTY-NOTICES").read_text()
    for relative in CRATE_MANIFESTS.values():
        if not relative.startswith("archive/native/"):
            continue
        path = (source / relative).parent / "THIRD-PARTY-NOTICES"
        native = path.read_text()
        if marker not in native:
            path.write_text(native.rstrip() + "\n\n" + marker + "\n\n" + portable)


def prepare(root, output, version, allow_dirty=False):
    validate_sources(root, version)
    dirty = run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root, capture=True).strip()
    if dirty and not allow_dirty:
        raise ValueError("commit the reviewed candidate before preparing publication")
    if output.exists():
        raise ValueError(f"output already exists: {output}; choose a fresh candidate directory")
    output.mkdir(parents=True)
    source = output / "source"
    source.mkdir()
    # Local qualification may include current edits. CI always requires clean,
    # committed inputs, and only those candidates can enter publish-one.
    files = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root, capture=True)
    for relative in set(files.split("\0")) - {""}:
        path = root / relative
        if not path.exists():
            continue
        if path.is_symlink() and (not path.resolve().is_relative_to(root.resolve()) or not path.is_file()):
            raise ValueError(f"source symlink must resolve to a file inside the repository: {relative}")
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    allowed, vendor_config = vendor_reviewed_dependencies(source, output)
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    members = [str(Path(path).parent) for path in CRATE_MANIFESTS.values()]
    text = "[workspace]\nresolver = \"3\"\nmembers = " + json.dumps(members) + "\n"
    text += 'exclude = ["archive/native/jacs/examples/observability"]\n\n[workspace.package]\n'
    text += "\n".join(f"{key} = {json.dumps(value)}" for key, value in workspace["package"].items()) + "\n"
    (source / "Cargo.toml").write_text(text)
    (source / "archive/native/Cargo.toml").unlink()
    # Keep the portable lock as a coherent starting graph. Cargo adds native
    # packages from the reviewed vendor set without upgrading compatible
    # portable versions or invalidating their dependency notices.
    # Resolve workspace membership using only source-pinned third-party packages.
    run(["cargo", "metadata", "--offline", "--config", str(vendor_config), "--format-version", "1"], cwd=source, capture=True)
    resolved = tomllib.loads((source / "Cargo.lock").read_text())
    unexpected = third_party(resolved) - allowed
    if unexpected:
        raise ValueError(f"release workspace introduced unreviewed dependencies: {sorted(unexpected)}")
    portable = third_party(tomllib.loads((root / "Cargo.lock").read_text()))
    if not portable <= third_party(resolved):
        raise ValueError("release workspace changed reviewed portable dependency versions")
    supplement_native_notices(source)
    state = {"version": version, "source_commit": run(["git", "rev-parse", "HEAD"], cwd=root, capture=True).strip(),
             "publishable": not bool(dirty), "crates": list(CRATES),
             "source_lock_sha256": {relative: sha256(root / relative) for relative in SOURCE_LOCKS},
             "candidate_lock_sha256": sha256(source / "Cargo.lock")}
    (output / "candidate.json").write_text(json.dumps(state, indent=2) + "\n")
    print(f"Prepared {len(CRATES)} crates at {source}")


def cargo_environment(output):
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(output / "cargo")
    env["CARGO_BUILD_TARGET_DIR"] = env["CARGO_TARGET_DIR"]
    env["CARGO_BUILD_BUILD_DIR"] = str(output / "build")
    return env


def load_candidate(output):
    state = json.loads((output / "candidate.json").read_text())
    validate_semver(state["version"])
    if state["crates"] != list(CRATES):
        raise ValueError("candidate crate inventory differs from the release catalog")
    if sha256(output / "source/Cargo.lock") != state["candidate_lock_sha256"]:
        raise ValueError("reviewed candidate dependency lock changed")
    return state


def validate_archive(archive, name, version):
    prefix = f"{name}-{version}/"
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if any(not member.name.startswith(prefix) or not member.isfile()
               or ".." in Path(member.name).parts for member in members):
            raise ValueError(f"{name}: unsupported archive path or file type")
        names = {member.name.removeprefix(prefix) for member in members}
        required = {"Cargo.toml", "Cargo.lock", "LICENSE-APACHE", "THIRD-PARTY-NOTICES"}
        if not required <= names:
            raise ValueError(f"{name}: archive missing {sorted(required - names)}")
        manifest = tomllib.loads(bundle.extractfile(prefix + "Cargo.toml").read().decode())
        if manifest["package"]["name"] != name or manifest["package"]["version"] != version:
            raise ValueError(f"{name}: archive package identity mismatch")
        lock = tomllib.loads(bundle.extractfile(prefix + "Cargo.lock").read().decode())
        notices = bundle.extractfile(prefix + "THIRD-PARTY-NOTICES").read().decode()
        recorded = set(re.findall(r"(?m)^\s+-\s+(\S+)\s+(\S+)\s+\(", notices))
        missing = {(package["name"], package["version"]) for package in lock.get("package", [])
                   if "source" in package and package["name"] not in CRATES} - recorded
        if missing:
            raise ValueError(f"{name}: dependency notices omit packaged versions {sorted(missing)}")
        return lock


def validate_packaged_dependencies(lock, allowed, checksums, version):
    for package in lock.get("package", []):
        if "source" not in package:
            continue
        name = package["name"]
        if name in CRATES and package["version"] == version:
            if package.get("checksum") != checksums[f"{name}-{version}.crate"]:
                raise ValueError(f"packaged lock differs from reviewed {name} candidate checksum")
        elif (name, package["version"], package["source"], package.get("checksum")) not in allowed:
            raise ValueError(f"packaged lock introduced an unreviewed {name}@{package['version']}")


def package_all(output):
    state = load_candidate(output)
    env = cargo_environment(output)
    # Cargo packages the whole graph before compiling its extracted candidates
    # against a temporary registry. No real upload is needed for these checks.
    subprocess.run(["cargo", "package", "--workspace", "--locked"],
                   cwd=output / "source", env=env, check=True)
    archives = output / "archives"
    extracted = output / "extracted"
    archives.mkdir()
    extracted.mkdir()
    checksums = {}
    locks = []
    for name in CRATES:
        filename = f"{name}-{state['version']}.crate"
        archive = output / "cargo/package" / filename
        locks.append(validate_archive(archive, name, state["version"]))
        shutil.copy2(archive, archives / filename)
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(extracted, filter="data")
        checksums[filename] = sha256(archive)
    allowed = third_party(tomllib.loads((output / "source/Cargo.lock").read_text()))
    for lock in locks:
        validate_packaged_dependencies(lock, allowed, checksums, state["version"])
    (output / "checksums.json").write_text(json.dumps(checksums, indent=2) + "\n")
    (output / "sha256sums.txt").write_text("".join(f"{digest}  {name}\n" for name, digest in checksums.items()))


def publish_one(output, name):
    state = load_candidate(output)
    if not state["publishable"]:
        raise ValueError("dirty-source qualification candidates cannot be published")
    version = state["version"]
    archive = output / "archives" / f"{name}-{version}.crate"
    checksums = json.loads((output / "checksums.json").read_text())
    if sha256(archive) != checksums[archive.name]:
        raise ValueError("reviewed candidate checksum changed")
    manifest = CRATE_MANIFESTS[name]
    env = cargo_environment(output)
    # Cargo verifies the normalized registry package with the dependencies
    # already published earlier in the catalog, before each irreversible upload.
    subprocess.run(["cargo", "package", "--locked", "--manifest-path", manifest],
                   cwd=output / "source", env=env, check=True)
    repacked = output / "cargo/package" / archive.name
    if sha256(repacked) != checksums[archive.name]:
        raise ValueError(f"{name}: verified package differs from the complete reviewed candidate set")
    existing = fetch_exact_version_checksum(name, version)
    if existing is None:
        result = subprocess.run(["cargo", "publish", "--locked", "--manifest-path", manifest],
                                cwd=output / "source", env=env)
        if result.returncode and fetch_exact_version_checksum(name, version) is None:
            raise ValueError(f"{name}: cargo publish failed")
    wait_for_version(name, version)
    verify_archive_checksum(name, version, archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "prepare", "package", "publish-one"))
    parser.add_argument("--version")
    parser.add_argument("--output", type=Path, default=ROOT / "target/crate-release")
    parser.add_argument("--crate", choices=CRATES)
    parser.add_argument("--allow-dirty", action="store_true", help="local qualification only; publication is forbidden")
    args = parser.parse_args()
    output = args.output.resolve()
    try:
        if args.action in {"prepare", "validate"}:
            if not args.version:
                parser.error("--version is required")
            if args.action == "validate":
                validate_sources(ROOT, args.version)
            else:
                prepare(ROOT, output, args.version, args.allow_dirty)
        elif args.action == "package":
            package_all(output)
        else:
            if not args.crate:
                parser.error("--crate is required")
            publish_one(output, args.crate)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Rust release rejected: {error}\n")


if __name__ == "__main__":
    main()
