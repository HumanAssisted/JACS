#!/usr/bin/env python3
"""Offline, validated release-version updates for every published JACS package.

All edits are prepared and parsed before any file is staged. Replacements are
atomic per file; this is not a transaction across a process/power interruption.
Cargo.lock third-party versions and checksums are preserved exactly. Portable
and native packages share one release version without sharing a workspace.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import tomllib

# A plan must not create even incidental bytecode-cache files.
sys.dont_write_bytecode = True
try:
    from release_catalog import CRATE_MANIFESTS
except ModuleNotFoundError:
    from scripts.release_catalog import CRATE_MANIFESTS

CRATES = ("jacs-core", "jacs-wasm", "jacs-mobile", "jacs-mcp", "jacs-cli")
ARCHIVE_LOCKS = (
    "archive/native/Cargo.lock",
    "archive/native/jacs/examples/observability/Cargo.lock",
    "archive/native/jacs-surrealdb/Cargo.lock",
)
SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def replace_once(pattern, replacement, text, label):
    result, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    require(count == 1, f"{label}: expected one unambiguous version field")
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_json(text):
    return json.loads(text, object_pairs_hook=unique_object)


def dependencies(value):
    """Yield mutable dependency tables, including target-specific tables."""
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if key in ("dependencies", "dev-dependencies", "build-dependencies") and isinstance(child, dict):
            yield key, child
        elif isinstance(child, dict):
            yield from dependencies(child)


def manifest_edit(root, crate, text, current, new, *, package_name=None):
    parsed = tomllib.loads(text)
    require(isinstance(parsed.get("package"), dict), f"{crate}: package table missing")
    require(parsed["package"].get("name") == (package_name or crate), f"{crate}: package name mismatch")
    expected = copy.deepcopy(parsed)
    require(parsed["package"].get("version") == current, f"{crate}: package version mismatch")
    expected["package"]["version"] = new
    package = re.search(r"(?ms)^\[package\][^\n]*\n.*?(?=^\[|\Z)", text)
    require(package is not None, f"{crate}: missing package table")
    updated = replace_once(r'^(version\s*=\s*")[^"]+("[^\n]*)$', rf'\g<1>{new}\2', package[0], crate)
    text = text[:package.start()] + updated + text[package.end():]
    aliases = {}
    for kind, table in dependencies(expected):
        for alias, spec in table.items():
            target = spec.get("package", alias) if isinstance(spec, dict) else alias
            if target not in CRATE_MANIFESTS:
                continue
            require(isinstance(spec, dict) and isinstance(spec.get("path"), str), f"{crate}: {alias} must be a local path dependency")
            destination = (root / CRATE_MANIFESTS[target]).parent
            require((root / crate / spec["path"]).resolve() == destination.resolve(), f"{crate}: {alias} path mismatch")
            old = spec.get("version")
            if kind == "dev-dependencies" and old is None:
                # Cargo strips path-only dev dependencies from published crates.
                continue
            require(old in (current, "=" + current), f"{crate}: {alias} dependency version mismatch")
            spec["version"] = ("=" if old.startswith("=") else "") + new
            aliases.setdefault(alias, []).append((old, spec["version"]))
    for alias, versions in aliases.items():
        # Active manifests use inline dependency tables. Unknown future forms
        # fail before writing; never perform a broad version-string replacement.
        pattern = rf'^(\s*{re.escape(alias)}\s*=\s*\{{[^\n]*?\bversion\s*=\s*")([^"]+)(")'
        matches = list(re.finditer(pattern, text, re.MULTILINE))
        require(len(matches) == len(versions), f"{crate}: unsupported or ambiguous {alias} dependency syntax")
        allowed = {old: updated for old, updated in versions}
        def update(match):
            require(match[2] in allowed, f"{crate}: dependency changed during validation")
            return match[1] + allowed[match[2]] + match[3]
        text = re.sub(pattern, update, text, flags=re.MULTILINE)
    require(tomllib.loads(text) == expected, f"{crate}: manifest candidate changed unrelated metadata")
    return text


def lock_edit(text, current, new, *, crates=CRATES, allow_missing=False):
    parsed = tomllib.loads(text)
    require(parsed.get("version") in (3, 4), "Cargo.lock: unsupported format")
    expected = copy.deepcopy(parsed)
    packages = expected.get("package", [])
    require(isinstance(packages, list) and all(isinstance(package, dict) for package in packages), "Cargo.lock: malformed package tables")
    local = []
    for crate in crates:
        own = [package for package in packages if package.get("name") == crate and "source" not in package]
        require(len(own) == 1 or (allow_missing and not own), f"Cargo.lock: expected one local {crate} entry")
        if not own:
            continue
        require(own[0].get("version") == current and "checksum" not in own[0], f"Cargo.lock: {crate} is stale or not local")
        own[0]["version"] = new
        local.append(crate)
    for package in packages:
        for index, dependency in enumerate(package.get("dependencies", [])):
            parts = dependency.split()
            if parts and parts[0] in local and len(parts) > 1:
                if len(parts) == 3 and parts[2].startswith("(") and parts[2].endswith(")"):
                    # Source-qualified registry/git references are not local.
                    continue
                require(len(parts) == 2 and parts[1] == current, "Cargo.lock: ambiguous internal dependency reference")
                package["dependencies"][index] = parts[0] + " " + new
    chunks = re.split(r"(?m)(?=^\[\[package\]\]\s*$)", text)
    for index, chunk in enumerate(chunks):
        if chunk.startswith("[[package]]"):
            package = tomllib.loads(chunk)["package"][0]
            if package["name"] in local and "source" not in package:
                chunk = replace_once(r'^(version\s*=\s*")[^"]+("[^\n]*)$', rf'\g<1>{new}\2', chunk, "Cargo.lock")
            for crate in local:
                chunk = re.sub(rf'^(\s*"{re.escape(crate)} ){re.escape(current)}("[,]?\s*)$', rf'\g<1>{new}\2', chunk, flags=re.MULTILINE)
            chunks[index] = chunk
    result = "".join(chunks)
    require(tomllib.loads(result) == expected, "Cargo.lock: candidate changed unrelated dependency metadata")
    return result


def json_edit(text, current, new, server=False, field="version"):
    parsed = parse_json(text)
    require(isinstance(parsed, dict), "JSON package/contract must be an object")
    require(not server or isinstance(parsed.get("server"), dict), "JSON contract must contain a server object")
    target = parsed["server"] if server else parsed
    require(target.get(field) == current, f"JSON metadata {field} mismatch")
    expected = copy.deepcopy(parsed)
    (expected["server"] if server else expected)[field] = new
    result = replace_once(rf'("{re.escape(field)}"\s*:\s*"){re.escape(current)}(")', rf'\g<1>{new}\2', text, "JSON metadata")
    require(parse_json(result) == expected, "JSON candidate changed unrelated metadata")
    return result


def npm_lock_edit(text, current, new):
    parsed = parse_json(text)
    require(isinstance(parsed, dict) and parsed.get("lockfileVersion") in (2, 3),
            "npm package-lock: unsupported format")
    packages = parsed.get("packages")
    require(isinstance(packages, dict), "npm package-lock: package entries missing")
    package = packages.get("")
    require(isinstance(package, dict), "npm package-lock: root package missing")
    for metadata in (parsed, package):
        require(metadata.get("name") == "@hai.ai/jacs", "npm package-lock: package name mismatch")
        require(metadata.get("version") == current, "npm package-lock: version mismatch")
    expected = copy.deepcopy(parsed)
    expected["version"] = new
    expected["packages"][""]["version"] = new
    return json.dumps(expected, indent=2, ensure_ascii=False) + "\n"


def android_version_edit(text, current, new):
    pattern = r'^(version[ \t]*=[ \t]*")([^"\r\n]+)("[ \t]*)$'
    versions = re.findall(pattern, text, flags=re.MULTILINE)
    require(len(versions) == 1, "Android Maven metadata: expected one literal version field")
    require(versions[0][1] == current, "Android Maven metadata: version mismatch")
    return replace_once(pattern, rf'\g<1>{new}\3', text, "Android Maven metadata")


def python_project_edit(text, current, new):
    parsed = tomllib.loads(text)
    project = parsed.get("project", {})
    require(project.get("name") == "jacs" and project.get("version") == current,
            "Python project identity/version mismatch")
    expected = copy.deepcopy(parsed)
    expected["project"]["version"] = new
    section = re.search(r"(?ms)^\[project\][^\n]*\n.*?(?=^\[|\Z)", text)
    require(section is not None, "Python project table missing")
    updated = replace_once(r'^(version\s*=\s*")[^"]+("[^\n]*)$', rf'\g<1>{new}\2', section[0], "Python project")
    result = text[:section.start()] + updated + text[section.end():]
    require(tomllib.loads(result) == expected, "Python candidate changed unrelated metadata")
    return result


def python_lock_edit(text, current, new):
    parsed = tomllib.loads(text)
    expected = copy.deepcopy(parsed)
    own = [package for package in expected.get("package", [])
           if package.get("name") == "jacs" and package.get("source") == {"editable": "."}]
    require(len(own) == 1 and own[0].get("version") == current,
            "Python lock: expected one local jacs entry at the release version")
    own[0]["version"] = new
    chunks = re.split(r"(?m)(?=^\[\[package\]\]\s*$)", text)
    for index, chunk in enumerate(chunks):
        if not chunk.startswith("[[package]]"):
            continue
        package = tomllib.loads(chunk)["package"][0]
        if package.get("name") == "jacs" and package.get("source") == {"editable": "."}:
            chunks[index] = replace_once(r'^(version\s*=\s*")[^"]+("[^\n]*)$', rf'\g<1>{new}\2', chunk, "Python lock")
    result = "".join(chunks)
    require(tomllib.loads(result) == expected, "Python lock candidate changed unrelated metadata")
    return result


def prepare(root, bump):
    originals = {}
    edits = {}

    def read(relative):
        path = root / relative
        require(not path.is_symlink() and path.is_file(), f"{relative}: expected a regular file")
        text = path.read_text()
        originals[path] = text
        return text

    workspace = tomllib.loads(read("Cargo.toml"))["workspace"]
    require(set(workspace["members"]) == set(CRATES) and len(workspace["members"]) == len(CRATES), "Workspace must contain exactly the five portable crates")
    core = read("jacs-core/Cargo.toml")
    current = tomllib.loads(core)["package"]["version"]
    require(isinstance(current, str) and SEMVER.fullmatch(current), "Core version must be an ordinary X.Y.Z release")
    parts = list(map(int, current.split(".")))
    index = {"major": 0, "minor": 1, "patch": 2}[bump]
    parts[index] += 1
    parts[index + 1:] = [0] * (2 - index)
    new = ".".join(map(str, parts))
    for name, relative in CRATE_MANIFESTS.items():
        text = core if name == "jacs-core" else read(relative)
        edits[root / relative] = manifest_edit(root, str(Path(relative).parent), text, current, new, package_name=name)
    for relative, server in [("jacs-wasm/package.template.json", False), ("jacs-mcp/contract/jacs-mcp-contract.json", True), ("archive/native/jacs-mcp/contract/jacs-mcp-contract.json", True)]:
        edits[root / relative] = json_edit(read(relative), current, new, server)
    relative = "archive/native/jacsnpm/package.json"
    npm_package = read(relative)
    npm_metadata = parse_json(npm_package)
    require(isinstance(npm_metadata, dict) and npm_metadata.get("name") == "@hai.ai/jacs", "npm package name mismatch")
    edits[root / relative] = json_edit(npm_package, current, new)
    relative = "archive/native/jacsnpm/package-lock.json"
    edits[root / relative] = npm_lock_edit(read(relative), current, new)
    relative = "archive/native/jacspy/pyproject.toml"
    edits[root / relative] = python_project_edit(read(relative), current, new)
    relative = "archive/native/jacspy/uv.lock"
    edits[root / relative] = python_lock_edit(read(relative), current, new)
    relative = "jacs-mobile/distribution/android/library/build.gradle.kts"
    edits[root / relative] = android_version_edit(read(relative), current, new)
    # Align the source candidate without changing observed registry versions,
    # publication status, checksums, or provenance from previous releases.
    relative = "release/shipped-artifacts.json"
    edits[root / relative] = json_edit(read(relative), current, new, field="source_version")
    edits[root / "Cargo.lock"] = lock_edit(read("Cargo.lock"), current, new)
    for relative in ARCHIVE_LOCKS:
        path = root / relative
        if relative != ARCHIVE_LOCKS[0] and not path.exists() and not path.is_symlink():
            continue
        original = read(relative)
        primary = relative == ARCHIVE_LOCKS[0]
        crates = tuple(name for name, manifest in CRATE_MANIFESTS.items()
                       if name == "jacs-core" or (manifest.startswith("archive/native/") and name != "jacs-surrealdb")) if primary else CRATE_MANIFESTS
        updated = lock_edit(original, current, new, crates=crates, allow_missing=not primary)
        if updated != original:
            edits[path] = updated
    changelog = read("CHANGELOG.md")
    require(len(re.findall(rf"(?m)^## {re.escape(current)}$", changelog)) == 1, "Changelog must contain exactly one current-version section")
    require(not re.search(rf"(?m)^## {re.escape(new)}$", changelog), "Changelog already contains the next version; resolve it before bumping")
    edits[root / "CHANGELOG.md"] = f"## {new}\n\n(unreleased)\n\n" + changelog
    return current, new, originals, edits


def write_edits(originals, edits):
    staged = {}
    try:
        for path, value in edits.items():
            descriptor, temporary = tempfile.mkstemp(prefix=".jacs-version-", dir=path.parent)
            staged[path] = Path(temporary)
            with os.fdopen(descriptor, "w") as stream:
                os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        require(all(not path.is_symlink() and path.read_text() == previous for path, previous in originals.items()), "Release files changed during validation; no edits applied")
        for path, temporary in staged.items():
            os.replace(temporary, path)
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bump", choices=("major", "minor", "patch"))
    parser.add_argument("--check", action="store_true", help="Validate and print the planned bump without modifying files")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        current, new, originals, edits = prepare(root, args.bump)
        if not args.check:
            write_edits(originals, edits)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Version bump rejected: {error}\n")
    print(f"{'Validated' if args.check else 'Updated'} coordinated release version: {current} -> {new} ({len(edits)} files)")
    if not args.check:
        print("Review the diff, update release notes, regenerate dependency notices, then run make check. Nothing was published.")


if __name__ == "__main__":
    main()
