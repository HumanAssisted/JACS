#!/usr/bin/env python3
"""Plan and execute fail-closed JACS release tag creation and retry."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import NamedTuple

try:
    from http_policy import open_no_redirect
    from release_tag import parse_release_ref, validate_semver
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.http_policy import open_no_redirect
    from scripts.release_tag import parse_release_ref, validate_semver


REPOSITORY = "HumanAssisted/JACS"
DEFAULT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GIT_TIMEOUT_SECONDS = 30
DEFAULT_HTTP_TIMEOUT_SECONDS = 20
DEFAULT_VERIFY_TIMEOUT_SECONDS = 1800
DIAGNOSTIC_LIMIT = 4096
OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class ReleaseError(RuntimeError):
    """A release operation cannot proceed without risking the wrong artifact."""


class SurfaceSpec(NamedTuple):
    manifest: str
    tag_prefix: str
    version_path: tuple[str, ...]


class TagState(NamedTuple):
    object_id: str
    peeled_id: str


class RetryPlan(NamedTuple):
    tag: str
    object_id: str
    peeled_id: str
    local_exists: bool
    remote_exists: bool


class ReleasePlan(NamedTuple):
    tag: str
    action: str
    object_id: str | None
    peeled_id: str | None
    target_id: str | None


SURFACES = {
    "crate": SurfaceSpec("jacs/Cargo.toml", "crate/v", ("package", "version")),
    "pypi": SurfaceSpec("jacspy/pyproject.toml", "pypi/v", ("project", "version")),
    "cli": SurfaceSpec("jacs/Cargo.toml", "cli/v", ("package", "version")),
    "npm": SurfaceSpec("jacsnpm/package.json", "npm/v", ("version",)),
    "wasm": SurfaceSpec("jacs-wasm/package.template.json", "wasm-v", ("version",)),
    "jacsgo": SurfaceSpec("jacsgo/lib/Cargo.toml", "jacsgo/v", ("package", "version")),
}
RELEASE_ORDER = ("crate", "pypi", "cli", "npm", "wasm", "jacsgo")
STORAGE_CRATES = (
    "jacs-duckdb",
    "jacs-redb",
    "jacs-surrealdb",
    "jacs-postgresql",
)
RUST_CRATES = (
    "jacs-core",
    "jacs-media",
    "jacs",
    "jacs-binding-core",
    "jacs-mcp",
    "jacs-cli",
)
RUST_CRATE_MANIFESTS = {
    "jacs-core": "jacs-core/Cargo.toml",
    "jacs-media": "jacs-media/Cargo.toml",
    "jacs": "jacs/Cargo.toml",
    "jacs-binding-core": "binding-core/Cargo.toml",
    "jacs-mcp": "jacs-mcp/Cargo.toml",
    "jacs-cli": "jacs-cli/Cargo.toml",
}
GITHUB_RELEASES = {
    "cli": "HumanAssisted/JACS/.github/workflows/release-cli.yml",
    "jacsgo": "HumanAssisted/JACS/.github/workflows/release-jacsgo.yml",
}


CommandRunner = Callable[[list[str], int], subprocess.CompletedProcess[str]]
OpenUrl = Callable[..., object]


def _run_command(
    command: list[str], timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def _diagnostic(result: subprocess.CompletedProcess[str]) -> str:
    value = (result.stderr or result.stdout or "").strip()
    return value[-DIAGNOSTIC_LIMIT:]


def _invoke(
    run: CommandRunner,
    command: list[str],
    timeout_seconds: int,
    description: str,
) -> subprocess.CompletedProcess[str]:
    try:
        return run(command, timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise ReleaseError(
            f"{description} timed out after {timeout_seconds} seconds"
        ) from error
    except OSError as error:
        raise ReleaseError(f"{description} failed: {error}") from error


def _require_success(
    run: CommandRunner,
    command: list[str],
    timeout_seconds: int,
    description: str,
) -> subprocess.CompletedProcess[str]:
    result = _invoke(run, command, timeout_seconds, description)
    if result.returncode != 0:
        detail = _diagnostic(result)
        suffix = f": {detail}" if detail else ""
        raise ReleaseError(
            f"{description} failed with status {result.returncode}{suffix}"
        )
    return result


def _validated_object_id(raw: str, description: str) -> str:
    value = raw.strip()
    if OBJECT_ID.fullmatch(value) is None:
        raise ReleaseError(f"{description} returned an invalid Git object ID")
    return value


def validate_tag(tag: str) -> str:
    """Accept only JACS's exact release tag grammars."""

    ref = f"refs/tags/{tag}"
    if tag.startswith("crate/jacs-"):
        parse_release_ref("storage", ref)
        return tag
    for surface in ("crate", "pypi", "cli", "npm", "wasm", "jacsgo"):
        prefix = SURFACES[surface].tag_prefix
        if tag.startswith(prefix):
            parse_release_ref(surface, ref)
            return tag
    raise ValueError(f"unsupported JACS release tag: {tag!r}")


def _manifest_data(path: Path) -> object:
    try:
        with path.open("rb") as stream:
            if path.suffix == ".toml":
                return tomllib.load(stream)
            return json.load(stream)
    except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot read release manifest {path}: {error}") from error


def _nested_string(data: object, path: tuple[str, ...], manifest: Path) -> str:
    value = data
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise ValueError(f"release manifest {manifest} has no {'.'.join(path)}")
        value = value[key]
    if not isinstance(value, str):
        raise ValueError(f"release manifest {manifest} version must be a string")
    return validate_semver(value)


def _surface_version(surface: str, root: Path) -> str:
    try:
        spec = SURFACES[surface]
    except KeyError as error:
        raise ValueError(f"unknown release surface: {surface!r}") from error
    manifest = root / spec.manifest
    return _nested_string(_manifest_data(manifest), spec.version_path, manifest)


def surface_tag(surface: str, root: Path = DEFAULT_ROOT) -> str:
    spec = SURFACES[surface]
    return validate_tag(f"{spec.tag_prefix}{_surface_version(surface, root)}")


def storage_tag(crate: str, root: Path = DEFAULT_ROOT) -> str:
    if crate not in STORAGE_CRATES:
        raise ValueError(f"unsupported storage crate: {crate!r}")
    manifest = root / crate / "Cargo.toml"
    version = _nested_string(_manifest_data(manifest), ("package", "version"), manifest)
    return validate_tag(f"crate/{crate}/v{version}")


def local_tag_state(
    tag: str,
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> TagState | None:
    validate_tag(tag)
    ref = f"refs/tags/{tag}"
    result = _invoke(
        run,
        ["git", "rev-parse", "--verify", "--quiet", ref],
        timeout_seconds,
        f"local tag probe for {tag}",
    )
    if result.returncode == 1 and not result.stdout.strip():
        return None
    if result.returncode != 0:
        detail = _diagnostic(result)
        raise ReleaseError(
            f"local tag probe failed for {tag}: {detail or result.returncode}"
        )
    object_id = _validated_object_id(result.stdout, f"local tag probe for {tag}")
    peeled = _require_success(
        run,
        ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{}}"],
        timeout_seconds,
        f"local peeled-tag probe for {tag}",
    )
    return TagState(
        object_id,
        _validated_object_id(peeled.stdout, f"local peeled-tag probe for {tag}"),
    )


def remote_tag_state(
    tag: str,
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> TagState | None:
    validate_tag(tag)
    ref = f"refs/tags/{tag}"
    peeled_ref = f"{ref}^{{}}"
    result = _invoke(
        run,
        ["git", "ls-remote", "--tags", "origin", ref, peeled_ref],
        timeout_seconds,
        f"remote tag probe for {tag}",
    )
    if result.returncode != 0:
        detail = _diagnostic(result)
        suffix = f": {detail}" if detail else ""
        raise ReleaseError(
            f"remote tag probe failed for {tag} with status {result.returncode}{suffix}"
        )
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or parts[1] not in {ref, peeled_ref}:
            raise ReleaseError(f"remote tag probe returned unexpected data for {tag}")
        if parts[1] in observed:
            raise ReleaseError(f"remote tag probe returned duplicate refs for {tag}")
        observed[parts[1]] = _validated_object_id(
            parts[0], f"remote tag probe for {tag}"
        )
    if not observed:
        return None
    if ref not in observed:
        raise ReleaseError(f"remote tag probe returned a peeled ref without {ref}")
    return TagState(observed[ref], observed.get(peeled_ref, observed[ref]))


def _head_id(
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> str:
    result = _require_success(
        run,
        ["git", "rev-parse", "--verify", "--quiet", "HEAD"],
        timeout_seconds,
        "HEAD probe",
    )
    return _validated_object_id(result.stdout, "HEAD probe")


def worktree_changes(
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> tuple[str, ...]:
    """Return tracked, staged, and untracked changes using stable porcelain output."""

    result = _require_success(
        run,
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        timeout_seconds,
        "release worktree probe",
    )
    return tuple(line for line in result.stdout.splitlines() if line)


def require_clean_worktree(
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> None:
    """Fail before a tag write when manifests may not match committed HEAD."""

    changes = worktree_changes(run=run, timeout_seconds=timeout_seconds)
    if changes:
        preview = ", ".join(changes[:3])
        if len(changes) > 3:
            preview += f", and {len(changes) - 3} more"
        raise ReleaseError(
            "release worktree is not clean; commit or remove every tracked, staged, "
            f"and untracked change before creating/pushing tags ({preview})"
        )


def plan_release_tag(
    tag: str,
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> ReleasePlan:
    validate_tag(tag)
    local = local_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
    remote = remote_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
    if local is not None and remote is not None and local != remote:
        raise ReleaseError(
            f"local and remote {tag} identify different tag objects/commits; refusing"
        )
    if remote is not None:
        return ReleasePlan(
            tag, "already-remote", remote.object_id, remote.peeled_id, None
        )
    if local is not None:
        return ReleasePlan(tag, "push-local", local.object_id, local.peeled_id, None)
    return ReleasePlan(
        tag,
        "create-and-push",
        None,
        None,
        _head_id(run=run, timeout_seconds=timeout_seconds),
    )


def plan_retry_tag(
    tag: str,
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> RetryPlan:
    validate_tag(tag)
    local = local_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
    remote = remote_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
    if local is None and remote is None:
        raise ReleaseError(
            f"neither local nor remote original tag {tag} exists; refusing to retag HEAD"
        )
    if local is not None and remote is not None and local != remote:
        raise ReleaseError(
            f"local and remote {tag} identify different tag objects/commits; refusing"
        )
    identity = local if local is not None else remote
    assert identity is not None
    return RetryPlan(
        tag,
        identity.object_id,
        identity.peeled_id,
        local is not None,
        remote is not None,
    )


def _confirm_remote(
    tag: str,
    expected: TagState,
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> None:
    observed = remote_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
    if observed != expected:
        raise ReleaseError(
            f"remote {tag} does not identify the expected tag object/peeled commit"
        )


def _push_original(
    tag: str,
    expected: TagState,
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> None:
    ref = f"refs/tags/{tag}"
    try:
        result = _invoke(
            run,
            ["git", "push", "origin", f"{ref}:{ref}"],
            timeout_seconds,
            f"push of {tag}",
        )
    except ReleaseError as push_error:
        try:
            observed = remote_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
        except ReleaseError as probe_error:
            raise ReleaseError(
                f"push result for {tag} is uncertain and remote confirmation "
                "failed; the exact local original remains for a safe rerun"
            ) from probe_error
        if observed == expected:
            return
        raise ReleaseError(
            f"push of {tag} failed; the exact local original remains for a safe rerun"
        ) from push_error
    if result.returncode != 0:
        observed = remote_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
        if observed == expected:
            return
        detail = _diagnostic(result)
        suffix = f": {detail}" if detail else ""
        raise ReleaseError(
            f"push of {tag} failed; the exact local original remains for a safe "
            f"rerun{suffix}"
        )
    _confirm_remote(tag, expected, run=run, timeout_seconds=timeout_seconds)


def release_tag(
    tag: str,
    *,
    annotated_message: str | None = None,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> str:
    plan = plan_release_tag(tag, run=run, timeout_seconds=timeout_seconds)
    if plan.action == "already-remote":
        return "already-remote"
    require_clean_worktree(run=run, timeout_seconds=timeout_seconds)
    if plan.action == "push-local":
        head_id = _head_id(run=run, timeout_seconds=timeout_seconds)
        if plan.peeled_id != head_id:
            raise ReleaseError(
                f"local-only release tag {tag} does not point at HEAD; use the retry "
                "path for an earlier release or check out its original commit"
            )
    if plan.action == "create-and-push":
        assert plan.target_id is not None
        if annotated_message is None:
            command = ["git", "tag", tag, plan.target_id]
        else:
            command = [
                "git",
                "tag",
                "-a",
                tag,
                "-m",
                annotated_message,
                plan.target_id,
            ]
        _require_success(
            run,
            command,
            timeout_seconds,
            f"local creation of {tag}",
        )
        outcome = "created-and-pushed"
    else:
        outcome = "pushed-local"
    local = local_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
    if local is None:
        raise ReleaseError(f"local {tag} disappeared before push")
    _push_original(tag, local, run=run, timeout_seconds=timeout_seconds)
    return outcome


def _fetch_remote_original(
    plan: RetryPlan,
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> TagState:
    ref = f"refs/tags/{plan.tag}"
    _require_success(
        run,
        ["git", "fetch", "--no-tags", "origin", f"{ref}:{ref}"],
        timeout_seconds,
        f"fetch of original tag {plan.tag}",
    )
    local = local_tag_state(plan.tag, run=run, timeout_seconds=timeout_seconds)
    expected = TagState(plan.object_id, plan.peeled_id)
    if local != expected:
        raise ReleaseError(
            f"fetched {plan.tag} does not match its probed tag object/peeled commit"
        )
    return expected


def _delete_remote_tag(
    tag: str,
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> None:
    ref = f"refs/tags/{tag}"
    result = _invoke(
        run,
        ["git", "push", "origin", f":{ref}"],
        timeout_seconds,
        f"remote deletion of {tag}",
    )
    observed = remote_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
    if observed is None:
        return
    detail = _diagnostic(result)
    suffix = f": {detail}" if detail else ""
    if result.returncode != 0:
        raise ReleaseError(f"remote deletion of {tag} failed{suffix}")
    raise ReleaseError(f"remote deletion of {tag} reported success but tag remains")


def retry_tag(
    tag: str,
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> None:
    """Re-push the exact original tag object; never create a replacement."""

    plan = plan_retry_tag(tag, run=run, timeout_seconds=timeout_seconds)
    expected = TagState(plan.object_id, plan.peeled_id)
    if not plan.local_exists:
        _fetch_remote_original(plan, run=run, timeout_seconds=timeout_seconds)
    else:
        local = local_tag_state(tag, run=run, timeout_seconds=timeout_seconds)
        if local != expected:
            raise ReleaseError(f"local original {tag} changed after retry planning")
    if plan.remote_exists:
        _delete_remote_tag(tag, run=run, timeout_seconds=timeout_seconds)
    _push_original(tag, expected, run=run, timeout_seconds=timeout_seconds)


def _release_message(surface: str, version: str) -> str | None:
    if surface == "wasm":
        return f"Release @jacs/wasm {version}"
    return None


def _surface_entries(
    surfaces: Iterable[str], root: Path
) -> list[tuple[str, str | None]]:
    entries: list[tuple[str, str | None]] = []
    for surface in surfaces:
        tag = surface_tag(surface, root)
        entries.append(
            (tag, _release_message(surface, _surface_version(surface, root)))
        )
    return entries


def _storage_entries(root: Path) -> list[tuple[str, None]]:
    return [(storage_tag(crate, root), None) for crate in STORAGE_CRATES]


def _plan_release_entries(
    entries: Iterable[tuple[str, str | None]],
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> list[ReleasePlan]:
    plans = [
        plan_release_tag(tag, run=run, timeout_seconds=timeout_seconds)
        for tag, _message in entries
    ]
    if any(plan.action != "already-remote" for plan in plans):
        head_id = _head_id(run=run, timeout_seconds=timeout_seconds)
        for plan in plans:
            commit_id = (
                plan.target_id if plan.action == "create-and-push" else plan.peeled_id
            )
            if commit_id != head_id:
                raise ReleaseError(
                    "release batch tags must all identify the same commit as HEAD; "
                    f"{plan.tag} identifies {commit_id}, HEAD is {head_id}"
                )
    return plans


def _execute_release_entries(
    entries: list[tuple[str, str | None]],
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> None:
    # Plan every tag before the first write so a later conflict cannot produce a
    # knowingly partial release batch.
    plans = _plan_release_entries(entries, run=run, timeout_seconds=timeout_seconds)
    if any(plan.action != "already-remote" for plan in plans):
        require_clean_worktree(run=run, timeout_seconds=timeout_seconds)
    for tag, message in entries:
        outcome = release_tag(
            tag,
            annotated_message=message,
            run=run,
            timeout_seconds=timeout_seconds,
        )
        print(f"{tag}: {outcome}")


def release_all(
    root: Path = DEFAULT_ROOT,
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> None:
    entries = _surface_entries(RELEASE_ORDER, root) + _storage_entries(root)
    _execute_release_entries(entries, run=run, timeout_seconds=timeout_seconds)


def release_storage(
    root: Path = DEFAULT_ROOT,
    *,
    run: CommandRunner = _run_command,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> None:
    _execute_release_entries(
        _storage_entries(root), run=run, timeout_seconds=timeout_seconds
    )


def _probe_url(
    url: str,
    label: str,
    *,
    open_url: OpenUrl,
    timeout_seconds: int,
) -> bool:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "jacs-release-retry/1"},
    )
    try:
        with open_url(request, timeout=timeout_seconds) as response:
            status = getattr(response, "status", None)
            if status != 200:
                raise ReleaseError(
                    f"{label} probe returned HTTP {status}; failed closed"
                )
    except urllib.error.HTTPError as error:
        try:
            if error.code == 404:
                return False
            raise ReleaseError(
                f"{label} probe returned HTTP {error.code}; failed closed"
            ) from error
        finally:
            error.close()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ReleaseError(f"{label} probe failed closed: {error}") from error
    return True


def _verify_github_release(
    tag: str,
    workflow: str,
    root: Path,
    *,
    run_verifier: CommandRunner,
    timeout_seconds: int,
) -> None:
    command = [
        sys.executable,
        str(root / "scripts" / "verify_github_release_attestations.py"),
        tag,
        workflow,
    ]
    try:
        result = run_verifier(command, timeout_seconds)
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ReleaseError(
            f"{tag} exists but exact inventory/provenance verification failed; "
            "manual review required"
        ) from error
    if result.returncode != 0:
        detail = _diagnostic(result)
        suffix = f": {detail}" if detail else ""
        raise ReleaseError(
            f"{tag} exists but exact inventory/provenance verification failed; "
            f"manual review required{suffix}"
        )


def probe_retry_surfaces(
    root: Path = DEFAULT_ROOT,
    *,
    open_url: OpenUrl = open_no_redirect,
    run_verifier: CommandRunner = _run_command,
    http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
    verify_timeout_seconds: int = DEFAULT_VERIFY_TIMEOUT_SECONDS,
) -> list[str]:
    """Return only authoritatively absent surfaces; uncertainty raises."""

    main_version = _surface_version("crate", root)
    missing: list[str] = []
    rust_missing = False
    for crate in RUST_CRATES:
        manifest = root / RUST_CRATE_MANIFESTS[crate]
        crate_version = _nested_string(
            _manifest_data(manifest), ("package", "version"), manifest
        )
        if crate_version != main_version:
            raise ReleaseError(
                f"{crate} manifest version {crate_version} does not match "
                f"coordinated Rust release version {main_version}; failed closed"
            )
    for crate in RUST_CRATES:
        url = (
            "https://crates.io/api/v1/crates/"
            f"{urllib.parse.quote(crate, safe='')}/{main_version}"
        )
        if not _probe_url(
            url,
            f"crates.io {crate} {main_version}",
            open_url=open_url,
            timeout_seconds=http_timeout_seconds,
        ):
            rust_missing = True
    if rust_missing:
        missing.append("crate")

    pypi_version = _surface_version("pypi", root)
    if not _probe_url(
        f"https://pypi.org/pypi/jacs/{pypi_version}/json",
        f"PyPI jacs {pypi_version}",
        open_url=open_url,
        timeout_seconds=http_timeout_seconds,
    ):
        missing.append("pypi")

    for surface, package in (("npm", "@hai.ai/jacs"), ("wasm", "@jacs/wasm")):
        version = _surface_version(surface, root)
        encoded = urllib.parse.quote(package, safe="@")
        if not _probe_url(
            f"https://registry.npmjs.org/{encoded}/{version}",
            f"npm {package} {version}",
            open_url=open_url,
            timeout_seconds=http_timeout_seconds,
        ):
            missing.append(surface)

    for surface in ("cli", "jacsgo"):
        tag = surface_tag(surface, root)
        encoded_tag = urllib.parse.quote(tag, safe="")
        exists = _probe_url(
            f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{encoded_tag}",
            f"GitHub release {tag}",
            open_url=open_url,
            timeout_seconds=http_timeout_seconds,
        )
        if not exists:
            missing.append(surface)
            continue
        _verify_github_release(
            tag,
            GITHUB_RELEASES[surface],
            root,
            run_verifier=run_verifier,
            timeout_seconds=verify_timeout_seconds,
        )
    return missing


def _retry_plans(
    surfaces: Iterable[str],
    root: Path,
    *,
    run: CommandRunner,
    timeout_seconds: int,
) -> list[RetryPlan]:
    return [
        plan_retry_tag(
            surface_tag(surface, root), run=run, timeout_seconds=timeout_seconds
        )
        for surface in surfaces
    ]


def retry_everything(
    root: Path = DEFAULT_ROOT,
    *,
    execute: bool,
    run: CommandRunner = _run_command,
    open_url: OpenUrl = open_no_redirect,
    run_verifier: CommandRunner = _run_command,
    git_timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
    http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
    verify_timeout_seconds: int = DEFAULT_VERIFY_TIMEOUT_SECONDS,
) -> list[RetryPlan]:
    missing = probe_retry_surfaces(
        root,
        open_url=open_url,
        run_verifier=run_verifier,
        http_timeout_seconds=http_timeout_seconds,
        verify_timeout_seconds=verify_timeout_seconds,
    )
    plans = _retry_plans(missing, root, run=run, timeout_seconds=git_timeout_seconds)
    for plan in plans:
        print_retry_plan(plan)
    if execute:
        for plan in plans:
            retry_tag(plan.tag, run=run, timeout_seconds=git_timeout_seconds)
            print(f"{plan.tag}: exact original tag re-pushed")
    elif plans:
        print("Plan only; no tags were changed. Add --execute to apply this plan.")
    else:
        print("All release surfaces are complete; no retry is needed.")
    return plans


def print_release_plan(plan: ReleasePlan) -> None:
    identity = ""
    if plan.object_id is not None:
        identity = f" object={plan.object_id} peeled={plan.peeled_id}"
    if plan.target_id is not None:
        identity = f" target={plan.target_id}"
    print(f"PLAN {plan.tag}: {plan.action}{identity}")


def print_retry_plan(plan: RetryPlan) -> None:
    remote_action = "delete-and-repush" if plan.remote_exists else "push-local"
    source = "local" if plan.local_exists else "fetch-remote-first"
    print(
        f"PLAN {plan.tag}: {remote_action}; source={source}; "
        f"object={plan.object_id}; peeled={plan.peeled_id}"
    )


def _positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    if not raw.isdigit() or int(raw) < 1:
        raise ValueError(f"{name} must be a positive integer")
    return int(raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("release", "retry"):
        child = subparsers.add_parser(command)
        child.add_argument("--surface", required=True, choices=tuple(SURFACES))
        child.add_argument("--execute", action="store_true")
    for command in ("release-storage", "release-all", "retry-everything"):
        child = subparsers.add_parser(command)
        child.add_argument("--execute", action="store_true")
    subparsers.add_parser("check-worktree")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    git_timeout = _positive_env(
        "JACS_RELEASE_GIT_TIMEOUT_SECONDS", DEFAULT_GIT_TIMEOUT_SECONDS
    )
    try:
        if args.command == "check-worktree":
            require_clean_worktree(timeout_seconds=git_timeout)
            print("Release worktree is clean.")
        elif args.command == "release":
            tag = surface_tag(args.surface, args.root)
            version = _surface_version(args.surface, args.root)
            if args.execute:
                outcome = release_tag(
                    tag,
                    annotated_message=_release_message(args.surface, version),
                    timeout_seconds=git_timeout,
                )
                print(f"{tag}: {outcome}")
            else:
                print_release_plan(plan_release_tag(tag, timeout_seconds=git_timeout))
        elif args.command in {"release-storage", "release-all"}:
            entries = (
                _storage_entries(args.root)
                if args.command == "release-storage"
                else _surface_entries(RELEASE_ORDER, args.root)
                + _storage_entries(args.root)
            )
            if args.execute:
                _execute_release_entries(
                    entries, run=_run_command, timeout_seconds=git_timeout
                )
            else:
                for plan in _plan_release_entries(
                    entries, run=_run_command, timeout_seconds=git_timeout
                ):
                    print_release_plan(plan)
        elif args.command == "retry":
            tag = surface_tag(args.surface, args.root)
            plan = plan_retry_tag(tag, timeout_seconds=git_timeout)
            print_retry_plan(plan)
            if args.execute:
                retry_tag(tag, timeout_seconds=git_timeout)
                print(f"{tag}: exact original tag re-pushed")
            else:
                print(
                    "Plan only; no tag was changed. Add --execute to apply this plan."
                )
        else:
            retry_everything(
                args.root,
                execute=args.execute,
                git_timeout_seconds=git_timeout,
                http_timeout_seconds=_positive_env(
                    "JACS_RELEASE_HTTP_TIMEOUT_SECONDS", DEFAULT_HTTP_TIMEOUT_SECONDS
                ),
                verify_timeout_seconds=_positive_env(
                    "JACS_RELEASE_VERIFY_TIMEOUT_SECONDS",
                    DEFAULT_VERIFY_TIMEOUT_SECONDS,
                ),
            )
    except (ReleaseError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
