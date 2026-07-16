#!/usr/bin/env python3
"""Prove a packed Node package runs its real CLI postinstall lifecycle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.server
import io
import json
import math
import os
import platform
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

try:
    from release_tag import validate_semver
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.release_tag import validate_semver


ASSET_PLATFORM = "linux-x64"
DEFAULT_TIMEOUT_SECONDS = 180.0
MAX_TIMEOUT_SECONDS = 900.0
MAX_REPORTED_OUTPUT_BYTES = 256 * 1024
class CommandRunner(Protocol):
    def __call__(
        self,
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_seconds: float,
        label: str,
    ) -> subprocess.CompletedProcess[str]: ...


class _BoundedTail:
    def __init__(self, limit: int = MAX_REPORTED_OUTPUT_BYTES) -> None:
        self.limit = limit
        self.total = 0
        self.tail = bytearray()

    def append(self, chunk: bytes) -> None:
        self.total += len(chunk)
        if len(chunk) >= self.limit:
            self.tail[:] = chunk[-self.limit :]
            return
        self.tail.extend(chunk)
        overflow = len(self.tail) - self.limit
        if overflow > 0:
            del self.tail[:overflow]

    def text(self) -> str:
        content = bytes(self.tail).decode("utf-8", errors="replace")
        if self.total > len(self.tail):
            return f"[output truncated to final {self.limit} bytes]\n{content}"
        return content


def _drain_output(pipe: object, output: _BoundedTail) -> None:
    try:
        while chunk := pipe.read(64 * 1024):
            output.append(chunk)
    finally:
        pipe.close()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
    elif os.name == "posix":
        # A lifecycle child may outlive the npm parent while retaining the
        # process-group ID created below.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    label: str,
) -> subprocess.CompletedProcess[str]:
    """Run one smoke command with a hard deadline and bounded reported output."""

    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise RuntimeError(f"{label} could not capture subprocess output")
    stdout_tail = _BoundedTail()
    stderr_tail = _BoundedTail()
    readers = (
        threading.Thread(
            target=_drain_output,
            args=(process.stdout, stdout_tail),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_output,
            args=(process.stderr, stderr_tail),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        _kill_process_group(process)
        process.wait()
        for reader in readers:
            reader.join(timeout=5)
        raise RuntimeError(
            f"{label} timed out after {timeout_seconds:g} seconds"
        ) from error
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        _kill_process_group(process)
        for reader in readers:
            reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        raise RuntimeError(f"{label} left subprocess output streams open")
    stdout = stdout_tail.text()
    stderr = stderr_tail.text()

    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if stderr:
        print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)
    completed = subprocess.CompletedProcess(
        command,
        returncode,
        stdout,
        stderr,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{label} failed with exit code {completed.returncode}"
        )
    return completed


def validate_version(version: str) -> str:
    try:
        validate_semver(version)
    except ValueError as error:
        raise ValueError(
            f"version must be strict SemVer, got {version!r}"
        ) from error

    return version


def normalize_package_spec(package_spec: str | os.PathLike[str]) -> str:
    value = os.fspath(package_spec)
    if not value or value.startswith("-") or "\0" in value or "\n" in value or "\r" in value:
        raise ValueError("package spec must be a non-option npm package tarball or spec")
    candidate = Path(value).expanduser()
    if candidate.exists():
        return str(candidate.resolve(strict=True))
    return value


def require_linux_x64() -> None:
    machine = platform.machine().lower()
    if sys.platform != "linux" or machine not in {"x86_64", "amd64"}:
        raise RuntimeError(
            "normal postinstall smoke requires a Linux x86_64 glibc runner"
        )


def fake_cli_bytes(version: str) -> bytes:
    validate_version(version)
    return (
        "#!/bin/sh\n"
        f"printf '%s\\n' 'jacs-cli {version}'\n"
    ).encode("ascii")


def fake_cli_archive(version: str) -> bytes:
    binary = fake_cli_bytes(version)
    uncompressed = io.BytesIO()
    with tarfile.open(
        fileobj=uncompressed,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        member = tarfile.TarInfo("jacs-cli")
        member.size = len(binary)
        member.mode = 0o755
        member.mtime = 0
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        archive.addfile(member, io.BytesIO(binary))
    return gzip.compress(uncompressed.getvalue(), mtime=0)


class _ReleaseServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, files: dict[str, bytes]) -> None:
        self.release_files = files
        self.release_requests: list[str] = []
        self.release_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _ReleaseHandler)


class _ReleaseHandler(http.server.BaseHTTPRequestHandler):
    server: _ReleaseServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        with self.server.release_lock:
            self.server.release_requests.append(self.path)
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self.send_error(404)
            return
        payload = self.server.release_files.get(parsed.path)
        if payload is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


class LoopbackRelease:
    def __init__(self, version: str) -> None:
        version = validate_version(version)
        self.asset_name = f"jacs-cli-{version}-{ASSET_PLATFORM}.tar.gz"
        self.binary = fake_cli_bytes(version)
        archive = fake_cli_archive(version)
        checksum = hashlib.sha256(archive).hexdigest()
        files = {
            f"/{self.asset_name}": archive,
            "/sha256sums.txt": (
                f"{checksum}  {self.asset_name}\n"
            ).encode("ascii"),
        }
        self.server = _ReleaseServer(files)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="jacs-node-postinstall-smoke-server",
            daemon=True,
        )

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def requests(self) -> list[str]:
        with self.server.release_lock:
            return list(self.server.release_requests)

    def __enter__(self) -> "LoopbackRelease":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("loopback release server did not stop within 5 seconds")


def _write_project_manifest(project: Path) -> None:
    project.mkdir(mode=0o700)
    (project / "package.json").write_text(
        json.dumps(
            {
                "name": "jacs-normal-postinstall-smoke",
                "version": "1.0.0",
                "private": True,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _smoke_environment(temporary: Path, release_base: str) -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.lower() in {
            "npm_config_audit",
            "npm_config_cache",
            "npm_config_fund",
            "npm_config_ignore_scripts",
            "npm_config_update_notifier",
        }:
            env.pop(key)
    env.update(
        {
            "HOME": str(temporary / "home"),
            "JACS_CLI_RELEASE_BASE_URL": release_base,
            "JACS_INSTALL_CLI_AUTORUN": "1",
            "XDG_CACHE_HOME": str(temporary / "cli-cache"),
            "npm_config_audit": "false",
            "npm_config_cache": str(temporary / "npm-cache"),
            "npm_config_fund": "false",
            "npm_config_ignore_scripts": "false",
            "npm_config_update_notifier": "false",
        }
    )
    Path(env["HOME"]).mkdir(mode=0o700)
    return env


def _verify_installed_package(project: Path, expected_version: str) -> Path:
    package_json = project / "node_modules" / "@hai.ai" / "jacs" / "package.json"
    try:
        metadata = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("npm did not install a readable @hai.ai/jacs package") from error
    if metadata.get("version") != expected_version:
        raise RuntimeError(
            "installed @hai.ai/jacs version did not match the requested release: "
            f"{metadata.get('version')!r} != {expected_version!r}"
        )
    shim = project / "node_modules" / ".bin" / "jacs-cli"
    if not shim.exists() or not os.access(shim, os.X_OK):
        raise RuntimeError("installed package did not expose an executable jacs-cli bin shim")
    return shim


def _verify_cached_binary(
    cache_root: Path,
    version: str,
    expected_binary: bytes,
) -> Path:
    cached = cache_root / "jacs" / "bin" / version / ASSET_PLATFORM / "jacs-cli"
    try:
        metadata = cached.lstat()
    except FileNotFoundError as error:
        raise RuntimeError(
            "package postinstall did not install the controlled CLI binary"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or cached.is_symlink():
        raise RuntimeError("package postinstall produced an unsafe CLI cache entry")
    if not metadata.st_mode & stat.S_IXUSR:
        raise RuntimeError("package postinstall CLI binary was not executable")
    if cached.read_bytes() != expected_binary:
        raise RuntimeError("package postinstall CLI binary did not match the served asset")
    return cached


def smoke_package(
    package_spec: str | os.PathLike[str],
    version: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    run: CommandRunner = run_process,
    platform_guard: Callable[[], None] = require_linux_x64,
) -> None:
    """Install a package normally and prove its packaged postinstall and bin shim."""

    version = validate_version(version)
    package = normalize_package_spec(package_spec)
    if (
        not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise ValueError(
            f"timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    platform_guard()

    temp_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(
        prefix="jacs-node-postinstall-smoke-",
        dir=temp_root,
    ) as directory:
        temporary = Path(directory)
        project = temporary / "consumer"
        _write_project_manifest(project)
        with LoopbackRelease(version) as release:
            env = _smoke_environment(temporary, release.base_url)
            run(
                [
                    "npm",
                    "install",
                    "--no-audit",
                    "--no-fund",
                    "--omit=dev",
                    "--",
                    package,
                ],
                cwd=project,
                env=env,
                timeout_seconds=timeout_seconds,
                label="normal npm package install",
            )
            shim = _verify_installed_package(project, version)
            _verify_cached_binary(
                Path(env["XDG_CACHE_HOME"]),
                version,
                release.binary,
            )
            expected_requests = [
                "/sha256sums.txt",
                f"/{release.asset_name}",
            ]
            if release.requests != expected_requests:
                raise RuntimeError(
                    "package postinstall did not fetch the exact controlled release assets: "
                    f"{release.requests!r} != {expected_requests!r}"
                )
            result = run(
                [str(shim), "--version"],
                cwd=project,
                env=env,
                timeout_seconds=timeout_seconds,
                label="installed jacs-cli package bin",
            )
            expected_output = f"jacs-cli {version}"
            if result.stdout.strip() != expected_output:
                raise RuntimeError(
                    "installed jacs-cli package bin returned unexpected output: "
                    f"{result.stdout.strip()!r} != {expected_output!r}"
                )
            run(
                [
                    "node",
                    "-e",
                    "const {JacsSimpleAgent}=require('@hai.ai/jacs');"
                    "const a=JacsSimpleAgent.ephemeral('ed25519');"
                    "const signed=a.signMessage(JSON.stringify({release:true}));"
                    "const result=JSON.parse(a.verify(signed));"
                    "if (!result.valid) process.exit(1);",
                ],
                cwd=project,
                env=env,
                timeout_seconds=timeout_seconds,
                label="normally installed Node package sign/verify",
            )


def positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a number") from error
    if not math.isfinite(parsed) or parsed <= 0 or parsed > MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS:g}"
        )
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Install a packed @hai.ai/jacs package without --ignore-scripts and "
            "prove its postinstall and jacs-cli bin against a loopback release."
        )
    )
    parser.add_argument("--package", required=True, dest="package_spec")
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--timeout-seconds",
        type=positive_timeout,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    args = parser.parse_args()
    try:
        smoke_package(
            args.package_spec,
            args.version,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "OK: normal npm install ran packaged postinstall and invoked the installed jacs-cli bin"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
