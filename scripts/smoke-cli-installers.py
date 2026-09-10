#!/usr/bin/env python3
"""Exercise the unmodified Python and Node CLI installers on staged assets."""

from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKSUM_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+)$")


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


def package_version() -> str:
    with (ROOT / "jacspy/pyproject.toml").open("rb") as handle:
        python_version = tomllib.load(handle)["project"]["version"]
    with (ROOT / "jacsnpm/package.json").open(encoding="utf-8") as handle:
        node_version = json.load(handle)["version"]
    if python_version != node_version:
        raise ValueError(
            f"Python/Node installer versions differ: {python_version} != {node_version}"
        )
    return str(python_version)


def checksum_for_asset(checksum_path: Path, asset_name: str) -> str:
    matches = set()
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        match = CHECKSUM_LINE.fullmatch(line.strip())
        if match and Path(match.group(2).strip()).name == asset_name:
            matches.add(match.group(1).lower())
    if len(matches) != 1:
        raise ValueError(
            f"expected one checksum for {asset_name}, found {len(matches)}"
        )
    return next(iter(matches))


def run(
    command: list[str],
    env: dict[str, str],
    label: str,
    *,
    cwd: Path = ROOT,
) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")


# jacs/src/secure_io.rs refuses to create authority-bearing key files unless it
# can validate owner and ACL race-safely, which it only implements on Unix, so
# quickstart cannot mint keys on Windows. The installer smoke still proves the
# download, checksum, extraction and launch of both installers there.
SIGNING_SMOKE_SUPPORTED = os.name == "posix"


def smoke_sign_and_verify(
    launcher: list[str], env: dict[str, str], workspace: Path, label: str
) -> None:
    if not SIGNING_SMOKE_SUPPORTED:
        print(
            f"SKIP: {label} quickstart/sign/verify on {platform.system()}: "
            "JACS only creates authority-bearing key files where secure_io can "
            "validate owner and ACL race-safely (Unix).",
            flush=True,
        )
        return
    workspace.mkdir(mode=0o700)
    (workspace / "input.json").write_text(
        '{"action":"staged-installer-smoke"}\n', encoding="utf-8"
    )
    signed_env = env.copy()
    signed_env["JACS_PRIVATE_KEY_PASSWORD"] = "Installer-Smoke-Password!2026"
    signed_env["JACS_KEYCHAIN_BACKEND"] = "disabled"
    run(
        launcher
        + [
            "quickstart",
            "--name",
            "installer-smoke",
            "--domain",
            "example.test",
            "--algorithm",
            "ed25519",
        ],
        signed_env,
        f"{label} quickstart",
        cwd=workspace,
    )
    run(
        launcher
        + [
            "document",
            "create",
            "-f",
            "input.json",
            "--output",
            "signed.json",
        ],
        signed_env,
        f"{label} document signing",
        cwd=workspace,
    )
    run(
        launcher + ["verify", "jacs_data/signed.json"],
        signed_env,
        f"{label} signed-document verification",
        cwd=workspace,
    )


def smoke(asset_path: Path, checksum_path: Path) -> None:
    version = package_version()
    asset_name = asset_path.name
    if not asset_name.startswith(f"jacs-cli-{version}-"):
        raise ValueError(
            f"staged asset {asset_name} does not match package version {version}"
        )
    expected = checksum_for_asset(checksum_path, asset_name)
    actual = hashlib.sha256(asset_path.read_bytes()).hexdigest()
    if expected != actual:
        raise ValueError(
            f"staged checksum mismatch for {asset_name}: expected {expected}, got {actual}"
        )

    # macOS exposes its temp root through a /var symlink. Both installers
    # intentionally reject symlinked cache ancestors, so anchor the harness at
    # the canonical temp path while keeping all state ephemeral.
    temp_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(
        prefix="jacs-cli-installer-smoke-", dir=temp_root
    ) as directory:
        temporary = Path(directory)
        served = temporary / "served"
        served.mkdir(mode=0o700)
        shutil.copy2(asset_path, served / asset_name)
        (served / "sha256sums.txt").write_text(
            f"{expected}  {asset_name}\n", encoding="utf-8"
        )

        handler = functools.partial(QuietHandler, directory=str(served))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        release_base = f"http://127.0.0.1:{server.server_port}"
        try:
            python_env = os.environ.copy()
            python_env["JACS_CLI_RELEASE_BASE_URL"] = release_base
            python_env["XDG_CACHE_HOME"] = str(temporary / "python-cache")
            python_launcher = [
                sys.executable,
                str(ROOT / "jacspy/python/jacs/cli_runner.py"),
            ]
            run(
                python_launcher + ["--version"],
                python_env,
                "Python staged CLI installer",
            )
            smoke_sign_and_verify(
                python_launcher,
                python_env,
                temporary / "python-work",
                "Python staged CLI",
            )

            node_env = os.environ.copy()
            node_env["JACS_CLI_RELEASE_BASE_URL"] = release_base
            node_env["XDG_CACHE_HOME"] = str(temporary / "node-cache")
            run(
                ["node", str(ROOT / "jacsnpm/scripts/install-cli.js")],
                node_env,
                "Node staged CLI installer",
            )
            node_launcher = ["node", str(ROOT / "jacsnpm/bin/jacs-cli.js")]
            run(
                node_launcher + ["--version"],
                node_env,
                "Node staged CLI --version",
            )
            smoke_sign_and_verify(
                node_launcher,
                node_env,
                temporary / "node-work",
                "Node staged CLI",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    args = parser.parse_args()
    try:
        smoke(args.asset.resolve(strict=True), args.checksum.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: staged Python and Node CLI installers verified the aggregate checksum")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
