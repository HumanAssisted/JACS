from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from contextlib import redirect_stdout


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "smoke-node-package-postinstall.py"


def load_module():
    spec = importlib.util.spec_from_file_location("smoke_node_package_postinstall", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NodePackagePostinstallSmokeTests(unittest.TestCase):
    def test_generated_archive_is_accepted_by_the_packaged_node_extractor(self) -> None:
        module = load_module()
        installer = ROOT / "jacsnpm" / "scripts" / "install-cli.js"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "jacs-cli-1.2.3-linux-x64.tar.gz"
            destination = Path(directory) / "jacs-cli"
            archive.write_bytes(module.fake_cli_archive("1.2.3"))
            program = (
                "const installer=require(process.argv[1]);"
                "installer.extractTarBinary(process.argv[2],process.argv[3],'jacs-cli')"
                ".catch((error)=>{console.error(error);process.exit(1);});"
            )
            result = subprocess.run(
                [
                    "node",
                    "-e",
                    program,
                    str(installer),
                    str(archive),
                    str(destination),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_bytes(), module.fake_cli_bytes("1.2.3"))

    def test_normal_install_uses_loopback_asset_and_invokes_packaged_bin(self) -> None:
        module = load_module()
        version = "1.2.3-rc.1"
        calls: list[dict[str, object]] = []
        project_directory: Path | None = None

        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "hai-ai-jacs.tgz"
            package.write_bytes(b"fixture package bytes")

            def run(
                command: list[str],
                *,
                cwd: Path,
                env: dict[str, str],
                timeout_seconds: float,
                label: str,
            ) -> subprocess.CompletedProcess[str]:
                nonlocal project_directory
                project_directory = cwd
                calls.append(
                    {
                        "command": command,
                        "cwd": cwd,
                        "env": env.copy(),
                        "timeout_seconds": timeout_seconds,
                        "label": label,
                    }
                )
                if command[0] == "npm":
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    base = env["JACS_CLI_RELEASE_BASE_URL"]
                    asset_name = f"jacs-cli-{version}-linux-x64.tar.gz"
                    with opener.open(f"{base}/sha256sums.txt", timeout=2) as response:
                        checksum_line = response.read().decode("ascii").strip()
                    with opener.open(f"{base}/{asset_name}", timeout=2) as response:
                        archive = response.read()
                    self.assertEqual(
                        checksum_line,
                        f"{hashlib.sha256(archive).hexdigest()}  {asset_name}",
                    )
                    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as handle:
                        member = handle.getmember("jacs-cli")
                        source = handle.extractfile(member)
                        self.assertIsNotNone(source)
                        binary = source.read() if source is not None else b""

                    cached_binary = (
                        Path(env["XDG_CACHE_HOME"])
                        / "jacs"
                        / "bin"
                        / version
                        / "linux-x64"
                        / "jacs-cli"
                    )
                    cached_binary.parent.mkdir(parents=True)
                    cached_binary.write_bytes(binary)
                    cached_binary.chmod(0o700)

                    installed = cwd / "node_modules" / "@hai.ai" / "jacs"
                    installed.mkdir(parents=True)
                    (installed / "package.json").write_text(
                        json.dumps({"name": "@hai.ai/jacs", "version": version}),
                        encoding="utf-8",
                    )
                    shim = cwd / "node_modules" / ".bin" / "jacs-cli"
                    shim.parent.mkdir(parents=True)
                    shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                    shim.chmod(0o700)
                    return subprocess.CompletedProcess(command, 0, "installed\n", "")

                return subprocess.CompletedProcess(
                    command,
                    0,
                    f"jacs-cli {version}\n",
                    "",
                )

            module.smoke_package(
                package,
                version,
                timeout_seconds=7,
                run=run,
                platform_guard=lambda: None,
            )

        self.assertEqual(len(calls), 3)
        install = calls[0]
        self.assertEqual(
            install["command"],
            [
                "npm",
                "install",
                "--no-audit",
                "--no-fund",
                "--omit=dev",
                "--",
                str(package.resolve()),
            ],
        )
        self.assertNotIn("--ignore-scripts", install["command"])
        install_env = install["env"]
        self.assertIsInstance(install_env, dict)
        self.assertEqual(install_env["npm_config_ignore_scripts"], "false")
        self.assertEqual(install["timeout_seconds"], 7)
        self.assertEqual(calls[1]["timeout_seconds"], 7)
        self.assertEqual(calls[1]["command"][-1], "--version")
        self.assertEqual(calls[2]["command"][0:2], ["node", "-e"])
        self.assertIn("JacsSimpleAgent", calls[2]["command"][2])
        self.assertIsNotNone(project_directory)
        self.assertFalse(project_directory.exists())

    def test_missing_cached_binary_fails_even_when_npm_returns_success(self) -> None:
        module = load_module()

        def run(
            command: list[str],
            *,
            cwd: Path,
            env: dict[str, str],
            timeout_seconds: float,
            label: str,
        ) -> subprocess.CompletedProcess[str]:
            del env, timeout_seconds, label
            if command[0] == "npm":
                installed = cwd / "node_modules" / "@hai.ai" / "jacs"
                installed.mkdir(parents=True)
                (installed / "package.json").write_text(
                    '{"name":"@hai.ai/jacs","version":"1.2.3"}',
                    encoding="utf-8",
                )
                shim = cwd / "node_modules" / ".bin" / "jacs-cli"
                shim.parent.mkdir(parents=True)
                shim.write_text("#!/bin/sh\n", encoding="utf-8")
                shim.chmod(0o700)
            return subprocess.CompletedProcess(command, 0, "", "")

        with self.assertRaisesRegex(RuntimeError, "postinstall did not install"):
            module.smoke_package(
                "fixture.tgz",
                "1.2.3",
                run=run,
                platform_guard=lambda: None,
            )

    def test_rejects_unsafe_version_and_package_option(self) -> None:
        module = load_module()
        with self.assertRaisesRegex(ValueError, "SemVer"):
            module.smoke_package(
                "fixture.tgz",
                "1.2.3`touch injected`",
                platform_guard=lambda: None,
            )
        with self.assertRaisesRegex(ValueError, "package spec"):
            module.smoke_package(
                "--ignore-scripts",
                "1.2.3",
                platform_guard=lambda: None,
            )
        with self.assertRaisesRegex(module.argparse.ArgumentTypeError, "timeout"):
            module.positive_timeout("nan")

    def test_process_runner_timeout_kills_lifecycle_descendants(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant-survived"
            child = (
                "import pathlib,time;"
                "time.sleep(0.5);"
                f"pathlib.Path({str(marker)!r}).write_text('bad')"
            )
            parent = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
                "time.sleep(5)"
            )
            with self.assertRaisesRegex(RuntimeError, "timed out after 0.1"):
                module.run_process(
                    [sys.executable, "-c", parent],
                    cwd=ROOT,
                    env=os.environ.copy(),
                    timeout_seconds=0.1,
                    label="npm probe",
                )
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    def test_process_runner_reports_only_a_bounded_output_tail(self) -> None:
        module = load_module()
        size = module.MAX_REPORTED_OUTPUT_BYTES * 2
        with redirect_stdout(io.StringIO()):
            result = module.run_process(
                [sys.executable, "-c", f"import os; os.write(1, b'x' * {size})"],
                cwd=ROOT,
                env=os.environ.copy(),
                timeout_seconds=5,
                label="large output probe",
            )
        self.assertIn("output truncated", result.stdout)
        self.assertLessEqual(
            len(result.stdout.encode()),
            module.MAX_REPORTED_OUTPUT_BYTES + 128,
        )


if __name__ == "__main__":
    unittest.main()
