from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from workflow_policy_helpers import checkout_step_blocks


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release_tag.py"
WORKFLOWS = {
    "release-crate.yml": "crate",
    "release-storage-crate.yml": "storage",
    "release-cli.yml": "cli",
    "release-npm.yml": "npm",
    "release-pypi.yml": "pypi",
    "release-wasm.yml": "wasm",
    "release-jacsgo.yml": "jacsgo",
}
TAG_RELEASE_WORKFLOWS = tuple(WORKFLOWS) + ("release-homebrew.yml",)


def load_release_tag():
    spec = importlib.util.spec_from_file_location("release_tag", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shell_run_blocks(text: str) -> list[str]:
    """Extract scalar `run` values without requiring a YAML dependency."""

    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        if not stripped.startswith("run:"):
            index += 1
            continue
        indent = len(line) - len(stripped)
        value = stripped.removeprefix("run:").strip()
        if value not in {"|", ">", "|-", ">-", "|+", ">+"}:
            blocks.append(value)
            index += 1
            continue
        index += 1
        body: list[str] = []
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                break
            body.append(candidate)
            index += 1
        blocks.append("\n".join(body))
    return blocks


def workflow_job_blocks(text: str) -> dict[str, str]:
    """Extract top-level job blocks without depending on a YAML package."""

    lines = text.splitlines()
    jobs_index = next(index for index, line in enumerate(lines) if line == "jobs:")
    blocks: dict[str, str] = {}
    index = jobs_index + 1
    while index < len(lines):
        line = lines[index]
        if line and not line.startswith(" "):
            break
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            name = line.strip()[:-1]
            start = index
            index += 1
            while index < len(lines):
                candidate = lines[index]
                if candidate and not candidate.startswith(" "):
                    break
                if (
                    candidate.startswith("  ")
                    and not candidate.startswith("    ")
                    and candidate.endswith(":")
                ):
                    break
                index += 1
            blocks[name] = "\n".join(lines[start:index])
            continue
        index += 1
    return blocks


class ReleaseTagParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release_tag = load_release_tag()

    def test_accepts_exact_release_prefixes_and_strict_semver(self) -> None:
        cases = {
            "crate": ("refs/tags/crate/v0.11.4", {"version": "0.11.4"}),
            "cli": ("refs/tags/cli/v1.2.3-rc.1+build.7", {"version": "1.2.3-rc.1+build.7"}),
            "npm": ("refs/tags/npm/v0.11.4", {"version": "0.11.4"}),
            "pypi": ("refs/tags/pypi/v0.11.4", {"version": "0.11.4"}),
            "wasm": ("refs/tags/wasm-v0.11.4", {"version": "0.11.4"}),
            "jacsgo": ("refs/tags/jacsgo/v0.11.4", {"version": "0.11.4"}),
            "storage": (
                "refs/tags/crate/jacs-postgresql/v0.11.4",
                {"crate": "jacs-postgresql", "version": "0.11.4"},
            ),
        }
        for surface, (ref, expected) in cases.items():
            with self.subTest(surface=surface):
                self.assertEqual(self.release_tag.parse_release_ref(surface, ref), expected)

    def test_rejects_shell_payload_wrong_prefix_and_invalid_semver(self) -> None:
        invalid = (
            ("npm", "refs/tags/npm/v0.11.4`touch${IFS}TAG_INJECTION_PROVED`"),
            ("cli", "refs/tags/npm/v0.11.4"),
            ("crate", "refs/tags/crate/v01.2.3"),
            ("crate", "refs/tags/crate/v1.02.3"),
            ("crate", "refs/tags/crate/v1.2.03"),
            ("jacsgo", "refs/tags/jacsgo/v1.2.3-"),
            ("jacsgo", "refs/tags/jacsgo/v1.2.3-alpha..1"),
            ("storage", "refs/tags/crate/../../jacs/v0.11.4"),
            ("storage", "refs/tags/crate/jacs/v0.11.4"),
        )
        for surface, ref in invalid:
            with self.subTest(surface=surface, ref=ref):
                with self.assertRaises(ValueError):
                    self.release_tag.parse_release_ref(surface, ref)

    def test_cli_rejects_malicious_git_valid_tag_without_executing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "github-output"
            marker = root / "TAG_INJECTION_PROVED"
            env = os.environ.copy()
            env.update(
                {
                    "GITHUB_REF": "refs/tags/npm/v0.11.4`touch${IFS}TAG_INJECTION_PROVED`",
                    "GITHUB_OUTPUT": str(output),
                }
            )
            result = subprocess.run(
                ["python3", str(SCRIPT), "--surface", "npm"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())

    def test_release_workflows_use_shared_parser_and_do_not_interpolate_tag_outputs_in_shell(self) -> None:
        for workflow_name, surface in WORKFLOWS.items():
            with self.subTest(workflow=workflow_name):
                text = (ROOT / ".github" / "workflows" / workflow_name).read_text()
                self.assertIn(
                    f"python3 scripts/release_tag.py --surface {surface}", text
                )
                self.assertNotIn('TAG_VERSION="${{', text)
                self.assertNotIn('VERSION="${{ steps.', text)
                self.assertNotIn('CRATE="${{ steps.', text)
                for run in shell_run_blocks(text):
                    self.assertNotRegex(
                        run,
                        r"\$\{\{\s*(?:steps\.|needs\.verify-version\.)[^}]*outputs\.(?:version|crate)",
                        "validated release outputs must cross into shells through env",
                    )
                self.assertNotIn("ref: ${{ github.ref }}", text)
                self.assertIn("concurrency:", text)
                self.assertIn("cancel-in-progress: false", text)

    def test_tag_release_checkouts_pin_first_party_source_and_never_persist_credentials(self) -> None:
        for workflow_name in TAG_RELEASE_WORKFLOWS:
            with self.subTest(workflow=workflow_name):
                text = (ROOT / ".github" / "workflows" / workflow_name).read_text()
                checkout_steps = checkout_step_blocks(text)
                self.assertTrue(checkout_steps, "expected at least one checkout step")
                for step in checkout_steps:
                    self.assertIn("persist-credentials: false", step)
                    if "repository:" not in step:
                        self.assertIn(
                            "ref: ${{ github.sha }}",
                            step,
                            "first-party release source must be the immutable event SHA",
                        )

    def test_homebrew_push_uses_explicit_ephemeral_credentials(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release-homebrew.yml").read_text()
        self.assertIn("GIT_ASKPASS", text)
        self.assertIn("GIT_TERMINAL_PROMPT", text)
        self.assertIn("HOMEBREW_TAP_TOKEN", text)

    def test_security_executable_jobs_have_bounded_timeouts(self) -> None:
        text = (ROOT / ".github" / "workflows" / "security.yml").read_text()
        jobs = workflow_job_blocks(text)
        executable_jobs = {
            name: block for name, block in jobs.items() if "\n    runs-on:" in block
        }
        self.assertTrue(executable_jobs)
        for name, block in executable_jobs.items():
            with self.subTest(job=name):
                timeout_lines = [
                    line.strip()
                    for line in block.splitlines()
                    if line.startswith("    timeout-minutes:")
                ]
                self.assertEqual(len(timeout_lines), 1)
                timeout = int(timeout_lines[0].split(":", 1)[1].strip())
                self.assertGreater(timeout, 0)
                self.assertLessEqual(timeout, 360)


if __name__ == "__main__":
    unittest.main()
