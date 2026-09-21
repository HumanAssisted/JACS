from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release_retry.py"
ZERO = "0" * 40
ONE = "1" * 40
TWO = "2" * 40


def load_module():
    spec = importlib.util.spec_from_file_location("release_retry", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_target_block(text: str, name: str) -> str:
    lines = text.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith(f"{name}:")
    )
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace() and ":" in line and not line.startswith("#"):
            end = index
            break
    return "\n".join(lines[start:end])


def write_manifests(root: Path, version: str = "0.11.4") -> None:
    cargo_paths = ("jacs-core", "jacs-mcp", "jacs-cli")
    for relative in cargo_paths:
        directory = root / relative
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "Cargo.toml").write_text(
            f'[package]\nname = "fixture"\nversion = "{version}"\n',
            encoding="utf-8",
        )
    (root / "jacs-wasm").mkdir(parents=True, exist_ok=True)
    (root / "jacs-wasm" / "package.template.json").write_text(
        f'{{"name":"@jacs/wasm","version":"{version}"}}\n',
        encoding="utf-8",
    )


class FakeGit:
    def __init__(
        self,
        *,
        local: tuple[str, str] | None = None,
        remote: tuple[str, str] | None = None,
    ) -> None:
        self.local = local
        self.remote = remote
        self.head = TWO
        self.commands: list[tuple[str, ...]] = []
        self.fail_final_push = False
        self.fail_remote_probe = False
        self.dirty_output = ""

    def __call__(self, command: list[str], timeout_seconds: int):
        del timeout_seconds
        self.commands.append(tuple(command))
        if command[1:3] == ["status", "--porcelain=v1"]:
            return subprocess.CompletedProcess(command, 0, self.dirty_output, "")
        if self.fail_remote_probe and command[1] == "ls-remote":
            return subprocess.CompletedProcess(
                command, 128, "", "authentication failed"
            )
        if command[1:4] == ["rev-parse", "--verify", "--quiet"]:
            ref = command[4]
            if ref == "HEAD":
                return subprocess.CompletedProcess(command, 0, self.head + "\n", "")
            if self.local is None:
                return subprocess.CompletedProcess(command, 1, "", "")
            value = self.local[1] if ref.endswith("^{}") else self.local[0]
            return subprocess.CompletedProcess(command, 0, value + "\n", "")
        if command[1] == "ls-remote":
            if self.remote is None:
                return subprocess.CompletedProcess(command, 0, "", "")
            tag_ref = command[-2]
            peeled_ref = command[-1]
            output = f"{self.remote[0]}\t{tag_ref}\n"
            if self.remote[1] != self.remote[0]:
                output += f"{self.remote[1]}\t{peeled_ref}\n"
            return subprocess.CompletedProcess(command, 0, output, "")
        if command[1] == "fetch":
            self.local = self.remote
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[1] == "tag":
            self.local = (self.head, self.head)
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[1] == "push" and command[-1].startswith(":refs/tags/"):
            self.remote = None
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[1] == "push":
            if self.fail_final_push:
                return subprocess.CompletedProcess(command, 1, "", "push rejected")
            self.remote = self.local
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected command: {command}")


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class MakeReleaseTests(unittest.TestCase):
    def run_make(self, target: str, *, fail: tuple[str, ...] = ()):
        # Exercise Make's routing and prerequisite ordering without contacting
        # registries, building artifacts, or modifying real release tags.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "scripts").mkdir()
            (root / "scripts/check-action-pins.sh").write_text("exit 0\n")
            python = root / "bin/python3"
            python.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "print(json.dumps(sys.argv[1:]))\n"
                "sys.exit(1 if sys.argv[1:] == json.loads(os.environ['JACS_MAKE_TEST_FAIL']) else 0)\n"
            )
            python.chmod(0o755)
            result = subprocess.run(
                ["make", "--no-print-directory", "-s", "-f", str(ROOT / "Makefile"), target],
                cwd=root,
                env={**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ.get("PATH", ""), "JACS_MAKE_TEST_FAIL": json.dumps(fail)},
                capture_output=True, text=True, timeout=30,
            )
            calls = [json.loads(line) for line in result.stdout.splitlines()]
            return result, calls

    def test_make_release_planning_is_read_only_and_uses_safe_helper(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        plan = make_target_block(makefile, "plan-release-everything")
        self.assertIn("check-versions", plan.splitlines()[0])
        self.assertIn("scripts/release_retry.py release-all", plan)
        self.assertNotIn("--execute", plan)
        self.assertNotIn("cargo publish", makefile)
        self.assertNotIn("git tag", makefile)
        self.assertNotIn("git push", makefile)

    def test_make_plans_and_retries_route_only_to_active_surfaces(self) -> None:
        for suffix, surface in (("jacs", "crate"), ("cli", "cli"), ("jacs-wasm", "wasm"), ("everything", None)):
            for operation in ("release", "retry"):
                command = [operation, "--surface", surface] if surface else ["release-all" if operation == "release" else "retry-everything"]
                with self.subTest(target=f"plan-{operation}-{suffix}"):
                    result, calls = self.run_make(f"plan-{operation}-{suffix}")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(calls, [["scripts/check-release-matrix.py"], ["scripts/release_retry.py", *command]])
                if operation == "retry":
                    with self.subTest(target=f"retry-{suffix}"):
                        result, calls = self.run_make(f"retry-{suffix}")
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(calls, [["scripts/check-release-matrix.py"], ["scripts/release_retry.py", *command, "--execute"]])

        for target in ("release-jacsnpm", "release-jacspy", "release-jacsgo", "publish-jacs-wasm"):
            with self.subTest(archived_target=target):
                result, calls = self.run_make(target)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_make_release_execution_stops_when_preflight_fails(self) -> None:
        clean = ["scripts/release_retry.py", "check-worktree"]
        for suffix, surface in (("jacs", "crate"), ("cli", "cli"), ("jacs-wasm", "wasm"), ("everything", None)):
            command = ["release", "--surface", surface] if surface else ["release-all"]
            for failure in ((), ("scripts/check-release-matrix.py",), tuple(clean)):
                with self.subTest(target=f"release-{suffix}", failure=failure):
                    result, calls = self.run_make(f"release-{suffix}", fail=failure)
                    if failure:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(any("--execute" in call for call in calls))
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(calls[-2:], [clean, ["scripts/release_retry.py", *command, "--execute"]])

    def test_release_preflight_checks_source_and_clean_worktree(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        preflight = make_target_block(makefile, "release-preflight")
        self.assertEqual(preflight.splitlines()[0], "release-preflight: check")
        self.assertIn("scripts/release_retry.py check-worktree", preflight)
        check = make_target_block(makefile, "check")
        for gate in ("check-versions", "check-project-license", "check-third-party-notices"):
            self.assertIn(gate, check.splitlines()[0])
        self.assertIn("scripts/check-release-matrix.py", makefile)
        self.assertIn("scripts/check_workspace_boundary.py", check)

    def test_active_release_order_and_archived_tags_fail_closed(self) -> None:
        module = load_module()
        self.assertEqual(module.RELEASE_ORDER, ("crate", "cli", "wasm"))
        for tag in ("npm/v0.13.0", "pypi/v0.13.0", "jacsgo/v0.13.0", "crate/jacs-redb/v0.13.0"):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    module.validate_tag(tag)


class TagRetryTests(unittest.TestCase):
    def test_release_write_refuses_tracked_staged_and_untracked_changes(self) -> None:
        module = load_module()
        cases = (
            " M tracked.txt\n",
            "M  staged.txt\n",
            "?? untracked-release-file\n",
        )
        for status in cases:
            git = FakeGit()
            git.dirty_output = status
            with self.subTest(status=status.strip()):
                with self.assertRaisesRegex(module.ReleaseError, "worktree is not clean"):
                    module.release_tag("crate/v0.11.4", run=git)
                self.assertFalse(
                    any(command[1] in {"tag", "push"} for command in git.commands)
                )

    def test_retry_does_not_require_current_worktree_to_match_old_tag(self) -> None:
        module = load_module()
        git = FakeGit(local=(ZERO, ONE), remote=(ZERO, ONE))
        git.dirty_output = " M unrelated-current-work.txt\n"

        module.retry_tag("cli/v0.11.4", run=git)

        self.assertFalse(any(command[1] == "status" for command in git.commands))

    def test_malicious_tag_is_rejected_before_git_is_called(self) -> None:
        module = load_module()
        calls: list[list[str]] = []

        def run(command: list[str], timeout_seconds: int):
            del timeout_seconds
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with self.assertRaisesRegex(ValueError, "strict SemVer"):
            module.plan_retry_tag("cli/v0.11.4`touch-PWNED`", run=run)
        self.assertEqual(calls, [])

    def test_retry_plan_is_non_destructive_and_reports_exact_tag_identity(self) -> None:
        module = load_module()
        git = FakeGit(local=(ZERO, ONE), remote=(ZERO, ONE))

        plan = module.plan_retry_tag("cli/v0.11.4", run=git)

        self.assertEqual(plan.object_id, ZERO)
        self.assertEqual(plan.peeled_id, ONE)
        self.assertTrue(plan.remote_exists)
        self.assertFalse(
            any(command[1] in {"push", "fetch", "tag"} for command in git.commands)
        )

    def test_retry_preserves_annotated_object_and_peeled_commit(self) -> None:
        module = load_module()
        git = FakeGit(local=(ZERO, ONE), remote=(ZERO, ONE))

        module.retry_tag("cli/v0.11.4", run=git, timeout_seconds=7)

        self.assertEqual(git.local, (ZERO, ONE))
        self.assertEqual(git.remote, (ZERO, ONE))
        self.assertFalse(any(command[1] == "tag" for command in git.commands))
        self.assertFalse(
            any("tag" in command and "-d" in command for command in git.commands)
        )
        pushes = [command for command in git.commands if command[1] == "push"]
        self.assertEqual(pushes[0][-1], ":refs/tags/cli/v0.11.4")
        self.assertEqual(
            pushes[1][-1],
            "refs/tags/cli/v0.11.4:refs/tags/cli/v0.11.4",
        )

    def test_retry_fetches_remote_original_before_deleting_it(self) -> None:
        module = load_module()
        git = FakeGit(remote=(ZERO, ONE))

        module.retry_tag("cli/v0.11.4", run=git)

        operations = [command[1] for command in git.commands]
        self.assertLess(operations.index("fetch"), operations.index("push"))
        self.assertEqual(git.local, (ZERO, ONE))
        self.assertEqual(git.remote, (ZERO, ONE))

    def test_retry_refuses_without_a_local_or_remote_original(self) -> None:
        module = load_module()

        with self.assertRaisesRegex(module.ReleaseError, "neither local nor remote"):
            module.plan_retry_tag("wasm-v0.11.4", run=FakeGit())

    def test_retry_refuses_conflicting_local_and_remote_tag_identities(self) -> None:
        module = load_module()

        with self.assertRaisesRegex(module.ReleaseError, "different tag objects"):
            module.plan_retry_tag(
                "wasm-v0.11.4",
                run=FakeGit(local=(ZERO, ZERO), remote=(ONE, ONE)),
            )

    def test_remote_auth_failure_is_not_treated_as_an_absent_tag(self) -> None:
        module = load_module()
        git = FakeGit(local=(ZERO, ZERO))
        git.fail_remote_probe = True

        with self.assertRaisesRegex(module.ReleaseError, "remote tag probe failed"):
            module.plan_retry_tag("crate/v0.11.4", run=git)

    def test_remote_probe_timeout_fails_closed(self) -> None:
        module = load_module()

        def timeout(command: list[str], timeout_seconds: int):
            if command[1] == "ls-remote":
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            return FakeGit(local=(ZERO, ZERO))(command, timeout_seconds)

        with self.assertRaisesRegex(module.ReleaseError, "timed out"):
            module.plan_retry_tag("crate/v0.11.4", run=timeout)

    def test_failed_repush_keeps_the_exact_local_original_for_safe_rerun(self) -> None:
        module = load_module()
        git = FakeGit(local=(ZERO, ONE), remote=(ZERO, ONE))
        git.fail_final_push = True

        with self.assertRaisesRegex(module.ReleaseError, "local original remains"):
            module.retry_tag("cli/v0.11.4", run=git)

        self.assertEqual(git.local, (ZERO, ONE))
        self.assertIsNone(git.remote)
        self.assertFalse(any(command[1] == "tag" for command in git.commands))

    def test_timed_out_repush_is_accepted_only_after_exact_remote_confirmation(
        self,
    ) -> None:
        module = load_module()
        git = FakeGit(local=(ZERO, ONE), remote=(ZERO, ONE))
        final_pushes = 0

        def run(command: list[str], timeout_seconds: int):
            nonlocal final_pushes
            if command[1] == "push" and not command[-1].startswith(":refs/tags/"):
                final_pushes += 1
                git.remote = git.local
                git.commands.append(tuple(command))
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            return git(command, timeout_seconds)

        module.retry_tag("cli/v0.11.4", run=run)

        self.assertEqual(final_pushes, 1)
        self.assertEqual(git.remote, (ZERO, ONE))

    def test_release_refuses_to_push_a_local_tag_from_a_different_head(self) -> None:
        module = load_module()
        git = FakeGit(local=(ZERO, ZERO))
        git.head = TWO

        with self.assertRaisesRegex(module.ReleaseError, "does not point at HEAD"):
            module.release_tag("wasm-v0.11.4", run=git)

        self.assertFalse(any(command[1] == "push" for command in git.commands))

    def test_release_tag_distinguishes_remote_only_and_local_only_states(self) -> None:
        module = load_module()

        remote_only = FakeGit(remote=(ZERO, ZERO))
        outcome = module.release_tag("cli/v0.11.4", run=remote_only)
        self.assertEqual(outcome, "already-remote")
        self.assertFalse(any(command[1] == "tag" for command in remote_only.commands))

        local_only = FakeGit(local=(ZERO, ZERO))
        local_only.head = ZERO
        outcome = module.release_tag("cli/v0.11.4", run=local_only)
        self.assertEqual(outcome, "pushed-local")
        self.assertEqual(local_only.remote, (ZERO, ZERO))
        self.assertFalse(any(command[1] == "tag" for command in local_only.commands))

    def test_new_release_tags_explicit_head_and_uses_annotated_wasm_message(
        self,
    ) -> None:
        module = load_module()

        lightweight = FakeGit()
        outcome = module.release_tag("crate/v0.11.4", run=lightweight)
        self.assertEqual(outcome, "created-and-pushed")
        self.assertIn(("git", "tag", "crate/v0.11.4", TWO), lightweight.commands)

        annotated = FakeGit()
        outcome = module.release_tag(
            "wasm-v0.11.4",
            annotated_message="Release @jacs/wasm 0.11.4",
            run=annotated,
        )
        self.assertEqual(outcome, "created-and-pushed")
        self.assertIn(
            (
                "git",
                "tag",
                "-a",
                "wasm-v0.11.4",
                "-m",
                "Release @jacs/wasm 0.11.4",
                TWO,
            ),
            annotated.commands,
        )

    def test_release_batch_plans_every_tag_then_stops_on_first_push_failure(
        self,
    ) -> None:
        module = load_module()
        events: list[tuple[str, str]] = []
        entries = [
            ("crate/v0.11.4", None),
            ("cli/v0.11.4", None),
            ("wasm-v0.11.4", None),
        ]
        original_plan = module.plan_release_tag
        original_release = module.release_tag

        def plan(tag: str, **_kwargs):
            events.append(("plan", tag))
            return module.ReleasePlan(tag, "push-local", ZERO, ZERO, None)

        def release(tag: str, **_kwargs):
            events.append(("release", tag))
            if tag.startswith("cli/"):
                raise module.ReleaseError("simulated push failure")
            return "pushed-local"

        module.plan_release_tag = plan
        module.release_tag = release
        git = FakeGit()
        git.head = ZERO
        try:
            with self.assertRaisesRegex(module.ReleaseError, "push failure"):
                with contextlib.redirect_stdout(io.StringIO()):
                    module._execute_release_entries(entries, run=git, timeout_seconds=5)
        finally:
            module.plan_release_tag = original_plan
            module.release_tag = original_release

        self.assertEqual([event[0] for event in events[:3]], ["plan"] * 3)
        self.assertEqual(
            [event[1] for event in events if event[0] == "release"],
            [entries[0][0], entries[1][0]],
        )

    def test_release_batch_refuses_mixed_commits_before_any_write(self) -> None:
        module = load_module()
        entries = [("crate/v0.11.4", None), ("cli/v0.11.4", None)]
        plans = iter(
            (
                module.ReleasePlan(entries[0][0], "already-remote", ZERO, ONE, None),
                module.ReleasePlan(entries[1][0], "create-and-push", None, None, TWO),
            )
        )
        original_plan = module.plan_release_tag
        original_release = module.release_tag
        writes: list[str] = []
        module.plan_release_tag = lambda tag, **kwargs: next(plans)
        module.release_tag = lambda tag, **kwargs: writes.append(tag)
        try:
            with self.assertRaisesRegex(module.ReleaseError, "same commit"):
                module._execute_release_entries(
                    entries, run=FakeGit(), timeout_seconds=5
                )
        finally:
            module.plan_release_tag = original_plan
            module.release_tag = original_release
        self.assertEqual(writes, [])


class RetryRegistryProbeTests(unittest.TestCase):
    def test_rust_manifest_version_mismatch_fails_before_network_probe(self) -> None:
        module = load_module()
        urls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifests(root)
            (root / "jacs-cli" / "Cargo.toml").write_text(
                '[package]\nname = "jacs-cli"\nversion = "0.11.3"\n',
                encoding="utf-8",
            )

            def open_url(request: urllib.request.Request, *, timeout: int):
                del timeout
                urls.append(request.full_url)
                return FakeResponse()

            with self.assertRaisesRegex(module.ReleaseError, "does not match"):
                module.probe_retry_surfaces(root, open_url=open_url)

        self.assertEqual(urls, [])

    def test_probes_all_three_rust_crates_at_the_exact_version(self) -> None:
        module = load_module()
        urls: list[str] = []
        verifier_commands: list[list[str]] = []

        def open_url(request: urllib.request.Request, *, timeout: int):
            del timeout
            urls.append(request.full_url)
            return FakeResponse()

        def run_verifier(command: list[str], timeout_seconds: int):
            del timeout_seconds
            verifier_commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifests(root)
            missing = module.probe_retry_surfaces(
                root, open_url=open_url, run_verifier=run_verifier
            )

        self.assertEqual(missing, [])
        crate_urls = [url for url in urls if "crates.io/api/v1/crates" in url]
        self.assertEqual(len(crate_urls), 3)
        for crate in (
            "jacs-core",
            "jacs-mcp",
            "jacs-cli",
        ):
            self.assertIn(f"https://crates.io/api/v1/crates/{crate}/0.11.4", crate_urls)
        self.assertEqual(len(verifier_commands), 1)
        self.assertTrue(any("cli/v0.11.4" in command for command in verifier_commands))

    def test_only_authoritative_404_is_retryable(self) -> None:
        module = load_module()
        missing_url = "https://crates.io/api/v1/crates/jacs-core/0.11.4"

        def open_url(request: urllib.request.Request, *, timeout: int):
            del timeout
            if request.full_url == missing_url:
                raise urllib.error.HTTPError(
                    request.full_url, 404, "not found", {}, None
                )
            return FakeResponse()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifests(root)
            missing = module.probe_retry_surfaces(
                root,
                open_url=open_url,
                run_verifier=lambda command, timeout: subprocess.CompletedProcess(
                    command, 0, "", ""
                ),
            )

        self.assertEqual(missing, ["crate"])

    def test_http_errors_and_transport_failures_fail_closed(self) -> None:
        module = load_module()
        failures = (
            urllib.error.HTTPError(
                "https://example.invalid", 403, "forbidden", {}, None
            ),
            urllib.error.HTTPError("https://example.invalid", 429, "limited", {}, None),
            urllib.error.HTTPError("https://example.invalid", 503, "down", {}, None),
            urllib.error.URLError("network unavailable"),
        )
        for failure in failures:
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_manifests(root)

                    def open_url(request: urllib.request.Request, *, timeout: int):
                        del request, timeout
                        raise failure

                    with self.assertRaisesRegex(module.ReleaseError, "failed closed"):
                        module.probe_retry_surfaces(root, open_url=open_url)

    def test_existing_github_release_requires_exact_inventory_and_provenance(
        self,
    ) -> None:
        module = load_module()

        def run_verifier(command: list[str], timeout_seconds: int):
            del timeout_seconds
            if "cli/v0.11.4" in command:
                return subprocess.CompletedProcess(
                    command, 1, "", "missing attestation"
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifests(root)
            with self.assertRaisesRegex(module.ReleaseError, "manual review required"):
                module.probe_retry_surfaces(
                    root,
                    open_url=lambda request, timeout: FakeResponse(),
                    run_verifier=run_verifier,
                )

    def test_github_inventory_verifier_timeout_requires_manual_review(self) -> None:
        module = load_module()

        def run_verifier(command: list[str], timeout_seconds: int):
            raise subprocess.TimeoutExpired(command, timeout_seconds)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifests(root)
            with self.assertRaisesRegex(module.ReleaseError, "manual review required"):
                module.probe_retry_surfaces(
                    root,
                    open_url=lambda request, timeout: FakeResponse(),
                    run_verifier=run_verifier,
                    verify_timeout_seconds=9,
                )

    def test_malicious_manifest_version_is_rejected_before_any_command(self) -> None:
        module = load_module()
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifests(root, "0.11.4;touch-PWNED")
            with self.assertRaisesRegex(ValueError, "strict SemVer"):
                module.surface_tag("crate", root)
        self.assertEqual(commands, [])


if __name__ == "__main__":
    unittest.main()
