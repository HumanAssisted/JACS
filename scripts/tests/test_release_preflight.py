from __future__ import annotations

import re
import json
import unittest
from pathlib import Path

from scripts.release_catalog import CRATES

from workflow_policy_helpers import checkout_step_blocks


ROOT = Path(__file__).resolve().parents[2]


def workflow_text(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text()


def job_block(text: str, name: str) -> str:
    jobs_start = text.index("\njobs:\n")
    match = re.search(rf"(?m)^  {re.escape(name)}:\s*$", text[jobs_start:])
    if match is None:
        raise AssertionError(f"workflow has no {name!r} job")
    start = jobs_start + match.start()
    next_job = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\s*$", text[start + 1 :])
    end = len(text) if next_job is None else start + 1 + next_job.start()
    return text[start:end]


def make_target_block(text: str, name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(name)}:[^\n]*$", text)
    if match is None:
        raise AssertionError(f"Makefile has no {name!r} target")
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:[^=\n]*$", text[match.end() :])
    end = len(text) if next_target is None else match.end() + next_target.start()
    return text[match.start() : end]


class ReleaseCandidatePreflightTests(unittest.TestCase):


    def test_every_executable_release_job_has_an_explicit_timeout(self) -> None:
        workflows = (
            "release-cli.yml",
            "release-crate.yml",
            "release-readiness.yml",
            "release-wasm.yml",
            "release-npm.yml",
            "release-pypi.yml",
            "release-jacsgo.yml",
        )
        for workflow_name in workflows:
            text = workflow_text(workflow_name)
            jobs = text.split("\njobs:\n", 1)[1]
            names = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", jobs)
            for name in names:
                block = job_block(text, name)
                if re.search(r"(?m)^    uses:\s", block):
                    continue
                with self.subTest(workflow=workflow_name, job=name):
                    self.assertRegex(
                        block,
                        r"(?m)^    timeout-minutes: [1-9][0-9]*\s*$",
                    )


    def test_wasm_pack_runs_from_crate_directory_so_target_config_is_loaded(self) -> None:
        cargo_config = (ROOT / "jacs-wasm" / ".cargo" / "config.toml").read_text()
        self.assertIn("[target.wasm32-unknown-unknown]", cargo_config)
        self.assertIn("-zstack-size=4194304", cargo_config)

        for workflow_name in ("wasm-pr.yml", "release-wasm.yml"):
            workflow = workflow_text(workflow_name)
            steps = re.findall(
                r"(?ms)^      - name: [^\n]*\n(?:        [^\n]*\n)*?"
                r"        run: wasm-pack (?:test|build)[^\n]*$",
                workflow,
            )
            self.assertTrue(steps, workflow_name)
            for step in steps:
                with self.subTest(workflow=workflow_name, step=step.splitlines()[0]):
                    self.assertIn("working-directory: jacs-wasm", step)
                    self.assertRegex(
                        step, r"run: wasm-pack (?:test|build).* \. --locked\s*$"
                    )

    def test_release_rust_builds_pin_toolchain_and_lock_resolution(self) -> None:
        publish = job_block(workflow_text("release-crate.yml"), "publish")
        self.assertIn('toolchain: "1.97.0"', publish)
        self.assertIn('RUSTFLAGS: "-D warnings"', publish)
        self.assertIn("scripts/rust_release.py package", publish)
        helper = (ROOT / "scripts/rust_release.py").read_text()
        self.assertIn('"package", "--workspace", "--locked"', helper)
        self.assertNotIn("--no-verify", helper)
        for line in publish.splitlines():
            if ("cargo publish " in line or "cargo package " in line) and "echo " not in line and not line.lstrip().startswith("#"):
                self.assertIn("--locked", line)
        cli_build = job_block(workflow_text("release-cli.yml"), "build")
        self.assertIn("cargo build --locked --release", cli_build)
        wasm_build = job_block(workflow_text("release-wasm.yml"), "build-and-test")
        self.assertIn("wasm-pack test --headless --firefox . --locked", wasm_build)
        self.assertIn("wasm-pack build --target web --release . --locked", wasm_build)

    def test_release_workflows_call_portable_product_suites(self) -> None:
        self.assertIn("  workflow_call:", workflow_text("rust.yml"))
        for name in ("release-crate.yml", "release-cli.yml"):
            with self.subTest(workflow=name):
                text = workflow_text(name)
                self.assertIn("  functional-gate:", text)
                self.assertIn("uses: ./.github/workflows/rust.yml", text)
                self.assertRegex(text, r"needs: [^\n]*functional-gate")
        for name in ("wasm-pr.yml", "mobile-bindings.yml"):
            with self.subTest(workflow=name):
                self.assertIn("jacs-core/**", workflow_text(name))


    def test_rust_publish_preserves_portable_dependency_order(self) -> None:
        publish = job_block(workflow_text("release-crate.yml"), "publish")
        positions = [publish.index(f"scripts/rust_release.py publish-one --crate {name}\n") for name in CRATES]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("scripts/rust_release.py prepare", publish)
        self.assertLess(publish.index("scripts/rust_release.py package"), min(positions))
        self.assertLess(publish.index("Gate publish on complete Rust candidate evidence"), min(positions))

    def test_registry_matrix_runs_after_every_publication_workflow(self) -> None:
        text = workflow_text("release-readiness.yml")
        self.assertIn("workflow_run:", text)
        for workflow_name in (
            "Release CLI Binaries",
            "Release crates.io",
            "Release @hai.ai/jacs-wasm",
            "Release native npm",
            "Release PyPI",
            "Release jacsgo Native Libraries",
        ):
            self.assertIn(workflow_name, text)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", text)
        verify = job_block(text, "verify-public-registries")
        self.assertIn("attestations: read", verify)
        self.assertIn("verify_github_release_attestations.py", verify)
        self.assertIn("--matrix release/shipped-artifacts.json", verify)
        self.assertIn("verify_recorded_registry_provenance.py", verify)
        self.assertIn("npm@11.18.0", verify)
        self.assertIn("timeout-minutes:", verify)

    def test_cli_build_smokes_exact_staged_binary_on_every_platform(self) -> None:
        build = job_block(workflow_text("release-cli.yml"), "build")
        self.assertEqual(build.count("python3 scripts/smoke-portable-cli.py"), 1)
        self.assertEqual(build.count("python scripts/smoke-portable-cli.py"), 1)
        self.assertIn('$prefix/scripts/smoke-portable-cli.py', build)
        self.assertIn("Smoke the exact staged release binary (Unix)", build)
        self.assertIn("Smoke the exact staged release binary (Windows)", build)
        self.assertIn(".tar.gz.sha256", build)
        self.assertIn(".zip.sha256", build)
        harness = (ROOT / "scripts/smoke-portable-cli.py").read_text()
        for operation in ('"create"', '"sign"', '"verify"', '"rotate"', '"reencrypt"'):
            self.assertIn(operation, harness)


    def test_wasm_uses_oidc_publish_and_verifies_registry_provenance(self) -> None:
        text = workflow_text("release-wasm.yml")
        preflight = job_block(text, "preflight-publish")
        build = job_block(text, "build-and-test")
        candidate = job_block(text, "candidate-browser-smoke")
        publish = job_block(text, "publish")
        post_publish = job_block(text, "post-publish-smoke")
        self.assertIn("id-token: write", publish)
        self.assertIn("node-version: 24", publish)
        self.assertIn("npm@11.18.0", publish)
        self.assertIn("vars.JACS_NPM_WASM_BOOTSTRAP == 'true' && secrets.NPM_WASM_BOOTSTRAP_TOKEN", publish)
        self.assertIn("python3 scripts/check_npm_bootstrap.py", publish)
        self.assertIn("unset NODE_AUTH_TOKEN", publish)
        self.assertIn("--access public --provenance", publish)
        self.assertNotIn("npm whoami", preflight)
        self.assertIn("npm audit signatures", post_publish)
        self.assertIn("JACS_WASM_PACKAGE_ROOT", post_publish)
        self.assertIn("JACS_WASM_EXPECTED_VERSION", post_publish)
        self.assertIn("examples/vite-smoke", post_publish)
        self.assertIn("npm run test", post_publish)
        self.assertIn("playwright install", post_publish)
        self.assertIn("timeout-minutes:", post_publish)
        self.assertIn("contents: read", post_publish)
        self.assertIn("npm ci --ignore-scripts", candidate)
        self.assertIn("sha256sum -c", candidate)
        self.assertIn(".tgz.sha256", build)
        self.assertIn("candidate-browser-smoke", publish)
        self.assertNotIn("playwright", build.lower())
        self.assertTrue(
            (ROOT / "jacs-wasm" / "examples" / "vite-smoke" / "package-lock.json").is_file()
        )
        finalize = (ROOT / "jacs-wasm" / "scripts" / "finalize-pkg.sh").read_text()
        self.assertNotIn("typescript@5 ", finalize)
        self.assertIn("typescript@5.9.3", finalize)


    def test_cli_verifies_every_public_release_asset_attestation(self) -> None:
        cases = (
            (
                "release-cli.yml",
                "cli/v${{ needs.verify-version.outputs.version }}",
                "HumanAssisted/JACS/.github/workflows/release-cli.yml",
            ),
        )
        for workflow_name, tag, signer_workflow in cases:
            with self.subTest(workflow=workflow_name):
                text = workflow_text(workflow_name)
                verify = job_block(text, "verify-release-attestations")
                self.assertRegex(verify, r"needs: \[[^\]]*verify-version[^\]]*release[^\]]*\]")
                self.assertIn("attestations: read", verify)
                self.assertIn("scripts/verify_github_release_attestations.py", verify)
                self.assertIn(f"RELEASE_TAG: {tag}", verify)
                self.assertIn(signer_workflow, verify)
                self.assertIn("timeout-minutes:", verify)

        cli_release = job_block(workflow_text("release-cli.yml"), "release")
        self.assertIn("artifacts/**/*.sha256", cli_release)
        cli_prepare = job_block(workflow_text("release-cli.yml"), "prepare-release")
        self.assertIn("sha256sum -c", cli_prepare)

class ExecutableSupplyChainTests(unittest.TestCase):
    def test_crates_releases_prefer_trusted_publishing_with_explicit_migration_fallback(
        self,
    ) -> None:
        action = (
            "rust-lang/crates-io-auth-action@"
            "c6f97d42243bad5fab37ca0427f495c86d5b1a18 # v1"
        )
        cases = (("release-crate.yml", tuple(
            (name, "auth_" + name.replace("-", "_"), f"Verify and publish {name} to crates.io")
            for name in CRATES
        )),)

        for workflow_name, publishes in cases:
            publish = job_block(workflow_text(workflow_name), "publish")
            with self.subTest(workflow=workflow_name, contract="job permissions"):
                self.assertIn("environment: crates-io", publish)
                self.assertIn("contents: read", publish)
                self.assertIn("id-token: write", publish)
                self.assertNotIn("continue-on-error: true", publish)
                self.assertNotIn("cargo publish --token", publish)
                self.assertIn(
                    "vars.CRATES_IO_TRUSTED_PUBLISHING_ENABLED != 'true'",
                    publish,
                )
                self.assertIn("CRATES_IO_TOKEN migration fallback", publish)
                self.assertEqual(publish.count(action), len(publishes))
                self.assertEqual(
                    publish.count("outputs.token || secrets.CRATES_IO_TOKEN"),
                    len(publishes),
                )

            for label, auth_id, publish_name in publishes:
                with self.subTest(workflow=workflow_name, publish=label):
                    self.assertRegex(
                        publish,
                        rf"(?ms)- name: Authenticate {re.escape(label)} publish via crates.io OIDC\n"
                        rf"\s+if: vars\.CRATES_IO_TRUSTED_PUBLISHING_ENABLED == 'true'\n"
                        rf"\s+id: {re.escape(auth_id)}\n"
                        rf"\s+uses: {re.escape(action)}\n\n"
                        rf"\s+- name: {re.escape(publish_name)}\n"
                        rf"\s+env:\n"
                        rf"\s+CARGO_REGISTRY_TOKEN: \$\{{\{{ steps\.{re.escape(auth_id)}\.outputs\.token \|\| secrets\.CRATES_IO_TOKEN \}}\}}",
                    )

        releasing = (ROOT / "RELEASING.md").read_text()
        for required in (
            "CRATES_IO_TRUSTED_PUBLISHING_ENABLED",
            "release-crate.yml",
            "`crates-io` environment",
        ):
            with self.subTest(documented=required):
                self.assertIn(required, releasing)
        self.assertRegex(releasing, r"revoke\s+the old crates\.io API token")

    def test_every_workflow_declares_permissions_and_drops_checkout_credentials(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for workflow in workflows:
            text = workflow.read_text()
            with self.subTest(workflow=workflow.name, contract="permissions"):
                self.assertRegex(text, r"(?m)^permissions:\s*(?:\{\})?\s*$")
            checkout_steps = checkout_step_blocks(text)
            for index, step in enumerate(checkout_steps):
                with self.subTest(
                    workflow=workflow.name,
                    contract="checkout credentials",
                    checkout=index,
                ):
                    self.assertIn("persist-credentials: false", step)

    def test_dependabot_and_security_gate_cover_standalone_example_locks(self) -> None:
        dependabot = (ROOT / ".github" / "dependabot.yml").read_text()
        security = workflow_text("security.yml")

        self.assertNotRegex(
            dependabot,
            r'(?ms)- package-ecosystem: npm\s+directory: "/jacs-wasm"\s+schedule:',
        )
        self.assertRegex(
            dependabot,
            r'(?ms)- package-ecosystem: npm\s+directory: "/jacs-wasm/examples/vite-smoke"\s+schedule:',
        )
        self.assertIn("working-directory: jacs-wasm/examples/vite-smoke", security)
        self.assertIn("npm audit --package-lock-only --audit-level=high", security)


if __name__ == "__main__":
    unittest.main()
