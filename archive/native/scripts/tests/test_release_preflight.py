from __future__ import annotations

import re
import json
import unittest
from pathlib import Path

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
    def test_pq_target_builds_cli_before_running_cli_integration_tests(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        target = make_target_block(makefile, "test-jacs-pq")

        build_cli = target.find("cargo build --locked -p jacs-cli")
        run_tests = target.find("cargo test -p jacs")
        self.assertGreaterEqual(build_cli, 0, target)
        self.assertGreaterEqual(run_tests, 0, target)
        self.assertLess(build_cli, run_tests, target)

    def test_slow_target_runs_standalone_surrealdb_by_locked_manifest(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        target = make_target_block(makefile, "test-jacs-surrealdb")

        self.assertIn(
            "cargo test --manifest-path jacs-surrealdb/Cargo.toml --locked",
            target,
        )
        self.assertNotIn("cargo test -p jacs-surrealdb", target)

    def test_storage_release_denies_warnings_before_packaging(self) -> None:
        publish = job_block(workflow_text("release-storage-crate.yml"), "publish")
        check = 'cargo check --locked --manifest-path "$CRATE/Cargo.toml" --lib'
        package = 'cargo package --locked --manifest-path "$CRATE/Cargo.toml"'

        self.assertIn('RUSTFLAGS: "-D warnings"', publish)
        self.assertIn(check, publish)
        self.assertLess(publish.index(check), publish.index(package))

    def test_every_executable_release_job_has_an_explicit_timeout(self) -> None:
        workflows = (
            "release-cli.yml",
            "release-crate.yml",
            "release-homebrew.yml",
            "release-jacsgo.yml",
            "release-npm.yml",
            "release-pypi.yml",
            "release-readiness.yml",
            "release-storage-crate.yml",
            "release-wasm.yml",
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

    def test_node_runtime_contract_matches_release_and_omits_build_dependencies(self) -> None:
        package = json.loads((ROOT / "jacsnpm" / "package.json").read_text())
        self.assertEqual(package.get("dependencies"), {})
        self.assertIn("@napi-rs/cli", package["devDependencies"])
        self.assertNotIn("uuid", json.dumps(package))
        self.assertEqual(package.get("engines", {}).get("node"), ">=20")
        installation = (
            ROOT / "jacs" / "docs" / "jacsbook" / "src" / "nodejs" / "installation.md"
        ).read_text()
        self.assertNotIn("Version 16", installation)
        self.assertIn("Version 20.0 or higher", installation)
        self.assertIn("Should be 20+", installation)

    def test_node_commonjs_tests_pin_the_last_commonjs_chai(self) -> None:
        package = json.loads((ROOT / "jacsnpm" / "package.json").read_text())
        commonjs_tests = list((ROOT / "jacsnpm" / "test").glob("*.test.js"))
        self.assertTrue(
            any("require('chai')" in path.read_text() for path in commonjs_tests)
        )
        self.assertEqual(package["devDependencies"].get("chai"), "4.5.0")

    def test_node_examples_resolve_local_sdk_and_are_dependency_audited(self) -> None:
        examples = ROOT / "jacsnpm" / "examples"
        package = json.loads((examples / "package.json").read_text())
        local_spec = package["dependencies"]["jacsnpm"]
        self.assertTrue(local_spec.startswith("file:"))
        self.assertEqual(
            (examples / local_spec.removeprefix("file:")).resolve(),
            (ROOT / "jacsnpm").resolve(),
        )

        langchain = examples / "langchain"
        self.assertTrue((langchain / "package-lock.json").is_file())
        dependabot = (ROOT / ".github" / "dependabot.yml").read_text()
        self.assertIn('directory: "/jacsnpm/examples/langchain"', dependabot)
        security = workflow_text("security.yml")
        self.assertIn("--prefix examples/langchain", security)
        self.assertIn("jacsnpm/examples/langchain/package-lock.json", security)

    def test_wasm_pack_runs_from_crate_directory_so_target_config_is_loaded(self) -> None:
        cargo_config = (ROOT / "jacs-wasm" / ".cargo" / "config.toml").read_text()
        self.assertIn("[target.wasm32-unknown-unknown]", cargo_config)
        self.assertIn("-zstack-size=4194304", cargo_config)

        makefile = (ROOT / "Makefile").read_text()
        self.assertIn(
            "cd jacs-wasm && wasm-pack test --headless --chrome . --locked", makefile
        )
        self.assertIn(
            "cd jacs-wasm && wasm-pack build --target web --release . --locked", makefile
        )

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
        for workflow_name in ("release-crate.yml", "release-storage-crate.yml"):
            publish = job_block(workflow_text(workflow_name), "publish")
            with self.subTest(workflow=workflow_name):
                self.assertIn('toolchain: "1.97"', publish)

        crate_publish = job_block(workflow_text("release-crate.yml"), "publish")
        self.assertIn('RUSTFLAGS: "-D warnings"', crate_publish)
        self.assertIn("cargo check --locked", crate_publish)

        cli_build = job_block(workflow_text("release-cli.yml"), "build")
        self.assertIn("cargo build --locked --release", cli_build)

        pypi_build = job_block(workflow_text("release-pypi.yml"), "build-wheels")
        # native, zig, and the pinned manylinux_2_28 container builds
        self.assertEqual(pypi_build.count("maturin build --locked"), 3)
        self.assertIn("--compatibility manylinux_2_28", pypi_build)
        self.assertIn("manylinux_dockerfile: DockerfileBuilder", pypi_build)
        self.assertIn("manylinux_dockerfile: Dockerfile\n", pypi_build)

        npm_build = job_block(workflow_text("release-npm.yml"), "build")
        # Every napi build path (zig cross, native, Alpine container) stays locked.
        self.assertGreaterEqual(npm_build.count("npx napi build"), 3)
        self.assertEqual(npm_build.count("npx napi build"), npm_build.count("--cargo-flags=--locked"))

        wasm_build = job_block(workflow_text("release-wasm.yml"), "build-and-test")
        self.assertIn("wasm-pack test --headless --firefox . --locked", wasm_build)
        self.assertIn("wasm-pack build --target web --release . --locked", wasm_build)

        package = json.loads((ROOT / "jacsnpm" / "package.json").read_text())
        self.assertIn("--cargo-flags=--locked", package["scripts"]["build"])
        self.assertIn("--cargo-flags=--locked", package["scripts"]["build:debug"])

    def test_release_workflows_call_product_suites_and_shared_core_triggers_bindings(self) -> None:
        called = (
            "rust.yml",
            "nodejs.yml",
            "python.yml",
            "jacsgo.yml",
            "jacs-mcp.yml",
        )
        for workflow_name in called:
            text = workflow_text(workflow_name)
            with self.subTest(workflow=workflow_name):
                self.assertIn("  workflow_call:", text)

        for workflow_name in ("nodejs.yml", "python.yml", "jacsgo.yml", "jacs-mcp.yml"):
            text = workflow_text(workflow_name)
            with self.subTest(shared_paths=workflow_name):
                self.assertGreaterEqual(text.count('jacs-core/**'), 2)
                self.assertGreaterEqual(text.count('jacs-media/**'), 2)

        release_calls = {
            "release-crate.yml": "rust.yml",
            "release-storage-crate.yml": "rust.yml",
            "release-cli.yml": "rust.yml",
            "release-npm.yml": "nodejs.yml",
            "release-pypi.yml": "python.yml",
            "release-jacsgo.yml": "jacsgo.yml",
        }
        for release_workflow, called_workflow in release_calls.items():
            text = workflow_text(release_workflow)
            with self.subTest(release=release_workflow):
                self.assertIn("  functional-gate:", text)
                self.assertIn(f"uses: ./.github/workflows/{called_workflow}", text)
                self.assertRegex(text, r"needs: [^\n]*functional-gate")

        python = workflow_text("python.yml")
        self.assertNotIn("if: github.event_name == 'push'", python)

    def test_python_ci_pins_tools_and_checksum_verifies_rustup(self) -> None:
        workflow = workflow_text("python.yml")
        for requirement in (
            "maturin==1.5.0",
            "pytest==9.1.1",
            "pytest-asyncio==1.4.0",
            "pytest-xdist==3.8.0",
            "fastmcp==3.2.0",
            "mcp==1.26.0",
            "starlette==1.3.1",
            "uv==0.11.28",
            "cibuildwheel==4.1.0",
        ):
            self.assertIn(requirement, workflow)
        self.assertNotIn("curl https://sh.rustup.rs", workflow)
        self.assertIn("RUSTUP_VERSION=1.29.0", workflow)
        self.assertIn("RUST_VERSION=1.97.0", workflow)
        self.assertIn(
            "4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10",
            workflow,
        )
        self.assertIn(
            "9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792",
            workflow,
        )
        self.assertIn("sha256sum -c", workflow)
        self.assertIn("maturin build --locked", workflow)
        self.assertNotRegex(
            workflow,
            r"(?m)^\s+run:\s+[^\n]*--only-binary=:all:",
            "pip commands containing ': ' must use a YAML block scalar",
        )

        pyproject = (ROOT / "jacspy" / "pyproject.toml").read_text()
        self.assertIn('requires = ["maturin==1.5.0"]', pyproject)

    def test_direct_rust_publish_includes_jacs_core_in_dependency_order(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        publish_all = make_target_block(makefile, "publish-jacs")
        ordered_directories = (
            "cd jacs-core",
            "cd jacs-media",
            "cd jacs &&",
            "cd binding-core",
            "cd jacs-mcp",
            "cd jacs-cli",
        )
        positions = [publish_all.index(value) for value in ordered_directories]
        self.assertEqual(positions, sorted(positions))
        publish_core = make_target_block(makefile, "publish-jacs-core")
        self.assertIn("cd jacs-core && cargo publish --locked", publish_core)

        releasing = (ROOT / "RELEASING.md").read_text()
        self.assertIn(
            "`jacs-core`, `jacs-media`, `jacs`, `jacs-binding-core`, `jacs-mcp`, then `jacs-cli`",
            releasing,
        )

    def test_registry_matrix_runs_after_every_publication_workflow(self) -> None:
        text = workflow_text("release-readiness.yml")
        self.assertIn("workflow_run:", text)
        for workflow_name in (
            "Release CLI Binaries",
            "Release crates.io",
            "Release PyPI",
            "Release npm",
            "Release @jacs/wasm",
            "Release jacsgo Native Libraries",
        ):
            self.assertIn(workflow_name, text)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", text)
        verify = job_block(text, "verify-public-registries")
        self.assertIn("attestations: read", verify)
        self.assertIn("verify_github_release_attestations.py", verify)
        self.assertIn("--matrix release/shipped-artifacts.json", verify)
        self.assertIn("verify_recorded_registry_provenance.py", verify)
        self.assertIn("pypi-attestations==0.0.29", verify)
        self.assertIn("npm@11.18.0", verify)
        self.assertIn("timeout-minutes:", verify)

    def test_cli_build_runs_both_installers_against_staged_assets_on_every_platform(
        self,
    ) -> None:
        text = workflow_text("release-cli.yml")
        build = job_block(text, "build")
        self.assertEqual(build.count("python3 scripts/smoke-cli-installers.py"), 1)
        self.assertEqual(build.count("python scripts/smoke-cli-installers.py"), 1)
        self.assertIn('$prefix/scripts/smoke-cli-installers.py', build)
        self.assertIn("Smoke staged Python and Node installers (Unix)", build)
        self.assertIn("Smoke staged Python and Node installers (Windows)", build)
        self.assertIn("sha256sums.txt", build)
        harness = (ROOT / "scripts" / "smoke-cli-installers.py").read_text()
        self.assertIn('"quickstart"', harness)
        self.assertIn('"document",', harness)
        self.assertIn('"verify",', harness)

    def test_npm_publishes_checksum_verified_candidate_after_cjs_and_esm_smoke(self) -> None:
        text = workflow_text("release-npm.yml")
        preflight = job_block(text, "preflight-publish")
        assemble = job_block(text, "assemble-package")
        candidate = job_block(text, "candidate-smoke")
        publish = job_block(text, "publish")
        post_publish = job_block(text, "post-publish-smoke")
        self.assertRegex(publish, r"needs: \[[^\]]*candidate-smoke[^\]]*\]")
        self.assertIn("sha256sum -c", candidate)
        self.assertIn("require(\"@hai.ai/jacs\")", candidate)
        self.assertIn("--input-type=module", candidate)
        self.assertIn("sha256sum -c", publish)
        self.assertIn("id-token: write", publish)
        self.assertIn("node-version: 24", publish)
        self.assertIn("npm@11.18.0", publish)
        self.assertNotIn("NODE_AUTH_TOKEN", publish)
        self.assertNotIn("NPM_TOKEN", publish)
        self.assertNotIn("npm whoami", preflight)
        self.assertIn('"LICENSE"', assemble)
        self.assertIn("npm audit signatures", post_publish)
        self.assertIn("smoke-node-package-postinstall.py", candidate)
        self.assertIn("smoke-node-package-postinstall.py", post_publish)
        cli_ready = job_block(text, "cli-release-ready")
        self.assertIn("attestations: read", cli_ready)
        self.assertIn("verify_github_release_attestations.py", cli_ready)
        self.assertIn("cli/v$VERSION", cli_ready)
        self.assertIn("cli-release-ready", publish)
        self.assertIn("timeout-minutes:", cli_ready)
        self.assertIn("timeout-minutes:", post_publish)
        self.assertIn("contents: read", post_publish)

    def test_async_release_dependents_have_bounded_upstream_waits(self) -> None:
        npm = workflow_text("release-npm.yml")
        cli_ready = job_block(npm, "cli-release-ready")
        self.assertIn("timeout-minutes: 90", cli_ready)
        self.assertIn("JACS_RELEASE_METADATA_ATTEMPTS: \"360\"", cli_ready)

        storage = job_block(workflow_text("release-storage-crate.yml"), "publish")
        self.assertIn("timeout-minutes: 150", storage)
        self.assertIn("for attempt in $(seq 1 480)", storage)
        self.assertIn("--max-time 30", storage)

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
        self.assertNotIn("NODE_AUTH_TOKEN", publish)
        self.assertNotIn("NPM_TOKEN", publish)
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

    def test_release_help_does_not_request_obsolete_registry_tokens(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        self.assertNotIn("PYPI_API_TOKEN", makefile)
        self.assertNotIn("NPM_TOKEN", makefile)
        self.assertIn("crates.io, PyPI and npm prefer OIDC trusted publishers", makefile)
        self.assertIn("CRATES_IO_TOKEN  - migration fallback", makefile)
        release_everything = next(
            line for line in makefile.splitlines() if line.startswith("release-everything:")
        )
        self.assertLess(
            release_everything.index("release-cli"),
            release_everything.index("release-jacsnpm"),
        )

    def test_pypi_publishes_checksum_verified_bundle_after_local_wheel_smoke(self) -> None:
        text = workflow_text("release-pypi.yml")
        candidate = job_block(text, "candidate-smoke")
        publish = job_block(text, "publish")
        post_publish = job_block(text, "post-publish-smoke")
        self.assertRegex(publish, r"needs: \[[^\]]*candidate-smoke[^\]]*\]")
        self.assertIn("sha256sum -c", candidate)
        self.assertIn("--no-index", candidate)
        self.assertIn("--only-binary=:all:", candidate)
        self.assertIn("sign_message", candidate)
        self.assertIn("sha256sum -c", publish)
        self.assertIn("id-token: write", publish)
        self.assertNotIn("password:", publish)
        self.assertNotIn("username:", publish)
        self.assertIn("pypi-attestations==0.0.29", post_publish)
        self.assertIn("verify_pypi_release_attestations.py", post_publish)
        self.assertIn("JACS_PYPI_VERIFY_TIMEOUT_SECONDS", post_publish)
        self.assertIn("timeout-minutes:", post_publish)

    def test_pypi_smokes_every_supported_python_version(self) -> None:
        text = workflow_text("release-pypi.yml")
        supported = ("3.10", "3.11", "3.12", "3.13", "3.14")
        for job_name in ("candidate-smoke", "post-publish-smoke"):
            job = job_block(text, job_name)
            self.assertIn("matrix:", job)
            self.assertIn("python-version:", job)
            self.assertIn("python-version: ${{ matrix.python-version }}", job)
            for version in supported:
                self.assertIn(f"'{version}'", job)

        metadata = (ROOT / "jacspy" / "pyproject.toml").read_text()
        self.assertIn('requires-python = ">=3.10,<3.15"', metadata)
        for version in supported:
            self.assertIn(f"Programming Language :: Python :: {version}", metadata)

    def test_go_release_waits_for_staged_external_consumer(self) -> None:
        text = workflow_text("release-jacsgo.yml")
        candidate = job_block(text, "candidate-consumer-smoke")
        release = job_block(text, "release")
        self.assertRegex(candidate, r"needs: \[[^\]]*prepare-release[^\]]*\]")
        self.assertRegex(release, r"needs: \[[^\]]*candidate-consumer-smoke[^\]]*\]")
        self.assertIn("staged-consumer-smoke.sh", candidate)

    def test_cli_and_go_verify_every_public_release_asset_attestation(self) -> None:
        cases = (
            (
                "release-cli.yml",
                "cli/v${{ needs.verify-version.outputs.version }}",
                "HumanAssisted/JACS/.github/workflows/release-cli.yml",
            ),
            (
                "release-jacsgo.yml",
                "jacsgo/v${{ needs.verify-version.outputs.version }}",
                "HumanAssisted/JACS/.github/workflows/release-jacsgo.yml",
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
        cases = (
            (
                "release-crate.yml",
                (
                    ("jacs-core", "auth_jacs_core", "Publish jacs-core to crates.io"),
                    ("jacs-media", "auth_jacs_media", "Publish jacs-media to crates.io"),
                    ("jacs", "auth_jacs", "Publish jacs to crates.io"),
                    (
                        "jacs-binding-core",
                        "auth_jacs_binding_core",
                        "Publish jacs-binding-core to crates.io",
                    ),
                    ("jacs-mcp", "auth_jacs_mcp", "Publish jacs-mcp to crates.io"),
                    ("jacs-cli", "auth_jacs_cli", "Publish jacs-cli to crates.io"),
                ),
            ),
            (
                "release-storage-crate.yml",
                (("storage crate", "auth_storage_crate", "Publish to crates.io"),),
            ),
        )

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
            "release-storage-crate.yml",
            "environment `crates-io`",
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

        for directory in ("http", "mcp", "langchain"):
            with self.subTest(python_example=directory):
                self.assertRegex(
                    dependabot,
                    rf'(?ms)- package-ecosystem: pip\s+directory: "/jacspy/examples/{directory}"\s+schedule:',
                )
                self.assertIn(f"examples/{directory}/requirements.txt", security)

    def test_observability_target_includes_security_contract(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        target = makefile.split("test-jacs-observability:\n", 1)[1].split("\n\n", 1)[0]
        self.assertIn("--test security_observability", target)

    def test_mdbook_archive_is_pinned_and_verified_before_extraction(self) -> None:
        text = (ROOT / ".github" / "workflows" / "static.yml").read_text()
        build = job_block(text, "build")
        deploy = job_block(text, "deploy")
        self.assertIn("MDBOOK_SHA256", text)
        self.assertIn("sha256sum -c", text)
        self.assertIn("curl --fail", text)
        self.assertNotRegex(text, r"curl[^\n]*\|[^\n]*tar")
        self.assertIn("permissions: {}", text)
        self.assertIn("contents: read", build)
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("pages: write", build)
        self.assertNotIn("Install mdbook", deploy)
        self.assertIn("pages: write", deploy)
        self.assertIn("id-token: write", deploy)

    def test_manylinux_builders_pin_image_bootstrap_toolchain_and_maturin(self) -> None:
        cases = (
            (
                "Dockerfile",
                "FROM quay.io/pypa/manylinux_2_28_aarch64@sha256:d2380d927972b39b86041530b86c02c4307c19605afb4fe5ddf89e54f81e3bb6",
                "aarch64-unknown-linux-gnu/rustup-init",
                "9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792",
            ),
            (
                "DockerfileBuilder",
                "FROM quay.io/pypa/manylinux_2_28_x86_64@sha256:65140ef21cef92d0c13d001708afd7d304d7a154f7120d039df99dac708f3ffb",
                "x86_64-unknown-linux-gnu/rustup-init",
                "4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10",
            ),
        )
        for name, image, rustup_binary, rustup_sha256 in cases:
            text = (ROOT / "jacspy" / name).read_text()
            with self.subTest(dockerfile=name):
                self.assertEqual(text.splitlines()[0], image)
                self.assertIn("RUST_VERSION=1.97.0", text)
                self.assertIn("RUSTUP_VERSION=1.29.0", text)
                self.assertIn(f"RUSTUP_INIT_SHA256={rustup_sha256}", text)
                self.assertIn(rustup_binary, text)
                self.assertIn("sha256sum -c", text)
                self.assertNotIn("sh.rustup.rs", text)
                self.assertIn('maturin==1.5.0', text)

    def test_disconnected_observability_dockerfile_is_removed(self) -> None:
        self.assertFalse(
            (ROOT / "jacs" / "examples" / "observability" / "Dockerfile.jacs").exists()
        )

    def test_observability_compose_images_have_dependabot_coverage(self) -> None:
        compose = ROOT / "jacs" / "examples" / "observability" / "compose.yaml"
        self.assertTrue(compose.is_file())
        dependabot = (ROOT / ".github" / "dependabot.yml").read_text()
        self.assertRegex(
            dependabot,
            r'(?ms)- package-ecosystem: docker-compose\s+'
            r'directory: "/jacs/examples/observability"\s+schedule:',
        )

    def test_dependabot_covers_jacspy_dockerfiles(self) -> None:
        text = (ROOT / ".github" / "dependabot.yml").read_text()
        self.assertRegex(
            text,
            r'(?ms)- package-ecosystem: docker\s+directory: "/jacspy"\s+schedule:',
        )


if __name__ == "__main__":
    unittest.main()
