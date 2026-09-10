"""Source contract for shipping the existing verifier without shared OpenSSL."""

import fnmatch
import json
from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
FEATURE = "human-approval-vendored"


def manifest(path):
    return tomllib.loads((ROOT / path).read_text())


class NativeProofPackagingTests(unittest.TestCase):
    def test_embedded_protocol_schemas_ship_with_sources(self):
        for crate, source in (("jacs-core", "src/schema.rs"), ("jacs", "src/compatibility/ap2.rs")):
            include = manifest(f"{crate}/Cargo.toml")["package"]["include"]
            source_path = ROOT / crate / source
            for reference in re.findall(r'include_str!\(\s*"([^"]+)"', source_path.read_text()):
                path = (source_path.parent / reference).resolve().relative_to(ROOT / crate)
                with self.subTest(schema=str(path)):
                    self.assertTrue((ROOT / crate / path).is_file())
                    self.assertTrue(any(fnmatch.fnmatch(str(path), pattern) for pattern in include))

    def test_core_package_includes_every_explicit_cargo_target(self):
        core = manifest("jacs/Cargo.toml")
        for kind, directory in (("example", "examples"), ("bench", "benches")):
            for target in core.get(kind, []):
                path = target.get("path", f"{directory}/{target['name']}.rs")
                with self.subTest(target=path):
                    self.assertTrue((ROOT / "jacs" / path).is_file())
                    self.assertTrue(any(fnmatch.fnmatch(path, pattern) for pattern in core["package"]["include"]))

    def test_one_optional_backend_preserves_rust_defaults(self):
        core = manifest("jacs/Cargo.toml")
        self.assertEqual(core["features"]["default"], ["sqlite"])
        self.assertEqual(
            core["features"][FEATURE],
            ["human-approval", "dep:openssl", "openssl/vendored"],
        )
        backend = core["target"]['cfg(not(target_arch = "wasm32"))']["dependencies"]["openssl"]
        self.assertTrue(backend["optional"])
        self.assertFalse(backend["default-features"])

    def test_bindings_forward_without_changing_cargo_defaults(self):
        for path, upstream, defaults in (
            ("binding-core/Cargo.toml", "jacs", []),
            ("jacspy/Cargo.toml", "jacs-binding-core", ["a2a"]),
            ("jacsnpm/Cargo.toml", "jacs-binding-core", ["a2a", "attestation", "agreements"]),
            ("jacsgo/lib/Cargo.toml", "jacs-binding-core", ["a2a", "agreements"]),
        ):
            with self.subTest(path=path):
                features = manifest(path)["features"]
                self.assertEqual(features["default"], defaults)
                self.assertEqual(features[FEATURE], ["human-approval", f"{upstream}/{FEATURE}"])

    def test_distribution_profiles_require_the_verifier(self):
        self.assertIn(FEATURE, manifest("jacspy/pyproject.toml")["tool"]["maturin"]["features"])
        npm = json.loads((ROOT / "jacsnpm/package.json").read_text())
        self.assertIn(f"--features {FEATURE}", npm["scripts"]["build"])
        self.assertNotIn(FEATURE, npm["scripts"]["build:slim"])
        for name in ("release-npm.yml", "release-jacsgo.yml"):
            self.assertIn(f"--features {FEATURE}", (ROOT / ".github/workflows" / name).read_text())

    def test_candidate_and_published_consumers_check_public_proof(self):
        for name, probe in (
            ("release-pypi.yml", "verify_human_approval.py"),
            ("release-npm.yml", "verify_human_approval.cjs"),
        ):
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn(probe, text.split("  candidate-smoke:", 1)[1].split("\n  cli-release-ready:", 1)[0].split("\n  publish:", 1)[0])
                self.assertIn(probe, text.split("  post-publish-smoke:", 1)[1])

    def test_native_uploads_require_external_crypto_linkage_inspection(self):
        for name in ("release-pypi.yml", "release-npm.yml", "release-jacsgo.yml"):
            with self.subTest(workflow=name):
                text = (ROOT / ".github/workflows" / name).read_text()
                self.assertIn("scripts/check_native_crypto_linkage.py", text)

    def test_wasm_stays_on_portable_core_without_native_backend(self):
        wasm = manifest("jacs-wasm/Cargo.toml")
        self.assertNotIn("jacs", wasm["dependencies"])
        self.assertNotIn("openssl", wasm["dependencies"])
        self.assertNotIn("webauthn-rs", wasm["dependencies"])

    def test_go_consumers_share_one_public_fixture_probe(self):
        for name in ("staged-consumer-smoke.sh", "external-consumer-smoke.sh"):
            with self.subTest(script=name):
                text = (ROOT / "jacsgo/scripts" / name).read_text()
                self.assertIn("consumer-smoke/main.go", text)
                self.assertIn("human_approved_document_v1.json", text)
                self.assertIn("check-macos-install-name.sh", text)

    def test_go_macos_install_name_is_normalized_before_checksum(self):
        text = (ROOT / ".github/workflows/release-jacsgo.yml").read_text()
        normalize = text.index("install_name_tool -id '@loader_path/libjacsgo.dylib'")
        sign = text.index("codesign --force --sign -")
        inspect = text.index("bash jacsgo/scripts/check-macos-install-name.sh")
        checksum = text.index('sha256sum "$ASSET_NAME"')
        self.assertLess(normalize, sign)
        self.assertLess(sign, inspect)
        self.assertLess(inspect, checksum)

    def test_required_candidate_platforms_are_runtime_gated_before_publish(self):
        for name in ("release-pypi.yml", "release-npm.yml"):
            with self.subTest(workflow=name):
                text = (ROOT / ".github/workflows" / name).read_text()
                candidates = text.split("  candidate-smoke:", 1)[1].split("  candidate-musl-smoke:", 1)[0]
                for runner in ("ubuntu-latest", "ubuntu-24.04-arm", "macos-latest", "macos-14"):
                    self.assertIn(runner, candidates)
                musl = text.split("  candidate-musl-smoke:", 1)[1].split("\n  cli-release-ready:", 1)[0].split("\n  publish:", 1)[0]
                self.assertRegex(musl, r"(?:node:20|python:3\.11)-alpine@sha256:[0-9a-f]{64}")
                self.assertIn("--network none --read-only", musl)
                self.assertIn("/installed:ro", musl)
                self.assertIn("candidate-musl-smoke", text.split("  publish:", 1)[1].split("\n    runs-on:", 1)[0])

    def test_linux_only_cli_fixture_does_not_gate_other_native_platforms(self):
        text = (ROOT / ".github/workflows/release-npm.yml").read_text()
        step = text.split("      - name: Run exact candidate package postinstall and installed CLI shim", 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: matrix.os == 'ubuntu-latest' && matrix.architecture == 'x64'", step)

    def test_source_distribution_has_a_real_candidate_build_and_proof_gate(self):
        text = (ROOT / ".github/workflows/release-pypi.yml").read_text()
        source = text.split("  candidate-sdist-smoke:", 1)[1].split("\n  publish:", 1)[0]
        for command in ("sha256sum -c", "check_cargo_lock_subset.py", "maturin build --locked --release", "--no-index --no-deps", "verify_human_approval.py"):
            self.assertIn(command, source)
        self.assertIn("candidate-sdist-smoke", text.split("  publish:", 1)[1].split("\n    runs-on:", 1)[0])

    def test_unverified_optional_outputs_cannot_enter_registry_candidates(self):
        npm = (ROOT / ".github/workflows/release-npm.yml").read_text()
        self.assertIn("'experimental-bindings'", npm)
        assembly = npm.split("  assemble-package:", 1)[1].split("  candidate-smoke:", 1)[0]
        self.assertIn("pattern: bindings-*", assembly)
        self.assertNotIn('"jacs.freebsd-x64.node"', assembly)
        self.assertNotIn('"jacs.linux-riscv64-gnu.node"', assembly)
        for name in ("release-pypi.yml", "release-npm.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                musl = text.split("  candidate-musl-smoke:", 1)[1].split("\n  candidate-sdist-smoke:", 1)[0].split("\n  cli-release-ready:", 1)[0]
                self.assertIn("ubuntu-24.04-arm", musl)
                self.assertIn("steps.candidate.outputs.available == 'true'", musl)
                self.assertIn("no proof verification was performed", musl)
                self.assertNotIn("steps.build_native_module.conclusion", text)
                self.assertNotIn("steps.build_wheel.conclusion", text)


if __name__ == "__main__":
    unittest.main()
