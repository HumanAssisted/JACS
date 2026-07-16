import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = REPO_ROOT / "jacs-wasm" / "examples" / "vite-smoke"
RESOLVER = EXAMPLE_DIR / "resolve-wasm-package.mjs"
VITE_CONFIG = EXAMPLE_DIR / "vite.config.ts"


class WasmViteRegistryModeTests(unittest.TestCase):
    def run_resolver(self, env: dict[str, str]) -> dict[str, object]:
        script = """
const { resolveWasmPackage } = await import(process.argv[1]);

try {
  const result = resolveWasmPackage({
    exampleDir: process.argv[2],
    env: JSON.parse(process.argv[3]),
  });
  process.stdout.write(JSON.stringify({ ok: true, result }));
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    error: error instanceof Error ? error.message : String(error),
  }));
}
"""
        completed = subprocess.run(
            [
                "node",
                "--input-type=module",
                "--eval",
                script,
                RESOLVER.as_uri(),
                str(EXAMPLE_DIR),
                json.dumps(env),
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return json.loads(completed.stdout)

    @staticmethod
    def make_registry_package(root: Path, version: str = "9.8.7") -> None:
        (root / "worker").mkdir(parents=True)
        (root / "package.json").write_text(
            json.dumps(
                {
                    "name": "@jacs/wasm",
                    "version": version,
                    "exports": {
                        ".": {"import": "./index.js"},
                        "./worker": {"import": "./worker/index.js"},
                    },
                }
            ),
            encoding="utf-8",
        )
        (root / "index.js").write_text("export {};\n", encoding="utf-8")
        (root / "worker" / "index.js").write_text("export {};\n", encoding="utf-8")
        (root / "worker" / "jacs-worker.js").write_text(
            "export {};\n", encoding="utf-8"
        )

    def test_local_mode_defaults_to_workspace_pkg(self) -> None:
        outcome = self.run_resolver({})

        self.assertTrue(outcome["ok"], outcome)
        result = outcome["result"]
        self.assertEqual(result["mode"], "local")
        self.assertEqual(
            Path(result["packageRoot"]),
            (EXAMPLE_DIR / "../../pkg").resolve(),
        )
        self.assertEqual(
            Path(result["aliases"]["@jacs/wasm"]),
            (EXAMPLE_DIR / "../../pkg/index.js").resolve(),
        )
        self.assertEqual(
            Path(result["aliases"]["@jacs/wasm/worker"]),
            (EXAMPLE_DIR / "../../pkg/worker/index.js").resolve(),
        )

    def test_registry_mode_resolves_exact_installed_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = (
                Path(temp_dir) / "consumer" / "node_modules" / "@jacs" / "wasm"
            )
            self.make_registry_package(package_root)

            outcome = self.run_resolver(
                {
                    "JACS_WASM_PACKAGE_ROOT": str(package_root),
                    "JACS_WASM_EXPECTED_VERSION": "9.8.7",
                }
            )

        self.assertTrue(outcome["ok"], outcome)
        result = outcome["result"]
        self.assertEqual(result["mode"], "registry")
        self.assertEqual(Path(result["packageRoot"]), package_root.resolve())
        self.assertEqual(
            Path(result["aliases"]["@jacs/wasm"]),
            package_root.resolve() / "index.js",
        )
        self.assertEqual(
            Path(result["aliases"]["@jacs/wasm/worker"]),
            package_root.resolve() / "worker" / "index.js",
        )

    def test_registry_mode_requires_expected_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir) / "node_modules" / "@jacs" / "wasm"
            self.make_registry_package(package_root)
            outcome = self.run_resolver({"JACS_WASM_PACKAGE_ROOT": str(package_root)})

        self.assertFalse(outcome["ok"], outcome)
        self.assertIn("JACS_WASM_EXPECTED_VERSION", outcome["error"])

    def test_expected_version_without_registry_root_fails_closed(self) -> None:
        outcome = self.run_resolver({"JACS_WASM_EXPECTED_VERSION": "9.8.7"})

        self.assertFalse(outcome["ok"], outcome)
        self.assertIn("JACS_WASM_PACKAGE_ROOT", outcome["error"])

    def test_registry_mode_rejects_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir) / "node_modules" / "@jacs" / "wasm"
            self.make_registry_package(package_root, version="1.2.3")
            outcome = self.run_resolver(
                {
                    "JACS_WASM_PACKAGE_ROOT": str(package_root),
                    "JACS_WASM_EXPECTED_VERSION": "9.8.7",
                }
            )

        self.assertFalse(outcome["ok"], outcome)
        self.assertIn("expected version 9.8.7", outcome["error"])
        self.assertIn("found 1.2.3", outcome["error"])

    def test_registry_mode_rejects_workspace_or_arbitrary_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir) / "pkg"
            self.make_registry_package(package_root)
            outcome = self.run_resolver(
                {
                    "JACS_WASM_PACKAGE_ROOT": str(package_root),
                    "JACS_WASM_EXPECTED_VERSION": "9.8.7",
                }
            )

        self.assertFalse(outcome["ok"], outcome)
        self.assertIn("node_modules/@jacs/wasm", outcome["error"])

    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_registry_mode_rejects_symlink_that_can_mask_local_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            target = temp / "local-pkg"
            self.make_registry_package(target)
            package_root = temp / "node_modules" / "@jacs" / "wasm"
            package_root.parent.mkdir(parents=True)
            package_root.symlink_to(target, target_is_directory=True)

            outcome = self.run_resolver(
                {
                    "JACS_WASM_PACKAGE_ROOT": str(package_root),
                    "JACS_WASM_EXPECTED_VERSION": "9.8.7",
                }
            )

        self.assertFalse(outcome["ok"], outcome)
        self.assertIn("must not be a symlink", outcome["error"])

    def test_registry_mode_requires_main_worker_export_and_worker_bootstrap(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir) / "node_modules" / "@jacs" / "wasm"
            self.make_registry_package(package_root)
            (package_root / "worker" / "jacs-worker.js").unlink()

            outcome = self.run_resolver(
                {
                    "JACS_WASM_PACKAGE_ROOT": str(package_root),
                    "JACS_WASM_EXPECTED_VERSION": "9.8.7",
                }
            )

        self.assertFalse(outcome["ok"], outcome)
        self.assertIn("worker/jacs-worker.js", outcome["error"])

    def test_vite_config_delegates_mode_selection_to_validated_resolver(self) -> None:
        config = VITE_CONFIG.read_text(encoding="utf-8")

        self.assertIn("resolveWasmPackage", config)
        self.assertNotIn("../../pkg/index.js", config)
        self.assertNotIn("../../pkg/worker/index.js", config)


if __name__ == "__main__":
    unittest.main()
