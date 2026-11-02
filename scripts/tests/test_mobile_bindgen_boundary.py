"""The published mobile crate carries no binding generator or source-only dependency.

UniFFI's binding generator pulls in Askama, whose published releases still use
the unmaintained basic-toml. The generator therefore lives in an unpublished
tool crate; the published jacs-mobile crate depends only on UniFFI's runtime.
"""

from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = "tools/jacs-mobile-bindgen"
GENERATOR_ONLY_PACKAGES = {
    "uniffi_bindgen", "askama", "askama_derive", "askama_macros", "askama_parser", "basic-toml",
}


def manifest(relative: str) -> dict:
    return tomllib.loads((ROOT / relative).read_text())


class MobileBindgenBoundaryTests(unittest.TestCase):
    def test_published_mobile_crate_depends_on_the_uniffi_runtime_only(self) -> None:
        mobile = manifest("jacs-mobile/Cargo.toml")
        uniffi = mobile["dependencies"]["uniffi"]
        # UniFFI's default `cargo-metadata` feature names the generator as a weak
        # optional dependency, which Cargo then records in every consumer's lock.
        self.assertIs(uniffi.get("default-features"), False)
        self.assertNotIn("features", uniffi)
        self.assertNotIn("bindgen", mobile.get("features", {}))
        self.assertNotIn("bin", mobile)
        self.assertFalse((ROOT / "jacs-mobile/src/bin").exists())

    def test_generator_tool_is_unpublished_separate_and_pinned_with_the_runtime(self) -> None:
        tool = manifest(f"{TOOL}/Cargo.toml")
        self.assertIs(tool["package"].get("publish"), False)
        self.assertIn("workspace", tool)
        self.assertIn("cli", tool["dependencies"]["uniffi"]["features"])
        # Generated scaffolding must come from the UniFFI version the library links.
        self.assertEqual(
            tool["dependencies"]["uniffi"]["version"],
            manifest("jacs-mobile/Cargo.toml")["dependencies"]["uniffi"]["version"],
        )
        workspace = manifest("Cargo.toml")["workspace"]
        self.assertIn(TOOL, workspace["exclude"])
        self.assertNotIn(TOOL, workspace["members"])
        self.assertTrue((ROOT / TOOL / "Cargo.lock").is_file())

    def test_portable_workspace_has_no_source_patches_or_generator_packages(self) -> None:
        # Workspace patches never reach registry consumers of published crates.
        self.assertNotIn("patch", manifest("Cargo.toml"))
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        packages = lock.get("package", [])
        sources = {package["source"].split("+", 1)[0] for package in packages if "source" in package}
        self.assertEqual(sources, {"registry"})
        self.assertFalse(GENERATOR_ONLY_PACKAGES & {package["name"] for package in packages})

    def test_generation_ci_and_security_audits_cover_the_tool(self) -> None:
        script = (ROOT / "jacs-mobile/scripts/generate-bindings.sh").read_text()
        self.assertIn(f"cargo build --locked --manifest-path {TOOL}/Cargo.toml", script)
        self.assertNotIn("--features bindgen", script)
        mobile_ci = (ROOT / ".github/workflows/mobile-bindings.yml").read_text()
        self.assertIn(f'- "{TOOL}/**"', mobile_ci)
        security = (ROOT / ".github/workflows/security.yml").read_text()
        self.assertIn(f"cargo audit --file {TOOL}/Cargo.lock", security)
        self.assertIn(f"cargo deny --manifest-path {TOOL}/Cargo.toml --all-features check", security)


if __name__ == "__main__":
    unittest.main()
