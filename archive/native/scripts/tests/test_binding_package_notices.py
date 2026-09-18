from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class BindingPackageNoticeTests(unittest.TestCase):
    def test_node_package_ships_exact_current_notices(self) -> None:
        canonical = (ROOT / "THIRD-PARTY-NOTICES").read_bytes()
        packaged = (ROOT / "jacsnpm/THIRD-PARTY-NOTICES").read_bytes()
        manifest = json.loads(
            (ROOT / "jacsnpm/package.json").read_text(encoding="utf-8")
        )

        self.assertEqual(packaged, canonical)
        self.assertIn("THIRD-PARTY-NOTICES", manifest["files"])

    def test_python_wheel_source_ships_exact_current_notices(self) -> None:
        canonical = (ROOT / "THIRD-PARTY-NOTICES").read_bytes()
        packaged = (
            ROOT / "jacspy/python/jacs/THIRD-PARTY-NOTICES"
        ).read_bytes()
        with (ROOT / "jacspy/pyproject.toml").open("rb") as handle:
            manifest = tomllib.load(handle)

        self.assertEqual(packaged, canonical)
        self.assertIn(
            "THIRD-PARTY-NOTICES",
            manifest["tool"]["maturin"].get("include", []),
            "the sdist must expose the canonical notice at its package root",
        )

    def test_wasm_finalizer_copies_notices_into_the_package(self) -> None:
        template = json.loads(
            (ROOT / "jacs-wasm/package.template.json").read_text(encoding="utf-8")
        )
        finalizer = (ROOT / "jacs-wasm/scripts/finalize-pkg.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("THIRD-PARTY-NOTICES", template["files"])
        self.assertIn(
            'NOTICES_SOURCE="${JACS_WASM_DIR}/../THIRD-PARTY-NOTICES"',
            finalizer,
        )
        self.assertIn(
            'cp "${NOTICES_SOURCE}" "${PKG_DIR}/THIRD-PARTY-NOTICES"',
            finalizer,
        )


if __name__ == "__main__":
    unittest.main()
