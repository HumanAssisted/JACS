from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import tempfile
import tomllib
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-security-exceptions.py"
SPEC = importlib.util.spec_from_file_location("check_security_exceptions", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
security_exceptions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_exceptions)
ROOT = SCRIPT.parents[1]
REVIEWED_CLARIFICATIONS = ROOT / "scripts/third_party_license_clarifications.toml"


class SecurityExceptionPolicyTests(unittest.TestCase):
    @staticmethod
    def notice_source(
        *,
        name: str = "file-only",
        path: str = "LICENSE",
        cargo_deny_hash: int = 0x12345678,
        sha256: str = "a" * 64,
    ) -> str:
        return f"""Cargo license file SHA-256: {sha256}
Cargo-deny normalized XXH32: 0x{cargo_deny_hash:08x}
License source path: {path}
Used by 1 package(s):

  - {name} 1.2.3

License text (the SHA-256 above identifies the source bytes):
"""

    @staticmethod
    def reviewed_source() -> dict[str, dict[str, object]]:
        return {
            "file-only": {
                "expression": "MIT",
                "sources": {("LICENSE", 0x12345678, "a" * 64)},
            }
        }

    def test_file_only_dependency_licenses_are_source_bound(self) -> None:
        with (ROOT / "deny.toml").open("rb") as handle:
            policy = tomllib.load(handle)
        clarifications = {
            item["name"]: item["expression"] for item in policy["licenses"]["clarify"]
        }

        self.assertEqual(clarifications["surrealdb-collections"], "BUSL-1.1")
        self.assertEqual(clarifications["surrealdb-strand"], "BUSL-1.1")
        self.assertEqual(clarifications["tokio-tungstenite-wasm"], "MIT")
        reviewed = security_exceptions.load_reviewed_license_clarifications(
            REVIEWED_CLARIFICATIONS
        )
        security_exceptions.require_source_bound_license_clarifications(
            policy["licenses"]["clarify"],
            (ROOT / "THIRD-PARTY-NOTICES").read_text(encoding="utf-8"),
            reviewed,
        )
        self.assertEqual(set(clarifications), set(reviewed))
        self.assertIn("ring", reviewed)

    def test_license_clarification_rejects_empty_license_files(self) -> None:
        clarification = {
            "name": "file-only",
            "expression": "MIT",
            "license-files": [],
        }

        with self.assertRaisesRegex(ValueError, "license-files"):
            security_exceptions.require_source_bound_license_clarifications(
                [clarification], self.notice_source(), self.reviewed_source()
            )

    def test_license_clarification_requires_exact_notice_path_and_hash(self) -> None:
        for license_file in (
            {"path": "COPYING", "hash": 0x12345678},
            {"path": "LICENSE", "hash": 0x87654321},
        ):
            with self.subTest(license_file=license_file):
                clarification = {
                    "name": "file-only",
                    "expression": "MIT",
                    "license-files": [license_file],
                }
                with self.assertRaisesRegex(ValueError, "notice source"):
                    security_exceptions.require_source_bound_license_clarifications(
                        [clarification], self.notice_source(), self.reviewed_source()
                    )

    def test_license_clarification_accepts_exact_notice_path_and_hash(self) -> None:
        clarification = {
            "name": "file-only",
            "expression": "MIT",
            "license-files": [{"path": "LICENSE", "hash": 0x12345678}],
        }

        security_exceptions.require_source_bound_license_clarifications(
            [clarification], self.notice_source(), self.reviewed_source()
        )

    def test_license_clarification_rejects_reviewed_expression_mutation(self) -> None:
        clarification = {
            "name": "file-only",
            "expression": "Apache-2.0",
            "license-files": [{"path": "LICENSE", "hash": 0x12345678}],
        }

        with self.assertRaisesRegex(ValueError, "reviewed expression"):
            security_exceptions.require_source_bound_license_clarifications(
                [clarification], self.notice_source(), self.reviewed_source()
            )

    def test_license_clarification_rejects_notice_sha256_mutation(self) -> None:
        clarification = {
            "name": "file-only",
            "expression": "MIT",
            "license-files": [{"path": "LICENSE", "hash": 0x12345678}],
        }

        with self.assertRaisesRegex(ValueError, "notice source"):
            security_exceptions.require_source_bound_license_clarifications(
                [clarification],
                self.notice_source(sha256="b" * 64),
                self.reviewed_source(),
            )

    def test_license_clarification_rejects_missing_reviewed_name(self) -> None:
        clarification = {
            "name": "file-only",
            "expression": "MIT",
            "license-files": [{"path": "LICENSE", "hash": 0x12345678}],
        }
        reviewed = copy.deepcopy(self.reviewed_source())
        reviewed["unexpected"] = reviewed.pop("file-only")

        with self.assertRaisesRegex(ValueError, "name set"):
            security_exceptions.require_source_bound_license_clarifications(
                [clarification], self.notice_source(), reviewed
            )

    def test_cargo_deny_gate_requires_all_features(self) -> None:
        workflow = """
        run: |
          cargo deny check advisories
          cargo deny --all-features check licenses
        """

        with self.assertRaisesRegex(ValueError, "all features"):
            security_exceptions.require_all_features_cargo_deny(
                workflow, "workflow.yml"
            )

    def test_cargo_deny_gate_accepts_all_features(self) -> None:
        workflow = """
        run: |
          cargo deny --all-features check advisories
          cargo deny --all-features check licenses
        """

        security_exceptions.require_all_features_cargo_deny(workflow, "workflow.yml")

    def test_object_store_s3_isolation_accepts_opt_in_cloud_features(self) -> None:
        manifest = {
            "dependencies": {
                "object_store": {
                    "version": "0.14.0",
                    "default-features": False,
                    "features": ["fs"],
                }
            },
            "features": {
                "default": ["sqlite"],
                "s3": ["object_store/aws"],
                "s3-tests": ["s3"],
            },
        }

        security_exceptions.require_object_store_s3_isolation(manifest)

    def test_object_store_s3_isolation_accepts_target_scoped_dependency(self) -> None:
        manifest = {
            "target": {
                'cfg(not(target_arch = "wasm32"))': {
                    "dependencies": {
                        "object_store": {
                            "version": "0.14.0",
                            "default-features": False,
                            "features": ["fs"],
                        }
                    }
                }
            },
            "features": {
                "default": ["sqlite"],
                "s3": ["object_store/aws"],
                "s3-tests": ["s3"],
            },
        }

        security_exceptions.require_object_store_s3_isolation(manifest)

    def test_object_store_s3_isolation_rejects_cloud_features_in_base_dependency(
        self,
    ) -> None:
        manifest = {
            "dependencies": {
                "object_store": {
                    "version": "0.14.0",
                    "default-features": False,
                    "features": ["fs", "aws"],
                }
            },
            "features": {
                "default": ["sqlite"],
                "s3": ["object_store/aws"],
                "s3-tests": ["s3"],
            },
        }

        with self.assertRaisesRegex(ValueError, "base features"):
            security_exceptions.require_object_store_s3_isolation(manifest)

    def test_object_store_s3_isolation_rejects_default_s3_feature(self) -> None:
        manifest = {
            "dependencies": {
                "object_store": {
                    "version": "0.14.0",
                    "default-features": False,
                    "features": ["fs"],
                }
            },
            "features": {
                "default": ["sqlite", "s3"],
                "s3": ["object_store/aws"],
                "s3-tests": ["s3"],
            },
        }

        with self.assertRaisesRegex(ValueError, "default feature set"):
            security_exceptions.require_object_store_s3_isolation(manifest)

    def test_object_store_s3_isolation_rejects_unbound_test_feature(self) -> None:
        manifest = {
            "dependencies": {
                "object_store": {
                    "version": "0.14.0",
                    "default-features": False,
                    "features": ["fs"],
                }
            },
            "features": {
                "default": ["sqlite"],
                "s3": ["object_store/aws"],
                "s3-tests": [],
            },
        }

        with self.assertRaisesRegex(ValueError, "s3-tests"):
            security_exceptions.require_object_store_s3_isolation(manifest)

    def test_lock_parents_are_reported_exactly(self) -> None:
        lock = """
version = 4
[[package]]
name = "vulnerable"
version = "1.0.0"
[[package]]
name = "expected-parent"
version = "2.0.0"
dependencies = ["vulnerable"]
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.lock"
            path.write_text(lock)
            self.assertEqual(
                security_exceptions.lock_parents(path, "vulnerable"),
                {"expected-parent"},
            )

    def test_expired_review_deadline_is_rejected(self) -> None:
        markdown = "| RUSTSEC-2099-0001 | surface | disposition | owner | 2026-01-01 |"
        deadlines = security_exceptions.documented_deadlines(markdown)
        with self.assertRaises(ValueError):
            security_exceptions.require_unexpired(
                deadlines,
                {"RUSTSEC-2099-0001"},
                today=dt.date(2026, 1, 2),
            )


if __name__ == "__main__":
    unittest.main()
