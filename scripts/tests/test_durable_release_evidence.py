from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def job_block(text: str, name: str) -> str:
    jobs_start = text.index("\njobs:\n")
    match = re.search(rf"(?m)^  {re.escape(name)}:\s*$", text[jobs_start:])
    if match is None:
        raise AssertionError(f"workflow has no {name!r} job")
    start = jobs_start + match.start()
    next_job = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\s*$", text[start + 1 :])
    end = len(text) if next_job is None else start + 1 + next_job.start()
    return text[start:end]


class DurableReleaseEvidenceTests(unittest.TestCase):
    CASES = {
        "release-crate.yml": (
            "jacs-rust-packages.spdx.json",
            "jacs-rust-${{ needs.verify-version.outputs.version }}-sha256sums.txt",
            "publish",
        ),
        "release-storage-crate.yml": (
            "storage-crate.spdx.json",
            "storage-crate-sha256sums.txt",
            "publish",
        ),
        "release-npm.yml": (
            "jacsnpm.spdx.json",
            ".tgz.sha256",
            "post-publish-smoke",
        ),
        "release-pypi.yml": (
            "jacspy.spdx.json",
            "jacspy-${{ needs.verify-version.outputs.version }}-sha256sums.txt",
            "post-publish-smoke",
        ),
        "release-wasm.yml": (
            "jacs-wasm.spdx.json",
            ".tgz.sha256",
            "post-publish-smoke",
        ),
    }

    def test_registry_releases_publish_attested_durable_sbom_and_digest_evidence(
        self,
    ) -> None:
        for workflow_name, (sbom, checksums, prerequisite) in self.CASES.items():
            with self.subTest(workflow=workflow_name):
                workflow = (
                    ROOT / ".github" / "workflows" / workflow_name
                ).read_text(encoding="utf-8")
                evidence = job_block(workflow, "durable-release-evidence")

                self.assertIn(prerequisite, evidence)
                self.assertIn("contents: write", evidence)
                self.assertIn("id-token: write", evidence)
                self.assertIn("attestations: write", evidence)
                self.assertIn("actions/download-artifact@", evidence)
                self.assertIn("actions/attest-build-provenance@", evidence)
                self.assertIn("softprops/action-gh-release@", evidence)
                self.assertIn("tag_name: ${{ github.ref_name }}", evidence)
                self.assertIn("overwrite_files: true", evidence)
                self.assertIn("fail_on_unmatched_files: true", evidence)
                self.assertIn("make_latest: false", evidence)
                self.assertIn(sbom, evidence)
                self.assertIn(checksums, evidence)

    def test_rust_release_artifacts_record_candidate_digests_before_upload(self) -> None:
        crate = (
            ROOT / ".github/workflows/release-crate.yml"
        ).read_text(encoding="utf-8")
        storage = (
            ROOT / ".github/workflows/release-storage-crate.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("jacs-rust-${VERSION}-sha256sums.txt", crate)
        self.assertIn("storage-crate-sha256sums.txt", storage)
        self.assertIn("sha256sum", crate)
        self.assertIn("sha256sum", storage)

    def test_npm_evidence_consumers_use_upload_artifacts_preserved_path(self) -> None:
        for workflow_name in ("release-npm.yml", "release-wasm.yml"):
            with self.subTest(workflow=workflow_name):
                workflow = (
                    ROOT / ".github" / "workflows" / workflow_name
                ).read_text(encoding="utf-8")
                evidence = job_block(workflow, "durable-release-evidence")

                # The upload combines release-candidates/* with a root SBOM, so
                # upload-artifact preserves the release-candidates directory.
                self.assertIn(
                    "release-evidence/release-candidates/*.tgz.sha256", evidence
                )
                self.assertNotIn("\n            release-evidence/*.tgz.sha256", evidence)


if __name__ == "__main__":
    unittest.main()
