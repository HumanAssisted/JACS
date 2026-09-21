import subprocess
import unittest
from unittest.mock import patch

from scripts import homebrew_release as brew


class HomebrewReleaseTests(unittest.TestCase):
    def checksums(self):
        return {name: "a" * 64 for name in brew.release.release_spec("cli/v0.15.0").payload_assets}

    def test_formula_uses_published_portable_binary_for_four_platforms(self):
        formula = brew.render_formula("0.15.0", self.checksums())
        self.assertEqual(formula.count("https://github.com/HumanAssisted/JACS/releases/download/cli/v0.15.0/"), 4)
        self.assertIn('bin.install "jacs-cli" => "jacs"', formula)
        self.assertNotIn("cargo", formula)
        self.assertNotIn("windows", formula)

    def test_version_cannot_inject_ruby_or_paths(self):
        for version in ['0.15.0"; system("false")', "../0.15.0", "0.15.0\n"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                brew.render_formula(version, self.checksums())

    def test_incomplete_or_extra_inventory_is_rejected(self):
        for missing in self.checksums():
            checksums = self.checksums()
            del checksums[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                brew.render_formula("0.15.0", checksums)
        checksums = self.checksums()
        checksums["unreviewed.tar.gz"] = "b" * 64
        with self.assertRaises(ValueError):
            brew.render_formula("0.15.0", checksums)

    def test_checksum_cannot_inject_ruby(self):
        checksums = self.checksums()
        checksums[next(iter(checksums))] = '"; system("false")'
        with self.assertRaises(ValueError):
            brew.render_formula("0.15.0", checksums)

    def test_full_source_commit_is_required_before_network(self):
        with patch.object(brew.release, "fetch_complete_release_assets") as fetch:
            for source in ["main", "10c16ba0", "a" * 40 + "\n"]:
                with self.subTest(source=source), self.assertRaises(ValueError):
                    brew.verified_formula("0.15.0", source)
            fetch.assert_not_called()

    def test_checksum_failure_prevents_rendering(self):
        with patch.object(brew.release, "fetch_complete_release_assets", return_value=[]), \
             patch.object(brew.release, "download_release_assets", return_value=[]), \
             patch.object(brew.release, "verify_release_checksums", side_effect=RuntimeError("mismatch")), \
             patch.object(brew, "render_formula") as render:
            with self.assertRaisesRegex(RuntimeError, "mismatch"):
                brew.verified_formula("0.15.0", "a" * 40)
            render.assert_not_called()

    def test_provenance_enforces_source_commit_and_failure_prevents_rendering(self):
        def reject_attestations(spec, paths, *, run):
            run(["gh", "attestation", "verify", "candidate"], 60)
            raise RuntimeError("untrusted source")

        with patch.object(brew.release, "fetch_complete_release_assets", return_value=[]), \
             patch.object(brew.release, "download_release_assets", return_value=[]), \
             patch.object(brew.release, "verify_release_checksums"), \
             patch.object(brew.release, "verify_attestations", side_effect=reject_attestations), \
             patch.object(brew.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run, \
             patch.object(brew, "render_formula") as render:
            with self.assertRaisesRegex(RuntimeError, "untrusted source"):
                brew.verified_formula("0.15.0", "a" * 40)
            self.assertEqual(run.call_args.args[0][-2:], ["--source-digest", "a" * 40])
            render.assert_not_called()


if __name__ == "__main__":
    unittest.main()
