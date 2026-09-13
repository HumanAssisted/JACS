"""Exercise the installed schema generator against the actual schema sources."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SchemaDocsGenerationTests(unittest.TestCase):
    def test_generated_agreement_docs_exclude_unsupported_delegation_fields(self):
        with tempfile.TemporaryDirectory(prefix="jacs_schema_docs_test_") as temporary:
            # Match the source/output layout so generated relative links are
            # identical to the checked-in pages. Use the actual existing tool.
            staged = Path(temporary) / "jacs"
            shutil.copytree(ROOT / "jacs/schemas", staged / "schemas")
            output = staged / "docs/schema"
            subprocess.run(
                ["jsonschema2md", "-d", str(staged / "schemas"),
                 "-o", str(output), "-x", "-"],
                check=True,
            )
            clean = {page.name: page.read_bytes() for page in output.glob("*.md")}
            parent = "agreement-definitions-agreementsignature.md"
            self.assertIn(parent, clean)
            self.assertEqual(clean[parent], (ROOT / "jacs/docs/schema" / parent).read_bytes())
            orphans = (
                "agreement-definitions-party-properties-delegatedby.md",
                "agreement-definitions-agreementsignature-properties-delegationchain.md",
            )
            for name in orphans:
                self.assertNotIn(name, clean)
                self.assertFalse((ROOT / "jacs/docs/schema" / name).exists())


if __name__ == "__main__":
    unittest.main()
