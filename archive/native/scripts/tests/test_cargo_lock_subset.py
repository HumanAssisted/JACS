import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check_cargo_lock_subset.py"
spec = importlib.util.spec_from_file_location("cargo_lock_subset", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CargoLockSubsetTests(unittest.TestCase):
    def setUp(self):
        self.package = {"name": "fixture", "version": "1.0.0", "source": "registry+fixture", "checksum": "abc"}

    def test_allows_only_pruning_and_feature_edge_changes(self):
        original = {"package": [self.package, {"name": "unused", "version": "1.0.0"}]}
        resolved = {"package": [{**self.package, "dependencies": ["existing-edge"]}]}
        self.assertEqual(module.check_subset(original, resolved), 1)

    def test_rejects_added_package_or_upgraded_version(self):
        for changed in ({"name": "new", "version": "1.0.0"}, {**self.package, "version": "1.0.1"}):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    module.check_subset({"package": [self.package]}, {"package": [changed]})

    def test_rejects_source_or_checksum_changes(self):
        for field in ("source", "checksum"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    module.check_subset({"package": [self.package]}, {"package": [{**self.package, field: "changed"}]})

    def test_rejects_empty_resolved_graph(self):
        with self.assertRaises(ValueError):
            module.check_subset({"package": [self.package]}, {"package": []})


if __name__ == "__main__":
    unittest.main()
