"""SDK download failures must retry cleanly without bypassing instrumentation."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "install-android-test-sdk.sh"
IMAGE = "system-images/android-35/google_apis/x86_64"
SDKMANAGER = '''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

state = Path(os.environ["TEST_SDK_STATE"])
calls = json.loads(state.read_text()) if state.exists() else []
root = Path(sys.argv[1].split("=", 1)[1])
package = sys.argv[-1]
calls.append({"root": str(root), "package": package,
              "stdin": sys.stdin.read(), "user": os.environ["ANDROID_USER_HOME"],
              "license": (root / "licenses/android-sdk-license").read_text()})
state.write_text(json.dumps(calls))
mode = os.environ["TEST_SDK_MODE"]
target = root / package.replace(";", "/")
target.mkdir(parents=True, exist_ok=True)
(target / "package.xml").write_text("<localPackage/> ")
if mode == "incomplete":
    sys.exit(0)
if mode == "fail" or (mode == "retry" and len(calls) == 1):
    (root / ".temp").mkdir()
    (root / ".temp/corrupt.zip").write_text("not a ZIP")
    print("Error on ZipFile unknown archive", file=sys.stderr)
    sys.exit(1)
filename = {"emulator": "emulator", "platform-tools": "adb"}.get(package, "system.img")
binary = target / filename
binary.write_text("#!/bin/sh\\nexit 0\\n")
binary.chmod(0o755)
if package.startswith("system-images;"):
    (target / "ramdisk.img").write_text("ramdisk")
    (target / "kernel-ranchu").write_text("kernel")
'''


@unittest.skipUnless(shutil.which("timeout"), "Android installer requires GNU timeout")
class AndroidSdkInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sdk = self.root / "sdk"
        tools = self.sdk / "cmdline-tools/latest/bin"
        tools.mkdir(parents=True)
        manager = tools / "sdkmanager"
        manager.write_text(SDKMANAGER)
        manager.chmod(0o755)
        (self.sdk / "licenses").mkdir()
        (self.sdk / "licenses/android-sdk-license").write_text("existing receipt")
        self.cache = self.sdk / ".temp/other-download.zip"
        self.cache.parent.mkdir()
        self.cache.write_text("shared cache must survive")
        self.state = self.root / "calls.json"
        self.complete("platform-tools", "adb")
        self.complete(IMAGE, "system.img")

    def complete(self, relative, filename):
        target = self.sdk / relative
        target.mkdir(parents=True, exist_ok=True)
        (target / "package.xml").write_text("<localPackage/>")
        executable = target / filename
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        if relative == IMAGE:
            (target / "ramdisk.img").write_text("ramdisk")
            (target / "kernel-ranchu").write_text("kernel")

    def run_installer(self, mode="success"):
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.sdk)],
            env={**os.environ, "RUNNER_TEMP": str(self.root),
                 "TEST_SDK_STATE": str(self.state), "TEST_SDK_MODE": mode},
            capture_output=True, text=True, timeout=15,
        )

    def calls(self):
        return json.loads(self.state.read_text()) if self.state.exists() else []

    def test_complete_installed_packages_are_reused(self):
        self.complete("emulator", "emulator")
        result = self.run_installer("fail")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_corrupt_download_retries_in_fresh_owned_staging(self):
        result = self.run_installer("retry")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0]["root"], calls[1]["root"])
        for call in calls:
            self.assertEqual(call["package"], "emulator")
            self.assertEqual(call["stdin"], "")
            self.assertEqual(call["license"], "existing receipt")
            self.assertTrue(call["user"].startswith(call["root"] + "/"))
            self.assertFalse(Path(call["root"]).exists())
        self.assertTrue((self.sdk / "emulator/emulator").is_file())
        self.assertEqual(self.cache.read_text(), "shared cache must survive")

    def test_unhealthy_installed_executable_is_replaced(self):
        self.complete("emulator", "emulator")
        (self.sdk / "emulator/emulator").write_text("#!/bin/sh\nexit 1\n")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["package"] for call in self.calls()], ["emulator"])

    def test_incomplete_installed_image_is_replaced(self):
        self.complete("emulator", "emulator")
        (self.sdk / IMAGE / "ramdisk.img").unlink()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["package"] for call in self.calls()],
                         ["system-images;android-35;google_apis;x86_64"])
        self.assertTrue((self.sdk / IMAGE / "ramdisk.img").is_file())

    def test_persistent_failure_preserves_existing_partial_package(self):
        partial = self.sdk / "emulator/keep"
        partial.parent.mkdir()
        partial.write_text("preexisting")
        result = self.run_installer("fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed after 3 clean attempts", result.stderr)
        self.assertEqual(len(self.calls()), 3)
        self.assertEqual(partial.read_text(), "preexisting")
        self.assertEqual(self.cache.read_text(), "shared cache must survive")
        self.assertEqual(list(self.root.glob("jacs-android-sdk.*")), [])

    def test_failed_promotion_restores_existing_partial_package(self):
        partial = self.sdk / "emulator/keep"
        partial.parent.mkdir()
        partial.write_text("preexisting")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        real_mv = shutil.which("mv")
        wrapper = bin_dir / "mv"
        wrapper.write_text(
            "#!/usr/bin/env python3\nimport os, sys\nfrom pathlib import Path\n"
            "if 'jacs-android-sdk.' in sys.argv[1] and sys.argv[1].endswith('/emulator'):\n"
            "    target = Path(sys.argv[2])\n"
            "    target.mkdir()\n"
            "    (target / 'failed-copy').write_text('partial')\n"
            "    sys.exit(1)\n"
            f"os.execv({real_mv!r}, [{real_mv!r}, *sys.argv[1:]])\n"
        )
        wrapper.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": f"{bin_dir}:{os.environ['PATH']}"}):
            result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Could not install verified package", result.stderr)
        self.assertEqual(partial.read_text(), "preexisting")
        self.assertFalse((partial.parent / "failed-copy").exists())
        self.assertFalse((partial.parent / "previous-package").exists())
        self.assertEqual(list(self.root.glob("jacs-android-sdk.*")), [])

    def test_success_exit_without_complete_package_is_rejected(self):
        result = self.run_installer("incomplete")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls()), 3)
        self.assertFalse((self.sdk / "emulator").exists())

    def test_missing_license_receipt_fails_without_installing(self):
        (self.sdk / "licenses/android-sdk-license").unlink()
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
