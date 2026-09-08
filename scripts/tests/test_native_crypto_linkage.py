import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check_native_crypto_linkage.py"
spec = importlib.util.spec_from_file_location("native_crypto_linkage", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativeCryptoLinkageTests(unittest.TestCase):
    def test_rejects_elf_shared_crypto_even_when_renamed_by_wheel_repair(self):
        for name in ("libcrypto.so.3", "libssl.so.3", "libcrypto-a12345.so.3"):
            with self.subTest(name=name):
                self.assertEqual(module.external_crypto_dependencies(
                    f" 0x1 (NEEDED) Shared library: [{name}]\n", "elf"), [name])

    def test_rejects_macos_loader_and_absolute_crypto_paths(self):
        for name in ("@rpath/libcrypto.3.dylib", "/opt/homebrew/lib/libssl.3.dylib"):
            with self.subTest(name=name):
                self.assertEqual(module.external_crypto_dependencies(
                    f"artifact:\n\t{name} (compatibility version 3.0.0)\n", "macho"), [name])

    def test_allows_normal_platform_dependencies(self):
        self.assertEqual(module.external_crypto_dependencies(
            " 0x1 (NEEDED) Shared library: [libc.so.6]\n", "elf"), [])
        self.assertEqual(module.external_crypto_dependencies(
            "artifact:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n", "macho"), [])

    def test_rejects_absolute_builder_dependencies_and_runtime_search_paths(self):
        self.assertEqual(module.nonportable_loader_paths(
            " (NEEDED) Shared library: [/build/libhelper.so]\n"
            " (RUNPATH) Library runpath: [$ORIGIN:/build/libs]\n", "elf"),
            ["/build/libhelper.so", "/build/libs"])
        self.assertEqual(module.nonportable_loader_paths(
            " cmd LC_LOAD_DYLIB\n cmdsize 64\n name /build/libhelper.dylib (offset 24)\n"
            " cmd LC_RPATH\n cmdsize 64\n path /build/libs (offset 12)\n", "macho"),
            ["/build/libhelper.dylib", "/build/libs"])

    def test_allows_loader_relative_and_macos_system_dependencies(self):
        self.assertEqual(module.nonportable_loader_paths(
            " (NEEDED) Shared library: [libjacsgo.so]\n"
            " (RUNPATH) Library runpath: [$ORIGIN]\n", "elf"), [])
        self.assertEqual(module.nonportable_loader_paths(
            "artifact:\n\t@loader_path/libjacsgo.dylib (compatibility version 1.0.0)\n"
            "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n", "macho"), [])

    def test_macos_own_install_identity_is_not_a_loaded_dependency(self):
        output = (
            " cmd LC_ID_DYLIB\n cmdsize 64\n name /build/libjacsnpm.dylib (offset 24)\n"
            " cmd LC_LOAD_DYLIB\n cmdsize 64\n name /usr/lib/libSystem.B.dylib (offset 24)\n"
        )
        self.assertEqual(module.dependency_names(output, "macho"), ["/usr/lib/libSystem.B.dylib"])
        self.assertEqual(module.nonportable_loader_paths(output, "macho"), [])

    def test_rejects_cwd_relative_dependencies_and_search_paths(self):
        for kind, dependency, search in (
            ("elf", "./libhelper.so", "./lib"),
            ("elf", "../libhelper.so", "lib"),
            ("macho", "libhelper.dylib", "./lib"),
            ("macho", "../libhelper.dylib", "lib"),
        ):
            with self.subTest(kind=kind, dependency=dependency):
                output = (
                    f" (NEEDED) Shared library: [{dependency}]\n (RUNPATH) Library runpath: [{search}]\n"
                    if kind == "elf" else
                    f" cmd LC_LOAD_DYLIB\n cmdsize 64\n name {dependency} (offset 24)\n"
                    f" cmd LC_RPATH\n cmdsize 64\n path {search} (offset 12)\n"
                )
                self.assertEqual(module.nonportable_loader_paths(output, kind), [dependency, search])

    def test_rejects_loader_token_traversal_and_empty_search_entries(self):
        for kind, search in (
            ("elf", "$ORIGIN/../lib"), ("elf", "${ORIGIN}/./lib"),
            ("elf", "$ORIGIN:"), ("macho", "@loader_path/../lib"),
            ("macho", "@executable_path/./lib"), ("macho", "@rpath"),
        ):
            with self.subTest(kind=kind, search=search):
                output = (f" (RUNPATH) Library runpath: [{search}]\n" if kind == "elf" else
                          f" cmd LC_RPATH\n cmdsize 64\n path {search} (offset 12)\n")
                self.assertTrue(module.nonportable_loader_paths(output, kind))

    def test_allows_only_explicit_package_relative_search_tokens(self):
        self.assertEqual(module.nonportable_loader_paths(
            " (NEEDED) Shared library: [libhelper.so]\n"
            " (RUNPATH) Library runpath: [${ORIGIN}/lib:$ORIGIN]\n", "elf"), [])
        self.assertEqual(module.nonportable_loader_paths(
            " cmd LC_LOAD_DYLIB\n cmdsize 64\n name @rpath/libhelper.dylib (offset 24)\n"
            " cmd LC_RPATH\n cmdsize 64\n path @loader_path/lib (offset 12)\n", "macho"), [])


if __name__ == "__main__":
    unittest.main()
