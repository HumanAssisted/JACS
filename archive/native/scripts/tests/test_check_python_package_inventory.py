from __future__ import annotations

import importlib.util
import gzip
import io
import stat
import tarfile
import unittest
import warnings
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "check_python_package_inventory.py"
SPEC = importlib.util.spec_from_file_location(
    "check_python_package_inventory", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class PythonPackageInventoryTests(unittest.TestCase):
    canonical_license = (ROOT / "LICENSE-APACHE").read_bytes()
    canonical_notices = (ROOT / "THIRD-PARTY-NOTICES").read_bytes()

    def test_jacspy_license_copy_matches_repository_canonical_license(self) -> None:
        self.assertEqual(
            (ROOT / "jacspy" / "LICENSE-APACHE").read_bytes(),
            self.canonical_license,
        )
        self.assertEqual(
            (ROOT / "jacspy" / "THIRD-PARTY-NOTICES").read_bytes(),
            self.canonical_notices,
        )

    def test_wheel_requires_the_canonical_license(self) -> None:
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "jacs-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "jacs-1.0.0.dist-info/licenses/LICENSE-APACHE",
                    self.canonical_license,
                )
                archive.writestr(
                    "jacs-1.0.0.dist-info/licenses/THIRD-PARTY-NOTICES",
                    self.canonical_notices,
                )
            self.assertEqual(
                inventory.inventory_errors(
                    wheel, self.canonical_license, self.canonical_notices
                ),
                [],
            )

            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("jacs/__init__.py", "")
            self.assertEqual(
                inventory.inventory_errors(
                    wheel, self.canonical_license, self.canonical_notices
                ),
                [
                    "canonical Apache-2.0 license file is missing",
                    "THIRD-PARTY-NOTICES is missing",
                ],
            )

    def test_sdist_rejects_noncanonical_license_and_debug_transcript(self) -> None:
        with TemporaryDirectory() as directory:
            sdist = Path(directory) / "jacs-1.0.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("jacs-1.0.0/LICENSE", b"not Apache-2.0"),
                    ("jacs-1.0.0/jacs/src/crypt/debug.txt", b"signature transcript"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            self.assertEqual(
                inventory.inventory_errors(
                    sdist, self.canonical_license, self.canonical_notices
                ),
                [
                    "packaged license file does not match LICENSE-APACHE: "
                    "jacs-1.0.0/LICENSE",
                    "THIRD-PARTY-NOTICES is missing",
                    "debug signature transcript must not ship: "
                    "jacs-1.0.0/jacs/src/crypt/debug.txt",
                ],
            )

    def test_archive_rejects_conflicting_license_alongside_canonical_license(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "jacs-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "jacs-1.0.0.dist-info/license_files/LICENSE-APACHE",
                    self.canonical_license,
                )
                archive.writestr(
                    "jacs-1.0.0.dist-info/license_files/THIRD-PARTY-NOTICES",
                    self.canonical_notices,
                )
                archive.writestr("jacs/LICENSE", b"conflicting terms")
            self.assertEqual(
                inventory.inventory_errors(
                    wheel, self.canonical_license, self.canonical_notices
                ),
                ["packaged license file does not match LICENSE-APACHE: jacs/LICENSE"],
            )

    def test_wheel_rejects_duplicate_archive_paths(self) -> None:
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "jacs-1.0.0-py3-none-any.whl"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr(
                        "jacs-1.0.0.dist-info/licenses/LICENSE-APACHE",
                        self.canonical_license,
                    )
                    archive.writestr("jacs/THIRD-PARTY-NOTICES", self.canonical_notices)
                    archive.writestr("jacs/THIRD-PARTY-NOTICES", self.canonical_notices)

            self.assertEqual(
                inventory.inventory_errors(
                    wheel, self.canonical_license, self.canonical_notices
                ),
                ["duplicate archive path: jacs/THIRD-PARTY-NOTICES"],
            )

    def test_wheel_and_sdist_reject_excessive_entry_counts(self) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "jacs-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                archive.writestr("pkg/a.py", b"")
                archive.writestr("pkg/b.py", b"")

            sdist = root / "jacs-1.0.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                    ("pkg/a.py", b""),
                    ("pkg/b.py", b""),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            with mock.patch.object(inventory, "MAX_ARCHIVE_ENTRIES", 3, create=True):
                for archive in (wheel, sdist):
                    with self.subTest(archive=archive.name):
                        self.assertEqual(
                            inventory.inventory_errors(
                                archive, license_bytes, notices_bytes
                            ),
                            ["archive has more than 3 entries"],
                        )

    def test_wheel_and_sdist_enforce_per_file_and_total_uncompressed_limits(
        self,
    ) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archives: list[Path] = []

            wheel = root / "jacs-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                archive.writestr("pkg/payload.bin", b"0123456789")
            archives.append(wheel)

            sdist = root / "jacs-1.0.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                    ("pkg/payload.bin", b"0123456789"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            archives.append(sdist)

            for archive in archives:
                with self.subTest(archive=archive.name, limit="per-file"):
                    with mock.patch.object(
                        inventory,
                        "MAX_ENTRY_UNCOMPRESSED_BYTES",
                        9,
                        create=True,
                    ):
                        self.assertEqual(
                            inventory.inventory_errors(
                                archive, license_bytes, notices_bytes
                            ),
                            [
                                "archive entry exceeds 9 uncompressed bytes: "
                                "pkg/payload.bin (10 bytes)"
                            ],
                        )

                with self.subTest(archive=archive.name, limit="total"):
                    with mock.patch.object(
                        inventory,
                        "MAX_TOTAL_UNCOMPRESSED_BYTES",
                        11,
                        create=True,
                    ):
                        self.assertEqual(
                            inventory.inventory_errors(
                                archive, license_bytes, notices_bytes
                            ),
                            ["archive exceeds 11 total uncompressed bytes"],
                        )

    def test_wheel_and_sdist_reject_decompression_heavy_metadata(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        compressible = b"0" * 64_000
        with TemporaryDirectory() as directory:
            root = Path(directory)

            wheel = root / "jacs-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(
                wheel, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                archive.writestr("pkg/metadata.json", compressible)

            sdist = root / "jacs-1.0.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                    ("pkg/metadata.json", compressible),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            with mock.patch.object(
                inventory, "MAX_UNCOMPRESSED_RATIO", 10, create=True
            ):
                for archive in (wheel, sdist):
                    with self.subTest(archive=archive.name):
                        errors = inventory.inventory_errors(
                            archive, license_bytes, notices_bytes
                        )
                        self.assertEqual(len(errors), 1)
                        self.assertIn(
                            "archive uncompressed-to-compressed ratio exceeds 10:1",
                            errors[0],
                        )

    def test_alternate_legal_filenames_are_checked_for_conflicts(self) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        license_aliases = (
            "COPYING",
            "COPYING.LESSER",
            "LICENCE.md",
            "LICENSE.txt",
        )
        notice_aliases = (
            "NOTICE",
            "NOTICE.md",
            "NOTICE-DEPENDENCIES",
            "NOTICES",
        )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            for alias in license_aliases:
                with self.subTest(kind="license", alias=alias):
                    wheel = root / f"license-{alias.replace('.', '-')}.whl"
                    with zipfile.ZipFile(wheel, "w") as archive:
                        archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                        archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                        archive.writestr(f"pkg/{alias}", b"conflicting terms")
                    self.assertEqual(
                        inventory.inventory_errors(wheel, license_bytes, notices_bytes),
                        [
                            "packaged license file does not match LICENSE-APACHE: "
                            f"pkg/{alias}"
                        ],
                    )

            for alias in notice_aliases:
                with self.subTest(kind="notice", alias=alias):
                    sdist = root / f"notice-{alias.replace('.', '-')}.tar.gz"
                    with tarfile.open(sdist, "w:gz") as archive:
                        for name, data in (
                            ("pkg/LICENSE-APACHE", license_bytes),
                            ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                            (f"pkg/{alias}", b"stale notices"),
                        ):
                            info = tarfile.TarInfo(name)
                            info.size = len(data)
                            archive.addfile(info, io.BytesIO(data))
                    self.assertEqual(
                        inventory.inventory_errors(sdist, license_bytes, notices_bytes),
                        [
                            "packaged THIRD-PARTY-NOTICES does not match "
                            f"repository canonical file: pkg/{alias}"
                        ],
                    )

    def test_canonical_alternate_legal_filenames_remain_valid(self) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "jacs-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE.txt", license_bytes)
                archive.writestr("pkg/NOTICE", notices_bytes)

            self.assertEqual(
                inventory.inventory_errors(wheel, license_bytes, notices_bytes),
                [],
            )

    def test_sdist_rejects_all_nonregular_members(self) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        with TemporaryDirectory() as directory:
            sdist = Path(directory) / "jacs-1.0.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

                symlink = tarfile.TarInfo("pkg/COPYING")
                symlink.type = tarfile.SYMTYPE
                symlink.linkname = "LICENSE-APACHE"
                archive.addfile(symlink)

                hardlink = tarfile.TarInfo("pkg/NOTICE")
                hardlink.type = tarfile.LNKTYPE
                hardlink.linkname = "pkg/THIRD-PARTY-NOTICES"
                archive.addfile(hardlink)

                fifo = tarfile.TarInfo("pkg/runtime.pipe")
                fifo.type = tarfile.FIFOTYPE
                archive.addfile(fifo)

            self.assertEqual(
                inventory.inventory_errors(sdist, license_bytes, notices_bytes),
                [
                    "unsupported non-regular archive member: 'pkg/COPYING'",
                    "unsupported non-regular archive member: 'pkg/NOTICE'",
                    "unsupported non-regular archive member: 'pkg/runtime.pipe'",
                ],
            )

    def test_wheel_rejects_all_nonregular_members(self) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "jacs-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                symlink = zipfile.ZipInfo("pkg/COPYING")
                symlink.create_system = 3
                symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(symlink, "LICENSE-APACHE")

                module_symlink = zipfile.ZipInfo("pkg/module.py")
                module_symlink.create_system = 3
                module_symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(module_symlink, "module-real.py")

            self.assertEqual(
                inventory.inventory_errors(wheel, license_bytes, notices_bytes),
                [
                    "unsupported non-regular archive member: 'pkg/COPYING'",
                    "unsupported non-regular archive member: 'pkg/module.py'",
                ],
            )

    def test_wheel_and_sdist_casefold_paths_for_collisions_and_debug_transcript(
        self,
    ) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        entries = (
            ("Pkg/Data.txt", b"one"),
            ("pkg/data.txt", b"two"),
            ("JACS/SRC/CRYPT/DEBUG.TXT", b"transcript"),
        )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "casefold.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                for name, data in entries:
                    archive.writestr(name, data)

            sdist = root / "casefold.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                    *entries,
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            for archive in (wheel, sdist):
                with self.subTest(archive=archive.name):
                    errors = inventory.inventory_errors(
                        archive, license_bytes, notices_bytes
                    )
                    self.assertIn(
                        "duplicate normalized archive path: pkg/data.txt", errors
                    )
                    self.assertIn(
                        "debug signature transcript must not ship: "
                        "jacs/src/crypt/debug.txt",
                        errors,
                    )

    def test_wheel_and_sdist_reject_windows_path_aliases(self) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        trailing_aliases = (
            "pkg/trailing-dot.",
            "pkg/trailing-space ",
        )
        reserved_aliases = (
            "pkg/CON.txt",
            "pkg/prn",
            "pkg/AUX.json",
            "pkg/nul.whl",
            *(f"pkg/COM{number}.py" for number in range(1, 10)),
            *(f"pkg/LPT{number}.log" for number in range(1, 10)),
        )
        ads_alias = "pkg/file.txt:stream"
        debug_alias = "JACS/SRC/CRYPT/DEBUG.TXT."
        entries = tuple(
            (name, b"alias")
            for name in (*trailing_aliases, *reserved_aliases, ads_alias, debug_alias)
        )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "windows-aliases.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                for name, data in entries:
                    archive.writestr(name, data)

            sdist = root / "windows-aliases.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                    *entries,
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            for archive in (wheel, sdist):
                with self.subTest(archive=archive.name):
                    errors = inventory.inventory_errors(
                        archive, license_bytes, notices_bytes
                    )
                    rendered = "\n".join(errors)
                    for name in trailing_aliases:
                        self.assertIn(repr(name), rendered)
                        self.assertIn(
                            "trailing dots or spaces are not allowed", rendered
                        )
                    for name in reserved_aliases:
                        self.assertIn(repr(name), rendered)
                    self.assertIn(
                        "Windows reserved device names are not allowed", rendered
                    )
                    self.assertIn(repr(ads_alias), rendered)
                    self.assertIn(
                        "colon/alternate data streams are not allowed", rendered
                    )
                    self.assertIn(
                        "debug signature transcript must not ship: "
                        "jacs/src/crypt/debug.txt",
                        errors,
                    )

    def test_sdist_rejects_nonzero_or_excessive_data_after_end_marker(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            nonzero = root / "nonzero-trailer.tar.gz"
            nonzero.write_bytes(gzip.compress(raw.getvalue() + b"not TAR padding"))
            self.assertEqual(
                inventory.inventory_errors(nonzero, license_bytes, notices_bytes),
                ["non-zero TAR data follows its end marker"],
            )

            excessive = root / "excessive-padding.tar.gz"
            excessive.write_bytes(gzip.compress(raw.getvalue() + bytes(8_192)))
            with (
                mock.patch.object(
                    inventory, "MAX_TAR_TRAILING_PADDING_BYTES", 4_096, create=True
                ),
                mock.patch.object(
                    inventory.tarfile,
                    "open",
                    side_effect=AssertionError(
                        "tarfile.open must not run before trailer preflight"
                    ),
                ),
            ):
                self.assertEqual(
                    inventory.inventory_errors(excessive, license_bytes, notices_bytes),
                    ["TAR trailing padding exceeds 4096 bytes"],
                )

    def test_wheel_and_sdist_reject_a_path_swap_after_preflight(self) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"

        def write_wheel(path: Path, *, valid: bool) -> None:
            with zipfile.ZipFile(path, "w") as archive:
                if valid:
                    archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                    archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                else:
                    archive.writestr("pkg/replacement.py", b"replaced")

        def write_sdist(path: Path, *, valid: bool) -> None:
            with tarfile.open(path, "w:gz") as archive:
                entries = (
                    (
                        (
                            "pkg/LICENSE-APACHE",
                            license_bytes,
                        ),
                        ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                    )
                    if valid
                    else (("pkg/replacement.py", b"replaced"),)
                )
                for name, data in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

        with TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                ("path-swap.whl", write_wheel, "_preflight_zip"),
                ("path-swap.tar.gz", write_sdist, "_preflight_tar"),
            )
            for filename, writer, preflight_name in cases:
                with self.subTest(archive=filename):
                    archive = root / filename
                    replacement = root / f"replacement-{filename}"
                    writer(archive, valid=True)
                    writer(replacement, valid=False)
                    real_preflight = getattr(inventory, preflight_name)

                    def preflight_then_swap(*args, **kwargs):
                        result = real_preflight(*args, **kwargs)
                        replacement.replace(archive)
                        return result

                    with mock.patch.object(
                        inventory, preflight_name, side_effect=preflight_then_swap
                    ):
                        self.assertEqual(
                            inventory.inventory_errors(
                                archive, license_bytes, notices_bytes
                            ),
                            ["archive changed while it was being inspected"],
                        )

    def test_tar_pax_and_gnu_metadata_count_toward_total_before_tarfile(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archives: list[Path] = []

            pax = root / "pax.tar.gz"
            with tarfile.open(pax, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                metadata = tarfile.TarInfo("payload")
                metadata.pax_headers = {"comment": "x" * 100_000}
                archive.addfile(metadata)
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            archives.append(pax)

            gnu = root / "gnu.tar.gz"
            with tarfile.open(gnu, "w:gz", format=tarfile.GNU_FORMAT) as archive:
                archive.addfile(tarfile.TarInfo("long/" + "x" * 100_000))
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            archives.append(gnu)

            for archive in archives:
                with self.subTest(archive=archive.name):
                    with (
                        mock.patch.object(
                            inventory,
                            "MAX_TOTAL_UNCOMPRESSED_BYTES",
                            10,
                        ),
                        mock.patch.object(
                            inventory.tarfile,
                            "open",
                            side_effect=AssertionError(
                                "tarfile.open must not run before metadata preflight"
                            ),
                        ),
                    ):
                        self.assertEqual(
                            inventory.inventory_errors(
                                archive, license_bytes, notices_bytes
                            ),
                            ["archive exceeds 10 total uncompressed bytes"],
                        )

    def test_tar_pax_metadata_has_an_explicit_metadata_bound(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            sdist = Path(directory) / "metadata.tar.gz"
            with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                metadata = tarfile.TarInfo("payload")
                metadata.pax_headers = {"comment": "x" * 4_096}
                archive.addfile(metadata)
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            with mock.patch.object(
                inventory, "MAX_ARCHIVE_METADATA_BYTES", 2_048, create=True
            ):
                self.assertEqual(
                    inventory.inventory_errors(sdist, license_bytes, notices_bytes),
                    ["TAR metadata exceeds 2048 bytes"],
                )

    def test_tar_pax_gnu_sparse_metadata_is_rejected_before_tarfile(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            sdist = Path(directory) / "modern-sparse.tar.gz"
            with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                sparse = tarfile.TarInfo("pkg/sparse.bin")
                sparse.size = 1
                sparse.pax_headers = {"GNU.sparse.realsize": "1"}
                archive.addfile(sparse, io.BytesIO(b"x"))
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            with mock.patch.object(
                inventory.tarfile,
                "open",
                side_effect=AssertionError(
                    "tarfile.open must not run before PAX sparse preflight"
                ),
            ):
                self.assertEqual(
                    inventory.inventory_errors(sdist, license_bytes, notices_bytes),
                    ["GNU sparse PAX metadata is not supported"],
                )

    def test_zip_central_directory_is_bounded_before_zipfile(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "metadata.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                metadata = zipfile.ZipInfo("pkg/metadata.json")
                metadata.comment = b"x" * 4_096
                archive.writestr(metadata, b"{}")

            with (
                mock.patch.object(
                    inventory, "MAX_ARCHIVE_METADATA_BYTES", 2_048, create=True
                ),
                mock.patch.object(
                    inventory.zipfile,
                    "ZipFile",
                    side_effect=AssertionError(
                        "ZipFile must not run before central-directory preflight"
                    ),
                ),
            ):
                self.assertEqual(
                    inventory.inventory_errors(wheel, license_bytes, notices_bytes),
                    ["ZIP central directory exceeds 2048 bytes"],
                )

    def test_zip_directory_markers_require_consistent_name_type_and_size(
        self,
    ) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"

        def dos_directory_without_slash() -> tuple[zipfile.ZipInfo, bytes]:
            info = zipfile.ZipInfo("pkg/dos-bit.py")
            info.create_system = 0
            info.external_attr = 0x10
            return info, b"x"

        def unix_directory_without_slash() -> tuple[zipfile.ZipInfo, bytes]:
            info = zipfile.ZipInfo("pkg/unix-bit.py")
            info.create_system = 3
            info.external_attr = (stat.S_IFDIR | 0o755) << 16
            return info, b""

        def nonempty_directory() -> tuple[zipfile.ZipInfo, bytes]:
            return zipfile.ZipInfo("pkg/nonempty/"), b"x"

        def regular_file_with_directory_name() -> tuple[zipfile.ZipInfo, bytes]:
            info = zipfile.ZipInfo("pkg/regular/")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            return info, b""

        cases = (
            dos_directory_without_slash,
            unix_directory_without_slash,
            nonempty_directory,
            regular_file_with_directory_name,
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for make_member in cases:
                info, data = make_member()
                with self.subTest(member=info.filename):
                    wheel = root / f"{make_member.__name__}.whl"
                    with zipfile.ZipFile(wheel, "w") as archive:
                        archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                        archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                        archive.writestr(info, data)

                    with mock.patch.object(
                        inventory.zipfile,
                        "ZipFile",
                        side_effect=AssertionError(
                            "ZipFile must not run before directory preflight"
                        ),
                    ):
                        self.assertEqual(
                            inventory.inventory_errors(
                                wheel, license_bytes, notices_bytes
                            ),
                            [
                                "inconsistent ZIP directory member: "
                                f"{info.filename!r}"
                            ],
                        )

    def test_wheel_rejects_prepended_bytes_before_zipfile(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "prepended.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
            wheel.write_bytes(b"prepended stub\n" + wheel.read_bytes())

            with mock.patch.object(
                inventory.zipfile,
                "ZipFile",
                side_effect=AssertionError(
                    "ZipFile must not run before central-offset preflight"
                ),
            ):
                self.assertEqual(
                    inventory.inventory_errors(wheel, license_bytes, notices_bytes),
                    ["ZIP central-directory offset is invalid"],
                )

    def test_wheel_rejects_rebased_polyglot_prefix_before_zipfile(self) -> None:
        """A prefix remains unsafe even when every ZIP offset is rebased."""

        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            wheel = Path(directory) / "rebased-prefix.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)

            prefix = b"MZ\x90\x00polyglot stub\n"
            contents = bytearray(wheel.read_bytes())
            eocd_offset = contents.rfind(inventory.ZIP_EOCD_SIGNATURE)
            self.assertGreaterEqual(eocd_offset, 0)
            central_size = int.from_bytes(
                contents[eocd_offset + 12 : eocd_offset + 16], "little"
            )
            central_offset = int.from_bytes(
                contents[eocd_offset + 16 : eocd_offset + 20], "little"
            )
            cursor = central_offset
            central_end = central_offset + central_size
            while cursor < central_end:
                self.assertEqual(
                    contents[cursor : cursor + 4], inventory.ZIP_CENTRAL_SIGNATURE
                )
                local_offset = int.from_bytes(
                    contents[cursor + 42 : cursor + 46], "little"
                )
                contents[cursor + 42 : cursor + 46] = (
                    local_offset + len(prefix)
                ).to_bytes(4, "little")
                name_size = int.from_bytes(
                    contents[cursor + 28 : cursor + 30], "little"
                )
                extra_size = int.from_bytes(
                    contents[cursor + 30 : cursor + 32], "little"
                )
                comment_size = int.from_bytes(
                    contents[cursor + 32 : cursor + 34], "little"
                )
                cursor += (
                    inventory.ZIP_CENTRAL_HEADER_BYTES
                    + name_size
                    + extra_size
                    + comment_size
                )
            self.assertEqual(cursor, central_end)
            contents[eocd_offset + 16 : eocd_offset + 20] = (
                central_offset + len(prefix)
            ).to_bytes(4, "little")
            wheel.write_bytes(prefix + contents)

            with mock.patch.object(
                inventory.zipfile,
                "ZipFile",
                side_effect=AssertionError(
                    "ZipFile must not run before local-offset preflight"
                ),
            ):
                self.assertEqual(
                    inventory.inventory_errors(wheel, license_bytes, notices_bytes),
                    ["ZIP local-file data must begin at byte zero"],
                )

    def test_wheel_and_sdist_reject_ambiguous_paths_and_normalize_security_checks(
        self,
    ) -> None:
        license_bytes = b"canonical license\n"
        notices_bytes = b"canonical notices\n"
        unsafe_entries = (
            ("/absolute.txt", b"absolute"),
            ("C:/drive.txt", b"drive"),
            ("pkg/../escape.txt", b"parent"),
            ("pkg/./dot.txt", b"dot"),
            ("pkg//empty.txt", b"empty"),
            ("pkg\\backslash.txt", b"backslash"),
            ("pkg/control\nname.txt", b"control"),
            ("pkg/data.txt", b"one"),
            ("pkg/alias/../data.txt", b"two"),
            ("jacs/src/crypt/ignored/../debug.txt", b"transcript"),
        )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "paths.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)
                for name, data in unsafe_entries:
                    archive.writestr(name, data)

            sdist = root / "paths.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                    *unsafe_entries,
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            for archive in (wheel, sdist):
                with self.subTest(archive=archive.name):
                    errors = inventory.inventory_errors(
                        archive, license_bytes, notices_bytes
                    )
                    rendered = "\n".join(errors)
                    for name, _ in unsafe_entries[:7]:
                        self.assertIn(repr(name), rendered)
                    self.assertIn(
                        "duplicate normalized archive path: pkg/data.txt", errors
                    )
                    self.assertIn(
                        "debug signature transcript must not ship: "
                        "jacs/src/crypt/debug.txt",
                        errors,
                    )

    def test_normal_archive_paths_and_directory_markers_remain_valid(self) -> None:
        license_bytes = b"L"
        notices_bytes = b"N"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "valid-paths.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pkg/", b"")
                archive.writestr("pkg/LICENSE-APACHE", license_bytes)
                archive.writestr("pkg/THIRD-PARTY-NOTICES", notices_bytes)

            sdist = root / "valid-paths.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                directory_info = tarfile.TarInfo("pkg/")
                directory_info.type = tarfile.DIRTYPE
                archive.addfile(directory_info)
                for name, data in (
                    ("pkg/LICENSE-APACHE", license_bytes),
                    ("pkg/THIRD-PARTY-NOTICES", notices_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            for archive in (wheel, sdist):
                with self.subTest(archive=archive.name):
                    self.assertEqual(
                        inventory.inventory_errors(
                            archive, license_bytes, notices_bytes
                        ),
                        [],
                    )

    def test_pypi_release_checks_wheels_and_source_distribution(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release-pypi.yml").read_text()
        self.assertGreaterEqual(workflow.count("check_python_package_inventory.py"), 2)
        self.assertGreaterEqual(workflow.count("--notices THIRD-PARTY-NOTICES"), 2)
        self.assertIn("jacspy/dist/*.whl", workflow)
        self.assertIn("jacspy/dist/*.tar.gz", workflow)

        pyproject = (ROOT / "jacspy/pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn('include = ["jacs/THIRD-PARTY-NOTICES"]', pyproject)


if __name__ == "__main__":
    unittest.main()
