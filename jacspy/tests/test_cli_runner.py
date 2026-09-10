"""Tests for the Python CLI launcher wrapper."""

import hashlib
import io
import os
import socket
import struct
import tarfile
import threading
import types
import zipfile
from pathlib import Path

import pytest

import jacs.cli_runner as cli_runner


def test_platform_key_linux_x64(monkeypatch):
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli_runner.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(cli_runner.platform, "libc_ver", lambda: ("glibc", "2.38"))
    assert cli_runner._platform_key() == "linux-x64"


def test_release_base_override_accepts_exact_loopback(monkeypatch):
    monkeypatch.setenv(
        "JACS_CLI_RELEASE_BASE_URL", "http://127.0.0.1:43123/staged/"
    )

    assert (
        cli_runner._release_base("0.11.4")
        == "http://127.0.0.1:43123/staged"
    )


def test_release_base_override_rejects_untrusted_host(monkeypatch):
    monkeypatch.setenv("JACS_CLI_RELEASE_BASE_URL", "https://example.com/staged")

    with pytest.raises(ValueError, match="release base"):
        cli_runner._release_base("0.11.4")


def test_platform_key_rejects_musl_without_published_cli_asset(monkeypatch):
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli_runner.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(cli_runner.platform, "libc_ver", lambda: ("musl", "1.2.5"))

    assert cli_runner._platform_key() is None
    assert "musl" in cli_runner._unsupported_platform_reason().lower()


def test_ensure_cli_returns_none_for_unsupported_platform(monkeypatch):
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: None)
    assert cli_runner.ensure_cli() is None


def test_main_exits_one_when_cli_unavailable(monkeypatch, capsys):
    monkeypatch.setattr(cli_runner, "ensure_cli", lambda: None)
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")
    # The hint honors CARGO_HOME (set in the manylinux builder image); pin the
    # default so the expected path is deterministic.
    monkeypatch.delenv("CARGO_HOME", raising=False)

    with pytest.raises(SystemExit) as exc:
        cli_runner.main()

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert str(Path.home() / ".cargo" / "bin" / "jacs") in stderr
    assert "virtual environment" in stderr


def test_main_forwards_args_to_downloaded_cli(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli_runner, "ensure_cli", lambda: "/tmp/fake-jacs-cli")

    def fake_run(args):
        captured["args"] = args
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_runner.sys, "argv", ["jacs", "mcp", "install", "--dry-run"])

    with pytest.raises(SystemExit) as exc:
        cli_runner.main()

    assert exc.value.code == 0
    assert captured["args"] == ["/tmp/fake-jacs-cli", "mcp", "install", "--dry-run"]


def _write_tar_gz(path: Path, members):
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(data))


def test_ensure_cli_downloads_and_verifies_archive(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")

    asset_name = "jacs-cli-0.9.3-test-linux-x64.tar.gz"
    archive_path = tmp_path / asset_name
    _write_tar_gz(archive_path, [("jacs-cli", b"#!/bin/sh\necho verified\n")])
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()

    def fake_download(url, dest, **_kwargs):
        dest_path = Path(dest)
        if url.endswith("sha256sums.txt") or url.endswith(".sha256"):
            dest_path.write_text(f"{digest}  {asset_name}\n", encoding="utf-8")
        else:
            dest_path.write_bytes(archive_path.read_bytes())

    monkeypatch.setattr(cli_runner, "_download", fake_download)

    cli_path = cli_runner.ensure_cli()
    assert cli_path == str(
        tmp_path / "cache" / "0.9.3-test" / "linux-x64" / "jacs-cli"
    )
    assert Path(cli_path).read_bytes() == b"#!/bin/sh\necho verified\n"


def test_ensure_cli_rejects_checksum_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")

    asset_name = "jacs-cli-0.9.3-test-linux-x64.tar.gz"
    archive_path = tmp_path / asset_name
    _write_tar_gz(archive_path, [("jacs-cli", b"#!/bin/sh\necho mismatch\n")])

    def fake_download(url, dest, **_kwargs):
        dest_path = Path(dest)
        if url.endswith("sha256sums.txt") or url.endswith(".sha256"):
            dest_path.write_text(f"{'0' * 64}  {asset_name}\n", encoding="utf-8")
        else:
            dest_path.write_bytes(archive_path.read_bytes())

    monkeypatch.setattr(cli_runner, "_download", fake_download)

    assert cli_runner.ensure_cli() is None
    assert not (
        tmp_path / "cache" / "0.9.3-test" / "linux-x64" / "jacs-cli"
    ).exists()


def test_ensure_cli_requires_checksum_before_archive_download(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")
    requested = []

    def unavailable_checksum(url, _dest, **_kwargs):
        requested.append(url)
        raise OSError("checksum unavailable")

    monkeypatch.setattr(cli_runner, "_download", unavailable_checksum)

    assert cli_runner.ensure_cli() is None
    assert requested == [
        "https://github.com/HumanAssisted/JACS/releases/download/cli/v0.9.3-test/sha256sums.txt",
        "https://github.com/HumanAssisted/JACS/releases/download/cli/v0.9.3-test/"
        "jacs-cli-0.9.3-test-linux-x64.tar.gz.sha256",
    ]
    assert not (
        tmp_path / "cache" / "0.9.3-test" / "linux-x64" / "jacs-cli"
    ).exists()


def test_ensure_cli_rejects_unsafe_archive_members(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")

    asset_name = "jacs-cli-0.9.3-test-linux-x64.tar.gz"
    archive_path = tmp_path / asset_name
    _write_tar_gz(
        archive_path,
        [
            ("../../escape", b"nope"),
            ("jacs-cli", b"#!/bin/sh\necho unsafe\n"),
        ],
    )
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()

    def fake_download(url, dest, **_kwargs):
        dest_path = Path(dest)
        if url.endswith("sha256sums.txt") or url.endswith(".sha256"):
            dest_path.write_text(f"{digest}  {asset_name}\n", encoding="utf-8")
        else:
            dest_path.write_bytes(archive_path.read_bytes())

    monkeypatch.setattr(cli_runner, "_download", fake_download)

    assert cli_runner.ensure_cli() is None
    assert not (
        tmp_path / "cache" / "0.9.3-test" / "linux-x64" / "jacs-cli"
    ).exists()


def test_checksum_download_falls_back_to_per_asset_file(monkeypatch, tmp_path):
    destination = tmp_path / "checksum"
    requested = []

    def fake_download(url, dest, **_kwargs):
        requested.append(url)
        if url.endswith("sha256sums.txt"):
            raise OSError("manifest unavailable")
        Path(dest).write_text(f"{'a' * 64}\n", encoding="utf-8")

    monkeypatch.setattr(cli_runner, "_download", fake_download)
    selected = cli_runner._download_checksum(
        "https://example.test/release",
        "https://example.test/release/asset.tar.gz",
        destination,
    )

    assert selected.endswith("asset.tar.gz.sha256")
    assert requested == [
        "https://example.test/release/sha256sums.txt",
        "https://example.test/release/asset.tar.gz.sha256",
    ]


def test_checksum_download_falls_back_when_manifest_omits_asset(monkeypatch, tmp_path):
    destination = tmp_path / "checksum"
    requested = []
    digest = "a" * 64

    def fake_download(url, dest, **_kwargs):
        requested.append(url)
        if url.endswith("sha256sums.txt"):
            Path(dest).write_text(f"{'b' * 64}  other.tar.gz\n", encoding="utf-8")
        else:
            Path(dest).write_text(f"{digest}\n", encoding="utf-8")

    monkeypatch.setattr(cli_runner, "_download", fake_download)
    selected = cli_runner._download_checksum(
        "https://example.test/release",
        "https://example.test/release/asset.tar.gz",
        destination,
    )

    assert selected.endswith("asset.tar.gz.sha256")
    assert cli_runner._read_expected_sha256(destination, "asset.tar.gz") == digest
    assert len(requested) == 2


def test_checksum_download_rejects_conflicting_asset_hashes_without_fallback(
    monkeypatch, tmp_path
):
    destination = tmp_path / "checksum"
    requested = []

    def fake_download(url, dest, **_kwargs):
        requested.append(url)
        Path(dest).write_text(
            f"{'a' * 64}  asset.tar.gz\n{'b' * 64}  asset.tar.gz\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(cli_runner, "_download", fake_download)

    with pytest.raises(ValueError, match="Conflicting checksums"):
        cli_runner._download_checksum(
            "https://example.test/release",
            "https://example.test/release/asset.tar.gz",
            destination,
        )

    assert requested == ["https://example.test/release/sha256sums.txt"]
    assert not destination.exists()


class _FakeResponse:
    def __init__(self, body=b"", status=200, headers=None, on_read=None):
        self.status = status
        self.headers = headers or {}
        self._body = io.BytesIO(body)
        self._on_read = on_read
        self.closed = False

    def read(self, size=-1):
        if self._on_read is not None:
            self._on_read()
        return self._body.read(size)

    def close(self):
        self.closed = True


def test_download_follows_approved_redirect_and_streams_atomically(monkeypatch, tmp_path):
    requested = []
    responses = iter(
        [
            _FakeResponse(
                status=302,
                headers={
                    "Location": "https://release-assets.githubusercontent.com/release/asset"
                },
            ),
            _FakeResponse(body=b"verified", headers={"Content-Length": "8"}),
        ]
    )

    def fake_open(url, timeout):
        requested.append((url, timeout))
        return next(responses)

    monkeypatch.setattr(cli_runner, "_open_url", fake_open)
    destination = tmp_path / "asset.tar.gz"

    final_url = cli_runner._download(
        "https://github.com/HumanAssisted/JACS/releases/asset",
        destination,
        max_bytes=16,
    )

    assert final_url == "https://release-assets.githubusercontent.com/release/asset"
    assert destination.read_bytes() == b"verified"
    assert [url for url, _timeout in requested] == [
        "https://github.com/HumanAssisted/JACS/releases/asset",
        "https://release-assets.githubusercontent.com/release/asset",
    ]
    assert not list(tmp_path.glob(".*.download-*"))


def test_remote_download_rejects_redirect_to_loopback(monkeypatch, tmp_path):
    response = _FakeResponse(
        status=302,
        headers={"Location": "http://127.0.0.1:2375/containers/json"},
    )
    calls = []

    def fake_open(url, _timeout):
        calls.append(url)
        return response

    monkeypatch.setattr(cli_runner, "_open_url", fake_open)

    with pytest.raises(ValueError, match="redirect context"):
        cli_runner._download(
            "https://github.com/HumanAssisted/JACS/releases/asset",
            tmp_path / "download",
            max_bytes=16,
        )

    assert calls == ["https://github.com/HumanAssisted/JACS/releases/asset"]


@pytest.mark.parametrize(
    "location",
    [
        "http://localhost:8765/next",
        "http://127.0.0.1:8766/next",
        "https://github.com/HumanAssisted/JACS/releases/asset",
    ],
)
def test_loopback_download_redirect_must_stay_same_origin(
    monkeypatch, tmp_path, location
):
    response = _FakeResponse(status=302, headers={"Location": location})
    monkeypatch.setattr(cli_runner, "_open_url", lambda _url, _timeout: response)

    with pytest.raises(ValueError, match="redirect context"):
        cli_runner._download(
            "http://127.0.0.1:8765/start", tmp_path / "download", max_bytes=16
        )


@pytest.mark.parametrize(
    "unsafe_location",
    [
        "http://10.0.0.1/private",
        "https://127.0.0.1/private",
        "https://user:password@github.com/private",
        "https://github.com.evil.example/private",
    ],
)
def test_download_rejects_redirects_to_private_or_credentialed_origins(
    monkeypatch, tmp_path, unsafe_location
):
    response = _FakeResponse(status=302, headers={"Location": unsafe_location})
    monkeypatch.setattr(cli_runner, "_open_url", lambda _url, _timeout: response)
    destination = tmp_path / "download"

    with pytest.raises(ValueError, match="unsafe CLI download URL"):
        cli_runner._download(
            "http://127.0.0.1:8765/release", destination, max_bytes=16
        )

    assert response.closed
    assert not destination.exists()
    assert not list(tmp_path.glob(".*.download-*"))


def test_download_rejects_credentialed_initial_url_without_network(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli_runner,
        "_open_url",
        lambda _url, _timeout: pytest.fail("unsafe URL reached network opener"),
    )

    with pytest.raises(ValueError, match="unsafe CLI download URL") as error:
        cli_runner._download(
            "https://user:password@github.com/release", tmp_path / "download"
        )
    assert "user" not in str(error.value)
    assert "password" not in str(error.value)


def test_download_enforces_redirect_limit(monkeypatch, tmp_path):
    calls = []

    def redirect_forever(url, _timeout):
        calls.append(url)
        return _FakeResponse(status=302, headers={"Location": "/next"})

    monkeypatch.setattr(cli_runner, "_open_url", redirect_forever)

    with pytest.raises(RuntimeError, match="exceeded 5 redirects"):
        cli_runner._download(
            "http://localhost:8765/start", tmp_path / "download", max_bytes=16
        )

    assert len(calls) == cli_runner.MAX_REDIRECTS + 1
    assert not list(tmp_path.glob(".*.download-*"))


def test_download_rejects_oversized_declared_length_before_streaming(
    monkeypatch, tmp_path
):
    response = _FakeResponse(body=b"small", headers={"Content-Length": "9"})
    monkeypatch.setattr(cli_runner, "_open_url", lambda _url, _timeout: response)

    with pytest.raises(ValueError, match="exceeded 8 byte limit"):
        cli_runner._download(
            "http://localhost:8765/asset", tmp_path / "download", max_bytes=8
        )

    assert response.closed
    assert not (tmp_path / "download").exists()


def test_download_rejects_oversized_stream_and_removes_partial(monkeypatch, tmp_path):
    response = _FakeResponse(body=b"123456789")
    monkeypatch.setattr(cli_runner, "_open_url", lambda _url, _timeout: response)

    with pytest.raises(ValueError, match="exceeded 8 byte limit"):
        cli_runner._download(
            "http://[::1]:8765/asset", tmp_path / "download", max_bytes=8
        )

    assert not (tmp_path / "download").exists()
    assert not list(tmp_path.glob(".*.download-*"))


def test_download_enforces_total_timeout_and_removes_partial(monkeypatch, tmp_path):
    clock = {"now": 0.0}

    def advance_clock():
        clock["now"] = 2.0

    response = _FakeResponse(body=b"late", on_read=advance_clock)
    monkeypatch.setattr(cli_runner.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(cli_runner, "_open_url", lambda _url, _timeout: response)

    with pytest.raises(TimeoutError, match="total timeout"):
        cli_runner._download(
            "http://localhost:8765/asset",
            tmp_path / "download",
            max_bytes=8,
            total_timeout=1.0,
        )

    assert not (tmp_path / "download").exists()
    assert not list(tmp_path.glob(".*.download-*"))


def test_download_applies_connect_timeout_and_cleans_up(monkeypatch, tmp_path):
    observed = {}

    def timed_out(_url, timeout):
        observed["timeout"] = timeout
        raise socket.timeout("connect timed out")

    monkeypatch.setattr(cli_runner, "_open_url", timed_out)

    with pytest.raises(TimeoutError, match="connect timed out"):
        cli_runner._download(
            "http://localhost:8765/asset",
            tmp_path / "download",
            connect_timeout=0.25,
        )

    assert observed["timeout"] == pytest.approx(0.25)
    assert not (tmp_path / "download").exists()
    assert not list(tmp_path.glob(".*.download-*"))


def test_bounded_decompression_rejects_hidden_metadata_expansion():
    reader = cli_runner._BoundedDecompressedReader(io.BytesIO(b"12345"), 4)

    with pytest.raises(ValueError, match="expansion limit"):
        reader.read()


def test_tar_extraction_rejects_uncompressed_expansion(monkeypatch, tmp_path):
    archive = tmp_path / "archive.tar.gz"
    _write_tar_gz(archive, [("jacs-cli", b"12345")])
    monkeypatch.setattr(cli_runner, "MAX_EXTRACTED_BYTES", 4)

    with pytest.raises(ValueError, match="expansion limit"):
        cli_runner._extract_archive_binary(
            archive, tmp_path / "extract", "jacs-cli", False
        )


def test_tar_extraction_rejects_member_count(monkeypatch, tmp_path):
    archive = tmp_path / "archive.tar.gz"
    _write_tar_gz(archive, [("README", b"docs"), ("jacs-cli", b"binary")])
    monkeypatch.setattr(cli_runner, "MAX_ARCHIVE_MEMBERS", 1)
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="member limit"):
        cli_runner._extract_archive_binary(archive, extract_dir, "jacs-cli", False)

    assert not (extract_dir / "jacs-cli").exists()


def test_tar_extraction_rejects_symlink_even_when_not_candidate(tmp_path):
    archive = tmp_path / "archive.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        link = tarfile.TarInfo("redirect")
        link.type = tarfile.SYMTYPE
        link.linkname = "jacs-cli"
        tf.addfile(link)
        binary = tarfile.TarInfo("jacs-cli")
        binary.size = 6
        tf.addfile(binary, io.BytesIO(b"binary"))
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="link is not allowed"):
        cli_runner._extract_archive_binary(archive, extract_dir, "jacs-cli", False)

    assert not (extract_dir / "jacs-cli").exists()


def test_tar_extraction_rejects_internal_parent_traversal(tmp_path):
    archive = tmp_path / "archive.tar.gz"
    _write_tar_gz(archive, [("release/../jacs-cli", b"binary")])
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="Unsafe archive member path"):
        cli_runner._extract_archive_binary(archive, extract_dir, "jacs-cli", False)

    assert not (extract_dir / "jacs-cli").exists()


def test_tar_extraction_removes_staged_binary_when_later_member_is_unsafe(tmp_path):
    archive = tmp_path / "archive.tar.gz"
    _write_tar_gz(
        archive,
        [("jacs-cli", b"binary"), ("release/../escape", b"unsafe")],
    )
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="Unsafe archive member path"):
        cli_runner._extract_archive_binary(archive, extract_dir, "jacs-cli", False)

    assert not (extract_dir / "jacs-cli").exists()


def test_zip_extraction_rejects_symlink_and_supports_safe_binary(tmp_path):
    safe_archive = tmp_path / "safe.zip"
    with zipfile.ZipFile(safe_archive, "w") as archive:
        archive.writestr("release/jacs-cli.exe", b"binary")
    extract_dir = tmp_path / "safe-extract"
    extract_dir.mkdir()

    extracted = cli_runner._extract_archive_binary(
        safe_archive, extract_dir, "jacs-cli.exe", True
    )
    assert Path(extracted).read_bytes() == b"binary"

    unsafe_archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe_archive, "w") as archive:
        link = zipfile.ZipInfo("redirect")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "jacs-cli.exe")
        archive.writestr("jacs-cli.exe", b"binary")
    unsafe_dir = tmp_path / "unsafe-extract"
    unsafe_dir.mkdir()

    with pytest.raises(ValueError, match="symlink is not allowed"):
        cli_runner._extract_archive_binary(
            unsafe_archive, unsafe_dir, "jacs-cli.exe", True
        )


def _rewrite_zip_eocd(path, *, disk_entries=None, total_entries=None, cd_size=None):
    contents = bytearray(path.read_bytes())
    eocd = contents.rfind(b"PK\x05\x06")
    assert eocd >= 0
    if disk_entries is not None:
        struct.pack_into("<H", contents, eocd + 8, disk_entries)
    if total_entries is not None:
        struct.pack_into("<H", contents, eocd + 10, total_entries)
    if cd_size is not None:
        struct.pack_into("<I", contents, eocd + 12, cd_size)
    path.write_bytes(contents)


def test_zip_preflight_rejects_declared_member_count_before_infolist(
    monkeypatch, tmp_path
):
    archive_path = tmp_path / "many.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("jacs-cli.exe", b"binary")
    _rewrite_zip_eocd(
        archive_path,
        disk_entries=cli_runner.MAX_ARCHIVE_MEMBERS + 1,
        total_entries=cli_runner.MAX_ARCHIVE_MEMBERS + 1,
    )
    monkeypatch.setattr(
        zipfile,
        "ZipFile",
        lambda *_args, **_kwargs: pytest.fail("ZipFile parsed before preflight"),
    )

    with pytest.raises(ValueError, match="member limit"):
        cli_runner._extract_archive_binary(
            archive_path, tmp_path, "jacs-cli.exe", True
        )


def test_zip_preflight_rejects_central_directory_size_before_infolist(
    monkeypatch, tmp_path
):
    archive_path = tmp_path / "metadata.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("jacs-cli.exe", b"binary")
    monkeypatch.setattr(cli_runner, "MAX_ZIP_CENTRAL_DIRECTORY_BYTES", 1)

    with pytest.raises(ValueError, match="central directory"):
        cli_runner._extract_archive_binary(
            archive_path, tmp_path, "jacs-cli.exe", True
        )


def test_zip_preflight_counts_records_instead_of_trusting_eocd(monkeypatch, tmp_path):
    archive_path = tmp_path / "lying-count.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("README", b"docs")
        archive.writestr("jacs-cli.exe", b"binary")
    _rewrite_zip_eocd(archive_path, disk_entries=1, total_entries=1)
    monkeypatch.setattr(cli_runner, "MAX_ARCHIVE_MEMBERS", 1)

    with pytest.raises(ValueError, match="member limit"):
        cli_runner._extract_archive_binary(
            archive_path, tmp_path, "jacs-cli.exe", True
        )


def test_ensure_cli_rejects_preexisting_cached_symlink(monkeypatch, tmp_path):
    cache_root = tmp_path / "cache"
    cache = cache_root / "0.9.3-test" / "linux-x64"
    cache.mkdir(parents=True)
    host_binary = tmp_path / "host-jacs"
    host_binary.write_bytes(b"untrusted host binary")
    os.symlink(host_binary, cache / "jacs-cli")
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: cache_root)
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")

    assert cli_runner.ensure_cli() is None
    assert (cache / "jacs-cli").is_symlink()


def test_ensure_cli_rejects_symlink_in_cache_parent_component(monkeypatch, tmp_path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    cache_root = linked_parent / "nested" / "cache"
    downloads = []

    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: cache_root)
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        cli_runner,
        "_download",
        lambda *_args, **_kwargs: downloads.append(True),
    )

    assert cli_runner.ensure_cli() is None
    assert downloads == []
    assert not (real_parent / "nested").exists()


def test_concurrent_safe_cache_directory_creation_converges(tmp_path):
    cache_root = tmp_path / "cache-root"
    target = cache_root / "0.9.3-test" / "linux-x64"
    barrier = threading.Barrier(8)
    failures = []

    def create_cache():
        barrier.wait()
        try:
            cli_runner._ensure_safe_cache_directory(cache_root, target)
        except Exception as error:  # pragma: no cover - asserted below
            failures.append(error)

    workers = [threading.Thread(target=create_cache) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert failures == []
    assert target.is_dir()
    if os.name != "nt":
        for component in (cache_root, cache_root / "0.9.3-test", target):
            assert os.lstat(component).st_mode & 0o777 == 0o700


def test_atomic_install_refuses_destination_created_during_copy(
    monkeypatch, tmp_path
):
    source = tmp_path / "source"
    destination = tmp_path / "jacs-cli"
    source.write_bytes(b"verified executable")
    original_copy = cli_runner._copy_limited

    def copy_then_race(source_file, destination_file, expected_size):
        original_copy(source_file, destination_file, expected_size)
        destination.write_bytes(b"racing process won")

    monkeypatch.setattr(cli_runner, "_copy_limited", copy_then_race)

    with pytest.raises(FileExistsError, match="Refusing to replace"):
        cli_runner._install_binary_atomically(source, destination, False)

    assert destination.read_bytes() == b"racing process won"


def test_ensure_cli_does_not_reuse_binary_from_another_package_version(
    monkeypatch, tmp_path
):
    cache_root = tmp_path / "cache"
    old_cache = cache_root / "0.9.2" / "linux-x64"
    old_cache.mkdir(parents=True)
    old_binary = old_cache / "jacs-cli"
    old_binary.write_bytes(b"old host binary")
    old_binary.chmod(0o700)
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: cache_root)
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: None)

    assert cli_runner.ensure_cli() is None
    assert old_binary.read_bytes() == b"old host binary"


def test_ensure_cli_does_not_reuse_binary_from_another_platform(
    monkeypatch, tmp_path
):
    cache_root = tmp_path / "cache"
    wrong_cache = cache_root / "0.9.3-test" / "darwin-arm64"
    wrong_cache.mkdir(parents=True)
    wrong_binary = wrong_cache / "jacs-cli"
    wrong_binary.write_bytes(b"wrong architecture")
    wrong_binary.chmod(0o700)
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: cache_root)
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        cli_runner,
        "_download",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )

    assert cli_runner.ensure_cli() is None
    assert wrong_binary.read_bytes() == b"wrong architecture"
