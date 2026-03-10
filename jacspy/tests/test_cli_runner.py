"""Tests for the Python CLI launcher wrapper."""

import hashlib
import io
import tarfile
import types
from pathlib import Path

import pytest

import jacs.cli_runner as cli_runner


def test_platform_key_linux_x64(monkeypatch):
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli_runner.platform, "machine", lambda: "x86_64")
    assert cli_runner._platform_key() == "linux-x64"


def test_ensure_cli_returns_none_for_unsupported_platform(monkeypatch):
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: None)
    assert cli_runner.ensure_cli() is None


def test_main_exits_one_when_cli_unavailable(monkeypatch):
    monkeypatch.setattr(cli_runner, "ensure_cli", lambda: None)

    with pytest.raises(SystemExit) as exc:
        cli_runner.main()

    assert exc.value.code == 1


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

    def fake_download(url, dest):
        dest_path = Path(dest)
        if url.endswith(".sha256"):
            dest_path.write_text(f"{digest}  {asset_name}\n", encoding="utf-8")
        else:
            dest_path.write_bytes(archive_path.read_bytes())

    monkeypatch.setattr(cli_runner, "_download", fake_download)

    cli_path = cli_runner.ensure_cli()
    assert cli_path == str(tmp_path / "cache" / "jacs-cli")
    assert Path(cli_path).read_bytes() == b"#!/bin/sh\necho verified\n"


def test_ensure_cli_rejects_checksum_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_runner, "_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(cli_runner, "_get_version", lambda: "0.9.3-test")
    monkeypatch.setattr(cli_runner, "_platform_key", lambda: "linux-x64")
    monkeypatch.setattr(cli_runner.platform, "system", lambda: "Linux")

    asset_name = "jacs-cli-0.9.3-test-linux-x64.tar.gz"
    archive_path = tmp_path / asset_name
    _write_tar_gz(archive_path, [("jacs-cli", b"#!/bin/sh\necho mismatch\n")])

    def fake_download(url, dest):
        dest_path = Path(dest)
        if url.endswith(".sha256"):
            dest_path.write_text(f"{'0' * 64}  {asset_name}\n", encoding="utf-8")
        else:
            dest_path.write_bytes(archive_path.read_bytes())

    monkeypatch.setattr(cli_runner, "_download", fake_download)

    assert cli_runner.ensure_cli() is None
    assert not (tmp_path / "cache" / "jacs-cli").exists()


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

    def fake_download(url, dest):
        dest_path = Path(dest)
        if url.endswith(".sha256"):
            dest_path.write_text(f"{digest}  {asset_name}\n", encoding="utf-8")
        else:
            dest_path.write_bytes(archive_path.read_bytes())

    monkeypatch.setattr(cli_runner, "_download", fake_download)

    assert cli_runner.ensure_cli() is None
    assert not (tmp_path / "cache" / "jacs-cli").exists()
