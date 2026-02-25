"""Tests for the Python CLI launcher wrapper."""

import types

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
